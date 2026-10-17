#pragma once
#include "analysis_types.hpp"
#include <algorithm>
#include <map>

namespace wea {
struct TlsCallback {
    std::uint32_t index = 0, slotRva = 0;
    std::uint64_t targetVa = 0;
    std::optional<std::uint32_t> targetRva, duplicateOf;
    bool executableFileBacked = false, eligible = false;
    std::vector<std::string> issues;
};
struct TlsDirectory {
    static constexpr std::size_t callbackLimit = 4096;
    std::uint32_t rva = 0, size = 0;
    unsigned pointerSize = 0, headerSize = 0;
    bool headerRead = false, partial = false, malformed = false, terminated = false;
    std::string status = "absent";
    std::uint64_t rawDataStartVa = 0, rawDataEndVa = 0, indexVa = 0, callbacksVa = 0;
    std::uint32_t zeroFill = 0, characteristics = 0;
    std::optional<std::uint32_t> callbacksFieldRva, arrayRva, terminatorRva;
    std::vector<std::string> issues;
    std::vector<TlsCallback> callbacks;
};

// PE data directory 9 is an RVA/size pair; TLS address fields and callback
// values are preferred VAs. Do not apply relocations or infer live addresses.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-directory
// Image provides checked file readers and an already validated x86/x64 PE map.
template<class Image>
TlsDirectory parseTlsDirectory(const Image& pe, DiagnosticLog& log) {
    TlsDirectory out;
    out.pointerSize = pe.is64 ? 8 : 4;
    out.headerSize = out.pointerSize * 4 + 8;
    if (pe.directories.size() <= 9) return out;
    out.rva = pe.directories[9].first; out.size = pe.directories[9].second;
    if (!out.rva && !out.size) return out;
    auto emit = [&](DiagnosticCode code, const std::string& issue, std::uint32_t rva) {
        log.add(code, "tls", issue, Location{pe.moduleId, Address(Rva(rva))});
    };
    auto problem = [&](const std::string& text, DiagnosticCode code = DiagnosticCode::InvalidMetadata) {
        out.issues.push_back(text);
        if (code == DiagnosticCode::InvalidMetadata) out.malformed = true;
        emit(code, text, out.rva);
    };
    auto backed = [&](std::uint64_t at, std::uint64_t size, bool executable = false) {
        if (!size || at >= rvaEnd || size > rvaEnd - at || at + size > pe.imageSize) return false;
        // 32-bit preferred-address arithmetic must not wrap at the image edge.
        if (!pe.is64 && (pe.imageBase >= rvaEnd || at + size > rvaEnd - pe.imageBase)) return false;
        const auto end = at + size;
        while (at < end) {
            const auto n = pe.available(static_cast<std::uint32_t>(at), executable);
            if (!n) return false;
            at += std::min<std::uint64_t>(n, end - at);
        }
        return true;
    };
    auto read = [&](std::uint64_t at, unsigned width) {
        if (!backed(at, width)) throw std::out_of_range("TLS read outside file-backed image");
        std::uint64_t value = 0;
        for (unsigned j = 0; j < width; ++j)
            value |= std::uint64_t(pe.data.at(pe.offset(static_cast<std::uint32_t>(at+j), 1))) << (8*j);
        return value;
    };
    auto rvaOf = [&](std::uint64_t va) -> std::optional<std::uint32_t> {
        if (va < pe.imageBase || va - pe.imageBase >= rvaEnd || va - pe.imageBase >= pe.imageSize)
            return std::nullopt;
        return static_cast<std::uint32_t>(va - pe.imageBase);
    };
    if (!out.rva || out.size < out.headerSize) {
        problem("tls_directory_incomplete_or_short"); out.status = "malformed"; return out;
    }
    if (std::uint64_t(out.rva) + out.size > rvaEnd ||
        std::uint64_t(out.rva) + out.size > pe.imageSize) {
        problem("tls_directory_outside_image"); out.status = "malformed"; return out;
    }
    if (!backed(out.rva, out.headerSize)) {
        problem("tls_header_not_file_backed"); out.partial = true; out.status = "partial"; return out;
    }
    if (!backed(out.rva, out.size)) {
        problem("tls_directory_extent_not_file_backed"); out.partial = true;
    }
    const auto base = std::uint64_t(out.rva); const auto w = out.pointerSize;
    out.rawDataStartVa = read(base, w); out.rawDataEndVa = read(base+w, w);
    out.indexVa = read(base+2*w, w); out.callbacksVa = read(base+3*w, w);
    out.zeroFill = static_cast<std::uint32_t>(read(base+4*w, 4));
    out.characteristics = static_cast<std::uint32_t>(read(base+4*w+4, 4));
    out.callbacksFieldRva = static_cast<std::uint32_t>(base+3*w); out.headerRead = true;
    // A null array pointer is recorded as absent, not dereferenced and not
    // confused with a readable array containing a null terminator.
    if (!out.callbacksVa) {
        out.status = out.partial ? "partial" : "no_callback_array"; return out;
    }
    out.arrayRva = rvaOf(out.callbacksVa);
    if (!out.arrayRva) {
        problem("tls_callbacks_va_outside_image"); out.status = "malformed"; return out;
    }
    std::map<std::uint64_t, std::uint32_t> seen;
    // Permit an exact-limit array followed by a terminator. At most limit+1
    // pointer slots are read; the look-ahead non-null value is never stored.
    for (std::size_t k = 0; k <= out.callbackLimit; ++k) {
        const auto at = std::uint64_t(*out.arrayRva) + k*w;
        if (!backed(at, w)) {
            problem("tls_callback_array_unterminated_or_unbacked"); out.partial = true; break;
        }
        const auto target = read(at, w);
        if (!target) {
            out.terminated = true; out.terminatorRva = static_cast<std::uint32_t>(at); break;
        }
        if (k == out.callbackLimit) {
            problem("tls_callback_limit_reached", DiagnosticCode::BudgetExhausted); out.partial = true; break;
        }
        TlsCallback c; c.index = static_cast<std::uint32_t>(k);
        c.slotRva = static_cast<std::uint32_t>(at); c.targetVa = target; c.targetRva = rvaOf(target);
        if (!c.targetRva) c.issues.push_back("tls_callback_va_outside_image");
        else {
            c.executableFileBacked = backed(*c.targetRva, 1, true);
            if (!c.executableFileBacked) c.issues.push_back("tls_callback_not_file_backed_executable");
        }
        auto [it, inserted] = seen.emplace(target, c.index);
        if (!inserted) c.duplicateOf = it->second;
        for (const auto& issue : c.issues) { out.malformed = true; emit(DiagnosticCode::InvalidMetadata, issue, c.slotRva); }
        out.callbacks.push_back(std::move(c));
    }
    // A partial array remains visible but contributes no automatic roots.
    // Bad targets do not erase unrelated valid entries in a complete array.
    for (auto& c : out.callbacks)
        c.eligible = out.terminated && out.issues.empty() && c.executableFileBacked && c.issues.empty();
    out.status = out.partial ? "partial" : out.malformed ? "malformed" : "parsed";
    return out;
}
} // namespace wea
