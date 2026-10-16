#pragma once
#include "analysis_types.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <tuple>

namespace wea {
// Raw table facts are deliberately separate from CodeRange's decoded coverage.
struct RuntimeFunctionRecord {
    std::uint32_t index = 0, tableRva = 0;
    std::uint32_t beginRva = 0, endRva = 0, unwindRva = 0;
    bool rangeFileBacked = false, unwindAddressFileBacked = false;
    std::optional<std::uint32_t> duplicateOf, overlapWith;
    std::vector<std::string> issues;
};
struct ExceptionDirectory {
    static constexpr std::size_t recordLimit = 65536;
    std::uint32_t rva = 0, size = 0, declaredRecords = 0, trailingBytes = 0;
    bool supported = false, malformed = false, partial = false;
    std::string status = "absent";
    std::vector<std::string> issues;
    std::vector<RuntimeFunctionRecord> records;
};

// Image supplies the already-validated PE address map and bounded file readers.
// See Microsoft PE/COFF .pdata and x64 exception-handling RUNTIME_FUNCTION docs.
// This slice validates the table/range addresses, NOT unwind-code semantics.
// It never follows unwind links and never adds disassembly roots.
template<class Image>
ExceptionDirectory parseExceptionDirectory(const Image& pe, DiagnosticLog& log) {
    ExceptionDirectory out;
    out.supported = pe.is64; // PE::parse only sets this for AMD64 + PE32+.
    if (pe.directories.size() <= 3) return out;
    std::tie(out.rva, out.size) = pe.directories[3];
    if (!out.rva && !out.size) return out;
    auto report = [&](DiagnosticCode code, const std::string& issue, std::uint32_t at) {
        log.add(code, "exception_directory", issue,
                Location{pe.moduleId, Address(Rva(at))});
    };
    auto tableIssue = [&](const std::string& issue, DiagnosticCode code = DiagnosticCode::InvalidMetadata) {
        if (std::find(out.issues.begin(), out.issues.end(), issue) != out.issues.end()) return;
        out.issues.push_back(issue);
        if (code == DiagnosticCode::InvalidMetadata) out.malformed = true;
        report(code, issue, out.rva);
    };
    if (!out.supported) {
        out.status = "unsupported_architecture";
        tableIssue("AMD64 exception-table interpretation is not supported for this machine",
                   DiagnosticCode::UnsupportedFeature);
        return out;
    }
    out.declaredRecords = out.size / 12;
    out.trailingBytes = out.size % 12;
    if (!out.rva || !out.size) {
        tableIssue("exception_directory_incomplete_pair");
        out.status = "malformed";
        return out;
    }
    const std::uint64_t tableEnd = std::uint64_t(out.rva) + out.size;
    if (tableEnd > rvaEnd || tableEnd > pe.imageSize) {
        tableIssue("exception_directory_outside_image");
        out.partial = out.declaredRecords != 0;
        out.status = "malformed";
        return out;
    }
    if (out.rva % 4) tableIssue("exception_directory_unaligned");
    if (out.trailingBytes) tableIssue("exception_directory_trailing_bytes");

    // Support adjacent RVA regions even when their bytes are not adjacent in
    // the file. Never read beyond a mapped span or wrap a 32-bit RVA.
    auto backed = [&](std::uint64_t begin, std::uint64_t end, bool executable) {
        if (begin >= end || end > pe.imageSize || end > rvaEnd) return false;
        while (begin < end) {
            const auto count = pe.available(static_cast<std::uint32_t>(begin), executable);
            if (!count) return false;
            begin += std::min<std::uint64_t>(count, end - begin);
        }
        return true;
    };
    auto readRecord = [&](std::uint32_t at) {
        std::array<std::uint8_t, 12> bytes{};
        std::size_t copied = 0;
        while (copied < bytes.size()) {
            const auto cursor = static_cast<std::uint32_t>(std::uint64_t(at) + copied);
            const auto n = std::min<std::size_t>(pe.available(cursor), bytes.size() - copied);
            const auto offset = pe.offset(cursor, n);
            std::copy_n(pe.data.begin() + offset, n, bytes.begin() + copied);
            copied += n;
        }
        return bytes;
    };
    auto recordIssue = [&](RuntimeFunctionRecord& r, const std::string& issue) {
        if (std::find(r.issues.begin(), r.issues.end(), issue) == r.issues.end()) {
            r.issues.push_back(issue);
            out.malformed = true;
            report(DiagnosticCode::InvalidMetadata, issue, r.tableRva);
        }
    };
    if (!backed(out.rva, tableEnd, false)) {
        tableIssue("exception_directory_not_file_backed");
        out.partial = true;
    }
    const auto count = std::min<std::size_t>(out.declaredRecords, out.recordLimit);
    out.records.reserve(count);
    for (std::size_t k = 0; k < count; ++k) {
        const auto at = static_cast<std::uint32_t>(std::uint64_t(out.rva) + k * 12);
        if (!backed(at, std::uint64_t(at) + 12, false)) {
            tableIssue("exception_directory_not_file_backed");
            out.partial = true;
            break; // Keep the readable prefix; never fabricate records from zero-fill.
        }
        const auto bytes = readRecord(at);
        auto word = [&](std::size_t offset) {
            std::uint32_t v = 0;
            for (unsigned j = 0; j < 4; ++j) v |= std::uint32_t(bytes[offset + j]) << (8 * j);
            return v;
        };
        RuntimeFunctionRecord r;
        r.index = static_cast<std::uint32_t>(k); r.tableRva = at;
        r.beginRva = word(0); r.endRva = word(4); r.unwindRva = word(8);
        if (!r.beginRva || r.beginRva >= r.endRva) {
            recordIssue(r, "invalid_half_open_range");
        } else if (r.endRva > pe.imageSize) {
            recordIssue(r, "code_range_outside_image");
        } else {
            r.rangeFileBacked = backed(r.beginRva, r.endRva, true);
            if (!r.rangeFileBacked) recordIssue(r, "code_range_not_file_backed_executable");
        }
        if (!r.unwindRva) recordIssue(r, "null_unwind_rva");
        else if (r.unwindRva % 4) recordIssue(r, "unaligned_or_unsupported_unwind_rva");
        else {
            // Only prove that a minimum four-byte header can be read. Version,
            // opcodes, chained entries, handlers and their targets remain opaque.
            r.unwindAddressFileBacked = backed(r.unwindRva, std::uint64_t(r.unwindRva) + 4, false);
            if (!r.unwindAddressFileBacked) recordIssue(r, "unwind_header_not_file_backed");
        }
        if (!out.records.empty() && r.beginRva < out.records.back().beginRva)
            recordIssue(r, "unsorted_begin_rva");
        out.records.push_back(std::move(r));
    }
    if (out.declaredRecords > out.recordLimit) {
        out.partial = true;
        tableIssue("exception_record_limit_reached", DiagnosticCode::BudgetExhausted);
    }

    // Preserve every raw entry and original table order. Detect duplicate and
    // conflicting ranges in O(n log n), without expanding overlapping pairs.
    using Key = std::tuple<std::uint32_t, std::uint32_t, std::uint32_t>;
    std::map<Key, std::uint32_t> seen;
    std::vector<std::size_t> ordered;
    for (auto& r : out.records) {
        auto [it, added] = seen.emplace(Key{r.beginRva, r.endRva, r.unwindRva}, r.index);
        if (!added) {
            r.duplicateOf = it->second;
            recordIssue(out.records[it->second], "duplicate_runtime_function");
            recordIssue(r, "duplicate_runtime_function");
        } else if (r.beginRva < r.endRva && r.endRva <= pe.imageSize) {
            ordered.push_back(r.index);
        }
    }
    std::sort(ordered.begin(), ordered.end(), [&](auto a, auto b) {
        const auto& x = out.records[a]; const auto& y = out.records[b];
        return std::tie(x.beginRva, x.endRva, x.index) < std::tie(y.beginRva, y.endRva, y.index);
    });
    std::optional<std::size_t> furthest;
    for (auto index : ordered) {
        auto& r = out.records[index];
        if (furthest) {
            auto& other = out.records[*furthest];
            if (r.beginRva < other.endRva) {
                recordIssue(r, "overlapping_runtime_functions");
                recordIssue(other, "overlapping_runtime_functions");
                if (!r.overlapWith) r.overlapWith = other.index;
                if (!other.overlapWith) other.overlapWith = r.index;
            }
            if (r.endRva > other.endRva) furthest = index;
        } else furthest = index;
    }
    out.status = out.partial ? "partial" : out.malformed ? "malformed" : "parsed";
    return out;
}
} // namespace wea
