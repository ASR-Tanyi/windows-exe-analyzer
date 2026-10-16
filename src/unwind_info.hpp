#pragma once
#include "exception_directory.hpp"
#include <limits>

namespace wea {
struct UnwindOperation {
    unsigned slot = 0, offset = 0, opcode = 0, info = 0, slots = 0;
    std::uint64_t operand = 0;
};
struct ChainedFunction {
    std::uint32_t fieldRva = 0, beginRva = 0, endRva = 0, unwindRva = 0;
};
struct UnwindNode {
    std::uint32_t rva = 0;
    unsigned version = 0, flags = 0, prologSize = 0, codeSlots = 0;
    unsigned frameRegister = 0, frameOffset = 0;
    bool headerRead = false;
    std::string status = "not_read";
    std::vector<std::string> issues;
    std::vector<UnwindOperation> operations;
    std::optional<ChainedFunction> chain;
    std::optional<std::uint32_t> handlerRva, handlerFieldRva, handlerDataRva;
};
struct UnwindAssessment {
    std::uint32_t recordIndex = 0;
    std::string status = "not_examined";
    bool eligible = false;
    unsigned chainDepth = 0;
    std::optional<std::uint32_t> primaryBeginRva;
    std::vector<std::string> reasons;
};
struct UnwindLimits {
    std::size_t nodes = 65536, slots = 1048576;
    unsigned chain = 32;
};
struct UnwindCatalog {
    std::size_t nodeLimit = 65536, slotLimit = 1048576;
    unsigned chainLimit = 32;
    bool partial = false;
    std::size_t slotsRead = 0;
    std::map<std::uint32_t, UnwindNode> nodes;
    std::vector<UnwindAssessment> records;
};

// A structural v1 validator, not a stack unwinder or instruction interpreter.
// Specification: https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
// v2/v3 and unknown versions are retained as opaque headers, not read as v1.
template<class Image>
UnwindCatalog parseUnwindInfo(const Image& pe, const ExceptionDirectory& directory,
                             DiagnosticLog& diagnostics, UnwindLimits limits = {}) {
    UnwindCatalog out;
    // Tests may lower limits; callers cannot raise the production ceilings.
    out.nodeLimit = std::min(out.nodeLimit, limits.nodes);
    out.slotLimit = std::min(out.slotLimit, limits.slots);
    out.chainLimit = std::min(out.chainLimit, limits.chain);
    if (!directory.supported || directory.records.empty()) return out;
    auto backed = [&](std::uint64_t at, std::uint64_t size, bool code = false) {
        if (!size || at >= rvaEnd || size > rvaEnd - at || at + size > pe.imageSize)
            return false;
        const auto end = at + size;
        while (at < end) {
            const auto n = pe.available(static_cast<std::uint32_t>(at), code);
            if (!n) return false;
            at += std::min<std::uint64_t>(n, end - at);
        }
        return true;
    };
    auto read = [&](std::uint64_t at, std::size_t size) {
        if (!backed(at, size)) throw std::out_of_range("Unwind read outside image bytes");
        std::vector<std::uint8_t> bytes(size);
        for (std::size_t copied = 0; copied < size;) {
            const auto cursor = static_cast<std::uint32_t>(at + copied);
            const auto n = std::min(pe.available(cursor), size - copied);
            const auto offset = pe.offset(cursor, n);
            std::copy_n(pe.data.begin() + offset, n, bytes.begin() + copied);
            copied += n;
        }
        return bytes;
    };
    auto word = [](const auto& bytes, std::size_t offset, unsigned size) {
        std::uint64_t value = 0;
        for (unsigned i = 0; i < size; ++i) value |= std::uint64_t(bytes.at(offset+i)) << (8*i);
        return value;
    };
    auto emit = [&](DiagnosticCode code, const std::string& text, std::uint32_t at) {
        diagnostics.add(code, "unwind_info", text, Location{pe.moduleId, Address(Rva(at))});
    };
    auto issue = [&](UnwindNode& n, const std::string& text,
                     DiagnosticCode code = DiagnosticCode::InvalidMetadata) {
        if (std::find(n.issues.begin(), n.issues.end(), text) != n.issues.end()) return;
        n.issues.push_back(text);
        if (code == DiagnosticCode::InvalidMetadata) n.status = "invalid";
        else if (n.status != "invalid")
            n.status = code == DiagnosticCode::BudgetExhausted ? "budget_exhausted" : "unsupported";
        if (code == DiagnosticCode::BudgetExhausted) out.partial = true;
        emit(code, text, n.rva);
    };
    auto nonvolatile = [](unsigned reg) {
        return reg == 3 || reg == 5 || reg == 6 || reg == 7 || reg >= 12;
    };
    bool nodeLimitReported = false;
    auto getNode = [&](std::uint32_t rva) -> const UnwindNode* {
        if (auto it = out.nodes.find(rva); it != out.nodes.end()) return &it->second;
        if (out.nodes.size() >= out.nodeLimit) {
            out.partial = true;
            if (!nodeLimitReported) { emit(DiagnosticCode::BudgetExhausted, "unwind_node_limit", rva); nodeLimitReported = true; }
            return nullptr;
        }
        auto& n = out.nodes[rva]; n.rva = rva; n.status = "supported_v1";
        if (!rva || rva % 4 || !backed(rva, 4)) {
            issue(n, "unreadable_or_unaligned_unwind_header"); return &n;
        }
        auto h = read(rva, 4);
        n.headerRead = true; n.version = h[0] & 7; n.flags = h[0] >> 3;
        n.prologSize = h[1]; n.codeSlots = h[2];
        n.frameRegister = h[3] & 15; n.frameOffset = h[3] >> 4;
        if (n.version != 1) {
            issue(n, "unsupported_unwind_version", DiagnosticCode::UnsupportedFeature); return &n;
        }
        if (n.flags & ~7u) {
            issue(n, "unsupported_unwind_flags", DiagnosticCode::UnsupportedFeature); return &n;
        }
        if ((n.flags & 4) && (n.flags & 3)) { issue(n, "chain_and_handler_flags_conflict"); return &n; }
        if ((!n.frameRegister && n.frameOffset) ||
            (n.frameRegister && !nonvolatile(n.frameRegister))) issue(n, "invalid_frame_register");
        const std::size_t arraySize = ((n.codeSlots + 1u) & ~1u) * 2u;
        const auto trailer = std::uint64_t(rva) + 4 + arraySize;
        if (arraySize && !backed(std::uint64_t(rva) + 4, arraySize)) {
            issue(n, "truncated_unwind_slots_or_padding"); return &n;
        }
        if (out.slotsRead + n.codeSlots > out.slotLimit) {
            issue(n, "unwind_slot_limit", DiagnosticCode::BudgetExhausted); return &n;
        }
        out.slotsRead += n.codeSlots;
        const auto codes = arraySize ? read(std::uint64_t(rva) + 4, arraySize) : std::vector<std::uint8_t>{};
        unsigned previousOffset = 256, frameOps = 0;
        for (unsigned slot = 0; slot < n.codeSlots;) {
            UnwindOperation op{slot, codes[slot*2], unsigned(codes[slot*2+1] & 15),
                               unsigned(codes[slot*2+1] >> 4), 1, 0};
            if (op.offset > n.prologSize || op.offset > previousOffset) issue(n, "invalid_unwind_code_offset_order");
            previousOffset = op.offset;
            switch (op.opcode) {
                case 0: case 4: case 5:
                    if (!nonvolatile(op.info)) issue(n, "unsupported_saved_integer_register", DiagnosticCode::UnsupportedFeature);
                    op.slots = op.opcode == 4 ? 2 : op.opcode == 5 ? 3 : 1; break;
                case 1:
                    if (op.info > 1) issue(n, "invalid_alloc_large_info");
                    op.slots = op.info == 0 ? 2 : 3; break;
                case 2: op.operand = op.info * 8 + 8; break;
                case 3:
                    ++frameOps;
                    if (op.info || !n.frameRegister || frameOps > 1) issue(n, "invalid_set_fpreg");
                    op.operand = n.frameOffset * 16; break;
                case 8: case 9:
                    if (op.info < 6) issue(n, "unsupported_saved_vector_register", DiagnosticCode::UnsupportedFeature);
                    op.slots = op.opcode == 8 ? 2 : 3; break;
                case 10:
                    if (op.info > 1) issue(n, "invalid_machine_frame_info");
                    op.operand = op.info ? 48 : 40; break;
                default:
                    issue(n, "unsupported_unwind_opcode", DiagnosticCode::UnsupportedFeature);
                    n.operations.push_back(op); slot = n.codeSlots; continue;
            }
            if (slot + op.slots > n.codeSlots) {
                issue(n, "truncated_multi_slot_operation"); n.operations.push_back(op); break;
            }
            if (op.slots > 1) {
                op.operand = word(codes, (slot+1)*2, (op.slots-1)*2);
                if ((op.opcode == 1 && !op.info) || op.opcode == 4) op.operand *= 8;
                if (op.opcode == 8) op.operand *= 16;
                const unsigned alignment = op.opcode == 9 ? 16 : 8;
                if (op.operand % alignment || (op.opcode == 1 && !op.operand)) issue(n, "invalid_unwind_stack_offset");
            }
            // Supported secondary records inherit the primary frame and only
            // add MOV-based integer saves, or describe a zero-code fragment.
            // Other chained forms are opaque rather than declared loader-invalid.
            if ((n.flags & 4) && op.opcode != 4 && op.opcode != 5)
                issue(n, "unsupported_chained_operation", DiagnosticCode::UnsupportedFeature);
            n.operations.push_back(op); slot += op.slots;
        }
        if (!(n.flags & 4) && n.frameRegister && frameOps != 1) issue(n, "missing_frame_setup");
        if (n.flags & 4) {
            if (!backed(trailer, 12)) issue(n, "truncated_chained_record");
            else {
                const auto c = read(trailer, 12);
                n.chain = ChainedFunction{static_cast<std::uint32_t>(trailer),
                    static_cast<std::uint32_t>(word(c,0,4)), static_cast<std::uint32_t>(word(c,4,4)),
                    static_cast<std::uint32_t>(word(c,8,4))};
            }
        } else if (n.flags & 3) {
            if (!backed(trailer, 4)) issue(n, "truncated_handler_pointer");
            else {
                n.handlerFieldRva = static_cast<std::uint32_t>(trailer);
                n.handlerRva = static_cast<std::uint32_t>(word(read(trailer,4),0,4));
                // This is a location, not a known-size language-specific object.
                if (trailer + 4 < pe.imageSize) n.handlerDataRva = static_cast<std::uint32_t>(trailer+4);
                if (!*n.handlerRva || !backed(*n.handlerRva, 1, true)) issue(n, "handler_not_file_backed_executable");
            }
        }
        return &n;
    };
    bool directoryGate = directory.issues.empty() && !directory.partial;
    for (const auto& r : directory.records)
        if (std::find(r.issues.begin(), r.issues.end(), "unsorted_begin_rva") != r.issues.end()) directoryGate = false;
    auto recordGate = [](const RuntimeFunctionRecord& r) {
        return r.rangeFileBacked && r.unwindAddressFileBacked &&
            std::all_of(r.issues.begin(), r.issues.end(), [](const auto& x) { return x == "duplicate_runtime_function"; });
    };
    for (const auto& r : directory.records) {
        UnwindAssessment a; a.recordIndex = r.index;
        auto reject = [&](const std::string& reason, const std::string& status, DiagnosticCode code, std::uint32_t at) {
            a.status = status; a.reasons.push_back(reason); emit(code, reason, at);
        };
        ChainedFunction current{r.tableRva, r.beginRva, r.endRva, r.unwindRva};
        std::set<std::uint32_t> visited;
        const UnwindNode* child = nullptr;
        while (true) {
            if (visited.size() >= out.chainLimit) {
                out.partial = true;
                reject("unwind_chain_depth_limit", "budget_exhausted", DiagnosticCode::BudgetExhausted, current.fieldRva); break;
            }
            if (!visited.insert(current.unwindRva).second) {
                reject("unwind_chain_cycle", "invalid", DiagnosticCode::InvalidMetadata, current.fieldRva); break;
            }
            const auto* node = getNode(current.unwindRva);
            if (!node) { a.status = "budget_exhausted"; a.reasons.push_back("unwind_node_limit"); break; }
            if (node->status != "supported_v1") {
                a.status = node->status; a.reasons.push_back("unwind_node_" + node->status); break;
            }
            if (!current.beginRva || current.beginRva >= current.endRva ||
                !backed(current.beginRva, std::uint64_t(current.endRva) - current.beginRva, true)) {
                reject("unwind_context_range_invalid", "invalid", DiagnosticCode::InvalidMetadata, current.fieldRva); break;
            }
            if (node->prologSize > current.endRva - current.beginRva) {
                reject("prolog_exceeds_runtime_range", "invalid", DiagnosticCode::InvalidMetadata, current.fieldRva); break;
            }
            if (child && (child->frameRegister != node->frameRegister || child->frameOffset != node->frameOffset)) {
                reject("chained_frame_mismatch", "invalid", DiagnosticCode::InvalidMetadata, current.fieldRva); break;
            }
            if (!node->chain) { a.status = "supported_v1"; a.primaryBeginRva = current.beginRva; break; }
            child = node; current = *node->chain; ++a.chainDepth;
        }
        const bool canonicalOK = !r.duplicateOf || recordGate(directory.records.at(*r.duplicateOf));
        a.eligible = a.status == "supported_v1" && directoryGate && recordGate(r) && canonicalOK;
        if (!directoryGate) a.reasons.push_back("directory_incomplete_or_unsorted");
        if (!recordGate(r) || !canonicalOK) a.reasons.push_back("runtime_record_conflict_or_invalid");
        out.records.push_back(std::move(a));
    }
    return out;
}
} // namespace wea
