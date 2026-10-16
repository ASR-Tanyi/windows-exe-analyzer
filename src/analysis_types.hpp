#pragma once
#include <compare>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// New analysis facts use tagged addresses. Legacy decoding APIs still accept
// integers; conversions at that boundary must be explicit.
namespace wea {
using AddressValue = std::uint64_t;
inline constexpr AddressValue rvaEnd = AddressValue{1} << 32;

class Rva {
    std::uint32_t value_;
public:
    explicit Rva(AddressValue value) : value_(0) {
        if (value >= rvaEnd) throw std::out_of_range("RVA exceeds 32 bits");
        value_ = static_cast<std::uint32_t>(value);
    }
    std::uint32_t value() const { return value_; }
    auto operator<=>(const Rva&) const = default;
};
struct FileOffset {
    AddressValue value;
    explicit FileOffset(AddressValue v) : value(v) {}
    auto operator<=>(const FileOffset&) const = default;
};
struct PreferredVa {
    AddressValue value;
    explicit PreferredVa(AddressValue v) : value(v) {}
    auto operator<=>(const PreferredVa&) const = default;
};
enum class AddressSpace { Rva, FileOffset, PreferredVa };
class Address {
    AddressSpace space_;
    AddressValue value_;
public:
    explicit Address(Rva v) : space_(AddressSpace::Rva), value_(v.value()) {}
    explicit Address(FileOffset v) : space_(AddressSpace::FileOffset), value_(v.value) {}
    explicit Address(PreferredVa v) : space_(AddressSpace::PreferredVa), value_(v.value) {}
    AddressSpace space() const { return space_; }
    AddressValue value() const { return value_; }
    auto operator<=>(const Address&) const = default;
};
struct Location {
    std::string moduleId;
    Address address;
    auto operator<=>(const Location&) const = default;
};
inline const char* name(AddressSpace v) {
    switch (v) {
        case AddressSpace::Rva: return "rva";
        case AddressSpace::FileOffset: return "file_offset";
        case AddressSpace::PreferredVa: return "preferred_va";
    }
    throw std::logic_error("Invalid address space");
}

enum class EvidenceOrigin { PeHeader, ExportTable, DecodedInstruction, Analyst, AnalysisRule };
enum class Resolution { Encoded, Supplied, Inferred };
enum class EvidenceStatus { Confirmed, Candidate, Assertion, Heuristic };
inline const char* name(EvidenceOrigin v) {
    switch (v) {
        case EvidenceOrigin::PeHeader: return "pe_header";
        case EvidenceOrigin::ExportTable: return "export_table";
        case EvidenceOrigin::DecodedInstruction: return "decoded_instruction";
        case EvidenceOrigin::Analyst: return "analyst";
        case EvidenceOrigin::AnalysisRule: return "analysis_rule";
    }
    throw std::logic_error("Invalid evidence origin");
}
inline const char* name(Resolution v) {
    switch (v) {
        case Resolution::Encoded: return "encoded";
        case Resolution::Supplied: return "supplied";
        case Resolution::Inferred: return "inferred";
    }
    throw std::logic_error("Invalid resolution");
}
inline const char* name(EvidenceStatus v) {
    switch (v) {
        case EvidenceStatus::Confirmed: return "confirmed";
        case EvidenceStatus::Candidate: return "candidate";
        case EvidenceStatus::Assertion: return "assertion";
        case EvidenceStatus::Heuristic: return "heuristic";
    }
    throw std::logic_error("Invalid evidence status");
}
struct Evidence {
    EvidenceOrigin origin;
    std::string claim;
    Resolution resolution;
    EvidenceStatus status;
    std::string rule;
    std::uint32_t ruleVersion = 1;
    std::optional<Location> source;
    std::string detail;
    std::vector<std::string> assumptions;
    auto operator<=>(const Evidence&) const = default;
};
// Sorted facts deduplicate identical evidence but retain distinct call sites.
using EvidenceSet = std::set<Evidence>;

// Only decoded coverage is emitted in M0. A future metadata parser must supply
// its own origin/validation rather than disguising metadata as decoded bytes.
class CodeRange {
    Rva begin_;
    AddressValue end_;
public:
    CodeRange(Rva begin, AddressValue end) : begin_(begin), end_(end) {
        if (end <= begin.value() || end > rvaEnd)
            throw std::out_of_range("Invalid half-open RVA range");
    }
    Rva begin() const { return begin_; }
    AddressValue end() const { return end_; }
    AddressValue size() const { return end_ - begin_.value(); }
    bool contains(Rva r) const { return r.value() >= begin_.value() && r.value() < end_; }
    const char* origin() const { return "decoded_instructions"; }
    const char* validation() const { return "file_backed_decoding"; }
    auto operator<=>(const CodeRange&) const = default;
};
// Input must be ordered and non-overlapping. Join adjacency, never fill holes.
inline void appendDecodedRange(std::vector<CodeRange>& ranges, CodeRange next) {
    if (!ranges.empty()) {
        auto& last = ranges.back();
        if (next.begin().value() < last.end())
            throw std::logic_error("Decoded ranges overlap or are not ordered");
        if (next.begin().value() == last.end()) {
            last = CodeRange(last.begin(), next.end());
            return;
        }
    }
    ranges.push_back(next);
}

enum class DiagnosticCode {
    InvalidMetadata, UnsupportedFeature, UnmappedTarget, OverlappingDecode,
    DecodeFailed, BudgetExhausted, UnresolvedSeed, IgnoredAnnotation, AmbiguousOwner
};
inline const char* name(DiagnosticCode v) {
    switch (v) {
        case DiagnosticCode::InvalidMetadata: return "invalid_metadata";
        case DiagnosticCode::UnsupportedFeature: return "unsupported_feature";
        case DiagnosticCode::UnmappedTarget: return "unmapped_target";
        case DiagnosticCode::OverlappingDecode: return "overlapping_decode";
        case DiagnosticCode::DecodeFailed: return "decode_failed";
        case DiagnosticCode::BudgetExhausted: return "budget_exhausted";
        case DiagnosticCode::UnresolvedSeed: return "unresolved_seed";
        case DiagnosticCode::IgnoredAnnotation: return "ignored_annotation";
        case DiagnosticCode::AmbiguousOwner: return "ambiguous_owner";
    }
    throw std::logic_error("Invalid diagnostic code");
}
struct Diagnostic {
    DiagnosticCode code;
    std::string phase;
    std::string message;
    std::optional<Location> location;
};
class DiagnosticLog {
    std::size_t limit_;
    std::uint64_t total_ = 0;
    std::map<DiagnosticCode, std::uint64_t> counts_;
    std::vector<Diagnostic> items_;
public:
    explicit DiagnosticLog(std::size_t limit = 100) : limit_(limit) {}
    void add(DiagnosticCode code, std::string phase, std::string message,
             std::optional<Location> location = std::nullopt) {
        ++total_;
        ++counts_[code];
        if (items_.size() < limit_)
            items_.push_back({code, std::move(phase), std::move(message), std::move(location)});
    }
    std::size_t limit() const { return limit_; }
    std::uint64_t total() const { return total_; }
    std::uint64_t omitted() const { return total_ - items_.size(); }
    const auto& counts() const { return counts_; }
    const auto& items() const { return items_; }
};
} // namespace wea
