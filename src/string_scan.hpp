#pragma once
#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace wea {
// Discovery is independent of static-data embedding. Limits count selected
// input bytes once; three bounded detector passes inspect each selected range.
struct StringOptions {
    bool enabled = true;
    std::uint32_t minCharacters = 4;
    std::size_t scanLimit = 32u * 1024u * 1024u, candidateLimit = 10000;
};
struct StaticString {
    std::uint32_t rva = 0;
    std::uint64_t fileOffset = 0, byteLength = 0, codeUnits = 0, characters = 0;
    std::string encoding, section, endReason;
    std::u32string preview;
    bool terminated = false, previewTruncated = false;
};
struct StringCatalog {
    static constexpr std::size_t previewCharacters = 256, previewBudget = 1048576;
    StringOptions options;
    std::uint64_t readableBytes = 0, selectedBytes = 0;
    std::size_t completedPasses = 0, previewScalars = 0;
    bool partial = false;
    std::vector<std::string> reasons;
    std::vector<StaticString> candidates;
};
// A deliberately broad candidate filter, not a Unicode category/word detector.
// Noncharacters are valid Unicode, but excluded by this *text* heuristic.
inline bool stringTextScalar(std::uint32_t c) {
    return c >= 0x20 && !(c >= 0x7f && c <= 0x9f) && c <= 0x10ffff &&
           !(c >= 0xd800 && c <= 0xdfff) && !(c >= 0xfdd0 && c <= 0xfdef) &&
           (c & 0xffff) < 0xfffe && c != 0xfeff && c != 0x200e && c != 0x200f &&
           !(c >= 0x202a && c <= 0x202e) && !(c >= 0x2066 && c <= 0x2069);
}
// Image contract: PE's bounded file bytes, image/header sizes and section map.
// No input is executed. No bytes in virtual zero-fill or unmapped gaps are read.
template<class Image>
StringCatalog scanStaticStrings(const Image& pe, StringOptions options = {}) {
    if (!options.minCharacters || options.minCharacters > 1024 ||
        options.scanLimit > 256u * 1024u * 1024u || options.candidateLimit > 100000)
        throw std::invalid_argument("Invalid string discovery limits");
    StringCatalog out; out.options = options;
    if (!options.enabled) return out;
    struct Region {std::uint64_t rva, offset, size; std::string name;};
    std::vector<Region> regions;
    const auto imageEnd = std::min<std::uint64_t>(pe.imageSize, 0x100000000ull);
    const auto headerSize = std::min<std::uint64_t>({pe.headersSize, pe.data.size(), imageEnd});
    if (headerSize) regions.push_back({0, 0, headerSize, "[headers]"});
    for (const auto& s : pe.sections) {
        if (!(s.flags & 0x40000000u) || s.rva >= imageEnd || s.raw >= pe.data.size()) continue;
        const auto n = std::min<std::uint64_t>({s.virtualSize ? std::min(s.rawSize,s.virtualSize) : s.rawSize,
                                             pe.data.size()-s.raw, imageEnd-s.rva});
        if (n) regions.push_back({s.rva, s.raw, n, s.name});
    }
    std::stable_sort(regions.begin(), regions.end(), [](const auto& x, const auto& y){return x.rva < y.rva;});
    auto partial = [&](const std::string& reason) {
        out.partial = true;
        if (std::find(out.reasons.begin(),out.reasons.end(),reason)==out.reasons.end()) out.reasons.push_back(reason);
    };
    std::uint64_t previousEnd = 0;
    for (auto& r : regions) {
        if (r.rva < previousEnd) {
            const auto skip = std::min(r.size, previousEnd-r.rva);
            r.rva += skip; r.offset += skip; r.size -= skip;
            partial("overlapping_image_ranges_skipped");
        }
        previousEnd = std::max(previousEnd,r.rva+r.size); out.readableBytes += r.size;
    }
    bool stopped = false;
    for (const auto& region : regions) {
        if (stopped) break;
        const auto n = std::min<std::uint64_t>(region.size, options.scanLimit-out.selectedBytes);
        if (!n) continue;
        out.selectedBytes += n;
        const auto* data = pe.data.data() + region.offset;
        auto word = [&](std::uint64_t at) {return std::uint32_t(data[at]) | (std::uint32_t(data[at+1]) << 8);};
        // Maximal runs per encoding/alignment, not every possible suffix.
        // UTF-16LE's two alignment passes admit unaligned static strings.
        for (unsigned pass=0; pass<3 && !stopped; ++pass) {
            const bool wide = pass != 0;
            std::uint64_t pos = pass==2 ? 1 : 0, start = pos, chars = 0, units = 0;
            std::u32string preview;
            auto emit = [&](const std::string& reason) {
                if (chars >= options.minCharacters) {
                    if (out.candidates.size() >= options.candidateLimit) {partial("candidate_limit"); stopped=true;}
                    else if (preview.size() > StringCatalog::previewBudget-out.previewScalars) {partial("preview_budget"); stopped=true;}
                    else {
                        out.previewScalars += preview.size();
                        out.candidates.push_back({static_cast<std::uint32_t>(region.rva+start), region.offset+start,
                            units*(wide?2u:1u), units, chars, wide?"UTF-16LE":"ASCII", region.name, reason,
                            preview, reason=="nul", chars>preview.size()});
                    }
                }
                chars=units=0; preview.clear();
            };
            while (pos < n && !stopped) {
                std::uint32_t scalar=0; unsigned bytes=wide?2:1;
                std::string stopReason;
                if (!wide) {
                    scalar=data[pos];
                    if (scalar < 0x20 || scalar > 0x7e) stopReason=scalar?"non_text":"nul";
                } else if (n-pos < 2) {break;}
                else {
                    scalar=word(pos);
                    if (scalar >= 0xd800 && scalar <= 0xdbff) {
                        if (n-pos < 4) {
                            emit(n<region.size?"scan_limit":"incomplete_utf16"); pos=n; break;
                        }
                        const auto low=word(pos+2);
                        if (low < 0xdc00 || low > 0xdfff) stopReason="invalid_utf16";
                        else {scalar=0x10000+((scalar-0xd800)<<10)+(low-0xdc00);bytes=4;}
                    } else if (scalar >= 0xdc00 && scalar <= 0xdfff) stopReason="invalid_utf16";
                    if (stopReason.empty() && !stringTextScalar(scalar)) stopReason=scalar?"non_text":"nul";
                }
                if (!stopReason.empty()) {emit(stopReason);pos+=bytes;start=pos;continue;}
                if (!chars) start=pos;
                ++chars; units+=wide?bytes/2:bytes;
                if (preview.size()<StringCatalog::previewCharacters) preview.push_back(static_cast<char32_t>(scalar));
                pos+=bytes;
            }
            if (!stopped && chars) emit(n<region.size?"scan_limit":"range_end");
            if (!stopped) ++out.completedPasses;
        }
    }
    if (out.selectedBytes < out.readableBytes && !stopped) partial("scan_limit");
    // Limits decide retention in documented range/ASCII/even/odd pass order;
    // presentation order is stable by RVA and then encoding, not textual value.
    std::sort(out.candidates.begin(),out.candidates.end(),[](const auto& x,const auto& y){
        return x.rva != y.rva ? x.rva < y.rva : x.encoding < y.encoding;
    });
    return out;
}
inline std::string stringHex(std::uint64_t value) {std::ostringstream o;o<<"0x"<<std::hex<<value;return o.str();}
inline std::string stringJsonText(const std::u32string& s) {
    std::ostringstream o; o<<'"';
    auto escape=[&](std::uint32_t c){o<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<c;};
    for (auto ch:s) {
        const auto c=static_cast<std::uint32_t>(ch);
        if (c=='"' || c=='\\') o<<'\\'<<static_cast<char>(c);
        else if (c >= 32 && c < 127 && c!='<' && c!='>' && c!='&') o<<static_cast<char>(c);
        else if (c<=0xffff) escape(c);
        else {escape(0xd800+((c-0x10000)>>10));escape(0xdc00+((c-0x10000)&1023));}
    }
    o<<'"';return o.str();
}
inline std::string stringJsonBytes(const std::string& s) {
    // PE section labels are untrusted byte strings, as in the base report.
    std::u32string u;for(unsigned char c:s)u.push_back(c);return stringJsonText(u);
}
inline std::string stringCatalogJson(const std::string& moduleId,const StringCatalog& c) {
    std::ostringstream o;
    o<<"{\"version\":1,\"enabled\":"<<(c.options.enabled?"true":"false")
     <<",\"minCharacters\":"<<c.options.minCharacters<<",\"scanLimit\":"<<c.options.scanLimit
     <<",\"candidateLimit\":"<<c.options.candidateLimit<<",\"previewCharacters\":"<<c.previewCharacters
     <<",\"previewScalarBudget\":"<<c.previewBudget<<",\"previewScalars\":"<<c.previewScalars
     <<",\"readableBytes\":"<<c.readableBytes<<",\"selectedBytes\":"<<c.selectedBytes
     <<",\"completedDetectorPasses\":"<<c.completedPasses<<",\"partial\":"<<(c.partial?"true":"false")
     <<",\"scope\":\"file_backed_headers_and_readable_sections\",\"reasons\":[";
    bool comma=false;for(const auto& s:c.reasons){if(comma)o<<',';comma=true;o<<stringJsonBytes(s);}o<<"],\"candidates\":[";
    comma=false;for(const auto& s:c.candidates){
        if(comma){o<<',';}comma=true;
        const auto id=moduleId+"_str_"+(s.encoding=="ASCII"?"a_":"w_")+stringHex(s.rva).substr(2);
        o<<"{\"id\":"<<stringJsonBytes(id)<<",\"rva\":"<<s.rva
         <<",\"fileOffset\":"<<stringJsonBytes(stringHex(s.fileOffset))<<",\"byteLength\":"<<s.byteLength
         <<",\"codeUnits\":"<<s.codeUnits<<",\"characters\":"<<s.characters
         <<",\"encoding\":"<<stringJsonBytes(s.encoding)<<",\"section\":"<<stringJsonBytes(s.section)
         <<",\"endReason\":"<<stringJsonBytes(s.endReason)<<",\"terminated\":"<<(s.terminated?"true":"false")
         <<",\"previewTruncated\":"<<(s.previewTruncated?"true":"false")<<",\"text\":"<<stringJsonText(s.preview)<<"}";
    }
    o<<"]}";return o.str();
}
template<class Image>
inline void appendStringCatalog(std::string& report,const Image& pe,StringOptions options={}) {
    if (report.empty() || report.back()!='}') throw std::logic_error("Report object required for string extension");
    const auto catalog=scanStaticStrings(pe,options);
    report.pop_back();report+=",\"strings\":"+stringCatalogJson(pe.moduleId,catalog)+"}";
}
} // namespace wea
