#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wea {
// Storage overlap only. A slice does not describe zero-extension, merging,
// conditional writes, vector lane effects, or any other instruction semantics.
struct RegisterSlice {
    std::string name;
    std::string family;
    unsigned bitOffset=0, bitWidth=0, familyWidth=0;
    bool known() const { return !family.empty(); }
};

inline RegisterSlice registerSlice(const std::string& name, bool x64) {
    RegisterSlice r{name, "", 0, 0, 0};
    constexpr const char* gpr[][5]={
        {"rax","eax","ax","al","ah"}, {"rbx","ebx","bx","bl","bh"},
        {"rcx","ecx","cx","cl","ch"}, {"rdx","edx","dx","dl","dh"},
        {"rsi","esi","si","sil",""}, {"rdi","edi","di","dil",""},
        {"rbp","ebp","bp","bpl",""}, {"rsp","esp","sp","spl",""}
    };
    constexpr unsigned widths[]={64,32,16,8,8};
    for (const auto& names:gpr) for (unsigned k=0;k<5;++k) {
        if (name.empty() || name!=names[k]) continue;
        if (!x64 && (k==0 || (k==3 && names[4][0]=='\0'))) return r;
        return {name,names[x64?0:1],k==4?8u:0u,widths[k],x64?64u:32u};
    }
    if (x64) for (unsigned k=8;k<16;++k) {
        const auto family="r"+std::to_string(k);
        if(name==family) return {name,family,0,64,64};
        if(name==family+"d") return {name,family,0,32,64};
        if(name==family+"w") return {name,family,0,16,64};
        if(name==family+"b") return {name,family,0,8,64};
    }
    if (name=="ip" || name=="eip" || (x64 && name=="rip"))
        return {name,x64?"rip":"eip",0,name=="ip"?16u:name=="eip"?32u:64u,x64?64u:32u};
    for (const auto* segment:{"cs","ds","es","fs","gs","ss"})
        if(name==segment) return {name,name,0,16,16}; // selector, not segment base
    for (unsigned k=0;k<32;++k) for (unsigned width:{128u,256u,512u}) {
        const auto n=std::to_string(k);
        if(name==(width==128?"xmm":width==256?"ymm":"zmm")+n)
            return {name,"zmm"+n,0,width,512};
    }
    // Flags, x87/MMX, control/debug registers and unrecognized names remain
    // opaque. In particular, x87/MMX overlap is not a flat register slice.
    return r;
}

enum class OperandKind { Unknown, Register, Immediate, Memory };
enum class OperandAccess { Unknown, Read, Write, ReadWrite, Address };
inline const char* name(OperandKind v) {
    switch(v) {
        case OperandKind::Register:return "register";
        case OperandKind::Immediate:return "immediate";
        case OperandKind::Memory:return "memory";
        default:return "unknown";
    }
}
inline const char* name(OperandAccess v) {
    switch(v) {
        case OperandAccess::Read:return "read";
        case OperandAccess::Write:return "write";
        case OperandAccess::ReadWrite:return "read-write";
        case OperandAccess::Address:return "address";
        default:return "unknown";
    }
}
struct MemoryOperand {
    std::optional<RegisterSlice> segment,base,index;
    unsigned scale=1;
    std::int64_t displacement=0;
};
struct Operand {
    OperandKind kind=OperandKind::Unknown;
    unsigned widthBits=0; // decoder operand width; zero means unavailable
    OperandAccess access=OperandAccess::Unknown;
    std::optional<RegisterSlice> reg;
    std::optional<std::uint64_t> immediate;
    bool immediateIsTarget=false; // preferred VA, not the encoded relative offset
    std::optional<MemoryOperand> memory;
};
struct EncodingField { unsigned offset=0,widthBits=0; };
struct OperandDetails {
    bool available=false;
    unsigned addressWidthBits=0;
    std::vector<Operand> operands;
    // Actual leading legacy/REX bytes retain mandatory SSE prefixes that the
    // decoder's effective prefix groups may omit. Vector prefixes stay in bytes.
    std::vector<std::uint8_t> leadingPrefixes;
    std::array<std::uint8_t,4> legacyPrefixGroups{};
    std::uint8_t decoderRex=0;
    std::optional<EncodingField> immediateEncoding,displacementEncoding;
    bool implicitRegistersReported=false;
    std::vector<RegisterSlice> implicitReads,implicitWrites;
    // No adapter claims complete implicit effects or instruction semantics.
};
struct DecoderInfo {
    std::string name;
    std::optional<std::string> version,headerVersion;
    bool structuredOperands=false,registerSlices=false,operandAccess=false;
    bool implicitRegisters=false,encodingFields=false;
};

inline std::vector<std::uint8_t> leadingPrefixes(const std::uint8_t* bytes, unsigned size, bool x64) {
    std::vector<std::uint8_t> out;
    for (unsigned k=0;k<size && k<15;++k) {
        const auto b=bytes[k];
        if(b==0xf0 || b==0xf2 || b==0xf3 || b==0x2e || b==0x36 || b==0x3e ||
           b==0x26 || b==0x64 || b==0x65 || b==0x66 || b==0x67 ||
           (x64 && b>=0x40 && b<=0x4f)) out.push_back(b);
        else break;
    }
    return out;
}
} // namespace wea
