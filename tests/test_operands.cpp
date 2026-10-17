#include "operands.hpp"
#include <iostream>
#include <stdexcept>

static unsigned checks=0;
static void check(bool ok,const char* message){if(!ok)throw std::runtime_error(message);++checks;}
int main(){try {
    for(bool x64:{false,true}) {
        const auto al=wea::registerSlice("al",x64),ah=wea::registerSlice("ah",x64);
        const auto ax=wea::registerSlice("ax",x64),eax=wea::registerSlice("eax",x64);
        check(al.family==(x64?"rax":"eax") && al.familyWidth==(x64?64u:32u),"Mode-specific GPR storage");
        check(ah.family==al.family && ah.bitOffset==8 && ah.bitWidth==8,"High byte overlaps AX bits 8..15");
        check(al.bitOffset==0 && al.bitWidth==8 && ax.bitWidth==16 && eax.bitWidth==32,"Partial GPR slices");
        check(wea::registerSlice("eip",x64).family==(x64?"rip":"eip"),"IP aliasing");
    }
    for(const auto* name:{"rax","r8","r8d","r15w","r15b","sil","dil","bpl","spl"}) {
        check(wea::registerSlice(name,true).known(),"x64 register slice available");
        check(!wea::registerSlice(name,false).known(),"x64-only names must not become x86 registers");
    }
    check(wea::registerSlice("r15b",true).family=="r15" && wea::registerSlice("r15b",true).bitWidth==8,"Extended byte register");
    check(wea::registerSlice("sil",true).family=="rsi" && wea::registerSlice("sil",true).bitOffset==0,"REX low byte register");
    check(wea::registerSlice("fs",true).bitWidth==16,"Segment selector, not base");
    const auto xmm=wea::registerSlice("xmm3",true),ymm=wea::registerSlice("ymm3",true);
    check(xmm.family=="zmm3" && ymm.family==xmm.family && xmm.bitWidth==128 && ymm.bitWidth==256,"Vector storage overlap only");
    for(const auto* name:{"","made_up","eflags","st(0)","mm0","cr0","r16","xmm32"})
        check(!wea::registerSlice(name,true).known(),"Unsupported register alias must be unknown");
    const std::uint8_t mandatory[]={0xf3,0x0f,0x10,0xc1};
    check(wea::leadingPrefixes(mandatory,4,true)==std::vector<std::uint8_t>{0xf3},"Preserve mandatory SSE prefix");
    const std::uint8_t rex[]={0x40,0x88,0xe0};
    check(wea::leadingPrefixes(rex,3,true)==std::vector<std::uint8_t>{0x40},"REX prefix in x64");
    check(wea::leadingPrefixes(rex,3,false).empty(),"0x40 is an opcode in x86, not REX");
    const std::uint8_t duplicate[]={0x66,0x66,0x67,0x48,0x8b,0x00};
    check(wea::leadingPrefixes(duplicate,6,true)==std::vector<std::uint8_t>({0x66,0x66,0x67,0x48}),"Keep prefix order and duplicates");
    wea::OperandDetails unknown;
    check(!unknown.available && !unknown.implicitRegistersReported,"Default metadata is unknown");
    std::cout<<"PASS: "<<checks<<" operand type checks\n";
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
