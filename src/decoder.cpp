#include "decoder.hpp"
#include <regex>
#ifdef WEA_USE_LLVM
// Minimal declarations for LLVM's public C disassembler ABI. No private LLVM API.
// API reference: llvm/include/llvm-c/Disassembler.h and DisassemblerTypes.h.
extern "C" {
using OpCallback=int(*)(void*,u64,u64,u64,u64,int,void*);
using SymbolCallback=const char*(*)(void*,u64,u64*,u64,const char**);
void LLVMInitializeX86TargetInfo();void LLVMInitializeX86Target();void LLVMInitializeX86TargetMC();
void LLVMInitializeX86AsmPrinter();void LLVMInitializeX86Disassembler();
void* LLVMCreateDisasm(const char*,void*,int,OpCallback,SymbolCallback);
int LLVMSetDisasmOptions(void*,u64);void LLVMDisasmDispose(void*);
size_t LLVMDisasmInstruction(void*,u8*,u64,u64,char*,size_t);
}
struct Decoder::State {void* handle=nullptr;std::optional<u64> target;
    static const char* symbol(void* self,u64 value,u64* type,u64,const char** name){
        if(*type==1)static_cast<State*>(self)->target=value;
        *type=0;*name=nullptr;return nullptr;
    }
};
Decoder::Decoder(bool x64):s(std::make_unique<State>()){
    LLVMInitializeX86TargetInfo();LLVMInitializeX86Target();LLVMInitializeX86TargetMC();LLVMInitializeX86AsmPrinter();LLVMInitializeX86Disassembler();
    s->handle=LLVMCreateDisasm(x64?"x86_64-pc-windows-msvc":"i386-pc-windows-msvc",s.get(),0,nullptr,State::symbol);
    if(!s->handle)throw std::runtime_error("LLVM disassembler initialization failed");
    if(!LLVMSetDisasmOptions(s->handle,6))throw std::runtime_error("LLVM Intel syntax unavailable");
}
Decoder::~Decoder(){if(s->handle)LLVMDisasmDispose(s->handle);}
const char* Decoder::backend(){return "LLVM C disassembler (assembly/CFG backend)";}
#else
#include <capstone/capstone.h>
struct Decoder::State{csh handle=0;};
Decoder::Decoder(bool x64):s(std::make_unique<State>()){
    if(cs_open(CS_ARCH_X86,x64?CS_MODE_64:CS_MODE_32,&s->handle)!=CS_ERR_OK)throw std::runtime_error("Capstone initialization failed");
    if(cs_option(s->handle,CS_OPT_DETAIL,CS_OPT_ON)!=CS_ERR_OK)throw std::runtime_error("Capstone detail mode unavailable");
}
Decoder::~Decoder(){if(s->handle)cs_close(&s->handle);}
const char* Decoder::backend(){return "Capstone 5";}
#endif

static bool starts(const std::string&s,const std::string&p){return s.rfind(p,0)==0;}
static void classify(Instruction&i){
    auto n=i.mnemonic;
    // Prefixes such as "rep ret" and "bnd jmp" do not change the transfer class.
    if(auto p=n.find_last_of(" ");p!=std::string::npos)n=n.substr(p+1);
    i.call=n=="call"||n=="lcall";i.jump=starts(n,"j")||starts(n,"loop")||n=="ljmp";
    i.conditional=i.jump&&n!="jmp"&&n!="ljmp";
    i.ret=starts(n,"ret")||starts(n,"iret")||n=="lret";
    i.stop=i.ret||n=="int"||n=="int3"||n=="into"||n=="ud2"||n=="hlt"||n=="sysret"||n=="sysexit";
    if(i.call)i.notes="Call; continuation assumes that the callee returns.";
    else if(i.ret)i.notes="Return via the saved execution context; not a fixed CFG target.";
    else if(i.jump)i.notes=i.conditional?"Conditional branch: taken and not-taken paths are shown.":"Unconditional transfer: no fall-through edge.";
    else if(n=="cmp"||n=="test")i.notes="Updates status flags; the following branch may consume them.";
    else if(n=="lea")i.notes="Computes an effective address; does not read the pointed-to memory.";
    else if(n=="mov"||n=="movabs")i.notes="Copies a value; widths and register aliasing matter.";
    else i.notes="Assembly observation only; instruction semantics are not fully lifted.";
}

static std::string memoryAccess(const Instruction&i,unsigned operand){
    auto n=i.mnemonic;auto p=n.find_last_of(' ');if(p!=std::string::npos)n=n.substr(p+1);
    if(n=="lea")return "address";
    if(i.call||i.jump||n=="cmp"||n=="test"||n=="push"||starts(n,"cmov"))return "read";
    if(n=="pop"||starts(n,"set"))return "write";
    const std::set<std::string> moves={"mov","movabs","movzx","movsx","movsxd","movss","movsd","movaps","movups","movapd","movupd","movd","movq","movdqa","movdqu"};
    if(moves.contains(n))return operand==0?"write":"read";
    const std::set<std::string> modify={"add","sub","adc","sbb","and","or","xor","inc","dec","neg","not","shl","shr","sal","sar","rol","ror","rcl","rcr","xadd","cmpxchg","bts","btr","btc"};
    if(n=="xchg"||modify.contains(n))return operand==0||n=="xchg"?"read-write":"read";
    return "unknown";
}
#ifdef WEA_USE_LLVM
static u32 memoryWidth(const std::string&s){
    static const std::map<std::string,u32> sizes={{"byte",1},{"word",2},{"dword",4},{"qword",8},{"tbyte",10},{"xmmword",16},{"ymmword",32},{"zmmword",64}};
    auto it=sizes.find(s);return it==sizes.end()?0:it->second;
}
static bool hasAddressOverride(const u8*bytes,size_t count){
    for(size_t k=0;k<count;k++){
        u8 b=bytes[k];if(b==0x67)return true;
        if(b==0x66||b==0xf0||b==0xf2||b==0xf3||b==0x2e||b==0x36||b==0x3e||b==0x26||b==0x64||b==0x65||(b>=0x40&&b<=0x4f))continue;
        break;
    }return false;
}
#endif

std::optional<Instruction> Decoder::decode(const PE&pe,u32 rva){
    size_t count=std::min<size_t>(pe.available(rva,true),15);if(!count)return {};
    size_t off=pe.offset(rva,1,true);Instruction i;i.rva=rva;
#ifdef WEA_USE_LLVM
    char text[1024]{};s->target.reset();
    i.size=static_cast<u16>(LLVMDisasmInstruction(s->handle,const_cast<u8*>(pe.data.data()+off),count,pe.imageBase+rva,text,sizeof(text)));
    if(!i.size)return {};
    std::string line=trim(text);auto pos=line.find_first_of(" \t");
    i.mnemonic=line.substr(0,pos);i.operands=pos==line.npos?"":trim(line.substr(pos));
    const std::set<std::string> prefixes={"lock","rep","repne","repe","repz","repnz","bnd","notrack","data16","addr32"};
    while(prefixes.contains(i.mnemonic.substr(i.mnemonic.find_last_of(' ')==std::string::npos?0:i.mnemonic.find_last_of(' ')+1))&&!i.operands.empty()){
        auto split=i.operands.find_first_of(" \t");
        i.mnemonic+=" "+i.operands.substr(0,split);
        i.operands=split==std::string::npos?"":trim(i.operands.substr(split));
    }
    classify(i);if(i.call||i.jump){i.targetVA=s->target;
        if(i.targetVA){if(!pe.is64)*i.targetVA&=0xffffffffu;i.operands=hex(*i.targetVA);}
    }
    // LLVM's C API exposes text, not structured operands. Resolve only a narrow,
    // anchored constant-address grammar. Register/index/segment forms stay unknown.
    static const std::regex ip(R"(^(rip|eip)(?:\s*([+-])\s*(0x[0-9a-f]+|[0-9]+))?$)");
    static const std::regex absolute(R"(^(-?)(0x[0-9a-f]+|[0-9]+)$)");
    static const std::regex sizePattern(R"((byte|word|dword|qword|tbyte|xmmword|ymmword|zmmword) ptr\s*$)");
    for(size_t begin=0;(begin=i.operands.find('[',begin))!=std::string::npos;){
        size_t end=i.operands.find(']',begin);if(end==std::string::npos)break;
        std::string expr=trim(i.operands.substr(begin+1,end-begin-1));
        std::string prefix=trim(i.operands.substr(0,begin));std::smatch m;
        MemoryReference r;r.textBegin=begin;r.textEnd=end+1;
        r.operand=static_cast<unsigned>(std::count(i.operands.begin(),i.operands.begin()+begin,','));
        bool resolved=false;
        if(!prefix.empty()&&prefix.back()==':'){begin=end+1;continue;}
        if(std::regex_match(expr,m,ip)){
            u64 magnitude=m[3].matched?std::stoull(m[3],nullptr,0):0;
            // A hardware IP-relative displacement is signed 32-bit.
            if(magnitude<=(m[2]=="-"?0x80000000ull:0x7fffffffull)){
                r.displacement=m[2]=="-"?-std::int64_t(magnitude):std::int64_t(magnitude);
                r.va=pe.imageBase+rva+i.size+u64(r.displacement);
                r.mode=m[1]=="rip"?"rip-relative":"eip-relative";
                if(m[1]=="eip")r.va&=0xffffffffu;
                resolved=true;
            }
        }else if(std::regex_match(expr,m,absolute)){
            u64 value=std::stoull(m[2],nullptr,0);r.va=m[1]=="-"?u64(0)-value:value;
            if(!pe.is64||hasAddressOverride(pe.data.data()+off,i.size))r.va&=0xffffffffu;
            r.mode="absolute";resolved=true;
        }
        if(resolved){
            std::smatch w;
            if(std::regex_search(prefix,w,sizePattern))r.width=memoryWidth(w[1]);
            r.access=memoryAccess(i,r.operand);if(r.access=="address")r.width=0;
            r.evidence="LLVM text: constant-address grammar (not full operand semantics)";
            i.dataRefs.push_back(r);
        }
        begin=end+1;
    }
#else
    cs_insn* decoded=nullptr;size_t n=cs_disasm(s->handle,pe.data.data()+off,count,pe.imageBase+rva,1,&decoded);
    if(!n)return {};
    const cs_insn& c=decoded[0];i.size=c.size;i.mnemonic=c.mnemonic;i.operands=c.op_str;classify(i);
    if(c.detail){
        const auto& x=c.detail->x86;
        if((i.call||i.jump)&&x.op_count==1&&x.operands[0].type==X86_OP_IMM)
            i.targetVA=pe.is64?u64(x.operands[0].imm):u64(u32(x.operands[0].imm));
        size_t bracket=0;
        for(unsigned op=0;op<x.op_count;op++){
            const auto&o=x.operands[op];if(o.type!=X86_OP_MEM)continue;
            size_t begin=i.operands.find('[',bracket),end=begin==std::string::npos?begin:i.operands.find(']',begin);
            if(end!=std::string::npos)bracket=end+1;
            if(o.mem.segment!=X86_REG_INVALID||o.mem.index!=X86_REG_INVALID)continue;
            MemoryReference r;r.operand=op;r.width=o.size;r.displacement=o.mem.disp;
            if(o.mem.base==X86_REG_RIP){r.va=c.address+c.size+u64(o.mem.disp);r.mode="rip-relative";}
            else if(o.mem.base==X86_REG_EIP){r.va=u32(c.address+c.size+u64(o.mem.disp));r.mode="eip-relative";}
            else if(o.mem.base==X86_REG_INVALID){r.va=x.addr_size==8?u64(o.mem.disp):u64(u32(o.mem.disp));r.mode="absolute";}
            else continue;
            r.access=memoryAccess(i,op);
            if(r.access=="address")r.width=0;
            else if(o.access){bool read=o.access&CS_AC_READ,write=o.access&CS_AC_WRITE;
                r.access=read&&write?"read-write":write?"write":read?"read":"unknown";}
            if(begin!=std::string::npos&&end!=std::string::npos){r.textBegin=begin;r.textEnd=end+1;}
            r.evidence="Capstone structured memory operand";i.dataRefs.push_back(r);
        }
    }
    cs_free(decoded,n);
#endif
    // For control-flow resolution, a memory reference is the pointer storage
    // address, not a resolved execution destination.
    if((i.call||i.jump)&&i.dataRefs.size()==1&&i.dataRefs[0].operand==0)
        i.memoryVA=i.dataRefs[0].va;
    std::ostringstream bytes;for(size_t k=0;k<i.size;k++){if(k)bytes<<' ';bytes<<std::hex<<std::setfill('0')<<std::setw(2)<<unsigned(pe.data[off+k]);}i.bytes=bytes.str();
    return i;
}
