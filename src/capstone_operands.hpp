#pragma once
#include "operands.hpp"
#include <capstone/capstone.h>

namespace wea {
inline OperandDetails capstoneOperands(csh handle,const cs_insn& insn,bool x64,bool branch) {
    OperandDetails d;
    if(!insn.detail) return d;
    const auto& x=insn.detail->x86;
    const bool accessAvailable=!cs_support(CS_SUPPORT_DIET);
    d.available=true;
    if(x.addr_size==2 || x.addr_size==4 || x.addr_size==8) d.addressWidthBits=x.addr_size*8;
    d.leadingPrefixes=leadingPrefixes(insn.bytes,insn.size,x64);
    for(unsigned k=0;k<4;++k) d.legacyPrefixGroups[k]=x.prefix[k];
    d.decoderRex=x.rex;
    auto encoding=[&](unsigned offset,unsigned size)->std::optional<EncodingField> {
        if(!offset || !size || offset>=insn.size || size>insn.size-offset) return {};
        return EncodingField{offset,size*8};
    };
    d.immediateEncoding=encoding(x.encoding.imm_offset,x.encoding.imm_size);
    d.displacementEncoding=encoding(x.encoding.disp_offset,x.encoding.disp_size);
    auto reg=[&](unsigned id) {
        const auto* n=cs_reg_name(handle,id);
        return registerSlice(n?n:"unknown",x64);
    };
    auto optionalReg=[&](unsigned id)->std::optional<RegisterSlice> {
        return id==X86_REG_INVALID?std::nullopt:std::optional(reg(id));
    };
    for(unsigned k=0;k<x.op_count;++k) {
        const auto& src=x.operands[k];Operand op;op.widthBits=src.size*8;
        if(accessAvailable) {
            const bool read=src.access&CS_AC_READ,write=src.access&CS_AC_WRITE;
            if(read && write)op.access=OperandAccess::ReadWrite;
            else if(read)op.access=OperandAccess::Read;
            else if(write)op.access=OperandAccess::Write;
            // An access byte of zero is unavailable, not "no effects".
        }
        switch(src.type) {
            case X86_OP_REG:op.kind=OperandKind::Register;op.reg=reg(src.reg);break;
            case X86_OP_IMM:
                op.kind=OperandKind::Immediate;op.immediate=std::uint64_t(src.imm);
                op.immediateIsTarget=branch && x.op_count==1;
                if(op.immediateIsTarget) {
                    if(!x64)*op.immediate&=0xffffffffu;
                } else if(op.widthBits && op.widthBits<64) *op.immediate&=(std::uint64_t(1)<<op.widthBits)-1;
                break;
            case X86_OP_MEM:
                op.kind=OperandKind::Memory;
                op.memory=MemoryOperand{optionalReg(src.mem.segment),optionalReg(src.mem.base),
                    optionalReg(src.mem.index),unsigned(src.mem.scale),src.mem.disp};
                if(insn.id==X86_INS_LEA)op.access=OperandAccess::Address;
                break;
            default:break; // retain an unknown operand at the original index
        }
        d.operands.push_back(op);
    }
    if(accessAvailable) {
        d.implicitRegistersReported=true;
        for(unsigned k=0;k<insn.detail->regs_read_count;++k)d.implicitReads.push_back(reg(insn.detail->regs_read[k]));
        for(unsigned k=0;k<insn.detail->regs_write_count;++k)d.implicitWrites.push_back(reg(insn.detail->regs_write[k]));
    }
    return d;
}
} // namespace wea
