#pragma once
// Included by report.cpp after quote(). All wide values are lossless strings.
static const char* jsonBool(bool value) { return value?"true":"false"; }
static void registerJson(std::ostream& o,const wea::RegisterSlice& r) {
    o<<"{\"name\":"<<quote(r.name)<<",\"family\":"<<(r.known()?quote(r.family):"null")
     <<",\"bitOffset\":"<<(r.known()?std::to_string(r.bitOffset):"null")
     <<",\"bitWidth\":"<<(r.known()?std::to_string(r.bitWidth):"null")
     <<",\"familyWidth\":"<<(r.known()?std::to_string(r.familyWidth):"null")<<"}";
}
static void optionalRegisterJson(std::ostream& o,const std::optional<wea::RegisterSlice>& r) {
    if(r)registerJson(o,*r);else o<<"null";
}
static void encodingFieldJson(std::ostream& o,const std::optional<wea::EncodingField>& f) {
    if(f)o<<"{\"offset\":"<<f->offset<<",\"widthBits\":"<<f->widthBits<<"}";
    else o<<"null";
}
static void decoderInfoJson(std::ostream& o,const wea::DecoderInfo& d) {
    o<<"{\"name\":"<<quote(d.name)<<",\"apiVersion\":"<<(d.version?quote(*d.version):"null")
     <<",\"headerVersion\":"<<(d.headerVersion?quote(*d.headerVersion):"null")
     <<",\"capabilities\":{\"structuredOperands\":"<<jsonBool(d.structuredOperands)
     <<",\"registerSlices\":"<<jsonBool(d.registerSlices)<<",\"operandAccess\":"<<jsonBool(d.operandAccess)
     <<",\"implicitRegisterAccess\":"<<jsonBool(d.implicitRegisters)<<",\"encodingFields\":"<<jsonBool(d.encodingFields)
     <<",\"completeImplicitRegisterAccess\":false,\"instructionSemantics\":false}}";
}
static void operandDetailsJson(std::ostream& o,const wea::OperandDetails& d) {
    bool slices=d.available,widths=d.available,access=d.available,kinds=d.available;
    auto checkReg=[&](const std::optional<wea::RegisterSlice>& r){if(r && !r->known())slices=false;};
    for(const auto& op:d.operands) {
        if(!op.widthBits)widths=false;
        if(op.access==wea::OperandAccess::Unknown)access=false;
        if(op.kind==wea::OperandKind::Unknown)kinds=false;
        checkReg(op.reg);
        if(op.memory){checkReg(op.memory->segment);checkReg(op.memory->base);checkReg(op.memory->index);}
    }
    o<<"{\"source\":"<<quote(d.available?"capstone_detail":"unavailable")
     <<",\"capabilities\":{\"structuredOperands\":"<<jsonBool(kinds)
     <<",\"registerSlices\":"<<jsonBool(slices)<<",\"operandWidths\":"<<jsonBool(widths)
     <<",\"operandAccess\":"<<jsonBool(access)<<",\"implicitRegisterAccess\":"<<jsonBool(d.implicitRegistersReported)
     <<",\"completeImplicitRegisterAccess\":false,\"instructionSemantics\":false}"
     <<",\"addressWidthBits\":"<<(d.addressWidthBits?std::to_string(d.addressWidthBits):"null")<<",\"operands\":";
    if(!d.available)o<<"null";
    else {
        o<<'[';bool comma=false;
        for(const auto& op:d.operands) {
            if(comma){o<<',';}comma=true;
            o<<"{\"kind\":"<<quote(wea::name(op.kind))<<",\"widthBits\":"<<(op.widthBits?std::to_string(op.widthBits):"null")
             <<",\"access\":"<<quote(wea::name(op.access));
            if(op.reg){o<<",\"register\":";registerJson(o,*op.reg);}
            if(op.immediate)o<<",\"immediate\":{\"value\":"<<quote(hex(*op.immediate))
                <<",\"interpretation\":"<<quote(op.immediateIsTarget?"preferred_va":"bit_pattern")<<"}";
            if(op.memory) {
                const auto& m=*op.memory;o<<",\"memory\":{\"segment\":";optionalRegisterJson(o,m.segment);
                o<<",\"base\":";optionalRegisterJson(o,m.base);o<<",\"index\":";optionalRegisterJson(o,m.index);
                o<<",\"scale\":"<<m.scale<<",\"displacement\":"<<quote(std::to_string(m.displacement))<<"}";
            }
            o<<'}';
        }o<<']';
    }
    o<<",\"prefixes\":";
    if(!d.available)o<<"null";
    else {
        o<<"{\"leadingBytes\":[";
        for(size_t k=0;k<d.leadingPrefixes.size();++k){if(k)o<<',';o<<unsigned(d.leadingPrefixes[k]);}
        o<<"],\"legacyGroups\":[";
        for(size_t k=0;k<d.legacyPrefixGroups.size();++k){if(k)o<<',';o<<unsigned(d.legacyPrefixGroups[k]);}
        o<<"],\"decoderRex\":"<<unsigned(d.decoderRex)<<",\"vectorSemantics\":false}";
    }
    o<<",\"encoding\":";
    if(!d.available)o<<"null";
    else {
        o<<"{\"immediate\":";encodingFieldJson(o,d.immediateEncoding);
        o<<",\"displacement\":";encodingFieldJson(o,d.displacementEncoding);o<<'}';
    }
    o<<",\"implicitRegisters\":{\"status\":"<<quote(d.implicitRegistersReported?"reported_partial":"unavailable")
     <<",\"complete\":false,\"reads\":";
    auto registers=[&](const std::vector<wea::RegisterSlice>& regs) {
        if(!d.implicitRegistersReported){o<<"null";return;}
        o<<'[';bool comma=false;
        for(const auto& r:regs){if(comma)o<<',';comma=true;registerJson(o,r);}o<<']';
    };
    registers(d.implicitReads);o<<",\"writes\":";registers(d.implicitWrites);o<<"}}";
}
