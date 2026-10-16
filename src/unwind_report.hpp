#pragma once
// Included by report.cpp after quote/locationJson; no additional JSON library.
static void unwindInfoJson(std::ostream& o,const PE& pe,const Analysis& a){
    const auto& u=pe.unwindInfo;
    auto boolean=[](bool value){return value?"true":"false";};
    auto strings=[&](const auto& values){o<<'[';bool comma=false;for(const auto& value:values){if(comma){o<<',';}comma=true;o<<quote(value);}o<<']';};
    auto optionalRva=[&](const std::optional<u32>& value){o<<(value?quote(hex(*value)):"null");};
    o<<"{\"version\":1,\"scope\":\"structural_v1_not_stack_unwinding\",\"supportedVersions\":[1]"
     <<",\"partial\":"<<boolean(u.partial)<<",\"nodeLimit\":"<<u.nodeLimit
     <<",\"slotLimit\":"<<u.slotLimit<<",\"chainLimit\":"<<u.chainLimit<<",\"slotsRead\":"<<u.slotsRead
     <<",\"discoveryEnabled\":"<<boolean(a.metadataDiscovery)
     <<",\"seedLocations\":"<<a.metadataSeedRvas.size()<<",\"nodes\":[";
    bool comma=false;
    for(const auto& [rva,n]:u.nodes){
        if(comma){o<<',';}comma=true;
        o<<"{\"rva\":"<<quote(hex(rva))<<",\"headerRead\":"<<boolean(n.headerRead)
         <<",\"version\":"<<n.version<<",\"flags\":"<<n.flags<<",\"prologSize\":"<<n.prologSize
         <<",\"codeSlots\":"<<n.codeSlots<<",\"frameRegister\":"<<n.frameRegister<<",\"frameOffset\":"<<n.frameOffset
         <<",\"status\":"<<quote(n.status)<<",\"issues\":";strings(n.issues);
        o<<",\"handlerRva\":";optionalRva(n.handlerRva);
        o<<",\"handlerFieldRva\":";optionalRva(n.handlerFieldRva);
        o<<",\"handlerDataRva\":";optionalRva(n.handlerDataRva);
        o<<",\"chain\":";
        if(n.chain){const auto& c=*n.chain;
            o<<"{\"fieldRva\":"<<quote(hex(c.fieldRva))<<",\"beginRva\":"<<quote(hex(c.beginRva))
             <<",\"endRva\":"<<quote(hex(c.endRva))<<",\"unwindRva\":"<<quote(hex(c.unwindRva))<<"}";
        }else o<<"null";
        o<<",\"operations\":[";bool sep=false;
        for(const auto& op:n.operations){if(sep)o<<',';sep=true;
            o<<"{\"slot\":"<<op.slot<<",\"offset\":"<<op.offset<<",\"opcode\":"<<op.opcode
             <<",\"info\":"<<op.info<<",\"slots\":"<<op.slots<<",\"operand\":"<<quote(hex(op.operand))<<"}";
        }o<<"]}";
    }
    o<<"],\"records\":[";comma=false;
    for(const auto& assessment:u.records){
        if(comma){o<<',';}comma=true;
        const auto& r=pe.exceptionDirectory.records.at(assessment.recordIndex);
        const bool attempted=a.metadataSeedRvas.contains(r.beginRva);
        const bool decoded=attempted&&a.functions.contains(r.beginRva)&&a.instructions.contains(r.beginRva);
        o<<"{\"recordIndex\":"<<assessment.recordIndex<<",\"status\":"<<quote(assessment.status)
         <<",\"eligible\":"<<boolean(assessment.eligible)<<",\"chainDepth\":"<<assessment.chainDepth
         <<",\"primaryBeginRva\":";optionalRva(assessment.primaryBeginRva);
        o<<",\"reasons\":";strings(assessment.reasons);
        o<<",\"discovery\":"<<quote(!a.metadataDiscovery?"disabled":!assessment.eligible?"blocked":decoded?"decoded_candidate":attempted?"not_decoded":"not_attempted")<<"}";
    }o<<"]}";
}
