#pragma once
// Included by report.cpp after quote(); all address values remain strings.
static void tlsDirectoryJson(std::ostream& o,const PE& pe,const Analysis& a){
    const auto& d=pe.tlsDirectory;
    auto boolean=[](bool value){return value?"true":"false";};
    auto opt=[&](const std::optional<u32>& v){o<<(v?quote(hex(*v)):"null");};
    auto strings=[&](const auto& v){o<<'[';bool comma=false;for(const auto& x:v){if(comma)o<<',';comma=true;o<<quote(x);}o<<']';};
    o<<"{\"version\":1,\"origin\":\"tls_directory\",\"status\":"<<quote(d.status)
     <<",\"directoryRva\":"<<quote(hex(d.rva))<<",\"directorySize\":"<<d.size
     <<",\"pointerSize\":"<<d.pointerSize<<",\"headerSize\":"<<d.headerSize
     <<",\"headerRead\":"<<boolean(d.headerRead)<<",\"partial\":"<<boolean(d.partial)
     <<",\"malformed\":"<<boolean(d.malformed)<<",\"terminated\":"<<boolean(d.terminated)
     <<",\"callbackLimit\":"<<d.callbackLimit<<",\"discoveryEnabled\":"<<boolean(a.tlsDiscovery)
     <<",\"seedLocations\":"<<a.tlsSeedRvas.size()
     <<",\"relationship\":\"loader_callback_not_cfg_call\",\"ordering\":\"encoded_array_order_not_runtime_trace\""
     <<",\"rawDataStartVa\":"<<quote(hex(d.rawDataStartVa))<<",\"rawDataEndVa\":"<<quote(hex(d.rawDataEndVa))
     <<",\"indexVa\":"<<quote(hex(d.indexVa))<<",\"callbacksVa\":"<<quote(hex(d.callbacksVa))
     <<",\"zeroFill\":"<<d.zeroFill<<",\"characteristics\":"<<quote(hex(d.characteristics))
     <<",\"callbacksFieldRva\":";opt(d.callbacksFieldRva);
    o<<",\"arrayRva\":";opt(d.arrayRva);o<<",\"terminatorRva\":";opt(d.terminatorRva);
    o<<",\"issues\":";strings(d.issues);o<<",\"callbacks\":[";bool comma=false;
    for(const auto& c:d.callbacks){
        if(comma)o<<',';comma=true;
        const bool attempted=c.targetRva&&a.tlsSeedRvas.contains(*c.targetRva);
        const bool decoded=attempted&&a.functions.contains(*c.targetRva)&&a.instructions.contains(*c.targetRva);
        o<<"{\"index\":"<<c.index<<",\"slotRva\":"<<quote(hex(c.slotRva))
         <<",\"targetVa\":"<<quote(hex(c.targetVa))<<",\"targetRva\":";opt(c.targetRva);
        o<<",\"duplicateOf\":"<<(c.duplicateOf?std::to_string(*c.duplicateOf):"null")
         <<",\"executableFileBacked\":"<<boolean(c.executableFileBacked)<<",\"eligible\":"<<boolean(c.eligible)
         <<",\"discovery\":"<<quote(!a.tlsDiscovery?"disabled":!c.eligible?"blocked":decoded?"decoded_candidate":attempted?"not_decoded":"not_attempted")
         <<",\"issues\":";strings(c.issues);o<<'}';
    }o<<"]}";
}
