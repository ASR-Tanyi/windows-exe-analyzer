#include "report.hpp"
#include "viewer_embedded.hpp"
#include "static_data.hpp"
static std::string quote(const std::string&v){
    std::ostringstream o;o<<'"';for(unsigned char c:v){switch(c){
        case '"':o<<"\\\"";break;case '\\':o<<"\\\\";break;case '\n':o<<"\\n";break;case '\r':o<<"\\r";break;case '\t':o<<"\\t";break;
        default:if(c<32||c>=127||c=='<'||c=='>'||c=='&')o<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<unsigned(c)<<std::dec;else o<<char(c);
    }}o<<'"';return o.str();
}
// Additive analysis-model extension: existing schema-2 fields and IDs remain.
static std::string locationJson(const wea::Location& loc){
    return "{\"moduleId\":"+quote(loc.moduleId)+",\"space\":"+quote(wea::name(loc.address.space()))+
           ",\"value\":"+quote(hex(loc.address.value()))+"}";
}
static void evidenceJson(std::ostream& o,const wea::EvidenceSet& facts){
    o<<'[';bool comma=false;
    for(const auto& e:facts){
        if(comma){o<<',';}comma=true;
        o<<"{\"origin\":"<<quote(wea::name(e.origin))<<",\"claim\":"<<quote(e.claim)
         <<",\"resolution\":"<<quote(wea::name(e.resolution))<<",\"status\":"<<quote(wea::name(e.status))
         <<",\"rule\":"<<quote(e.rule)<<",\"ruleVersion\":"<<e.ruleVersion
         <<",\"source\":"<<(e.source?locationJson(*e.source):"null")
         <<",\"detail\":"<<quote(e.detail)<<",\"assumptions\":[";
        bool sep=false;for(const auto& assumption:e.assumptions){if(sep)o<<',';sep=true;o<<quote(assumption);}
        o<<"]}";
    }o<<']';
}
static void rangeJson(std::ostream& o,const wea::CodeRange& r){
    o<<"{\"beginRva\":"<<quote(hex(r.begin().value()))<<",\"endRva\":"<<quote(hex(r.end()))
     <<",\"origin\":"<<quote(r.origin())<<",\"validation\":"<<quote(r.validation())<<"}";
}
static void diagnosticsJson(std::ostream& o,const wea::DiagnosticLog& d){
    o<<"{\"limit\":"<<d.limit()<<",\"total\":"<<d.total()<<",\"omitted\":"<<d.omitted()<<",\"counts\":{";
    bool comma=false;for(const auto& [code,count]:d.counts()){
        if(comma){o<<',';}comma=true;o<<quote(wea::name(code))<<':'<<count;
    }o<<"},\"items\":[";comma=false;
    for(const auto& item:d.items()){
        if(comma){o<<',';}comma=true;
        o<<"{\"code\":"<<quote(wea::name(item.code))<<",\"phase\":"<<quote(item.phase)
         <<",\"message\":"<<quote(item.message)<<",\"location\":"
         <<(item.location?locationJson(*item.location):"null")<<"}";
    }o<<"]}";
}
static void exceptionDirectoryJson(std::ostream& o,const wea::ExceptionDirectory& d){
    o<<"{\"version\":1,\"origin\":\"exception_directory\",\"status\":"<<quote(d.status)
     <<",\"directoryRva\":"<<quote(hex(d.rva))<<",\"directorySize\":"<<d.size
     <<",\"supported\":"<<(d.supported?"true":"false")
     <<",\"malformed\":"<<(d.malformed?"true":"false")<<",\"partial\":"<<(d.partial?"true":"false")
     <<",\"recordLimit\":"<<d.recordLimit<<",\"declaredRecords\":"<<d.declaredRecords
     <<",\"omittedRecords\":"<<(d.declaredRecords-d.records.size())<<",\"trailingBytes\":"<<d.trailingBytes
     <<",\"unwindSemantics\":\"not_decoded\",\"discoverySeedsAdded\":false,\"issues\":[";
    bool comma=false;for(const auto& issue:d.issues){if(comma){o<<',';}comma=true;o<<quote(issue);}
    o<<"],\"records\":[";comma=false;
    for(const auto& r:d.records){
        if(comma){o<<',';}comma=true;
        o<<"{\"index\":"<<r.index<<",\"tableRva\":"<<quote(hex(r.tableRva))
         <<",\"beginRva\":"<<quote(hex(r.beginRva))<<",\"endRva\":"<<quote(hex(r.endRva))
         <<",\"unwindRva\":"<<quote(hex(r.unwindRva))
         <<",\"rangeFileBacked\":"<<(r.rangeFileBacked?"true":"false")
         <<",\"unwindAddressFileBacked\":"<<(r.unwindAddressFileBacked?"true":"false")
         <<",\"validation\":"<<quote(r.issues.empty()?"bounds_checked":"issues_present")
         <<",\"duplicateOf\":"<<(r.duplicateOf?std::to_string(*r.duplicateOf):"null")
         <<",\"overlapWith\":"<<(r.overlapWith?std::to_string(*r.overlapWith):"null")<<",\"issues\":[";
        bool sep=false;for(const auto& issue:r.issues){if(sep)o<<',';sep=true;o<<quote(issue);}o<<"]}";
    }o<<"]}";
}
std::string reportJson(const PE&pe,const Analysis&a,const std::string&filename,size_t dataLimit,const std::map<u32,std::string>&dataNames){
    std::ostringstream o;auto q=[](const std::string&s){return quote(s);};
    auto blockId=[&](u32 r){return pe.moduleId+"_b_"+hex(r).substr(2);};
    auto insnId=[&](u32 r){return pe.moduleId+"_i_"+hex(r).substr(2);};
    auto dataId=[&](u32 r){return pe.moduleId+"_d_"+hex(r).substr(2);};
    o<<"{\"schema\":2,\"analysisModelVersion\":1,\"module\":{\"id\":"<<q(pe.moduleId)<<",\"name\":"<<q(filename)<<",\"architecture\":"<<q(pe.is64?"x64 / PE32+":"x86 / PE32")
      <<",\"kind\":"<<q(pe.dll?"DLL":"EXE")<<",\"imageBase\":"<<q(hex(pe.imageBase))<<",\"entryRva\":"<<pe.entryRva
      <<",\"entryId\":"<<(a.blocks.contains(pe.entryRva)?q(blockId(pe.entryRva)):"null")<<",\"mainId\":"<<(a.mainRva&&a.blocks.contains(*a.mainRva)?q(blockId(*a.mainRva)):"null")
      <<",\"decoder\":"<<q(Decoder::backend())<<",\"instructionCount\":"<<a.instructions.size()<<",\"truncated\":"<<(a.truncated?"true":"false")<<"},\"functions\":[";
    bool comma=false;for(const auto&[r,f]:a.functions){
        if(comma){o<<',';}comma=true;
        o<<"{\"rva\":"<<r<<",\"id\":"<<q(blockId(r))<<",\"name\":"<<q(f.name)<<",\"evidence\":"<<q(f.evidence)
         <<",\"location\":"<<locationJson({pe.moduleId,wea::Address(wea::Rva(r))})<<",\"evidenceRecords\":";
        evidenceJson(o,f.evidenceRecords);o<<",\"decodedRanges\":[";
        bool sep=false;for(const auto& range:f.decodedRanges){if(sep)o<<',';sep=true;rangeJson(o,range);}o<<"]}";
    }
    o<<"],\"blocks\":[";comma=false;
    for(const auto&[r,b]:a.blocks){if(comma){o<<',';}comma=true;
        o<<"{\"rva\":"<<r<<",\"va\":"<<q(hex(pe.imageBase+r))<<",\"id\":"<<q(blockId(r))<<",\"name\":"<<q(b.name)<<",\"role\":"<<q(b.role)<<",\"summary\":"<<q(b.summary)<<",\"evidence\":"<<q(b.evidence)<<",\"location\":"<<locationJson({pe.moduleId,wea::Address(wea::Rva(r))})
         <<",\"evidenceRecords\":";evidenceJson(o,b.evidenceRecords);
        o<<",\"decodedRange\":";if(b.decodedRange)rangeJson(o,*b.decodedRange);else o<<"null";
        o<<",\"owners\":[";
        bool sep=false;for(u32 own:b.owners){if(sep)o<<',';sep=true;o<<q(blockId(own));}o<<"],\"instructions\":[";sep=false;
        for(u32 ip:b.instructions){if(sep)o<<',';sep=true;const auto&i=a.instructions.at(ip);
            o<<"{\"rva\":"<<ip<<",\"va\":"<<q(hex(pe.imageBase+ip))<<",\"id\":"<<q(insnId(ip))<<",\"size\":"<<i.size<<",\"bytes\":"<<q(i.bytes)<<",\"mnemonic\":"<<q(i.mnemonic)<<",\"operands\":"<<q(i.operands)<<",\"notes\":"<<q(i.notes)<<",\"dataRefs\":[";
            bool rc=false;for(const auto&ref:i.dataRefs){if(rc)o<<',';rc=true;auto target=pe.rvaOf(ref.va);
                o<<"{\"va\":"<<q(hex(ref.va))<<",\"rva\":"<<(target?std::to_string(*target):"null")
                 <<",\"to\":"<<(target?q(dataId(*target)):"null")<<",\"mode\":"<<q(ref.mode)
                 <<",\"access\":"<<q(ref.access)<<",\"width\":"<<ref.width<<",\"operand\":"<<ref.operand
                 <<",\"textBegin\":"<<ref.textBegin<<",\"textEnd\":"<<ref.textEnd
                 <<",\"displacement\":"<<ref.displacement<<",\"evidence\":"<<q(ref.evidence)<<"}";
            }o<<"]}";}

        o<<"]}";
    }o<<"],\"edges\":[";comma=false;
    for(const auto&e:a.edges){if(comma){o<<',';}comma=true;o<<"{\"from\":"<<q(blockId(e.from))<<",\"source\":"<<q(insnId(e.source))<<",\"to\":"<<(e.to?q(blockId(*e.to)):"null")<<",\"kind\":"<<q(e.kind)<<",\"external\":"<<q(e.external)<<",\"target\":"<<q(e.target)<<"}";}
    o<<"],\"imports\":[";comma=false;for(const auto&[r,i]:pe.imports){if(comma){o<<',';}comma=true;o<<"{\"id\":"<<q(pe.moduleId+"_iat_"+hex(r).substr(2))<<",\"rva\":"<<r<<",\"dll\":"<<q(i.dll)<<",\"name\":"<<q(i.name)<<"}";}
    o<<"],\"exports\":[";comma=false;for(const auto&e:pe.exports){if(comma){o<<',';}comma=true;o<<"{\"rva\":"<<e.rva<<",\"name\":"<<q(e.name)<<",\"forwarder\":"<<q(e.forwarder)<<"}";}
    o<<"],\"data\":{";
    auto data=collectStaticData(pe,a,dataLimit);
    o<<"\"budget\":"<<data.budget<<",\"embeddedBytes\":"<<data.embedded<<",\"fileBytes\":"<<data.fileBytes
     <<",\"truncated\":"<<(data.embedded<data.fileBytes?"true":"false")<<",\"regions\":[";comma=false;
    static const char* digits="0123456789abcdef";
    for(const auto&r:data.regions){if(comma){o<<',';}comma=true;
        o<<"{\"rva\":"<<r.rva<<",\"size\":"<<r.size<<",\"fileSize\":"<<r.fileSize<<",\"fileOffset\":"<<r.fileOffset
         <<",\"name\":"<<q(r.name)<<",\"flags\":"<<r.flags<<",\"chunks\":[";bool sep=false;
        for(const auto&[offset,bytes]:r.chunks){if(sep)o<<',';sep=true;std::string encoded;encoded.reserve(bytes.size()*2);
            for(u8 b:bytes){encoded+=digits[b>>4];encoded+=digits[b&15];}
            o<<"{\"offset\":"<<offset<<",\"hex\":"<<q(encoded)<<"}";
        }o<<"]}";
    }
    o<<"],\"targets\":[";comma=false;std::set<u32> targets;
    for(const auto&[ip,i]:a.instructions){(void)ip;for(const auto&ref:i.dataRefs){auto target=pe.rvaOf(ref.va);if(target)targets.insert(*target);}}
    for(const auto&[r,name]:dataNames){(void)name;targets.insert(r);}
    for(u32 target:targets){if(comma){o<<',';}comma=true;
        std::string name="data_"+hex(target).substr(2),evidence="Referenced address; object boundaries and types are not inferred";
        if(pe.imports.contains(target)){const auto&imp=pe.imports.at(target);name="iat_"+imp.name;evidence="IAT slot from PE import metadata";}
        if(dataNames.contains(target)){name=dataNames.at(target);evidence="Analyst-supplied data label";}
        o<<"{\"rva\":"<<target<<",\"id\":"<<q(dataId(target))<<",\"name\":"<<q(name)<<",\"evidence\":"<<q(evidence)<<"}";
    }
    o<<"]},\"diagnostics\":";diagnosticsJson(o,a.diagnostics);o<<",\"exceptionDirectory\":";exceptionDirectoryJson(o,pe.exceptionDirectory);o<<",\"warnings\":[";comma=false;for(const auto&w:a.warnings){if(comma){o<<',';}comma=true;o<<q(w);}o<<"]}";return o.str();
}
void writeHtml(const std::string&path,const std::string&json){std::string html=VIEWER_TEMPLATE;auto pos=html.find("__REPORT_JSON__");if(pos==html.npos)throw std::runtime_error("HTML template missing data slot");html.replace(pos,15,json);
    std::ofstream f(path,std::ios::binary);if(!f||!f.write(html.data(),static_cast<std::streamsize>(html.size())))throw std::runtime_error("Cannot write HTML: "+path);
}
