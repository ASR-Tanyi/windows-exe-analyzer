#pragma once
#include "decoder.hpp"
inline Analysis analyze(const PE&pe,size_t limit,std::optional<u32> mainRva,const std::map<u32,std::string>&names,bool metadataDiscovery=true){
    using wea::DiagnosticCode;
    Analysis a;a.metadataDiscovery=metadataDiscovery;a.mainRva=mainRva;a.names=names;a.warnings=pe.warnings;
    a.diagnostics=pe.diagnostics;Decoder decoder(pe.is64);std::queue<u32> todo;
    auto location=[&](u32 r){return wea::Location{pe.moduleId,wea::Address(wea::Rva(r))};};
    auto warn=[&](DiagnosticCode code,const std::string& message,
                  std::optional<wea::Location> at=std::nullopt){
        a.diagnostics.add(code,"discovery",message,std::move(at));
        if(a.warnings.size()<a.diagnostics.limit())a.warnings.push_back(message);
    };
    auto recordFunction=[&](u32 rva,std::string name,std::string legacy,wea::Evidence fact){
        auto [it,inserted]=a.functions.try_emplace(rva);
        if(inserted){it->second.rva=rva;it->second.name=std::move(name);it->second.evidence=std::move(legacy);}
        it->second.evidenceRecords.insert(std::move(fact));
    };
    auto root=[&](u32 rva,std::string name,std::string legacy,wea::Evidence fact){
        if(!pe.available(rva,true)){
            warn(DiagnosticCode::UnmappedTarget,"Cannot decode function seed "+hex(rva),location(rva));return;
        }
        recordFunction(rva,std::move(name),std::move(legacy),std::move(fact));todo.push(rva);
    };
    if(pe.entryRva)root(pe.entryRva,"pe_entry","PE AddressOfEntryPoint; not automatically main()",
        {wea::EvidenceOrigin::PeHeader,"image_entry",wea::Resolution::Encoded,
         wea::EvidenceStatus::Confirmed,"pe.entry",1,
         pe.entryFieldOffset?std::optional<wea::Location>{{pe.moduleId,wea::Address(*pe.entryFieldOffset)}}:std::nullopt,
         "PE AddressOfEntryPoint",{"The image entry is not necessarily a source-level function or main()."}});
    for(const auto&e:pe.exports)if(e.forwarder.empty()&&pe.available(e.rva,true))
        root(e.rva,e.name,"Export name; executable function candidate",
            {wea::EvidenceOrigin::ExportTable,"function_entry",wea::Resolution::Encoded,
             wea::EvidenceStatus::Candidate,"pe.executable_export",1,
             e.tableEntryRva?std::optional<wea::Location>{location(*e.tableEntryRva)}:std::nullopt,
             e.name,{"An executable export is a function candidate, not a complete boundary."}});
    if(mainRva){
        root(*mainRva,"main","Analyst-supplied main RVA; not auto-detected",
            {wea::EvidenceOrigin::Analyst,"application_entry",wea::Resolution::Supplied,
             wea::EvidenceStatus::Assertion,"cli.main_rva",1,std::nullopt,"--main-rva",
             {"This role was supplied by the analyst; startup has not been recognized."}});
        if(a.functions.contains(*mainRva)){a.functions[*mainRva].name="main";a.functions[*mainRva].evidence="Analyst-supplied main RVA; not auto-detected";}
    }
    std::set<u32> attempted;
    bool budgetHit=false;
    std::map<u32,u32> metadataBounds;
    // Existing entry/export/direct-call traversal wins instruction-boundary
    // conflicts. Only after it finishes do metadata-only roots expand the CFG.
    for(unsigned phase=0;phase<2;++phase){
      if(phase==1&&metadataDiscovery){
        for(const auto& assessment:pe.unwindInfo.records){
            if(!assessment.eligible)continue;
            const auto& record=pe.exceptionDirectory.records.at(assessment.recordIndex);
            const u32 rva=record.beginRva;
            const bool first=a.metadataSeedRvas.insert(rva).second;
            recordFunction(rva,(assessment.chainDepth?"fragment_":"sub_")+hex(rva).substr(2),
                "Supported v1 runtime-function metadata; candidate entry",
                {wea::EvidenceOrigin::ExceptionDirectory,
                 assessment.chainDepth?"procedure_fragment_entry":"function_entry",wea::Resolution::Encoded,
                 wea::EvidenceStatus::Candidate,"pe.unwind_v1_seed",1,location(record.tableRva),
                 "Record #"+std::to_string(record.index)+"; primary range begins at "+hex(*assessment.primaryBeginRva),
                 {"Structural unwind validation does not prove machine-code semantics or a source function.",
                  "Chained fragments retain their primary association; source-level ownership is not merged."}});
            a.functions.at(rva).metadataRecords.push_back(record.index);
            metadataBounds.emplace(rva,record.endRva);
            if(first)todo.push(rva);
        }
      }
      while(!todo.empty()&&!budgetHit){u32 pc=todo.front();todo.pop();
        std::optional<u32> stopRva;
        if(phase==1){auto it=metadataBounds.upper_bound(pc);if(it!=metadataBounds.begin()){
            --it;if(pc<it->second)stopRva=it->second;
        }}
        while(!attempted.contains(pc)){
            if(!pe.available(pc,true)){
                warn(DiagnosticCode::UnmappedTarget,"Traversal reached non-file-backed code: "+hex(pc),location(pc));break;
            }
            // Only report exhaustion if there really is more unvisited code.
            // A return at exactly the limit is not a truncated traversal.
            if(a.instructions.size()>=limit){budgetHit=true;break;}
            attempted.insert(pc);
            auto upper=a.instructions.upper_bound(pc);
            if(upper!=a.instructions.begin()){const auto&prev=std::prev(upper)->second;if(u64(prev.rva)+prev.size>pc){warn(DiagnosticCode::OverlappingDecode,"Overlapping instruction target rejected: "+hex(pc),location(pc));break;}}
            auto maybe=decoder.decode(pe,pc);if(!maybe){warn(DiagnosticCode::DecodeFailed,"Undecodable bytes at "+hex(pc),location(pc));break;}Instruction i=*maybe;
            if(upper!=a.instructions.end()&&u64(pc)+i.size>upper->first){warn(DiagnosticCode::OverlappingDecode,"Overlapping instruction stream rejected: "+hex(pc),location(pc));break;}
            if(stopRva&&u64(pc)+i.size>*stopRva){
                warn(DiagnosticCode::InvalidMetadata,"Decoded instruction crosses metadata range end: "+hex(pc),location(pc));break;
            }
            a.instructions[pc]=i;
            if((i.call||i.jump)&&i.targetVA){auto t=pe.rvaOf(*i.targetVA);if(t&&pe.available(*t,true)){
                if(i.call)recordFunction(*t,"sub_"+hex(*t).substr(2),"Direct-call target; inferred function boundary",
                    {wea::EvidenceOrigin::DecodedInstruction,"function_entry",wea::Resolution::Encoded,
                     wea::EvidenceStatus::Candidate,"cfg.direct_call",1,location(i.rva),
                     "Direct-call destination",{"A call destination is not proof of a source-level function boundary."}});
                todo.push(*t);
            }else warn(DiagnosticCode::UnmappedTarget,"Direct control-flow target is not file-backed executable code: "+hex(*i.targetVA),
                       wea::Location{pe.moduleId,wea::Address(wea::PreferredVa(*i.targetVA))});}
            if(i.stop||(i.jump&&!i.conditional))break;
            u64 next=u64(pc)+i.size;if(next>UINT32_MAX||(stopRva&&next>=*stopRva))break;pc=u32(next);
        }
    }
    } // discovery phases
    a.truncated=budgetHit;if(a.truncated)warn(DiagnosticCode::BudgetExhausted,"Instruction limit reached; report is partial.");
    for(auto it=a.functions.begin();it!=a.functions.end();){if(!a.instructions.contains(it->first)){warn(DiagnosticCode::UnresolvedSeed,"Unresolved function seed: "+hex(it->first),location(it->first));it=a.functions.erase(it);}else ++it;}
    std::set<u32> leaders;for(const auto&[r,f]:a.functions){(void)f;leaders.insert(r);}
    if(!a.instructions.empty())leaders.insert(a.instructions.begin()->first);
    for(const auto&[r,n]:names){(void)n;if(a.instructions.contains(r))leaders.insert(r);else warn(DiagnosticCode::IgnoredAnnotation,"Name ignored: RVA not decoded: "+hex(r),location(r));}
    for(const auto&[r,i]:a.instructions){
        if((i.jump||i.call)&&i.targetVA){auto t=pe.rvaOf(*i.targetVA);if(t&&a.instructions.contains(*t))leaders.insert(*t);}
        u64 next=u64(r)+i.size;
        if((i.jump||i.call||i.stop)&&next<=UINT32_MAX&&a.instructions.contains(u32(next)))leaders.insert(u32(next));
    }
    u32 current=0;u64 expected=UINT64_MAX;
    for(const auto&[r,i]:a.instructions){
        if(expected!=r||leaders.contains(r)){current=r;Block b;b.rva=r;a.blocks[r]=b;}
        a.blocks[current].instructions.push_back(r);expected=u64(r)+i.size;
        if(i.call||i.jump||i.stop)expected=UINT64_MAX;
    }
    std::map<u32,u32> blockOf;for(const auto&[r,b]:a.blocks)for(u32 ip:b.instructions)blockOf[ip]=r;
    auto edge=[&](const Block&b,const Instruction&i,std::string kind,std::optional<u64> target,bool importable){
        Edge e;e.from=b.rva;e.source=i.rva;e.kind=std::move(kind);
        if(target){e.target=hex(*target);auto t=pe.rvaOf(*target);if(t&&blockOf.contains(*t))e.to=blockOf[*t];}
        if(importable&&i.memoryVA){auto slot=pe.rvaOf(*i.memoryVA);if(slot&&pe.imports.contains(*slot)){
            const auto&im=pe.imports.at(*slot);e.external=im.dll+"!"+im.name;e.target="iat_"+hex(*slot).substr(2);
        }}
        if(!target&&e.external.empty())e.target=i.operands.empty()?"unknown":i.operands;
        a.edges.push_back(std::move(e));
    };
    for(const auto&[r,b]:a.blocks){(void)r;const auto&i=a.instructions.at(b.instructions.back());u64 next=pe.imageBase+i.rva+i.size;
        if(i.call){edge(b,i,"call",i.targetVA,true);edge(b,i,"continuation",next,false);}
        else if(i.jump){edge(b,i,i.conditional?"taken":"jump",i.targetVA,true);if(i.conditional)edge(b,i,"not_taken",next,false);}
        else if(!i.stop)edge(b,i,"fallthrough",next,false);
    }
    std::map<u32,std::vector<size_t>> outgoing;for(size_t k=0;k<a.edges.size();k++)outgoing[a.edges[k].from].push_back(k);
    // Function membership is inferred via non-call CFG edges. Shared blocks keep all owners.
    size_t ownershipWork=0;
    for(const auto&[r,f]:a.functions){(void)f;std::queue<u32> q;q.push(r);std::set<u32> seen;
        while(!q.empty()&&ownershipWork<2000000){u32 b=q.front();q.pop();if(!seen.insert(b).second||!a.blocks.contains(b))continue;
            if(b!=r&&a.functions.contains(b))continue;
            ++ownershipWork;a.blocks[b].owners.push_back(r);
            for(size_t k:outgoing[b]){const auto&e=a.edges[k];if(e.to&&e.kind!="call")q.push(*e.to);}
        }
    }
    if(ownershipWork>=2000000)warn(DiagnosticCode::BudgetExhausted,"Function-membership work limit reached; some owners omitted.");
    std::set<u32> backwardTargets;
    for(const auto&e:a.edges)if(e.to&&*e.to<=e.from&&e.kind!="call"&&e.kind!="continuation")backwardTargets.insert(*e.to);
    for(auto&[r,b]:a.blocks){
        const auto&i=a.instructions.at(b.instructions.back());std::string suffix=hex(r).substr(2);b.evidence="Structural hint from decoded instructions; not recovered source meaning";
        if(i.ret){b.role="return path";b.name="return_"+suffix;b.summary="Ends with a return instruction. The caller destination is runtime state.";}
        else if(i.call){b.role="call site";b.name="call_"+suffix;b.summary="Calls another target. The continuation is shown separately and assumes a returning callee.";}
        else if(i.conditional){b.role="condition check";b.name="check_"+suffix;b.summary="Ends with "+i.mnemonic+"; inspect the flag-producing instructions and both outgoing paths.";}
        else if(i.jump){b.role="jump block";b.name="jump_"+suffix;b.summary="Ends with an unconditional transfer. There is no sequential fall-through.";}
        else if(i.stop){b.role="stop/trap";b.name="stop_"+suffix;b.summary="Analysis stops at this return, trap, or context-transfer instruction.";}
        else {b.role="straight-line block";b.name="block_"+suffix;b.summary="Sequential instructions up to another block boundary or analysis boundary.";}
        if(backwardTargets.contains(r)){b.role+=" / backward target";b.summary+=" A backward edge targets this block; this is a loop clue, not proof of a natural loop.";}
        if(a.functions.contains(r)){const auto&f=a.functions.at(r);b.name=f.name;b.evidence=f.evidence;b.role="function entry / "+b.role;}
        b.evidenceRecords.insert({wea::EvidenceOrigin::AnalysisRule,"block_role",wea::Resolution::Inferred,
            wea::EvidenceStatus::Heuristic,"cfg.block_role",1,location(i.rva),b.role,
            {"Based on a partial static CFG; not recovered source meaning."}});
        if(names.contains(r)){
            b.name=names.at(r);b.evidence="Analyst-supplied label";
            wea::Evidence label{wea::EvidenceOrigin::Analyst,"display_name",wea::Resolution::Supplied,
                wea::EvidenceStatus::Assertion,"cli.name",1,std::nullopt,b.name,{}};
            b.evidenceRecords.insert(label);
            if(a.functions.contains(r)){
                auto& f=a.functions[r];f.name=b.name;f.evidence=b.evidence;f.evidenceRecords.insert(label);
            }
        }
        if(a.functions.contains(r)){
            const auto& facts=a.functions.at(r).evidenceRecords;
            b.evidenceRecords.insert(facts.begin(),facts.end());
        }
        b.decodedRange=wea::CodeRange(wea::Rva(r),u64(i.rva)+i.size);
        for(u32 owner:b.owners)wea::appendDecodedRange(a.functions.at(owner).decodedRanges,*b.decodedRange);
        if(b.owners.size()>1)warn(DiagnosticCode::AmbiguousOwner,
            "Block has multiple inferred function owners: "+hex(r),location(r));
        if(r==pe.entryRva)b.summary="PE entry RVA from the image header. This is not automatically main(), and TLS initialization may precede it. "+b.summary;
        if(mainRva&&r==*mainRva)b.summary="Marked as main by the analyst; no automatic CRT-to-main recovery. "+b.summary;
    }
    return a;
}
