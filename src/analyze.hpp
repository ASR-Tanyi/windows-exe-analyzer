#pragma once
#include "decoder.hpp"
inline Analysis analyze(const PE&pe,size_t limit,std::optional<u32> mainRva,const std::map<u32,std::string>&names){
    Analysis a;a.mainRva=mainRva;a.names=names;a.warnings=pe.warnings;Decoder decoder(pe.is64);std::queue<u32> todo;
    auto warn=[&](const std::string&s){if(a.warnings.size()<100)a.warnings.push_back(s);};
    auto root=[&](u32 rva,std::string name,std::string evidence){
        if(!pe.available(rva,true)){warn("Cannot decode function seed "+hex(rva));return;}
        if(!a.functions.contains(rva))a.functions[rva]={rva,std::move(name),std::move(evidence)};
        todo.push(rva);
    };
    if(pe.entryRva)root(pe.entryRva,"pe_entry","PE AddressOfEntryPoint; not automatically main()");
    for(const auto&e:pe.exports)if(e.forwarder.empty()&&pe.available(e.rva,true))root(e.rva,e.name,"Export name; executable function candidate");
    if(mainRva){root(*mainRva,"main","Analyst-supplied main RVA; not auto-detected");if(a.functions.contains(*mainRva)){a.functions[*mainRva].name="main";a.functions[*mainRva].evidence="Analyst-supplied main RVA; not auto-detected";}}
    std::set<u32> attempted;
    while(!todo.empty()&&a.instructions.size()<limit){u32 pc=todo.front();todo.pop();
        while(a.instructions.size()<limit&&!attempted.contains(pc)){
            attempted.insert(pc);if(!pe.available(pc,true))break;
            auto upper=a.instructions.upper_bound(pc);
            if(upper!=a.instructions.begin()){const auto&prev=std::prev(upper)->second;if(u64(prev.rva)+prev.size>pc){warn("Overlapping instruction target rejected: "+hex(pc));break;}}
            auto maybe=decoder.decode(pe,pc);if(!maybe){warn("Undecodable bytes at "+hex(pc));break;}Instruction i=*maybe;
            if(upper!=a.instructions.end()&&u64(pc)+i.size>upper->first){warn("Overlapping instruction stream rejected: "+hex(pc));break;}
            a.instructions[pc]=i;
            if((i.call||i.jump)&&i.targetVA){auto t=pe.rvaOf(*i.targetVA);if(t&&pe.available(*t,true)){
                if(i.call&&!a.functions.contains(*t))a.functions[*t]={*t,"sub_"+hex(*t).substr(2),"Direct-call target; inferred function boundary"};
                todo.push(*t);
            }}
            if(i.stop||(i.jump&&!i.conditional))break;
            u64 next=u64(pc)+i.size;if(next>UINT32_MAX)break;pc=u32(next);
        }
    }
    a.truncated=a.instructions.size()>=limit;if(a.truncated)warn("Instruction limit reached; report is partial.");
    for(auto it=a.functions.begin();it!=a.functions.end();){if(!a.instructions.contains(it->first)){warn("Unresolved function seed: "+hex(it->first));it=a.functions.erase(it);}else ++it;}
    std::set<u32> leaders;for(const auto&[r,f]:a.functions){(void)f;leaders.insert(r);}
    if(!a.instructions.empty())leaders.insert(a.instructions.begin()->first);
    for(const auto&[r,n]:names){(void)n;if(a.instructions.contains(r))leaders.insert(r);else warn("Name ignored: RVA not decoded: "+hex(r));}
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
    if(ownershipWork>=2000000)warn("Function-membership work limit reached; some owners omitted.");
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
        if(names.contains(r)){b.name=names.at(r);b.evidence="Analyst-supplied label";if(a.functions.contains(r)){a.functions[r].name=b.name;a.functions[r].evidence=b.evidence;}}
        if(r==pe.entryRva)b.summary="PE entry RVA from the image header. This is not automatically main(), and TLS initialization may precede it. "+b.summary;
        if(mainRva&&r==*mainRva)b.summary="Marked as main by the analyst; no automatic CRT-to-main recovery. "+b.summary;
    }
    return a;
}
