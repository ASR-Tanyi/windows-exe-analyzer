'use strict';
const assert = require('node:assert/strict');
const VA = require('../web/value-analysis'), SSA = require('../web/register-ssa'), S = require('../web/stack-storage');
const CALL = require('../web/call-summaries');
let checks = 0;
const check = (ok, message) => {assert.ok(ok, message); checks++;};
const reg = (name,width=64,offset=0,familyWidth=64) => ({kind:'register',name,width,offset,familyWidth});
const c = (value,width=64) => ({kind:'constant',value:String(value),width});
const mov = (target,value) => ({kind:'assign',target,value});
const plus = (a,b) => ({kind:'binary',operator:'+',width:a.width,left:a,right:b});
const mem = (address,width=64) => ({kind:'load',address,width});
const sp=reg('rsp'), fp=reg('rbp'), bx=reg('rbx'), cx=reg('rcx'), ax=reg('rax');
const at = (offset=0,width=64) => mem(plus(sp,c(offset)),width);
const adjust = n => mov(sp,plus(sp,c(n)));
const push = value => ({kind:'push',value,width:value.width});
const pop = value => ({kind:'pop',value,width:value.width});
const barrier = {kind:'barrier',reason:'unknown'};
const call = {kind:'call_summary',profile:CALL.PROFILE.id,target:c(0x401000),width:64};
function fixture(bodies,links=[],bits=64) {
    const lifted=new Map(), blocks=Object.entries(bodies).map(([id,ops],n) => {
        const instructions=ops.map((op,k)=>({source:id+'_'+k,rva:4096+n*256+k,status:op.kind==='call_summary'?'assumed':'supported',ops:[op]}));
        lifted.set(id,instructions);
        return {id,rva:4096+n*256,owners:['A'],instructions:instructions.map(i=>({id:i.source,rva:i.rva}))};
    });
    const edges=links.map(([from,to])=>({from,to,kind:'jump',source:lifted.get(from).at(-1).source}));
    const report={module:{architecture:bits===64?'x64':'x86',imageBase:'0x400000'},edges};
    const va=VA.analyze(report,blocks,edges,lifted,'A'), ssa=SSA.analyze(report,blocks,edges,lifted,'A');
    check(va.status==='converged' && ssa.status==='available','safe fixture analyses available');
    return {va,ssa,lifted};
}
function analyze(f,options) {
    const before=JSON.stringify([f.va,f.ssa,[...f.lifted]]), result=S.analyze(f.va,f.ssa,f.lifted,options);
    check(before===JSON.stringify([f.va,f.ssa,[...f.lifted]]),'classification cannot change addresses, aliases, SSA or effects');
    if (!options) check(result.status==='available',result.reason);
    const sources=new Set([...f.lifted.values()].flat().map(i=>i.source));
    for(const pair of result.pairs) {
        check(pair.saveSources.length>0 && pair.sources.includes(pair.loadSource) && pair.saveSources.every(s=>pair.sources.includes(s)),'pair has save/load witnesses');
        check(pair.sources.every(s=>sources.has(s)),'pair evidence identifies real instructions');
        check(result.slots.some(s=>s.id===pair.slot && s.offset===pair.offset && s.width===pair.width),'pair identifies physical slice');
    }
    return result;
}
const run=(ops,options)=>analyze(fixture({A:ops}),options);
const roles=r=>r.slots.flatMap(s=>s.roles.map(x=>x.kind));
let r=run([push(bx),mov(bx,c(7)),pop(bx)]);
check(r.pairs.length===1 && r.pairs[0].entryValue && r.pairs[0].register==='rbx','PUSH/POP restores incoming full register');
r=run([adjust(-32),mov(at(8),bx),mov(bx,c(7)),mov(bx,at(8)),adjust(32)]);
check(roles(r).includes('saved_register'),'MOV save/restore in allocated frame');
r=run([adjust(-16),mov(bx,c(9)),mov(at(),bx),mov(bx,c(7)),mov(bx,at()),adjust(16)]);
check(r.pairs.length===1 && !r.pairs[0].entryValue && roles(r).includes('register_spill'),'non-entry value is only a spill/reload candidate');
for(const [width,offset] of [[8,0],[8,8],[16,0],[32,0]]) {
    const slice=reg('rax',width,offset);
    r=run([adjust(-16),mov(at(0,width),slice),mov(slice,c(1,width)),mov(slice,at(0,width)),adjust(16)]);
    check(r.pairs.length===1 && !r.pairs[0].entryValue && r.pairs[0].registerOffset===offset,'partial slice does not prove full entry-register preservation');
}
for(const middle of [mov(mem(reg('rdi')),cx),mov(mem(c(0x400000)),cx),mov(at(4,8),c(1,8)),barrier,
    adjust(16),mov(sp,plus(sp,cx)),mov(reg('rsp',32),c(0,32)),call]) {
    r=run([adjust(-16),mov(at(),bx),middle,mov(bx,at())]);
    check(!r.pairs.length,'alias, overlap, deallocation, unknown SP and calls break the pair');
}
r=run([adjust(-16),mov(at(),bx),mov(at(8),cx),mov(bx,at())]);
check(r.pairs.length===1,'disjoint known stack write preserves the pair');
r=run([adjust(-16),mov(at(),bx),mov(cx,at()),mov(reg('rbx',32),at(0,32))]);
check(!r.pairs.length,'different register and mismatched width are not save/reload pairs');
r=run([adjust(-16),mov(at(),bx),adjust(16),adjust(-16),mov(bx,at())]);
check(!r.pairs.length,'reallocation does not resurrect released contents');
r=run([adjust(-16),mov(fp,sp),mov(at(),bx),mov(sp,plus(sp,cx)),mov(sp,fp),mov(bx,at())]);
check(!r.pairs.length,'restoring a frame pointer address does not resurrect contents after unknown adjustment');
const nop={kind:'nop'};
let f=fixture({A:[adjust(-16)],B:[mov(at(),bx)],C:[nop],D:[mov(bx,at())]},[['A','B'],['A','C'],['B','D'],['C','D']]);
check(!analyze(f).pairs.length,'a missing store on one predecessor cannot disappear');
f=fixture({A:[adjust(-16)],B:[mov(at(),bx)],C:[mov(at(),bx)],D:[mov(bx,at())]},[['A','B'],['A','C'],['B','D'],['C','D']]);
r=analyze(f);check(r.pairs.length===1 && r.pairs[0].saveSources.length===2 && r.pairs[0].entryValue,'matching stores on both paths retain both witnesses');
f=fixture({A:[adjust(-16)],B:[mov(bx,c(1)),mov(at(),bx)],C:[mov(bx,c(2)),mov(at(),bx)],D:[mov(bx,at())]},[['A','B'],['A','C'],['B','D'],['C','D']]);
check(!analyze(f).pairs.length,'different register definitions on incoming paths remain unknown');
f=fixture({A:[push(bx)],B:[mov(ax,c(1))],C:[pop(bx)]},[['A','B'],['B','B'],['B','C']]);
r=analyze(f);check(r.pairs.length===1 && r.pairs[0].entryValue,'loop-invariant saved value survives the fixed point');
f=fixture({A:[push(bx)],B:[mov(at(),cx)],C:[pop(bx)]},[['A','B'],['B','B'],['B','C']]);
check(!analyze(f).pairs.length,'loop write invalidates incoming save');
const esp=reg('esp',32,0,32),ebx=reg('ebx',32,0,32);
r=analyze(fixture({A:[push(ebx),mov(ebx,c(7,32)),pop(ebx)]},[],32));
check(r.pairs.length===1 && r.pairs[0].entryValue && r.pairs[0].width===32,'x86 pointer-width save/restore');
r=run([mov(mem(plus(sp,c(8))),cx)]);
check(roles(r).includes('entry_stack') && !roles(r).includes('call_home_space'),'incoming positive offset does not select a function ABI');
r=run([mov(at(),ax)]);check(roles(r).includes('entry_return_address'),'entry return region identified even if overwritten');
r=run([adjust(-64),mov(at(0,32),c(9,32)),mov(at(32,32),c(7,32)),call,adjust(64)]);
check(roles(r).includes('call_home_space') && roles(r).includes('call_return_address') && roles(r).includes('outgoing_argument'),'selected call areas plus possible stack argument');
check(r.slots.some(s=>s.width===32 && s.offset==='-64' && s.mixed && s.roles.some(x=>x.kind==='call_home_space')),'implicit home region applies to overlapping smaller slot');
check(r.slots.flatMap(s=>s.roles).filter(x=>['call_home_space','call_return_address','outgoing_argument'].includes(x.kind)).every(x=>x.assumptionSources.includes('A_3')),'ABI-derived roles carry the call assumption');
r=run([adjust(-64),mov(at(32,32),c(7,32)),barrier]);
check(!roles(r).includes('outgoing_argument') && !roles(r).includes('call_home_space'),'unselected call/unknown barrier establishes no ABI area');
r=run([adjust(-16),mov(at(0,32),c(7,32)),mov(reg('rax',32),at(0,32))]);
check(roles(r).includes('candidate_local'),'allocated general storage remains local/temporary candidate');
f=fixture({A:[push(bx),pop(bx)]});
for(const options of [{slots:0},{visits:0},{work:0},{sources:0},{pairs:0}]) {
    r=analyze(f,options);check(r.status==='budget_exceeded' && !r.pairs.length && !r.slots.length,'budget failure discards provisional roles');
}
const capped=JSON.parse(JSON.stringify(f.va));capped.accesses[0].proofTruncated=true;
check(!S.analyze(capped,f.ssa,f.lifted).pairs.length,'truncated address evidence cannot prove a pair');
const bare=JSON.parse(JSON.stringify(f.va));bare.slots.forEach(s=>s.sources=[]);
check(S.analyze(bare,f.ssa,f.lifted).slots[0].sources.includes('A_0'),'slot evidence always includes the actual memory instruction');
check(S.analyze({...f.va,status:'unavailable'},f.ssa,f.lifted).status==='unavailable','unavailable values disable classification');
check(S.analyze(f.va,{status:'unavailable'},f.lifted).status==='unavailable','unavailable SSA disables classification');
const large=fixture({A:[adjust(-4096),...Array.from({length:257},(_,n)=>mov(at(n,8),c(1,8)))]});
for(const options of [undefined,{slots:Infinity},{slots:NaN},{slots:100000}]) {
    r=analyze(large,options || {});check(r.status==='budget_exceeded' && !r.slots.length,'real slot ceiling cannot be disabled by invalid or larger options');
}
assert.deepEqual(S.analyze(f.va,f.ssa,f.lifted),S.analyze(f.va,f.ssa,f.lifted));checks++;
console.log(`PASS: ${checks} stack-storage checks`);
