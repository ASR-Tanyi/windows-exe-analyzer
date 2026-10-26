'use strict';
const assert = require('node:assert/strict'), SSA = require('../web/register-ssa'), ABI = require('../web/function-abi');
let checks = 0;
const check = (ok,why) => {assert.ok(ok,why); checks++;};
const reg = (name,width=64,offset=0) => ({kind:'register',name,width,offset,familyWidth:64});
const c = n => ({kind:'constant',value:String(n),width:64});
const mov = (target,value) => ({kind:'assign',target,value});
const ret = {kind:'return',width:64,adjustment:c(0)}, nop = {kind:'nop'};
function fixture(bodies,links=[]) {
    const lifted = new Map(), blocks = Object.entries(bodies).map(([id,ops],n) => {
        const instructions = ops.map((op,k) => ({source:id+'_'+k,rva:4096+n*256+k,status:op.kind==='barrier'?'barrier':'supported',
            ops:op.kind==='return'?[]:[op],...(op.kind==='return'?{control:op}:{})}));
        lifted.set(id,instructions);
        return {id,rva:4096+n*256,owners:['A'],instructions:instructions.map(i=>({id:i.source,rva:i.rva}))};
    });
    const edges = links.map(([from,to])=>({from,to,kind:'jump',source:lifted.get(from).at(-1).source}));
    const report = {module:{id:'module',architecture:'x64',imageBase:'0x400000'},functions:[{id:'A',rva:4096}],blocks,edges};
    return {report,lifted,graph:SSA.analyze(report,blocks,edges,lifted,'A')};
}
function run(f,options={},manifest={...ABI.emptyContract(f.report,'A'),profile:ABI.PROFILE.id}) {
    const before = JSON.stringify([f.report,f.graph,[...f.lifted]]);
    const result = ABI.analyze(f.report,f.graph,f.lifted,'A',manifest,()=>{throw Error('unexpected caller');},options);
    check(JSON.stringify([f.report,f.graph,[...f.lifted]])===before,'ABI evidence must not change inputs');
    const ids = new Set([...f.lifted.values()].flat().map(i=>i.source));
    for(const row of [...result.arguments,...result.returns]) check(row.sources.every(s=>ids.has(s)),'evidence refers to actual instructions');
    return result;
}
const ax=reg('rax'),cx=reg('rcx'),dx=reg('rdx');
let f=fixture({A:[mov(ax,cx),ret]}),r=run(f);
check(r.status==='available' && r.arguments.length===1 && r.arguments[0].register==='rcx','direct incoming argument read');
check(r.returns[0].status==='written' && r.returns[0].alternatives[0].source==='A_0','return definition at actual RET');
check(run(f,{},null).status==='default' && !run(f,{},null).arguments.length,'no automatic ABI');
r=run(fixture({A:[mov(reg('rcx',8),c(3)),mov(ax,cx),ret]}));
check(r.arguments[0].mask==='0xffffffffffffff00' && r.arguments[0].sources.includes('A_0'),'partial overwrite retains only incoming upper bits and its witness');
r=run(fixture({A:[mov(reg('rcx',32),c(3)),mov(ax,cx),ret]}));
check(!r.arguments.length,'x64 low32 write kills all incoming bits');
for(const operator of ['xor','sub']) {
    r=run(fixture({A:[{kind:'alu',operator,target:cx,left:cx,right:cx,width:64},ret]}));
    check(!r.arguments.length,'same-register clearing idiom is not an input');
}
r=run(fixture({A:[nop],B:[mov(cx,c(7))],C:[nop],D:[mov(ax,cx),ret]},[['A','B'],['A','C'],['B','D'],['C','D']]));
check(r.arguments.length===1 && r.arguments[0].sources.includes('C_0'),'incoming value on one predecessor is a possible input');
r=run(fixture({A:[nop],B:[mov(cx,c(7))],C:[mov(cx,c(8))],D:[mov(ax,cx),ret]},[['A','B'],['A','C'],['B','D'],['C','D']]));
check(!r.arguments.length,'all incoming paths overwrite input');
r=run(fixture({A:[nop],B:[mov(ax,cx),mov(cx,c(7))],C:[ret]},[['A','B'],['B','B'],['B','C']]));
check(r.arguments.length===1,'entry values remain distinct from a loop backedge');
r=run(fixture({A:[{kind:'barrier',reason:'unknown'},mov(ax,cx),ret]}));
check(!r.arguments.length,'unknown effects break incoming identity');
r=run(fixture({A:[ret],B:[mov(ax,cx),ret]}));
check(!r.arguments.length && r.returns.length===1 && r.returns[0].status==='incoming','unreachable read excluded and unwritten RAX remains incoming');
r=run(fixture({A:[nop],B:[mov(ax,c(1))],C:[{kind:'barrier',reason:'unknown'}],D:[ret]},[['A','B'],['A','C'],['B','D'],['C','D']]));
check(r.returns[0].status==='mixed' && r.returns[0].alternatives.length===2,'unknown and written return alternatives cannot collapse');
r=run(fixture({A:[mov(reg('rax',8),c(1)),{...ret,adjustment:c(8)}]}));
check(r.returns[0].alternatives[0].slice.width===8 && r.conflicts.length===1,'partial return widths and conflicting RET cleanup retained');
for(const patch of [{version:2},{moduleId:'wrong'},{functionId:'wrong'},{profile:'cdecl'},{extra:true},{profile:false}]) {
    r=run(f,{}, {...ABI.emptyContract(f.report,'A'),profile:ABI.PROFILE.id,...patch});
    check(r.status==='invalid' && !r.arguments.length && !r.contract.profile,'invalid manifest cannot activate evidence');
}
for(const manifest of [{},[],false,'text',42]) check(run(f,{},manifest).status==='invalid','invalid manifest shape');
for(const key of ['work','sources','observations','moduleItems']) {
    r=run(f,{[key]:0});check(r.status==='budget_exceeded' && !r.arguments.length && !r.returns.length,'budget discards provisional candidates: '+key);
}
// Exercise the real observation ceiling, including options that try to raise it.
const large=fixture({A:[...Array.from({length:257},()=>mov(ax,cx)),ret]});
for(const limit of [undefined,Infinity,NaN,100000]) {
    r=run(large,{observations:limit});check(r.status==='budget_exceeded' && !r.arguments.length,'hard observation ceiling cannot be disabled');
}
const manySources=fixture({A:[...Array.from({length:65},()=>mov(ax,cx)),ret]});
for(const limit of [64,Infinity,100000]) {
    r=run(manySources,{sources:limit});check(r.status==='budget_exceeded' && !r.arguments.length,'hard source cap discards provisional evidence');
}
const largeModule=fixture({A:[mov(ax,cx),ret]});
largeModule.report.functions=largeModule.report.functions.concat(Array.from({length:ABI.LIMITS.moduleItems},(_,n)=>({id:'outside_'+n,rva:8192+n})));
r=run(largeModule,{moduleItems:1000000});check(r.status==='budget_exceeded' && !r.arguments.length,'actual module scan cap cannot be raised');
const calls=fixture({A:[{kind:'barrier',reason:'call'},mov(cx,ax),ret]});
calls.lifted.get('A')[0].call={width:64,target:c(0x401000)};
const observed=SSA.analyze(calls.report,calls.report.blocks,[],calls.lifted,'A',{observeCallInputs:true});
check(observed.uses.filter(u=>u.role==='call-observation').length===4,'caller snapshots observe four locations');
check(observed.definitions.filter(d=>d.source==='A_0' && d.kind==='clobber').length===16,'observing call inputs retains every original clobber');
check(!calls.graph.uses.some(u=>u.role==='call-observation'),'normal SSA remains unchanged');
assert.deepEqual(run(f),run(f));checks++;
console.log(`PASS: ${checks} function-ABI graph checks`);
