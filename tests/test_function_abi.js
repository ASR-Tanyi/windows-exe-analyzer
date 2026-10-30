'use strict';
const assert = require('node:assert/strict'), SSA = require('../web/register-ssa'), ABI = require('../web/function-abi');
const VA = require('../web/value-analysis');
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
    return {report,lifted,graph:SSA.analyze(report,blocks,edges,lifted,'A'),values:VA.analyze(report,blocks,edges,lifted,'A')};
}
function run(f,options={},manifest={...ABI.emptyContract(f.report,'A'),profile:ABI.PROFILE.id}) {
    const before = JSON.stringify([f.report,f.graph,f.values,[...f.lifted]]);
    const result = ABI.analyze(f.report,f.graph,f.lifted,'A',manifest,()=>{throw Error('unexpected caller');},options,f.values);
    check(JSON.stringify([f.report,f.graph,f.values,[...f.lifted]])===before,'ABI evidence must not change inputs');
    const ids = new Set([...f.lifted.values()].flat().map(i=>i.source));
    for(const row of [...result.arguments,...result.returns,...result.stackArguments]) check(row.sources.every(s=>ids.has(s)),'evidence refers to actual instructions');
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
// Version 2 retains bounded, non-authoritative analyst declarations.
const decl = (id,patch={}) => ({id,source:'header.h',returnType:'unsigned',parameters:[{name:'x',type:'unsigned'}],variadic:'no',hiddenParameters:'no',...patch});
const contract2 = list => ({...ABI.emptyContract(f.report,'A'),version:2,profile:ABI.PROFILE.id,declarations:list});
let declared=run(f,{},contract2([decl('header'),decl('notes',{returnType:'void',parameters:[]})]));
check(declared.contract.version===2 && declared.contract.declarations.length===2,'both conflicting declarations retained');
check(declared.declarationConflicts.length===1 && declared.declarationConflicts[0].fields.includes('returnType'),'type-label disagreements visible');
check(declared.declarationReviews.some(r=>r.declaration==='notes' && r.kind==='candidate_outside_declaration'),'fixed count gets a cautious evidence review');
for (const key of ['arguments','returns','callers','conflicts','stackArguments']) assert.deepEqual(declared[key],run(f)[key]); checks++;
let noProfile={...contract2([decl('header')]),profile:null};
check(run(f,{},noProfile).status==='default' && run(f,{},noProfile).contract.declarations.length===1,'annotations do not activate the convention');
for (const patch of [{variadic:'unknown'},{hiddenParameters:'unknown'},{variadic:'yes'},{hiddenParameters:'yes'}]) {
    check(!run(f,{},contract2([decl('uncertain',{parameters:[],...patch})])).declarationReviews.length,'uncertainty prevents count claims');
}
check(!run(f,{},contract2([decl('a'),decl('b',{parameters:[{name:'renamed',type:'unsigned'}]})])).declarationConflicts.length,'parameter names do not cause type disagreements');
check(!run(f,{},contract2([decl('a'),decl('b',{returnType:null,parameters:[{name:'',type:null}],variadic:'unknown'})])).declarationConflicts.length,'unknown labels are not conflicting declarations');
for (const patch of [{extra:1},{returnType:8},{source:''},{id:'bad id'},{variadic:false},{hiddenParameters:'maybe'},
    {parameters:[{name:'x',type:'int',extra:1}]},{parameters:Array(33).fill({name:'x',type:null})},{returnType:'x'.repeat(129)},
    {source:'escape\nnewline'},{parameters:[{name:'x'.repeat(65),type:null}]}]) {
    const bad=run(f,{},contract2([decl('good'),decl('bad',patch)]));
    check(bad.status==='invalid' && !bad.contract.declarations && !bad.contract.profile,'invalid declaration rejects complete contract');
}
for (const list of [[decl('same'),decl('same')],Array.from({length:9},(_,n)=>decl('d'+n)),null,{}])
    check(run(f,{},contract2(list)).status==='invalid','declaration count, identity and array bounds');
const oversized=Array.from({length:8},(_,n)=>decl('large'+n,{parameters:Array.from({length:32},()=>({name:'x'.repeat(64),type:'界'.repeat(128)}))}));
check(run(f,{},contract2(oversized)).status==='invalid','normalized UTF-8 declaration budget');
const allDifferences=run(f,{},contract2([decl('a'),decl('b',{returnType:'void',parameters:[{name:'x',type:'int'},{name:'y',type:null}],variadic:'yes',hiddenParameters:'yes'})]));
check(['returnType','parameterCount','parameter[1].type','variadic','hiddenParameters'].every(k=>allDifferences.declarationConflicts[0].fields.includes(k)),'each supported disagreement field is explicit');
const exhausted=run(f,{observations:0},contract2([decl('a'),decl('b',{returnType:'void'})]));
check(exhausted.status==='budget_exceeded' && exhausted.contract.declarations.length===2 && exhausted.declarationConflicts.length===1 && !exhausted.declarationReviews.length && !exhausted.arguments.length,'budget fallback retains declarations but discards provisional evidence');
const unsafe=decl('html',{source:'<img src=x onerror=alert(1)>',returnType:'</textarea><script>bad()</script>'});
check(run(f,{},contract2([unsafe])).contract.declarations[0].source===unsafe.source,'plain text is preserved for escaped rendering');
assert.deepEqual(run(f,{},contract2([decl('a')])),run(f,{},contract2([decl('a')])));checks++;
// Stack identity is a must fact: all discovered paths, not one possible path.
const sp=reg('rsp'),fp=reg('rbp');
const plus=(a,b)=>({kind:'binary',operator:'+',width:64,left:a,right:b});
const mem=(address,width=64)=>({kind:'load',address,width});
const at=(offset,width=64)=>mem(plus(sp,c(offset)),width);
const adjust=n=>mov(sp,plus(sp,c(n)));
const read=mov(ax,at(40)), barrier={kind:'barrier',reason:'unknown'};
const diamond=[['A','B'],['A','C'],['B','D'],['C','D']];
f=fixture({A:[nop],B:[nop],C:[nop],D:[read,ret]},diamond);r=run(f);
check(r.stackArguments.length===1 && ['A_0','B_0','C_0','D_0'].every(s=>r.stackArguments[0].sources.includes(s)),'join read carries both predecessor witnesses');
for(const middle of [[mov(at(40),cx)],[mov(at(41,8),cx)],[mov(mem(cx),ax)],[barrier],
    [{kind:'call_summary',profile:require('../web/call-summaries').PROFILE.id,target:c(0x401000),width:64}],
    [adjust(48),adjust(-48)],[mov(fp,sp),mov(sp,cx),mov(sp,fp)]]) {
    r=run(fixture({A:[nop],B:middle,C:[nop],D:[read,ret]},diamond));
    check(!r.stackArguments.length,'one alias, barrier or lifetime-breaking path defeats incoming proof');
}
r=run(fixture({A:[nop],B:[mov(at(48),cx)],C:[mov(at(56),dx)],D:[read,ret]},diamond));
check(r.stackArguments.length===1,'different disjoint writes preserve incoming bytes');
r=run(fixture({A:[nop],B:[adjust(-8)],C:[nop],D:[read,ret]},diamond));
check(!r.stackArguments.length,'multi-valued join SP cannot establish an incoming slice');
r=run(fixture({A:[read,nop]},[['A','A']]));
check(r.stackArguments.length===1 && r.stackArguments[0].sources.includes('A_1'),'entry loop keeps virtual initial memory and backedge evidence');
r=run(fixture({A:[read,mov(at(40),cx),nop]},[['A','A']]));
check(!r.stackArguments.length,'late entry backedge write invalidates provisional earlier read');
r=run(fixture({A:[read,nop],B:[read,mov(at(40),cx),nop],C:[read,ret]},[['A','B'],['B','B'],['B','C']]));
check(r.stackArguments.length===1 && r.stackArguments[0].source==='A_0','pre-loop read survives but repeated and post-loop reads do not');
r=run(fixture({A:[nop],B:[read,mov(at(48),cx),nop],C:[read,ret]},[['A','B'],['B','B'],['B','C']]));
check(r.stackArguments.length===2,'loop invariant incoming bytes survive disjoint writes');
r=run(fixture({A:[nop],B:[read,ret],C:[mov(at(40),cx)]},[['A','B'],['C','B']]));
check(r.stackArguments.length===1,'unreachable predecessor cannot defeat a reachable proof');
const truncated=fixture({A:[nop],B:[read,ret]},[['A','B']]);truncated.values.accesses[0].proofTruncated=true;
check(!run(truncated).stackArguments.length,'truncated address proof is not an incoming witness');
const cyclic=fixture({A:[nop],B:[nop],C:[read,ret]},[['A','B'],['B','B'],['B','C']]);
for(const options of [{stackSlots:0},{stackVisits:0},{stackVisits:2},{sources:1}]) {
    r=run(cyclic,options);check(r.status==='budget_exceeded' && !r.stackArguments.length && !r.callers.length,'fixed-point fallback discards provisional evidence');
}
const manySlots=fixture({A:[...Array.from({length:257},(_,n)=>mov(ax,at(40+8*n))),ret]});
for(const limit of [undefined,Infinity,NaN,100000]) {
    r=run(manySlots,{stackSlots:limit});check(r.status==='budget_exceeded' && r.reason.includes('stack-slot') && !r.stackArguments.length,'actual stack-slice ceiling cannot be raised');
}
function caller(bodies,links,options={}) {
    const f=fixture({...bodies,D:[...(bodies.D || []),barrier],After:[ret],Target:[read,ret]},[...links,['D','After']]);
    const target=f.report.blocks.find(b=>b.id==='Target');target.owners=['Target'];f.report.functions.push({id:'Target',rva:target.rva});
    const instruction=f.lifted.get('D').at(-1);instruction.call={width:64,target:c(0x400000+target.rva)};
    f.report.edges.push({from:'D',to:'Target',kind:'call',source:instruction.source});
    const blocks=f.report.blocks.filter(b=>b.id!=='Target'),edges=f.report.edges;
    const load={lifted:f.lifted,graph:SSA.analyze(f.report,blocks,edges,f.lifted,'A',{observeCallInputs:true}),
        values:VA.analyze(f.report,blocks,edges,f.lifted,'A'),calls:{sites:[{source:instruction.source,eligible:true}]}};
    const graph=SSA.analyze(f.report,[target],[],f.lifted,'Target'),values=VA.analyze(f.report,[target],[],f.lifted,'Target');
    const before=JSON.stringify([f.report,load,graph,values,[...f.lifted]]);
    const result=ABI.analyze(f.report,graph,f.lifted,'Target',{...ABI.emptyContract(f.report,'Target'),profile:ABI.PROFILE.id},()=>load,options,values);
    check(before===JSON.stringify([f.report,load,graph,values,[...f.lifted]]),'cross-block caller observations leave all analyses unchanged');
    check(result.status==='available',result.reason);
    check(result.callers[0]?.status==='observed',result.callers[0]?.reason);
    return result.callers[0].stackArguments[0];
}
const store=mov(at(32),cx);
r=caller({A:[adjust(-40),store,nop],B:[nop],C:[nop]},diamond);
check(r.status==='matched_store' && r.stores.length===1 && ['A_1','A_2','B_0','C_0','D_0'].every(s=>r.sources.includes(s)),'one store surviving both predecessors retains path witnesses');
for(const change of [[mov(at(33,8),ax)],[mov(mem(cx),ax)],[adjust(40),adjust(-40)],
    [mov(fp,sp),mov(sp,cx),mov(sp,fp)],[barrier]]) {
    r=caller({A:[adjust(-40),store,nop],B:change,C:[nop]},diamond);
    check(r.status==='unknown' && !r.stores.length,'one caller path invalidating store stays unknown');
}
for(const right of [[nop],[store],[mov(at(32),c(7))]]) {
    r=caller({A:[adjust(-40),nop],B:[store],C:right},diamond);
    check(r.status==='unknown','missing or distinct stores never merge, even equal-looking values');
}
r=caller({A:[adjust(-40),store,nop],B:[nop]},[['A','B'],['B','B'],['B','D']]);
check(r.status==='matched_store','loop-invariant preceding store survives');
r=caller({A:[adjust(-40),nop],B:[store]},[['A','D'],['A','B'],['B','B'],['B','D']]);
check(r.status==='unknown','loop-only store cannot justify a zero-trip caller path');
r=caller({A:[adjust(-40),store,nop],B:[mov(at(33,8),ax)]},[['A','B'],['B','B'],['B','D']]);
check(r.status==='unknown','loop overwrite invalidates preceding store');
r=caller({A:[adjust(-40),nop],B:[store],C:[nop],D:[store]},diamond);
check(r.status==='matched_store' && r.stores[0].source==='D_0','fresh store after join establishes a new proof');
// Parsed annotations remain available independently of the machine profile
// and evidence budgets, while imported strings retain their exact spelling.
const typeFixture=fixture({A:[mov(ax,cx),ret]});
const typeContract={...ABI.emptyContract(typeFixture.report,'A'),version:2,profile:ABI.PROFILE.id,declarations:[decl('types',{
    returnType:'unsigned long int const * const',parameters:[{name:'s',type:'char const *'},{name:'h',type:'HANDLE'},
        {name:'a',type:'int[4]'},{name:'u',type:null}]})]};
const typed=run(typeFixture,{},typeContract),bare=run(typeFixture);
check(typed.version===8 && typed.declarationTypeGrammar==='c11-scalar-pointer-v1','annotation grammar and evidence schema are versioned');
check(typed.declarationTypes[0].returnType.canonical==='const unsigned long int * const','parsed return annotation is separate');
check(typed.declarationTypes[0].parameters.map(t=>t.status).join(',')==='parsed,unsupported,unsupported,unknown','mixed type results retained');
assert.deepEqual(typed.contract,typeContract);checks++;
for(const key of ['arguments','returns','callers','conflicts','stackArguments','work','observations']) {assert.deepEqual(typed[key],bare[key]);checks++;}
for(const options of [{},{work:0}]) {
    const result=run(typeFixture,options,{...typeContract,profile:options.work===0?ABI.PROFILE.id:null});
    check(result.status===(options.work===0?'budget_exceeded':'default'),'type parsing independent of machine evidence status');
    assert.deepEqual(result.declarationTypes,typed.declarationTypes);checks++;
}
const typeInvalid=run(typeFixture,{}, {...typeContract,declarations:[...typeContract.declarations,decl('bad',{returnType:3})]});
check(typeInvalid.status==='invalid' && !typeInvalid.declarationTypes.length,'invalid whole contract exposes no partial type annotations');
const spelling=run(typeFixture,{}, {...typeContract,declarations:[decl('a',{returnType:'unsigned'}),decl('b',{returnType:'unsigned int'})]});
check(spelling.declarationTypes[0].returnType.canonical===spelling.declarationTypes[1].returnType.canonical && spelling.declarationConflicts[0].fields.includes('returnType'),
    'normalized spellings do not silently remove existing textual disagreements');
check(spelling.declarationComparisonPolicy==='parsed-annotation-forms-v1' && spelling.declarationComparisons[0].fields[0].status==='same','matching forms coexist with textual disagreement');
const comparedContract={...typeContract,declarations:[...typeContract.declarations,decl('other',{
    returnType:'unsigned long int * const',parameters:[{name:'s',type:'char const *'},{name:'h',type:'HANDLE'}],variadic:'unknown'})]};
const compared=run(typeFixture,{},comparedContract),beforeCompare=run(typeFixture,{},typeContract);
check(compared.declarationComparisons[0].counts.different>0 && compared.declarationComparisons[0].counts.unknown>0,'known differences never hide unresolved annotations');
for(const key of ['arguments','returns','callers','conflicts','stackArguments','declarationReviews','work','observations']) {
    assert.deepEqual(compared[key],beforeCompare[key]);checks++;
}
for(const options of [{},{work:0}]) {
    const result=run(typeFixture,options,{...comparedContract,profile:options.work===0?ABI.PROFILE.id:null});
    assert.deepEqual(result.declarationComparisons,compared.declarationComparisons);checks++;
    assert.deepEqual(result.contract.declarations,comparedContract.declarations);checks++;
}
check(!typeInvalid.declarationComparisons.length && !typed.declarationComparisons.length,'invalid or single declarations expose no pairwise results');
const saturated=run(typeFixture,{}, {...typeContract,declarations:Array.from({length:8},(_,n)=>decl('d'+n,{
    parameters:Array.from({length:32},()=>({name:'',type:n%2?'const int ****':'int ****'}))}))});
check(saturated.status==='available' && saturated.declarationComparisons.length===28 && saturated.declarationComparisons.every(p=>p.fields.length===36),'real comparison bound is independent of the machine observation budget');
const aliasContract={...typeContract,version:3,typeAliases:[{name:'Count',type:'unsigned',source:'header.h'},{name:'P',type:'int *',source:'notes'}],
    declarations:[decl('a',{returnType:'Count',parameters:[{name:'p',type:'const P'}]}),decl('b',{returnType:'unsigned int',parameters:[{name:'p',type:'int * const'}]})]};
const withAliases=run(typeFixture,{},aliasContract),withoutAliases=run(typeFixture,{}, {...aliasContract,typeAliases:[]});
check(withAliases.version===8 && withAliases.declarationAliasPolicy==='explicit-scalar-pointer-aliases-v1','alias interpretation is versioned');
assert.deepEqual(withAliases.contract,aliasContract);checks++;
check(withAliases.declarationAliases.length===2 && withAliases.declarationTypes[0].parameters[0].canonical==='int * const','pointer alias qualifier is preserved in the model');
check(withAliases.declarationComparisons[0].counts.same===5 && withAliases.declarationConflicts.length===1,'alias agreement retains original textual disagreements');
for(const key of ['arguments','returns','callers','conflicts','stackArguments','declarationReviews','work','observations','declarationConflicts']) {
    assert.deepEqual(withAliases[key],withoutAliases[key]);checks++;
}
for(const [options,profile] of [[{},null],[{work:0},ABI.PROFILE.id],[{observations:0},ABI.PROFILE.id]]) {
    const r=run(typeFixture,options,{...aliasContract,profile});
    assert.deepEqual(r.declarationTypes,withAliases.declarationTypes);checks++;
    assert.deepEqual(r.declarationComparisons,withAliases.declarationComparisons);checks++;
    assert.deepEqual(r.contract.typeAliases,aliasContract.typeAliases);checks++;
}
for(const patch of [{version:2},{typeAliases:null},{typeAliases:[...aliasContract.typeAliases,aliasContract.typeAliases[0]]},{extra:1}]) {
    const r=run(typeFixture,{}, {...aliasContract,...patch});
    check(r.status==='invalid' && !r.declarationAliases.length && !r.declarationTypes.length && !r.contract.typeAliases,'invalid alias contract commits no partial state');
}
const cyclicAlias=run(typeFixture,{}, {...aliasContract,typeAliases:[{name:'P',source:'notes',type:'P'}]});
check(cyclicAlias.status==='available' && cyclicAlias.declarationTypes[0].parameters[0].status==='unsupported' && cyclicAlias.contract.typeAliases[0].type==='P','cyclic source remains retained without successful expansion');
check(run(typeFixture,{}, {...typeContract,version:3,typeAliases:[]}).contract.version===3,'empty version 3 aliases retain explicit schema');
check(withAliases.declarationLocationPolicy==='windows-x64-declared-integer-pointer-v1' && withAliases.declarationLocations.every(d=>d.status==='mapped'),'locations use a separate versioned policy');
check(withAliases.declarationLocations[0].returnType.location.register==='rax' && withAliases.declarationLocations[0].parameters[0].location.register==='rcx','resolved declarations map independently of actual reads');
const declaredStack={...typeContract,declarations:[decl('fixed',{returnType:'void',parameters:['char','short','long','void *','unsigned short'].map((type,n)=>({name:'p'+n,type}))})]};
const placements=run(typeFixture,{},declaredStack);
check(placements.declarationLocations[0].parameters[4].location.byteOffset==='40' && placements.declarationLocations[0].returnType.status==='none','declared stack offsets are relative to callee entry');
for(const options of [{work:0},{observations:0}]) {
    assert.deepEqual(run(typeFixture,options,declaredStack).declarationLocations,placements.declarationLocations);checks++;
}
check(run(typeFixture,{}, {...declaredStack,profile:null}).declarationLocations.every(d=>d.status==='unknown' && d.parameters.every(p=>p.location===null)),'unknown convention clears every declared coordinate');
check(!typeInvalid.declarationLocations.length && !run(typeFixture).declarationLocations.length,'invalid and missing declarations expose no locations');
for(const key of ['arguments','returns','callers','conflicts','stackArguments','work','observations']) {
    assert.deepEqual(placements[key],bare[key]);checks++;
}
console.log(`PASS: ${checks} function-ABI graph checks`);
