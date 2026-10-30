'use strict';
const assert=require('node:assert/strict'),A=require('../web/declaration-abi'),T=require('../web/declaration-types'),E=require('../web/declaration-evidence');
let checks=0;
const check=(ok,why)=>{assert.ok(ok,why);checks++;};
const declaration=(id='header',types=['char','short','long','int *','short','long long'])=>({id,source:'header.h',returnType:'int',variadic:'no',hiddenParameters:'no',parameters:types.map(type=>({name:'',type}))});
const locations=list=>A.declarations(list,T.declarations(list),A.PROFILE);
const use=(mask,source='read')=>({mask,source,sources:[source,'path']});
const base=()=>({status:'available',declarationLocations:locations([declaration()]),arguments:[{register:'rcx',uses:[use('0xff')]},{register:'rdx',uses:[use('0xff','partial')]}],stackStatus:'available',stackArguments:[{entryOffset:'40',width:64,source:'stack',sources:['stack','address','path']}],assumptionSources:['assumed-call']});
function run(a,options) {const before=JSON.stringify(a),r=E.associate(a,options);check(JSON.stringify(a)===before,'associations cannot mutate evidence or annotations');return r;}
let r=run(base()),p=r.declarations[0].parameters;
check(r.policy===E.POLICY && r.status==='available' && r.links===3,'three independent existing read links');
check(p[0].reads[0].relation==='covers' && p[0].reads[0].overlapMask==='0xff','exact register overlap');
check(p[1].reads[0].relation==='partial' && p[1].reads[0].overlapMask==='0xff','narrow read is partial');
check(p[2].status==='no_observation' && p[3].status==='no_observation','missing candidate is not a disproven parameter');
check(p[4].reads[0].relation==='covers' && p[4].reads[0].width===64 && p[4].reads[0].overlapBytes===2,'wide stack read retains original width and declared intersection');
check(p[5].status==='no_observation' && r.declarations[0].returnType.status==='not_reviewed','absence and deferred return handling are explicit');
assert.deepEqual(r.assumptionSources,['assumed-call']);checks++;
assert.deepEqual(p[4].reads[0].sources,['stack','address','path']);checks++;
for(const [observed,relation,overlap] of [['0xffff','covers','0xff'],['0xf0','partial','0xf0'],['0xffffffffffffff00','disjoint','0x0']]) {
 const a=base();a.arguments=[{register:'rcx',uses:[use(observed)]}];r=run(a);
 const u=r.declarations[0].parameters[0].reads[0];check(u.relation===relation && u.overlapMask===overlap && u.observedMask===observed,'retain precise incoming masks including disjoint upper bits');
}
const a=base();a.arguments=[{register:'rcx',uses:[use('0xf','low'),use('0xf0','high')]}];
r=run(a);check(r.declarations[0].parameters[0].reads.every(r=>r.relation==='partial'),'separate paths/reads are never merged to claim full coverage');
a.stackArguments=[{entryOffset:'40',width:8,source:'byte',sources:['byte']},{entryOffset:'48',width:64,source:'other',sources:['other']}];
r=run(a);check(r.declarations[0].parameters[4].reads[0].relation==='partial' && r.declarations[0].parameters[4].reads.length===1,'stack association uses exact entry offset and keeps narrow reads partial');
a.stackStatus='unavailable';a.stackReason='lost stack identity';r=run(a);
check(r.declarations[0].parameters[4].status==='unavailable' && !r.declarations[0].parameters[4].reads.length && r.declarations[0].parameters[0].status==='observed','unavailable stack does not erase register links or expose stale stack reads');
const uncertain={...declaration('uncertain'),variadic:'unknown'};a.declarationLocations=locations([uncertain]);r=run(a);
check(r.declarations[0].parameters.every(p=>p.status==='unresolved'&&!p.reads.length),'uncertain declarations expose no provisional associations');
a.declarationLocations=locations([declaration('byte',['char']),declaration('wide',['long long'])]);r=run(a);
check(r.declarations[0].parameters[0].reads[0].relation==='partial' && r.declarations[1].parameters[0].reads[0].relation==='partial','competing declarations remain separate');
a.arguments=[{register:'rcx',uses:[use('0xff')]}];r=run(a);
check(r.declarations[0].parameters[0].reads[0].relation==='covers' && r.declarations[1].parameters[0].reads[0].relation==='partial','same observation can have different overlap without choosing a declaration');
for(const status of ['default','unavailable','budget_exceeded','invalid']) {
 const b=base();b.status=status;r=run(b);check(r.status==='unavailable' && r.links===0 && r.declarations[0].parameters.every(p=>p.status==='unavailable'&&!p.reads.length),'failed machine evidence cannot leak provisional links');
}
for(const field of ['work','links','sources']) {
 r=run(base(),{[field]:0});check(r.status==='budget_exceeded' && r.links===0 && r.declarations.every(d=>d.parameters.every(p=>!p.reads.length)),'independent association budget discards all links: '+field);
}
const saturated=base();saturated.declarationLocations=locations(Array.from({length:8},(_,n)=>declaration('d'+n,Array(32).fill('long long'))));
saturated.arguments=[{register:'rcx',uses:Array.from({length:65},(_,n)=>use('0xff','read'+n))}];
for(const links of [undefined,100000,Infinity,NaN]) {r=run(saturated,{links});check(r.status==='budget_exceeded' && r.links===0,'real 512-link cap cannot be raised');}
saturated.arguments=[{register:'rcx',uses:[use('0xff')]}];saturated.stackArguments=Array.from({length:160},(_,n)=>({entryOffset:'40',width:8,source:'s'+n,sources:['s'+n]}));
r=run(saturated);check(r.status==='budget_exceeded','bounded whole pass for many stack links');
const costly=base();costly.declarationLocations=locations(Array.from({length:8},(_,n)=>declaration('d'+n,Array(32).fill('long long'))));costly.arguments=[];costly.stackArguments=Array.from({length:160},()=>({entryOffset:'8192',width:8,source:'far',sources:['far']}));
for(const work of [undefined,100000,Infinity]) {r=run(costly,{work});check(r.status==='budget_exceeded' && r.reason.includes('work'),'real work limit cannot be raised even without matching links');}
const manySources=base();manySources.arguments[0].uses[0].sources=Array.from({length:65},(_,n)=>'s'+n);r=run(manySources,{sources:1000});check(r.status==='budget_exceeded' && r.reason.includes('source'),'source hard cap');
const empty=base();empty.declarationLocations=[];check(run(empty).status==='empty','no declarations produce no associations');
const max=base();max.arguments=[];max.stackArguments=[];max.declarationLocations=locations(Array.from({length:8},(_,n)=>declaration('d'+n,Array(32).fill('int'))));r=run(max);
check(r.declarations.reduce((n,d)=>n+d.parameters.length+1,0)===264 && r.links===0,'maximum declaration rows are bounded and explicit');
check(E.describe(p[0].reads[0]).includes('overlap 0xff') && E.describe(p[4].reads[0]).includes('2 overlapping byte'),'shared display preserves bit/byte units');
console.log(`PASS: ${checks} declaration-evidence association checks`);
