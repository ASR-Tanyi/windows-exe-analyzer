'use strict';
const assert=require('node:assert/strict'),T=require('../web/declaration-types'),A=require('../web/declaration-abi');
let checks=0;
const check=(ok,why)=>{assert.ok(ok,why);checks++;};
const decl=(id='a',returnType='int',parameters=[],patch={})=>({id,source:'header.h',returnType,parameters:parameters.map((type,n)=>({name:'p'+(n+1),type})),variadic:'no',hiddenParameters:'no',...patch});
function map(list,profile=A.PROFILE,context=null) {
    const types=T.declarations(list,context),before=JSON.stringify([list,types]);
    const result=A.declarations(list,types,profile);
    check(JSON.stringify([list,types])===before,'mapping leaves original and parsed declarations unchanged');
    return result;
}
for(const [type,width] of [['char',8],['signed char',8],['unsigned char',8],['short',16],['unsigned short',16],
    ['int',32],['unsigned',32],['long',32],['unsigned long',32],['long long',64],['unsigned long long',64],
    ['void *',64],['const int * volatile',64],['float *',64],['int ****',64]]) {
    const d=map([decl('a',type,[type])])[0];
    check(d.status==='mapped' && !d.blockers.length,'reviewed type: '+type);
    assert.deepEqual(d.returnType.location,{kind:'register',register:'rax',bitOffset:0,width,containerWidth:64});checks++;
    assert.deepEqual(d.parameters[0].location,{kind:'register',register:'rcx',bitOffset:0,width,containerWidth:64});checks++;
    check(d.returnType.width===width && d.parameters[0].width===width,'declared LLP64 widths');
}
let d=map([decl('a','int *',['char','short','long','void *','unsigned char','unsigned short','unsigned long','unsigned long long'])])[0];
check(d.parameters.slice(0,4).map(p=>p.location.register).join(',')==='rcx,rdx,r8,r9','authored first four ordinal locations');
assert.deepEqual(d.parameters.slice(4).map(p=>p.location),[
    {kind:'stack',base:'entry_rsp',byteOffset:'40',width:8,slotBytes:8},
    {kind:'stack',base:'entry_rsp',byteOffset:'48',width:16,slotBytes:8},
    {kind:'stack',base:'entry_rsp',byteOffset:'56',width:32,slotBytes:8},
    {kind:'stack',base:'entry_rsp',byteOffset:'64',width:64,slotBytes:8}]);checks++;
check(A.describe(d.parameters[0])==='RCX bits 0–7' && A.describe(d.parameters[4])==='entry RSP + 40 bytes · 8 bits in an 8-byte slot','UI and CLI share precise location descriptions');
check(!JSON.stringify(d).includes('extension') || !d.parameters[0].location.extension,'no sign/zero extension field');
d=map([decl('a','void')])[0];
check(d.status==='mapped' && d.returnType.status==='none' && d.returnType.location===null && !d.parameters.length,'void return and empty supplied list retain their distinct meanings');
check(A.describe(d.returnType)==='No declared return value','void is not a fabricated RAX location');
for(const profile of [null,'','cdecl','system-v-x64']) {
    d=map([decl('a','long',['int *'])],profile)[0];
    check(d.status==='unknown' && d.blockers.some(b=>b.field==='profile') && [d.returnType,...d.parameters].every(r=>r.width===null && r.location===null),'unknown profile never supplies widths or locations');
}
for(const field of ['variadic','hiddenParameters']) for(const value of ['yes','unknown']) {
    d=map([decl('a','int',['int'],{[field]:value})])[0];
    check(d.status==='unknown' && d.blockers.some(b=>b.field===field) && d.returnType.location===null && d.parameters[0].location===null,'uncertain declaration stays fully unresolved');
}
for(const bad of [null,'Missing','int[2]','struct S','int (*)(void)','float','double','long double','_Bool']) {
    for(const field of ['return','parameter']) {
        d=map([field==='return'?decl('a',bad,['int']):decl('a','int',['int',bad,'int'])])[0];
        check(d.status==='unknown' && d.blockers.some(b=>b.field===(field==='return'?'returnType':'parameter[2].type')),'unsupported field identifies its blocker');
        check([d.returnType,...d.parameters].every(r=>r.status==='unknown' && r.location===null && r.width===null),'no partial placement beside an unsupported type');
        if(field==='parameter') check(d.parameters[2].position===3,'unsupported record is never silently removed');
    }
}
d=map([decl('a','void',['void'])])[0];
check(d.status==='unknown' && d.blockers[0].reason.includes('empty parameter list'),'literal void parameter is not rewritten into an empty list');
const context=T.aliasContext([{name:'Size',type:'unsigned long',source:'header.h'},{name:'P',type:'int *',source:'notes'}]);
d=map([decl('a','const P',['Size'])],A.PROFILE,context)[0];
check(d.returnType.width===64 && d.returnType.canonical==='int * const' && d.parameters[0].width===32,'aliases resolve before the selected Windows data model');
check(d.returnType.aliases[0]==='P' && d.parameters[0].aliases[0]==='Size' && d.source==='header.h','raw and alias provenance retained');
const pair=map([decl('a','void',['char']),decl('b','int',['long long','int *'])]);
check(pair.length===2 && pair[0].returnType.status==='none' && pair[1].returnType.width===32 && pair[0].parameters.length===1 && pair[1].parameters.length===2,'conflicting supplied declarations stay independently visible');
const maximum=Array.from({length:8},(_,n)=>decl('d'+n,'int',Array(32).fill('int')));
const all=map(maximum);
check(all.length===8 && all.reduce((n,d)=>n+1+d.parameters.length,0)===264 && all.every(d=>d.parameters[31].location.byteOffset==='256'),'real 264-field bound and last stack position');
assert.throws(()=>map([...maximum,decl('extra')]),/at most 8/);checks++;
assert.throws(()=>map([decl('a','int',Array(33).fill('int'))]),/at most 8/);checks++;
assert.throws(()=>A.declarations([decl()],[],A.PROFILE),/matching/);checks++;
assert.throws(()=>A.declarations([decl()],T.declarations([decl('other')]),A.PROFILE),/matching/);checks++;
check(map([]).length===0,'no declaration invents no locations');
const input=[decl('a','P',['Size'])],parsed=T.declarations(input,context),rows=A.declarations(input,parsed,A.PROFILE);
rows[0].returnType.aliases.push('bad');rows[0].parameters[0].location.width=3;
check(!parsed[0].returnType.aliases.includes('bad') && A.declarations(input,parsed,A.PROFILE)[0].parameters[0].width===32,'independent result arrays and objects');
console.log(`PASS: ${checks} declared-ABI location checks`);
