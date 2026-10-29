'use strict';
const assert=require('node:assert/strict'), T=require('../web/declaration-types');
let checks=0;
const check=(ok,why)=>{assert.ok(ok,why);checks++;};
const declaration=(id,returnType='int',parameters=[],patch={})=>({id,source:'header.h',returnType,
    parameters:parameters.map((type,n)=>({name:'p'+n,type})),variadic:'no',hiddenParameters:'no',...patch});
function compare(a,b) {
    const list=[a,b],parsed=T.declarations(list),before=JSON.stringify([list,parsed]);
    const result=T.compareDeclarations(list,parsed)[0];
    check(before===JSON.stringify([list,parsed]),'comparisons leave declarations and parsed trees unchanged');
    check(Object.values(result.counts).reduce((a,b)=>a+b,0)===result.fields.length,'counts account for every field');
    check(!('status' in result),'no whole-prototype verdict');
    return result;
}
const field=(pair,name='returnType')=>pair.fields.find(f=>f.field===name);
for(const [a,b] of [['unsigned','unsigned int'],['int signed','int'],['long long unsigned','unsigned long long int'],
    ['int volatile const','const volatile int'],['const const int *','int const *'],['char* const*','char * const *'],['void','void']]) {
    const r=field(compare(declaration('a',a),declaration('b',b)));
    check(r.status==='same' && !r.differences.length,'matching normalized forms: '+a+' / '+b);
    check(r.left.label===a && r.right.label===b,'both raw spellings remain visible');
}
for(const [a,b,kind,depth] of [['int','unsigned int','base',0],['char','signed char','base',0],['double','long double','base',0],
    ['const int','int','qualifiers',0],['const int *','int *','qualifiers',1],['int * const','int *','qualifiers',0],
    ['int * volatile * const','int * const * const','qualifiers',1],['int *','int **','shape',1],['int','int *','shape',0],
    ['char ****','int ****','base',4]]) {
    const r=field(compare(declaration('a',a),declaration('b',b)));
    check(r.status==='different' && r.differences.some(d=>d.kind===kind && d.depth===depth),'precise structural difference: '+a+' / '+b);
    check(!r.reason.includes('incompatible'),'no machine incompatibility claim');
}
for(const [a,b] of [['size_t','size_t'],['size_t','unsigned long'],['int (*)(void)','int (*)(void)'],[null,null],[null,'int'],
    ['int *****','int *****'],['<img src=x onerror=alert(1)>','int']]) {
    const r=field(compare(declaration('a',a),declaration('b',b)));
    check(r.status==='unknown' && !r.differences.length,'unresolved text never becomes equality or a partial difference');
    check(r.left.label===a && r.right.label===b,'unknown annotations retain their labels');
}
let a=declaration('a','unsigned',['const int *','size_t',null]),b=declaration('b','unsigned int',['int *','size_t'],{variadic:'unknown',hiddenParameters:'yes'});
let pair=compare(a,b);
check(field(pair).status==='same' && field(pair,'parameter[1].type').status==='different','matching return and differing argument coexist');
check(field(pair,'parameter[2].type').status==='unknown','identical typedefs remain unresolved');
check(field(pair,'parameterCount').status==='different','supplied counts differ without an inferred arity');
check(field(pair,'parameter[3].type').right.status==='missing' && field(pair,'parameter[3].type').left.status==='unknown','missing record differs from null type label');
check(field(pair,'variadic').status==='unknown' && field(pair,'hiddenParameters').status==='different','unknown and differing flags remain separate');
check(pair.counts.unknown===3 && pair.counts.different===3 && pair.counts.same===1,'mixed evidence keeps every uncertainty');
const reverse=compare(b,a);
for(const row of pair.fields) {
    const other=field(reverse,row.field);check(row.status===other.status,'comparison is symmetric');
    assert.deepEqual(row.left,other.right);assert.deepEqual(row.right,other.left);checks++;
    for(let n=0;n<(row.differences || []).length;n++) {
        assert.deepEqual(row.differences[n].left,other.differences[n].right);
        assert.deepEqual(row.differences[n].right,other.differences[n].left);checks++;
    }
}
pair=compare(declaration('a','int',['int']),declaration('b','int',['int'],{parameters:[{name:'renamed',type:'int'}],source:'notes'}));
check(pair.counts.same===5 && !pair.counts.different,'source and parameter names do not alter type comparisons');
pair=compare(declaration('a','int',[],{variadic:'unknown',hiddenParameters:'unknown'}),declaration('b','int',[],{variadic:'unknown',hiddenParameters:'unknown'}));
check(pair.counts.unknown===2,'matching unknown flags do not establish agreement');
check(!T.compareDeclarations([]).length && !T.compareDeclarations([a]).length,'fewer than two declarations have no pairs');
const many=Array.from({length:8},(_,n)=>declaration('d'+n,'int',Array(32).fill(n%2?'int *':'const int *')));
const all=T.compareDeclarations(many);
check(all.length===28 && all.every(p=>p.fields.length===36) && new Set(all.map(p=>p.declarations.join('/'))).size===28,'all 28 unordered pairs at the real 1008-field bound');
assert.throws(()=>T.compareDeclarations([...many,declaration('too-many')]),/at most 8/);checks++;
assert.throws(()=>T.compareDeclarations([declaration('too-wide','int',Array(33).fill('int'))]),/at most 32/);checks++;
pair=compare(declaration('a','const int *'),declaration('b','int *'));
pair.fields[0].differences[0].left.push('bad');
check(!JSON.stringify(T.compareDeclarations([declaration('a','const int *'),declaration('b','int *')])).includes('bad'),'difference arrays are fresh');
check(T.comparisonLabel(field(pair))==='Different parsed form','UI and CLI label only parsed forms');
check(T.describeDifference({kind:'qualifiers',depth:1,left:['const'],right:[]})==='qualifiers at pointee depth 1: const / unqualified','qualifier depth is readable');
console.log(`PASS: ${checks} declaration comparison checks`);
