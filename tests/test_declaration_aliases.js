'use strict';
const assert=require('node:assert/strict'),T=require('../web/declaration-types');
let checks=0;
const check=(ok,why)=>{assert.ok(ok,why);checks++;};
const alias=(name,type,source='header.h')=>({name,type,source});
const definitions=[alias('Count','unsigned'),alias('P','int *'),alias('CP','const P'),alias('PP','P *'),alias('CV','volatile CP')];
const original=JSON.stringify(definitions),ctx=T.aliasContext(definitions);
for(const [label,expected,path] of [
    ['Count','unsigned int',['Count']],['const Count *','const unsigned int *',['Count']],
    ['P','int *',['P']],['const P','int * const',['P']],['P const * volatile','int * const * volatile',['P']],
    ['CP','int * const',['CP','P']],['const PP','int * * const',['PP','P']],
    ['volatile CP * const','int * const volatile * const',['CP','P']],['CV','int * const volatile',['CV','CP','P']],
    ['int *','int *',[]],['void','void',[]]]) {
    const r=ctx.parse(label);
    check(r.status==='parsed' && r.canonical===expected,'authored canonical form: '+label);
    assert.deepEqual(r.type,T.parse(expected).type);checks++;
    assert.deepEqual(r.aliases,path);checks++;
}
check(ctx.parse('P const').type.qualifiers.includes('const') && !ctx.parse('P const').type.to.qualifiers.length,'typedef qualifier stays on pointer, not pointee');
check(JSON.stringify(definitions)===original,'original definitions remain unchanged');
for(const label of ['size_t','Unknown *','P Count','unsigned Count','P int','P P','P * Count','P[2]','P (*)()', 'P;','P\n','const','*P']) {
    const r=ctx.parse(label);check(r.status==='unsupported' && r.type===null && r.canonical===null,'no guessed or partial expansion: '+label);
}
check(ctx.parse(null).status==='unknown','unspecified type remains unknown');
check(T.parse('P').status==='unsupported' && T.aliasContext([]).parse('P').status==='unsupported','no implicit or global aliases');
check(T.aliasContext([alias('P','char *')]).parse('P').canonical==='char *','contexts are independent');
const forward=T.aliasContext([alias('A','B'),alias('B','long')]);
check(forward.parse('A').canonical==='long int','forward references are resolved within the explicit set');
check(T.aliasContext([alias('B','long'),alias('A','B')]).parse('A').canonical===forward.parse('A').canonical,'definition order does not select a different type');
for(const defs of [[alias('A','A')],[alias('A','B *'),alias('B','A')]]) {
    const c=T.aliasContext(defs),r=c.parse('const A *');
    check(r.status==='unsupported' && r.type===null && r.reason.includes('cycle'),'cycles cannot produce partial trees');
    check(c.definitions.length===defs.length && c.results.every(a=>a.result.status==='unsupported'),'cyclic source definitions remain available');
}
for(const type of ['Missing','int[4]','int (*)(void)','<img src=x onerror=alert(1)>']) {
    const c=T.aliasContext([alias('A',type)]),r=c.parse('A');
    check(r.status==='unsupported' && !r.type && r.aliases[0]==='A','unsupported definition retains its dependency trace');
    check(c.definitions[0].type===type,'unsupported original definition retained');
}
const pointers=T.aliasContext([alias('P','int **'),alias('Q','P **')]);
check(pointers.parse('Q').canonical==='int * * * *','combined four-pointer bound accepted');
check(pointers.parse('Q *').status==='unsupported' && pointers.parse('Q *').reason.includes('four pointer'),'hidden pointer depth is counted');
const chain=n=>Array.from({length:n},(_,i)=>alias('A'+i,i===n-1?'int':'A'+(i+1)));
check(T.aliasContext(chain(8)).parse('A0').aliases.length===8,'eight aliases allowed');
check(T.aliasContext(chain(9)).parse('A0').reason.includes('eight definitions'),'ninth alias expansion rejected');
const tokens=chain(8).map((a,i)=>({...a,type:'const '.repeat(i===7?14:15)+a.type}));
check(T.aliasContext(tokens).parse('A0').canonical==='const int','exact 128-token expanded label accepted');
tokens[7].type='const '+tokens[7].type;
check(T.aliasContext(tokens).parse('A0').reason.includes('128 total tokens'),'129 expanded tokens rejected independently of depth');
const maximum=Array.from({length:32},(_,i)=>alias('T'+i,'int'));
check(T.aliasContext(maximum).results.length===32,'32 source definitions accepted');
for(const defs of [null,{},[...maximum,alias('extra','int')],[alias('A','int'),alias('A','char')],
    [alias('int','char')],[alias('const','int')],[alias('_Atomic','int')],[alias('typedef','int')],
    [alias('A B','int')],[alias('1A','int')],[alias('界','int')],[alias('A'.repeat(65),'int')],
    [alias('A',null)],[alias('A','')],[alias('A','int\n')],[alias('A','x'.repeat(129))],[alias('A','int','')],
    [alias('A','int','s'.repeat(257))],[{...alias('A','int'),extra:1}],
    maximum.map(a=>({...a,source:'界'.repeat(256)}))]) {
    assert.throws(()=>T.aliasContext(defs));checks++;
}
for(const name of ['__proto__','constructor','toString']) check(T.aliasContext([alias(name,'int')]).parse(name).canonical==='int','Map lookup does not use object prototypes: '+name);
const first=ctx.parse('CV');first.type.qualifiers.push('bad');first.aliases.push('bad');ctx.results[1].result.type.to.name='bad';
check(ctx.parse('CV').canonical==='int * const volatile' && !ctx.parse('CV').aliases.includes('bad'),'all result trees and traces are independent');
ctx.definitions[0].type='float';definitions[1].type='char';
check(ctx.parse('Count').canonical==='unsigned int' && ctx.parse('P').canonical==='int *','resolution captures validated definitions');
const list=[{id:'a',returnType:'Count',parameters:[],variadic:'no',hiddenParameters:'no'},
    {id:'b',returnType:'unsigned int',parameters:[],variadic:'no',hiddenParameters:'no'}];
const typed=T.declarations(list,ctx),comparison=T.compareDeclarations(list,typed)[0];
check(comparison.fields[0].status==='same' && comparison.fields[0].left.aliases[0]==='Count','comparisons expose the supplied alias assumption');
comparison.fields[0].left.aliases.push('bad');
check(!typed[0].returnType.aliases.includes('bad'),'comparison trace is independent');
check(T.describe(typed[0].returnType).includes('Supplied aliases: Count'),'shared display makes alias provenance explicit');
console.log(`PASS: ${checks} declaration alias checks`);
