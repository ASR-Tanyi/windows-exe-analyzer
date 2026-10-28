'use strict';
const assert = require('node:assert/strict'), T = require('../web/declaration-types');
let checks = 0;
const check = (ok,why) => {assert.ok(ok,why); checks++;};
// Expected forms are authored from N1570 6.7.2, not calculated by the parser.
const forms = [
    ['void','void'],['_Bool','_Bool'],['char','char'],['signed char','signed char'],['char unsigned','unsigned char'],
    ['short','short int'],['short int','short int'],['signed short','short int'],['short signed int','short int'],
    ['short unsigned','unsigned short int'],['int unsigned short','unsigned short int'],
    ['int','int'],['signed','int'],['int signed','int'],['unsigned','unsigned int'],['int unsigned','unsigned int'],
    ['long','long int'],['int long','long int'],['long signed','long int'],['signed int long','long int'],
    ['unsigned long','unsigned long int'],['long unsigned int','unsigned long int'],
    ['long long','long long int'],['long int long','long long int'],['long signed long','long long int'],
    ['long signed int long','long long int'],['unsigned long long','unsigned long long int'],['long int unsigned long','unsigned long long int'],
    ['float','float'],['double','double'],['double long','long double'],
    [' const unsigned  long int ','const unsigned long int'],['int volatile const','const volatile int'],
    ['const int const','const int'],['int volatile volatile','volatile int'],
    ['void*','void *'],['char const*','const char *'],['int*const','int * const'],
    ['volatile long * const * volatile','volatile long int * const * volatile'],
    ['unsigned *const volatile const**volatile*','unsigned int * const volatile * * volatile *']
];
for (const [label,canonical] of forms) {
    const r=T.parse(label);
    check(r.status==='parsed' && r.canonical===canonical && r.reason===null,'parse '+label);
    assert.deepEqual(T.parse(canonical),r);checks++;
    check(!JSON.stringify(r.type).includes('width'),'syntax never supplies a machine width');
}
const base={kind:'builtin',name:'int',qualifiers:['const']};
assert.deepEqual(T.parse('const int * volatile * const').type,
    {kind:'pointer',qualifiers:['const'],to:{kind:'pointer',qualifiers:['volatile'],to:base}});checks++;
check(T.parse('char').canonical!==T.parse('signed char').canonical,'plain char is not silently assigned signedness');
check(T.parse('double').canonical!==T.parse('long double').canonical,'implementation data models do not merge types');
check(T.parse('const int *').canonical!==T.parse('int * const').canonical,'pointee and pointer qualifiers remain distinct');
for (const label of [undefined,0,false,{},[], '', ' ', 'int\n', 'int\t*', 'i'.repeat(129),
    'int\u00a0*','INT','bool','BOOL','DWORD','size_t','uint32_t','uintptr_t','LPVOID','MyType *','const MyType **',
    '__int64','unsigned __int64','__int128','wchar_t','char16_t','restrict int *','int * restrict','_Atomic int',
    '_Atomic(int)','float _Complex','struct Item *','enum Kind','union Data *','int&','int&&','int[4]',
    'int (*)[4]','int (*)(void)','int(char)','int *value','int, char','int;','int = 3','int /*note*/ *',
    'unsignedunsigned','unsigned int x','const','const volatile *','*int','void int','signed unsigned',
    'short long','long long long','int int','char int','signed signed','long float','unsigned double',
    'short double','signed _Bool','void unsigned','double double','int * unsigned','int ** int',
    'int *****','int'+'*'.repeat(32),'</textarea><script>bad()</script>','__proto__','constructor']) {
    const r=T.parse(label);
    check(r.status==='unsupported' && r.canonical===null && r.type===null && !!r.reason,'retain unparsed syntax: '+String(label));
}
check(T.parse(null).status==='unknown' && T.parse(null).type===null,'null stays distinct from unsupported syntax');
check(T.parse('int ****').status==='parsed' && T.parse('int *****').reason.includes('four pointer'),'pointer-depth boundary');
check(T.parse('int'+'*'.repeat(32)).reason.includes('32-token'),'actual token ceiling');
check(T.parse(' '.repeat(125)+'int').status==='parsed' && T.parse(' '.repeat(126)+'int').status==='unsupported','128-character boundary');
const list=[{id:'d',returnType:'unsigned',parameters:[{name:'x',type:'char const *'},{name:'n',type:'size_t'},{name:'?',type:null}]}];
const before=JSON.stringify(list), parsed=T.declarations(list);
check(JSON.stringify(list)===before && list[0].returnType==='unsigned','raw labels and names are immutable');
check(parsed[0].declaration==='d' && parsed[0].parameters.map(p=>p.status).join(',')==='parsed,unsupported,unknown','every field gets an independent result');
check(T.describe(parsed[0].returnType)==='Parsed annotation: unsigned int','shared UI/text description');
check(T.describe(parsed[0].parameters[1]).startsWith('Unparsed annotation:'),'unresolved names are explicit');
check(T.describe(parsed[0].parameters[2])==='No type annotation supplied.','unknown display');
const again=T.parse('const int *');again.type.to.qualifiers.push('bad');
assert.deepEqual(T.parse('const int *').type.to.qualifiers,['const']);checks++;
console.log(`PASS: ${checks} declaration-type syntax checks`);
