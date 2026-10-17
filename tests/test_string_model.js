'use strict';
const assert=require('node:assert/strict'),{create}=require('../web/string-model.js');
let checks=0;function test(name,fn){fn();checks++;}
const s=(id,rva,len,encoding='ASCII')=>({id,rva,byteLength:len,encoding,text:id});
const i=(id,rva,access='address')=>({id,dataRefs:[{rva,access,width:1}]});
const report={strings:{candidates:[s('a',100,10),s('w',102,6,'UTF-16LE'),s('other',200,10)]},
 blocks:[{id:'b',owners:['f','g'],instructions:[i('i',100),i('j',103,'read'),i('k',110),i('x',null),i('y',201,'write')]}]};
let m=create(report);
test('exact',()=>assert.equal(m.entries.get('a').refs[0].kind,'exact'));
test('interior byte offset',()=>assert.equal(m.entries.get('w').refs[0].offset,1));
test('preserve writes',()=>assert.equal(m.entries.get('other').refs[0].ref.access,'write'));
test('shared owners',()=>assert.deepEqual(m.entries.get('a').refs[0].owners,['f','g']));
test('exclude terminator/end',()=>assert(!m.byInstruction.has('k')));
test('ignore unknown address',()=>assert(!m.byInstruction.has('x')));
test('overlap contains both',()=>assert.equal(m.at(103).length,2));
test('before ranges',()=>assert.equal(m.at(99).length,0));
test('after ranges',()=>assert.equal(m.at(1000).length,0));
test('invalid addresses',()=>assert.equal(m.at(-1).length+m.at(2**32).length,0));
test('index associations',()=>assert.equal(m.links,4));
test('exact cap',()=>assert.equal(create(report,4).partial,false));
test('bounded cap',()=>{const x=create(report,1);assert(x.partial);assert.equal(x.links,1);});
test('zero cap',()=>{const x=create(report,0);assert(x.partial);assert.equal(x.links,0);});
test('empty candidates',()=>assert.equal(create({}).candidates.length,0));
test('no mutation',()=>{const before=JSON.stringify(report);create(report);assert.equal(JSON.stringify(report),before);});
test('high RVA',()=>{const x=create({strings:{candidates:[s('high',0xfffffff0,10)]}});assert.equal(x.at(0xfffffff5)[0].id,'high');});
test('same text distinct id',()=>assert.equal(create({strings:{candidates:[s('a',10,5),s('b',20,5)]}}).entries.size,2));
console.log('PASS: '+checks+' string reference model cases');
