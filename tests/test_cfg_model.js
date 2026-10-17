'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert');
vm.runInThisContext(fs.readFileSync(require('path').join(__dirname,'..','web','function-model.js'),'utf8'));
vm.runInThisContext(fs.readFileSync(require('path').join(__dirname,'..','web','cfg-model.js'),'utf8'));
let checks=0;const check=(name,fn)=>{fn();checks++;};
const insn=(r)=>({id:'m_i_'+r.toString(16),rva:r,size:1,dataRefs:[]});
const block=(id,r,owners=['f'])=>({id,rva:r,owners,instructions:[insn(r)]});
const edge=(from,to,kind='jump')=>({from,to,source:'m_i_'+({f:0x1000,a:0x1010,b:0x1020,c:0x1030,d:0x1040}[from]||0x1000).toString(16),kind,external:'',target:''});
function report(blocks,edges,truncated=false){return {module:{truncated},functions:[{id:'f',rva:0x1000}],blocks,edges};}
function analyze(r,limits){const fi=WEAFunctionModel.create(r);return WEACfgModel.analyze(r,fi,'f',limits);}
const diamond=report([block('f',0x1000),block('a',0x1010),block('b',0x1020),block('c',0x1030)],[edge('f','a','taken'),edge('f','b','not_taken'),edge('a','c'),edge('b','c')]);
check('diamond acyclic',()=>{const g=analyze(diamond);assert.equal(g.regions.filter(x=>x.cyclic).length,0);assert.equal(g.loops.length,0);assert.equal(g.reachable.size,4);assert.equal(g.idom.get('c'),'f');});
const nested=report([block('f',0x1000),block('a',0x1010),block('b',0x1020),block('c',0x1030),block('d',0x1040)],[edge('f','a'),edge('a','b'),edge('b','c'),edge('c','b','taken'),edge('c','a','jump'),edge('a','d','not_taken')]);
check('natural loop headers use dominance',()=>{const g=analyze(nested);assert(g.loops.some(x=>x.header==='b'));assert(g.loops.some(x=>x.header==='a'));});
const irr=report([block('f',0x1000),block('a',0x1010),block('b',0x1020),block('c',0x1030)],[edge('f','a'),edge('f','b'),edge('a','c'),edge('b','c'),edge('c','a'),edge('c','b')]);
check('irreducible SCC retained',()=>{const g=analyze(irr);const r=g.regions.find(x=>x.cyclic);assert(r);assert(r.irreducible);assert(r.entryTargets.length>1);});
const self=report([block('f',0x1000)],[edge('f','f')]);
check('self loop is cyclic and natural',()=>{const g=analyze(self);assert(g.regions[0].cyclic);assert.equal(g.loops[0].header,'f');});
const unreachable=report([block('f',0x1000),block('a',0x1010),block('b',0x1020)],[edge('f','a')]);
check('unreachable remains explicit',()=>assert.deepEqual(analyze(unreachable).unreachable,['b']));
const unknown=report([block('f',0x1000)],[{from:'f',to:null,source:'m_i_1000',kind:'jump',external:'',target:'rax'}],true);
check('incomplete from unresolved and truncation',()=>{const g=analyze(unknown);assert(g.incomplete);assert.equal(g.unresolved.length,1);});
check('graph limits switch to fallback without dropping facts',()=>{const g=analyze(diamond,{nodeLimit:2});assert(!g.bounded);assert.equal(g.nodes.length,4);assert.equal(g.edges.length,4);});
check('dominator budget exhaustion is visible',()=>{const g=analyze(nested,{iterationLimit:0});assert(g.dominatorBudgetExceeded);assert.equal(g.loops.length,0);});
check('shared ownership retained',()=>{const r=report([block('f',0x1000,['f','other'])],[]);r.functions.push({id:'other',rva:0x2000});const g=analyze(r);assert.equal(g.shared.length,1);});
check('analysis never mutates report',()=>{const before=JSON.stringify(irr);analyze(irr);assert.equal(JSON.stringify(irr),before);});
console.log('PASS: '+checks+' cfg-model cases');
