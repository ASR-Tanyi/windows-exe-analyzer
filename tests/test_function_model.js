'use strict';
const assert = require('node:assert/strict');
const {create} = require('../web/function-model.js');
let checks = 0;
function check(name, fn) { fn(); ++checks; console.log('PASS ' + name); }
const insn = (rva, size = 1, refs = []) => ({id:'i'+rva,rva,size,dataRefs:refs});
const block = (id,rva,owners,instructions) => ({id,rva,owners,instructions});
const edge = (from,to,source,kind = 'jump',external = '') => ({from,to,source,kind,external});
const report = {
    functions:[{id:'f',rva:10},{id:'g',rva:30},{id:'empty',rva:80}],
    blocks:[block('f',10,['f'],[insn(10,2)]),block('b',20,['f','f'],[insn(20,2)]),
        block('g',30,['g'],[insn(30)]),block('shared',40,['f','g'],[insn(40)]),
        block('orphan',50,[],[insn(50)])],
    edges:[edge('f','g','i10','call'),edge('f','b','i10','continuation'),
        edge('b','shared','i20'),edge('g','shared','i30'),edge('shared',null,'i40','jump')]
};
check('preserves reported membership and omits orphan', () => assert.deepEqual(create(report).get('f').blocks.map(b=>b.id),['f','b','shared']));
check('keeps shared block in both owners', () => {
    const x=create(report);assert.equal(x.get('f').sharedBlocks.length,1);assert.equal(x.get('g').sharedBlocks.length,1);
});
check('does not double count duplicate owner entries', () => assert.equal(create(report).get('f').rows.length,3));
check('disjoint ranges remain disjoint', () => assert.deepEqual(create(report).get('f').ranges,[[10,12],[20,22],[40,41]]));
check('unique byte count excludes holes', () => assert.equal(create(report).get('f').byteCount,5));
check('calls do not become intraprocedural CFG edges', () => {
    const f=create(report).get('f');assert.equal(f.calls.length,1);assert.equal(f.cfg.length,2);assert(f.cfg.every(e=>e.kind!=='call'));
});
check('only call edges are incoming callers', () => assert.equal(create(report).get('g').callers.length,1));
check('unknown branch remains explicit', () => assert.equal(create(report).get('f').unresolved.length,1));
check('empty membership is not silently inferred', () => {const f=create(report).get('empty');assert.equal(f.rows.length,0);assert(f.ownershipMissing);});
check('never claims complete analysis', () => assert.equal(create(report).get('f').completeness,'not_proven'));
check('unknown function returns null', () => assert.equal(create(report).get('absent'),null));
check('does not modify embedded report facts', () => {const before=JSON.stringify(report);create(report).get('f');assert.equal(JSON.stringify(report),before);});
check('recursive calls are calls, not graph back edges', () => {
    const r=structuredClone(report);r.edges.push(edge('f','f','i10','call'));
    const f=create(r).get('f');assert.equal(f.calls.length,2);assert.equal(f.callers.length,1);assert.equal(f.callSites,1);
});
check('tail transfer is not a call', () => {
    const r=structuredClone(report);r.edges=[edge('f','g','i10','jump')];const x=create(r);
    assert.equal(x.get('f').transfers.length,1);assert.equal(x.get('f').calls.length,0);assert.equal(x.get('g').callers.length,0);
});
check('import identity is not an unresolved target', () => {
    const r=structuredClone(report);r.edges=[edge('f',null,'i10','call','dll!api')];
    const f=create(r).get('f');assert.equal(f.calls.length,1);assert.equal(f.unresolved.length,0);
});
check('interior calls and shared-target callers retained', () => {
    const r=structuredClone(report);r.edges=[edge('orphan','shared','i50','call')];const x=create(r);
    assert.equal(x.get('f').callers.length,1);assert.equal(x.get('g').callers.length,1);
});
check('counts data references independently from unique target addresses', () => {
    const r=structuredClone(report);r.blocks[0].instructions[0].dataRefs=[{to:'d1',va:'0x1010'},{to:'d1',va:'0x1010'},{va:'0xffffffffffffffff'}];
    const f=create(r).get('f');assert.equal(f.refs.length,3);assert.equal(f.dataAddresses,2);
});
check('handles top-of-RVA-space intervals without bitwise truncation', () => {
    const r={functions:[{id:'f',rva:0xffffffff}],blocks:[block('f',0xffffffff,['f'],[insn(0xffffffff)])],edges:[]};
    assert.deepEqual(create(r).get('f').ranges,[[0xffffffff,0x100000000]]);
});
check('merges adjacent and overlapping bytes for counts only', () => {
    const r=structuredClone(report);r.blocks[0].instructions=[insn(10,3),insn(12,2),insn(14,1)];
    assert.deepEqual(create(r).get('f').ranges,[[10,15],[20,22],[40,41]]);
});
check('cache eviction does not change facts', () => {
    const r=structuredClone(report);for(let n=0;n<8;n++)r.functions.push({id:'x'+n,rva:100+n});
    const x=create(r), first=x.get('f');for(const f of r.functions)x.get(f.id);assert.deepEqual(x.get('f'),first);
});
console.log('PASS: '+checks+' function-model cases');
