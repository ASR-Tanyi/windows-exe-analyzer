'use strict';
const assert = require('node:assert/strict'), S = require('../web/register-ssa');
let checks = 0;
const check = (value, why) => {assert.ok(value, why); ++checks;};
const r = (name, width = 64, offset = 0, bits = 64) => ({kind: 'register', name, width, offset, familyWidth: bits});
const c = (value, width = 64) => ({kind: 'constant', value: String(value), width});
const mov = (target, value) => ({kind: 'assign', target, value});
const inc = target => ({kind: 'alu', operator: 'inc', target, left: target, right: null, width: target.width});
const ret = bits => ({kind: 'return', width: bits, adjustment: c(0, 16)});
function fixture(body, links = [], bits = 64) {
    const lifted = new Map(), blocks = Object.entries(body).map(([id, ops], n) => {
        const list = (ops.length ? ops : [{kind: 'nop'}]).map((op, k) => ({source: 'i_' + id + '_' + k,
            rva: 0x1000 + n * 0x20 + k, mnemonic: op.kind, ops: op.kind === 'return' ? [] : [op],
            ...(op.kind === 'return' ? {control: op} : {})}));
        lifted.set(id, list);
        return {id, rva: list[0].rva, owners: ['A'], instructions: list.map(i => ({id: i.source, rva: i.rva}))};
    });
    const edges = links.map(([from, to]) => ({from, to, kind: 'jump', source: lifted.get(from).at(-1).source}));
    const report = {module: {architecture: bits === 64 ? 'x64 / PE32+' : 'x86 / PE32'}, edges};
    return {report, blocks, edges, lifted};
}
function run(f, options) {return S.analyze(f.report, f.blocks, f.edges, f.lifted, 'A', options);}
function validate(g) {
    check(g.status === 'available', g.reason || 'available SSA');
    const defs = new Map(g.definitions.map(d => [d.id, d])), uses = new Map(g.uses.map(u => [u.id, u]));
    const blocks = new Map(g.blocks.map(b => [b.id, b]));
    check(defs.size === g.definitions.length && uses.size === g.uses.length, 'single, unique identities');
    // Independent dominance test: removing a defining block must cut every
    // entry-to-use path. PHI operands are uses on their predecessor's exit.
    function dominates(def, to) {
        if (to === null) return def === null;
        if (def === null || def === to) return true;
        const pending = ['A'], visited = new Set();
        while (pending.length) {const b = pending.pop(); if (b === def || visited.has(b)) continue;
            if (b === to) return false; visited.add(b); pending.push(...blocks.get(b).successors);}
        return true;
    }
    for (const u of g.uses) {
        const d = defs.get(u.definition), at = u.kind === 'phi' ? u.predecessor : u.block;
        check(d && d.register === u.register && d.uses.includes(u.id), 'typed reciprocal def-use edge');
        check(dominates(d.block, at), 'definition dominates use edge/location');
        if (d.source && u.kind === 'instruction' && d.block === u.block) {
            const order = blocks.get(u.block).sources;
            check(order.indexOf(d.source) < order.indexOf(u.source) || d.source === u.source && d.operation < u.operation,
                'same-block read sees a prior definition');
        }
    }
    for (const d of g.definitions) {
        for (const id of d.inputs) check(uses.has(id), 'definition inputs reference real uses');
        for (const id of d.uses) check(uses.get(id).definition === d.id, 'no stale reverse use');
        if (d.kind === 'phi') {
            const incoming = d.incoming.map(id => uses.get(id));
            assert.deepEqual(new Set(incoming.map(u => u.predecessor)), new Set(blocks.get(d.block).predecessors));
            check(incoming.length === blocks.get(d.block).predecessors.length, 'one phi operand per predecessor');
        }
    }
    return g;
}
const diamond = fixture({A: [], B: [mov(r('rax'), c(1))], C: [mov(r('rax'), c(2))], D: [ret(64)]},
    [['A','B'], ['A','C'], ['B','D'], ['C','D']]);
let g = validate(run(diamond));
check(g.stats.joins === 1 && g.definitions.find(d => d.kind === 'phi').register === 'rax', 'return boundary retains merged accumulator');
const shuffled = {...diamond, blocks: [...diamond.blocks].reverse(), edges: [...diamond.edges].reverse(), report: {...diamond.report, edges: [...diamond.edges].reverse()}};
assert.deepEqual(run(shuffled), g); ++checks;
const killed = fixture({A: [], B: [mov(r('rax'), c(1))], C: [mov(r('rax'), c(2))], D: [mov(r('rax'), c(3)), ret(64)]}, diamond.edges.map(e => [e.from,e.to]));
check(validate(run(killed)).stats.joins === 0, 'dead joins pruned without deleting definitions');
const loop = fixture({A: [mov(r('rax'), c(0))], B: [inc(r('rax'))], C: [ret(64)]}, [['A','B'], ['B','B'], ['B','C']]);
g = validate(run(loop));
check(g.stats.joins === 1 && g.definitions.find(d => d.kind === 'phi').block === 'B', 'loop-carried definition');
const entryLoop = fixture({A: [inc(r('rax'))], B: [ret(64)]}, [['A','A'], ['A','B']]);
g = validate(run(entryLoop));
check(g.uses.some(u => u.kind === 'phi' && u.predecessor === null), 'entry backedge has explicit initial operand');
validate(run(fixture({A: [], B: [mov(r('rax'), c(7))], C: [inc(r('rax'))], D: [ret(64)]},
    [['A','B'], ['A','C'], ['B','C'], ['B','D'], ['C','B'], ['C','D']])));
// A definition on one path must join the unknown incoming value on the other.
g = validate(run(fixture({A: [], B: [mov(r('rax'), c(1))], C: [ret(64)]}, [['A','B'], ['A','C'], ['B','C']])));
check(g.uses.some(u => u.kind === 'phi' && u.definition === 'A_ssa_in_rax'), 'unknown path not dropped');
// Read both RHS/old bytes before installing a partial result; a 32-bit x64
// assignment has no preserved old high half, even on false CMOV.
g = validate(run(fixture({A: [mov(r('rax'), c(5)), mov(r('rax', 8, 8), r('rax', 8)),
    mov(r('rax', 16), c(2, 16)), mov(r('rax', 32), c(3, 32)),
    {kind:'select', target:r('rax',32), value:r('rcx',32), condition:'e'}, ret(64)]})));
const bySource = source => g.definitions.find(d => d.source === source);
check(bySource('i_A_1').preserveMask === '0xffffffffffff00ff', 'AH write preserves all other bits');
check(g.uses.filter(u => u.source === 'i_A_1' && u.kind === 'instruction').every(u => u.definition === bySource('i_A_0').id), 'old byte read before write');
check(bySource('i_A_2').preserveMask === '0xffffffffffff0000', 'AX preservation');
check(bySource('i_A_3').zeroExtend && bySource('i_A_3').preserveMask === '0x0', 'EAX write zeroes high half');
check(bySource('i_A_4').inputs.length === 2 && bySource('i_A_4').zeroExtend, 'CMOV depends on both operands but not old high bits');
// Calls/unsupported forms are fresh unknown definitions for *every* GPR.
g = validate(run(fixture({A: [mov(r('rax'),c(7)), {kind:'barrier'}, mov(r('rcx'),r('rax')), ret(64)]})));
check(g.definitions.filter(d => d.kind === 'clobber').length === 16, 'all-state barrier includes nonvolatile and stack/frame registers');
check(g.uses.find(u => u.source === 'i_A_2' && u.role === 'value').definition === 'i_A_1_ssa_d_0_rax', 'post-call read cannot use pre-call definition');
check(g.instructions[1].memory.unknown && g.instructions[1].flags.unknown, 'unmodeled memory and flags marked unknown');
const load = address => ({kind:'load', width:64, address});
g = validate(run(fixture({A: [mov(load(r('rbx')), r('rax')), mov(r('rax'), load(r('rbx'))),
    {kind:'push', value:r('rsp'), width:64}, {kind:'pop', value:r('rbp'), width:64}, ret(64)]})));
check(g.instructions[0].writes.length === 0 && g.instructions[0].memory.write, 'store has address/value uses but no register write');
check(g.definitions.find(d => d.source === 'i_A_1').memoryRead, 'loaded value remains an explicit memory dependency');
const stackDef = g.definitions.find(d => d.source === 'i_A_2');
check(stackDef.inputs.length === 1 && g.instructions[2].reads.length === 2, 'PUSH SP uses the old SP for source and address');
check(g.instructions[3].writes.length === 2, 'POP defines SP and destination separately');
const x86 = validate(run(fixture({A:[mov(r('eax',8,8,32),c(5,8)),ret(32)]}, [],32)));
check(x86.definitions.find(d=>d.source==='i_A_0').preserveMask==='0xffff00ff', 'x86 high-byte width');
const disconnected = fixture({A:[ret(64)], B:[mov(r('rax'),c(1))]});
check(run(disconnected).stats.disconnectedBlocks === 1 && !run(disconnected).definitions.some(d=>d.block==='B'), 'no reaching definition invented for disconnected code');
for (const options of [{work:0},{definitions:2},{uses:1}]) {
    const x=run(loop,options);check(x.status==='budget_exceeded' && !x.definitions.length && !x.uses.length && !x.instructions.length, 'transactional budget fallback');
}
for (const mutate of [f=>f.report.module.truncated=true, f=>f.blocks[0].owners.push('other'),
    f=>f.edges[0].to=null, f=>f.report.edges.push({...f.edges[0],from:'outside',to:'B'}),
    f=>f.blocks.push(f.blocks[0])]) {
    const f=structuredClone(diamond); mutate(f);check(run(f).status==='unavailable', 'unsafe graph disabled');
}
check(run(fixture({A:[{kind:'unmodeled'}]})).status==='unavailable', 'unhandled typed effects never silently disappear');
check(run(fixture({A:[inc(r('rax'))]}, [['A','A']])).status==='available', 'nonterminating machine loop has a finite SSA graph');
const manyClobbers=run(fixture({A:Array.from({length:600},()=>({kind:'barrier'}))}));
check(manyClobbers.status==='budget_exceeded' && !manyClobbers.definitions.length, 'production node budget discards thousands of provisional clobbers');
const tooManyInstructions=fixture({A:Array.from({length:2049},()=>({kind:'nop'}))});
check(run(tooManyInstructions).status==='unavailable', 'instruction limit before graph construction');
const tooManyEdges=structuredClone(diamond);tooManyEdges.edges=Array.from({length:385},()=>diamond.edges[0]);
check(run(tooManyEdges).status==='unavailable', 'edge limit before graph construction');
console.log(`PASS: ${checks} register-SSA checks (including independent dominance and reciprocal edges)`);
