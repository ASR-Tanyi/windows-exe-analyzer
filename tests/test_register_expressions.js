'use strict';
const assert = require('node:assert/strict');
const SSA = require('../web/register-ssa'), E = require('../web/register-expressions');
const P = require('../web/pseudocode-model'), CALL = require('../web/call-summaries');
let checks = 0;
const check = (ok, message) => {assert.ok(ok, message); checks++;};
const reg = (name, width = 64, offset = 0, familyWidth = 64) => ({kind:'register', name, width, offset, familyWidth});
const c = (value, width = 64) => ({kind:'constant', value:String(value), width});
const mov = (target, value) => ({kind:'assign', target, value});
const alu = (operator, target, right = null) => ({kind:'alu', operator, target, left:target, right, width:target.width});
const r = reg('rax'), b = reg('rbx'), d = reg('rdx'), x = reg('rcx');
function fixture(bodies, links = [], bits = 64) {
    const lifted = new Map(), blocks = Object.entries(bodies).map(([id, ops], n) => {
        const instructions = ops.map((op, k) => ({source:id + '_' + k, rva:4096 + n * 256 + k, status:'supported', ops:[op]}));
        lifted.set(id, instructions);
        return {id, rva:4096 + n * 256, owners:['A'], instructions:instructions.map(i => ({id:i.source, rva:i.rva}))};
    });
    const edges = links.map(([from,to]) => ({from,to,kind:'jump',source:lifted.get(from).at(-1).source}));
    const report = {module:{architecture:bits === 64 ? 'x64 / PE32+' : 'x86 / PE32'},edges};
    const ssa = SSA.analyze(report, blocks, edges, lifted, 'A');
    check(ssa.status === 'available', ssa.reason);
    return {lifted, ssa};
}
function run(ops, options) {
    const f = fixture({A:ops}), snapshot = () => JSON.stringify([f.ssa, [...f.lifted]]), before = snapshot();
    const result = E.analyze(f.ssa, f.lifted, options);
    check(snapshot() === before, 'raw instructions and SSA remain immutable');
    if (!options) check(result.status === 'available', result.reason);
    const records = new Map(result.rewrites.map(r => [r.source, r]));
    const ids = new Set(f.ssa.definitions.map(d => d.id));
    for (const item of result.rewrites) {
        check(item.sources[0] === item.source && item.sources.every(id => f.lifted.get('A').some(i => i.source === id)), 'all evidence points to contributing instructions');
        check(item.definitions.every(id => ids.has(id)), 'propagated definition IDs belong to SSA');
        check(!JSON.stringify(item).includes('_definition'), 'internal leaf bindings do not leak into typed output');
    }
    return {result, at:n => records.get('A_' + n)};
}
let q = run([mov(r,c('18446744073709551615')), alu('add',r,c(2)), mov(d,r)]);
check(q.at(2).replacement.value.value === '1', '64-bit wrap uses BigInt');
check(q.at(1).replacement.kind === 'alu' && q.at(1).replacement.operator === 'add', 'constant propagation retains arithmetic flags');
assert.deepEqual(new Set(q.at(2).sources), new Set(['A_0','A_1','A_2'])); checks++;
q = run([mov(r,x), alu('add',r,c(5)), mov(d,r)]);
check(q.at(2).replacement.value.kind === 'integer' && P.expr(q.at(2).replacement.value).includes('rcx + 0x5'), 'copy/arithmetic chain substitutes a live input');
q = run([mov(r,x), alu('add',x,c(1)), mov(d,r)]);
check(!q.at(2), 'stale copied input rejected after source overwrite');
q = run([mov(r,x), mov(reg('rcx',8,8),c(0,8)), mov(d,r)]);
check(!q.at(2), 'partial write also invalidates a copied full-register input');
q = run([alu('add',r,c(1)), mov(d,r)]);
check(!q.at(1), 'self-update cannot reread the old version of its destination');
q = run([mov(reg('rax',32),c(0xffffffff,32)), mov(d,r), mov(b,reg('rax',8,8))]);
check(q.at(1).replacement.value.value === '4294967295', 'x64 32-bit assignment zero extends');
check(q.at(2).replacement.value.value === '255' && q.at(2).replacement.value.width === 8, 'high-byte extraction is width-correct');
q = run([mov(r,c(0x1234)), mov(reg('rax',8,8),c(0x56,8)), mov(d,r)]);
check(!q.at(2), 'partial result is not promoted to an invented full value');
q = run([mov(r,c(0x80)), mov(d,{kind:'cast',width:64,signed:true,value:reg('rax',8)})]);
check(q.at(1).replacement.value.value === '18446744073709551488', 'signed byte extension');
for (const [operator, value] of [['add',0],['sub',0],['imul',1],['and','18446744073709551615'],['or',0],['xor',0],['shl',64],['shr',64],['sar',64]]) {
    q = run([mov(r,x), alu(operator,r,c(value)), mov(d,r)]);
    check(q.at(2).replacement.value.name === 'rcx', operator + ' identity with width/count masking');
}
for (const operator of ['sub','xor']) {
    q = run([alu(operator,r,r),mov(d,r)]);
    check(q.at(1).replacement.value.value === '0', operator + ' same-version identity');
}
for (const boundary of [mov(b,{kind:'load',address:x,width:64}),mov({kind:'load',address:x,width:64},b),
    {kind:'barrier',reason:'test'}, {kind:'push',value:b,width:64}, {kind:'pop',value:b,width:64},
    mov(reg('rbx',8),{kind:'condition',code:'e',width:8}), {kind:'select',target:b,value:x,condition:'e'}]) {
    q = run([mov(r,c(7)),boundary,mov(d,r)]);
    check(!q.at(1) && !q.at(2), 'memory, stack, flag-dependent and unknown effects stop propagation');
}
// A selected ABI summary is still a propagation boundary, even for preserved RBX.
const sampleCall = {kind:'call_summary',profile:CALL.PROFILE.id,target:c(0x401000),width:64};
q = run([mov(b,c(7)),sampleCall,mov(d,b)]);
check(!q.at(1) && !q.at(2), 'selected calls stop propagation even for ABI-preserved registers');
const multi = fixture({A:[mov(r,c(7))], B:[mov(d,r)]},[['A','B']]);
check(E.analyze(multi.ssa,multi.lifted).rewrites.length === 0, 'no predecessor or PHI expression propagation');
for (const limit of [{work:0},{outputNodes:0}]) {
    q = run([mov(r,c(2)),mov(d,r)],limit);
    check(q.result.status === 'unavailable' && !q.result.rewrites.length, 'global budget rolls back every rewrite');
}
const unavailable = E.analyze({status:'unavailable'},new Map());
check(unavailable.status === 'unavailable' && !unavailable.rewrites.length, 'unavailable SSA preserves original effects');
// Expansion grows exponentially without a per-expression cap. It must stop
// locally and keep later small expressions useful.
const grow = [mov(r,x)];
for (let n=0;n<30;n++) grow.push(alu('add',r,r));
grow.push(mov(r,c(3)),mov(d,r));
q = run(grow);
check(q.result.stats.cappedExpressions > 0 && q.at(grow.length-1).replacement.value.value === '3', 'growth cap falls back locally and recovers');
const f32 = fixture({A:[mov(reg('eax',32,0,32),c(0xffffffff,32)),alu('inc',reg('eax',32,0,32)),mov(reg('edx',32,0,32),reg('eax',32,0,32))]},[],32);
check(E.analyze(f32.ssa,f32.lifted).rewrites.at(-1).replacement.value.value === '0', 'x86 wraps independently of x64 zero extension');
console.log(`PASS: ${checks} register-expression checks`);
