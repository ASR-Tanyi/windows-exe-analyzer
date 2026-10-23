'use strict';
const assert = require('node:assert/strict');
const SSA = require('../web/register-ssa'), E = require('../web/register-expressions'), C = require('../web/register-cleanup');
const CALL = require('../web/call-summaries'), {execute} = require('./pseudocode_eval');
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
    const report = {module:{architecture:bits === 64 ? 'x64 / PE32+' : 'x86 / PE32'}, edges};
    const ssa = SSA.analyze(report, blocks, edges, lifted, 'A');
    check(ssa.status === 'available', ssa.reason);
    return {lifted, ssa};
}
function run(ops, options) {
    const f = fixture({A:ops}), expressions = E.analyze(f.ssa, f.lifted);
    const snapshot = () => JSON.stringify([f.ssa, [...f.lifted], expressions]), before = snapshot();
    const result = C.analyze(f.ssa, f.lifted, expressions, options);
    check(snapshot() === before, 'raw operations, SSA and expression overlay remain immutable');
    if (!options) check(result.status === 'available', result.reason);
    const defs = new Map(f.ssa.definitions.map(d => [d.id, d]));
    for (const variant of [result.raw, result.simplified]) for (const item of variant.rewrites) {
        const write = defs.get(item.definition), killer = defs.get(item.overwrittenBy.definition);
        check(write.source === item.source && write.register === item.register, 'original SSA definition identifies removed write');
        check(killer.block === write.block && killer.register === write.register && killer.preserveMask === '0x0', 'witness is a full overwrite in same block');
        check(Number(killer.source.split('_')[1]) > Number(write.source.split('_')[1]), 'overwrite occurs later');
        check(!variant.rewrites.some(r => r.definition === killer.id), 'witness itself retains its register write');
        check(item.sources.includes(write.source) && item.sources.includes(killer.source) &&
            item.sources.every(s => f.lifted.get('A').some(i => i.source === s)), 'untruncated original and overwrite evidence');
        check(item.kind === 'removed' ? item.replacement === null : item.replacement.kind === 'alu' && item.replacement.target === null,
            'replacement either omits a pure operation or retains its flag helper');
    }
    return {result, at:(n, variant = 'raw') => result[variant].rewrites.find(r => r.source === 'A_' + n)};
}
let q = run([mov(r,c(1)),mov(r,c(2))]);
check(q.at(0)?.kind === 'removed' && !q.at(1), 'overwritten constant removed, complete exit state retained');
q = run([mov(r,x),mov(d,r),mov(r,c(7)),mov(d,c(8))]);
check(q.at(0)?.kind === 'removed' && q.at(1)?.kind === 'removed', 'backward scan removes cascading dead copies');
q = run([mov(r,x),mov(d,r),mov(r,c(7))]);
check(!q.at(0) && q.at(0,'simplified')?.kind === 'removed', 'raw and substituted operands have separate liveness');
q = run([mov(r,x),mov(x,c(5)),mov(d,r),mov(r,c(7))]);
check(!q.at(0,'simplified') && !q.at(1,'simplified'), 'old copied input cannot be replaced with an overwritten source');
for (const operator of ['add','sub','and','or','xor','imul','inc','dec','neg','shl','shr','sar']) {
    const op = alu(operator,r,['inc','dec','neg'].includes(operator) ? null : c(1));
    q = run([op,mov(r,c(9))]);
    assert.deepEqual(q.at(0)?.replacement,{...op,target:null}); checks++;
}
q = run([alu('not',r),mov(r,c(9))]);
check(q.at(0)?.kind === 'removed', 'NOT has no flag effects and can disappear');
q = run([mov(r,c(1)),alu('inc',r),mov(r,c(9))]);
check(!q.at(0) && q.at(1)?.kind === 'flags_only', 'flags-only ALU keeps its input definition');
check(q.at(0,'simplified')?.kind === 'removed', 'constant substitution can remove a flags-only helper input write');
q = run([mov(r,c(1)),{...alu('cmp',r,c(3)),target:null},mov(r,c(9))]);
check(!q.at(0) && !q.at(1), 'CMP operand still reads its definition');
for (const [width,offset] of [[8,0],[8,8],[16,0]]) {
    const partial = reg('rax',width,offset);
    q = run([mov(r,c(1)),mov(partial,c(2,width))]);
    check(!q.at(0) && !q.at(1), 'live partial write preserves remaining family bits');
    q = run([mov(partial,c(2,width)),mov(d,r),mov(r,c(9))]);
    check(!q.at(0), 'later whole-family read preserves partial definition');
    q = run([mov(partial,c(2,width)),mov(r,c(9))]);
    check(q.at(0)?.kind === 'removed', 'full overwrite kills earlier partial write');
}
q = run([mov(r,c('18446744073709551615')),mov(reg('rax',32),c(1,32))]);
check(q.at(0)?.kind === 'removed', 'x64 32-bit write kills old upper bits too');
const f32 = fixture({A:[mov(reg('eax',32,0,32),c(2,32)),mov(reg('eax',32,0,32),c(3,32))]},[],32);
check(C.analyze(f32.ssa,f32.lifted).raw.stats.removed === 1, 'x86 full family overwrite');
for (const boundary of [mov(b,{kind:'load',address:x,width:64}),mov({kind:'load',address:x,width:64},b),
    {...alu('add',r,c(1)),target:{kind:'load',address:x,width:64}}, {kind:'barrier',reason:'test'},
    {kind:'push',value:b,width:64}, {kind:'pop',value:b,width:64},
    mov(reg('rbx',8),{kind:'condition',code:'e',width:8}), {kind:'select',target:b,value:x,condition:'e'},
    {kind:'call_summary',profile:CALL.PROFILE.id,target:c(0x401000),width:64}]) {
    q = run([mov(r,c(7)),boundary,mov(r,c(9))]);
    check(!q.at(0) && !q.at(0,'simplified') && !q.at(1), 'memory, stack, calls, unknown and flag-dependent effects retain all incoming state');
}
q = run([mov(b,c(7)),{kind:'call_summary',profile:CALL.PROFILE.id,target:c(0x401000),width:64},mov(b,c(9))]);
check(!q.at(0) && !q.at(0,'simplified'), 'selected call observes even ABI-preserved input registers');
q = run([mov(r,{kind:'load',address:x,width:64}),mov(r,c(9))]);
check(!q.at(0), 'unused potentially faulting load is never removed');
q = run([mov(r,c(1)),{kind:'nop'},mov(r,c(2))]);
check(q.at(0)?.kind === 'removed' && !q.at(1), 'NOP retained without breaking liveness');
const multi = fixture({A:[mov(r,c(7))],B:[mov(r,c(9))]},[['A','B']]);
check(C.analyze(multi.ssa,multi.lifted).raw.stats.removed === 0, 'all GPRs remain live across blocks');
const disconnected = fixture({A:[mov(r,c(7))],B:[mov(r,c(8)),mov(r,c(9))]});
check(C.analyze(disconnected.ssa,disconnected.lifted).raw.stats.removed === 0, 'disconnected blocks stay original');
for (const limit of [{work:0},{rewrites:0},{rewrites:1}]) {
    q = run([mov(r,c(1)),mov(r,c(2))],limit);
    check(q.result.status === 'unavailable' && !q.result.raw.rewrites.length && !q.result.simplified.rewrites.length, 'budget failure discards both variants transactionally');
}
check(C.analyze({status:'unavailable'},new Map()).status === 'unavailable', 'unavailable SSA disables cleanup');
const fallback = C.analyze(f32.ssa,f32.lifted,{status:'unavailable'});
assert.deepEqual(fallback.raw,fallback.simplified); checks++;
// Check evaluator handling of flags-only zero/masked-count shifts, partial
// writes and preserved carry before the independent decoder/Unicorn suite.
for (const width of [8,16,32,64]) for (const operator of ['shl','shr','sar','inc','dec','not']) for (const count of [0,1,31,32,63,64]) {
    const target = reg('rax',width), ops = [alu(operator,target,c(count,8)),mov(r,c(9))];
    const f = fixture({A:ops}), e = E.analyze(f.ssa,f.lifted), cleanup = C.analyze(f.ssa,f.lifted,e);
    const body = ops.map((operation,n) => {
        const rewrite = cleanup.raw.rewrites.find(r => r.source === 'A_' + n);
        return {kind:'line',operation,...(rewrite ? {cleanOperation:rewrite.replacement} : {})};
    });
    const model = {functionId:'A',regions:[{id:'A',body,term:{kind:'return',control:{width:64,adjustment:c(0)}}}]};
    const input = {registers:{rax:'18446744073709551488',rsp:'4096'},memory:Object.fromEntries(Array.from({length:8},(_,n)=>[4096+n,0])),
        flags:{carry:true,zero:false,sign:true,overflow:false,parity:true,auxiliary:false}};
    const raw = execute(model,input), clean = execute(model,input,100000,false,true);
    delete raw.steps; delete clean.steps;
    assert.deepEqual(clean,raw,operator + '/' + width + '/' + count); checks++;
}
console.log(`PASS: ${checks} register-cleanup checks`);
