'use strict';
const assert = require('node:assert/strict');
const V = require('../web/value-domain.js');
const A = require('../web/value-analysis.js');
let checks = 0;
function check(ok, why) {assert.ok(ok, why); ++checks;}
function contains(v, n) {
    n = BigInt.asUintN(v.width, BigInt(n));
    return (n & v.mask) === v.value && (!v.atoms || v.atoms.some(a => ['constant', 'module'].includes(a.kind) && BigInt(a.value) === n));
}
const set = ns => ns.map(n => V.constant(8, n)).reduce(V.join);
const c = n => V.constant(64, n);
const scalar = v => V.singleNumber(v);
check(scalar(V.binary('+', V.constant(8, 255), V.constant(8, 1))) === 0n, 'wrap at operand width');
check(scalar(V.cast(V.constant(8, 128), 64, true)) === 0xffffffffffffff80n, 'signed extension');
check(scalar(V.insert(c(-1), V.constant(32, 7), 0, 32)) === 7n, '32-bit zero extension');
check(scalar(V.insert(c(0x123456), V.constant(8, 0xab), 8, 8)) === 0x12ab56n, 'high-byte preservation');
check(V.insert(c(-1), V.unknown(32), 0, 32).mask === 0xffffffff00000000n, 'known upper zero bits');
check(V.singleStack(V.binary('-', V.stack(64), c(32))) === -32n, 'stack allocation');
check(V.singleStack(V.binary('+', V.stack(64, -32), c(8))) === -24n, 'stack LEA');
check(scalar(V.binary('-', V.stack(64, -8), V.stack(64, -32))) === 24n, 'same stack base difference');
check(!V.cast(V.stack(64), 32).atoms, 'address-size truncation loses stack relation');
check(!V.insert(V.stack(64), V.constant(8, 1), 0, 8).atoms, 'partial pointer write loses relation');
check(!V.stack(64, V.LIMITS.stackOffset + 1).atoms, 'bounded stack offsets');
check(V.join(V.stack(64, -8), V.stack(64, -16)).atoms.length === 2, 'ambiguous stack address retained');
check(V.join(c(7), V.unknown(64)).atoms === null, 'unknown predecessor cannot be ignored');
check(V.join(V.moduleAddress(64, 0x140001000n, 'm', 0x140000000n), c(5)).atoms.length === 2, 'module and numeric alternatives');
check(V.join(V.importReference(64, 'm', 'ReadFile'), V.importReference(64, 'm', 'WriteFile')).atoms.length === 2, 'bounded supplied import alternatives');
check(V.binary('+', V.importReference(64, 'm', 'ReadFile'), c(4)).atoms === null, 'no invented import arithmetic');
check(set([0, 1, 2, 3, 4]).atoms === null && set([0, 1, 2, 3, 4]).mask === 0xf8n, 'set widening preserves common bits');
let proof = c(3);
for (let n = 0; n < 80; n++) proof = V.derived(proof, 'source_' + n);
check(proof.sources.length === V.LIMITS.sources && proof.proofTruncated, 'provenance capped explicitly');
check(JSON.parse(JSON.stringify(V.serialize(proof))).atoms[0].value === '3', 'JSON has no BigInt precision loss');
// Exhaustive concretization of several finite/known-bit domains. Expected
// values use independent integer arithmetic, not the shared bitvector helper.
const domains = [V.unknown(8), set([0, 1]), set([0, 16, 32, 48, 64]), set([128, 129, 130, 131, 132]), set([0, 255])];
const ops = {'+': (a,b) => a+b, '-': (a,b) => a-b, '*': (a,b) => a*b,
    and: (a,b) => a&b, or: (a,b) => a|b, xor: (a,b) => a^b};
for (const a of domains) for (const b of domains) for (const [op, concrete] of Object.entries(ops)) {
    const out = V.binary(op, a, b);
    for (let x = 0; x < 256; x++) if (contains(a, x)) for (let y = 0; y < 256; y++) if (contains(b, y))
        assert.ok(contains(out, (concrete(x, y) + 65536) % 256), op + ' must overapproximate all inputs');
    ++checks;
}
for (const a of domains) for (const count of [0, 1, 7, 8, 15, 31, 32, 63]) for (const op of ['shl', 'shr', 'sar']) {
    const out = V.binary(op, a, V.constant(8, count)), n = count & 31;
    for (let x = 0; x < 256; x++) if (contains(a, x)) {
        const want = op === 'shl' ? (x * 2 ** n) % 256 : op === 'shr' ? Math.floor(x / 2 ** n) :
            (Math.floor((x >= 128 ? x - 256 : x) / 2 ** n) + 256) % 256;
        assert.ok(contains(out, want), 'shift widening: ' + op);
    }
    ++checks;
}
// Unknown loads (including file-backed/IAT-shaped addresses), barriers and
// pointer writes never inherit the address's value as the loaded contents.
const state = A.newState(64), reg = {kind:'register',name:'rax',offset:0,width:64,familyWidth:64};
state.rsp = V.stack(64); state.rax = c(9);
A.apply({kind:'assign',target:reg,value:{kind:'load',width:64,address:{kind:'constant',width:64,value:'5368713216'}}}, state, 64, 'load');
check(state.rax.atoms === null && state.rax.mask === 0n, 'mutable load unknown');
A.apply({kind:'barrier'}, state, 64, 'call');
check(Object.values(state).every(v => !v.atoms && !v.mask), 'unknown call clears even stack/frame registers');
console.log(`PASS: ${checks} bounded-domain checks (including exhaustive 8-bit concretizations)`);
