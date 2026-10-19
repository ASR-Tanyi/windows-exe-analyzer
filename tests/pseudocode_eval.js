'use strict';
// Test-only bit-vector interpreter. No native input execution; unknown effects
// stop evaluation. The independent oracle is Unicorn, not the display strings.
const fs = require('node:fs');
const BV = require('../web/bitvectors.js');
const u = (v, n) => BigInt.asUintN(n, v), s = (v, n) => BigInt.asIntN(n, v);
function execute(model, input, maxSteps = 100000) {
    const regs = Object.fromEntries(Object.entries(input.registers).map(([k, v]) => [k, BigInt(v)]));
    const memory = new Map(Object.entries(input.memory || {}).map(([k, v]) => [BigInt(k), v]));
    const flags = {...input.flags}; let steps = 0, returned = false;
    const tick = () => {if (++steps > maxSteps) throw Error('evaluation budget');};
    const load = (addr, width) => {
        let value = 0n;
        for (let i = 0; i < width / 8; ++i) {
            if (!memory.has(addr + BigInt(i))) throw Error('unmapped read ' + addr.toString(16));
            value |= BigInt(memory.get(addr + BigInt(i))) << BigInt(i * 8);
        }
        return value;
    };
    const store = (addr, width, value) => {
        for (let i = 0; i < width / 8; ++i) memory.set(addr + BigInt(i), Number((value >> BigInt(i * 8)) & 255n));
    };
    function cc(code) {
        const need = (...names) => {for (const n of names) if (flags[n] === null || flags[n] === undefined) throw Error('unknown flag ' + n);};
        const table = {e: 'z', z: 'z', ne: 'nz', nz: 'nz', b: 'c', c: 'c', nae: 'c', ae: 'nc', nb: 'nc', nc: 'nc',
            be: 'cz', na: 'cz', a: 'ncz', nbe: 'ncz', l: 'so', nge: 'so', ge: 'nso', nl: 'nso', le: 'zso', ng: 'zso',
            g: 'nzso', nle: 'nzso', s: 's', ns: 'ns', o: 'o', no: 'no', p: 'p', pe: 'p', np: 'np', po: 'np'};
        const k = table[code]; if (!k) throw Error('unknown condition');
        if (k.includes('z')) need('zero'); if (k.includes('c')) need('carry');
        if (k.includes('s')) need('sign'); if (k.includes('o')) need('overflow'); if (k.includes('p')) need('parity');
        const values = {z: flags.zero, c: flags.carry, cz: flags.carry || flags.zero, so: flags.sign !== flags.overflow,
            zso: flags.zero || flags.sign !== flags.overflow, s: flags.sign, o: flags.overflow, p: flags.parity};
        return k.startsWith('n') ? !values[k.slice(1)] : values[k];
    }
    function value(e) {
        if (e.kind === 'constant') return BigInt(e.value);
        if (e.kind === 'register') return u(regs[e.name] >> BigInt(e.offset), e.width);
        if (e.kind === 'load') return load(value(e.address), e.width);
        if (e.kind === 'cast') return u(e.signed ? s(value(e.value), e.value.width) : value(e.value), e.width);
        if (e.kind === 'binary') {
            const a = value(e.left), b = value(e.right);
            return u(e.operator === '+' ? a + b : e.operator === '*' ? a * b : (() => {throw Error('operator');})(), e.width);
        }
        if (e.kind === 'condition') return cc(e.code) ? 1n : 0n;
        throw Error('expression');
    }
    function write(target, v) {
        v = u(v, target.width);
        if (target.kind === 'load') return store(value(target.address), target.width, v);
        if (target.width === target.familyWidth || target.width === 32 && target.familyWidth === 64) regs[target.name] = v;
        else {
            const mask = ((1n << BigInt(target.width)) - 1n) << BigInt(target.offset);
            regs[target.name] = u((regs[target.name] & ~mask) | v << BigInt(target.offset), target.familyWidth);
        }
    }
    function alu(op) {
        const n = op.width, a = value(op.left), b = op.right ? value(op.right) : 0n, sign = 1n << BigInt(n - 1);
        const kind = op.operator, result = BV.integerResult(kind, n, a, b); let raw;
        const arithmetic = (left, right, subtract) => {
            raw = subtract ? left - right : left + right;
            flags.carry = subtract ? left < right : raw >> BigInt(n) !== 0n;
            flags.overflow = !!((subtract ? (left ^ right) & (left ^ result) : ~(left ^ right) & (left ^ result)) & sign);
            flags.auxiliary = !!((left ^ right ^ result) & 16n);
        };
        if (['add', 'sub', 'cmp', 'inc', 'dec', 'neg'].includes(kind)) {
            const carry = flags.carry;
            arithmetic(kind === 'neg' ? 0n : a, ['inc', 'dec'].includes(kind) ? 1n : kind === 'neg' ? a : b, ['sub', 'cmp', 'dec', 'neg'].includes(kind));
            if (['inc', 'dec'].includes(kind)) flags.carry = carry;
        } else if (['and', 'test', 'or', 'xor', 'not'].includes(kind)) {
            if (kind !== 'not') {flags.carry = false; flags.overflow = false; flags.auxiliary = null;}
        } else if (kind === 'imul') {
            raw = s(a, n) * s(b, n);
            flags.carry = flags.overflow = s(result, n) !== raw;
            flags.zero = flags.sign = flags.parity = flags.auxiliary = null;
        } else if (['shl', 'shr', 'sar'].includes(kind)) {
            const count = Number(b & BigInt(n === 64 ? 63 : 31));
            if (!count) {write(op.target, result); return;}
            flags.carry = count >= n && kind !== 'sar' ? null : kind === 'shl' ? !!(a & (1n << BigInt(n - count))) : !!(a & (1n << BigInt(Math.min(count, n) - 1)));
            flags.overflow = count !== 1 ? null : kind === 'sar' ? false : kind === 'shr' ? !!(a & sign) : !!(result & sign) !== flags.carry;
            flags.auxiliary = null;
        } else throw Error('ALU operator');
        if (!['imul', 'not'].includes(kind)) {
            flags.zero = result === 0n; flags.sign = !!(result & sign);
            let parity = Number(result & 255n); parity ^= parity >> 4; parity ^= parity >> 2; parity ^= parity >> 1;
            flags.parity = !(parity & 1);
        }
        if (op.target) write(op.target, result);
    }
    function operation(op) {
        tick();
        if (op.kind === 'assign') write(op.target, value(op.value));
        else if (op.kind === 'alu') alu(op);
        else if (op.kind === 'select') write(op.target, cc(op.condition) ? value(op.value) : value(op.target));
        else if (op.kind === 'push' || op.kind === 'pop') {
            const sp = op.width === 64 ? 'rsp' : 'esp', size = BigInt(op.width / 8);
            if (op.kind === 'push') {const v = value(op.value); regs[sp] = u(regs[sp] - size, op.width); store(regs[sp], op.width, v);}
            else {const v = load(regs[sp], op.width); regs[sp] = u(regs[sp] + size, op.width); write(op.value, v);}
        } else if (op.kind !== 'nop') throw Error('unknown effects');
    }
    const test = t => Boolean(cc(t.code)) !== t.negate;
    function body(nodes) {
        for (const n of nodes) {
            tick();
            if (n.kind === 'line' && n.operation) operation(n.operation);
            else if (n.kind === 'if') body(test(n.test) ? n.yes : n.no);
            else if (n.kind === 'while') {while (true) {tick(); body(n.head); if (!test(n.test)) break; body(n.body);}}
            else if (n.kind === 'do') {do {tick(); body(n.body);} while (test(n.test));}
        }
    }
    if (model.regions) {
        const regions = new Map(model.regions.map(n => [n.id, n])); let next = model.functionId;
        while (next) {
            tick(); const n = regions.get(next); if (!n) throw Error('unresolved edge'); body(n.body);
            const t = n.term;
            if (t.kind === 'return') {
                const sp = t.control.width === 64 ? 'rsp' : 'esp';
                load(regs[sp], t.control.width);
                regs[sp] = u(regs[sp] + BigInt(t.control.width / 8) + value(t.control.adjustment), t.control.width);
                returned = true; break;
            }
            if (t.kind === 'goto') next = t.to;
            else if (t.kind === 'branch') next = test(t.test) ? t.yes : t.no;
            else throw Error('unknown control');
            if (!next) throw Error('unresolved edge');
        }
    } else for (const op of model.ops) operation(op);
    return {registers: Object.fromEntries(Object.entries(regs).map(([k, v]) => [k, v.toString()])),
        flags, memory: Object.fromEntries([...memory].map(([k, v]) => [k.toString(), v])), returned, steps};
}
module.exports = {execute};
if (require.main === module) {
    const requests = JSON.parse(fs.readFileSync(0, 'utf8'));
    console.log(JSON.stringify(requests.map(r => execute(r.model, r.input))));
}
