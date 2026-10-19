'use strict';
// A finite disjunction plus known bits. No memory values, speculative types or
// instruction-text parsing. Null atoms is top (subject to mask/value bits).
(function (root) {
    const BV = typeof module === 'object' && module.exports ? require('./bitvectors.js') : root.WEABitvectors;
    const LIMITS = Object.freeze({atoms: 4, sources: 64, stackOffset: 1048576});
    const full = width => (1n << BigInt(width)) - 1n;
    const numeric = a => a.kind === 'constant' || a.kind === 'module';
    const key = a => JSON.stringify(a);
    function proof(values = [], extra = []) {
        const sources = [...new Set([...values.flatMap(v => v.sources || []), ...extra])].sort();
        return {sources: sources.slice(0, LIMITS.sources), proofTruncated: sources.length > LIMITS.sources || values.some(v => v.proofTruncated)};
    }
    function make(width, atoms = null, mask = 0n, value = 0n, evidence = {}) {
        if (![8, 16, 32, 64].includes(width)) throw Error('value width');
        mask &= full(width); value &= mask;
        if (atoms) {
            atoms = [...new Map(atoms.map(a => [key(a), a])).values()].sort((a, b) => key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0);
            if (!atoms.length) throw Error('empty finite value is not top');
            if (atoms.every(numeric)) {
                mask = full(width); value = BigInt(atoms[0].value);
                for (const a of atoms) mask &= ~(value ^ BigInt(a.value));
                mask &= full(width); value &= mask;
            } else {mask = 0n; value = 0n;}
            if (atoms.length > LIMITS.atoms) atoms = null;
        }
        if (!atoms && mask === full(width)) atoms = [{kind: 'constant', value: value.toString()}];
        const p = proof([evidence]);
        return {width, atoms, mask, value, sources: p.sources, proofTruncated: p.proofTruncated};
    }
    const unknown = width => make(width);
    const constant = (width, value) => make(width, [{kind: 'constant', value: BigInt.asUintN(width, BigInt(value)).toString()}]);
    const stack = (width, offset = 0n, base = 'entry_sp') => {
        offset = BigInt.asIntN(width, BigInt(offset));
        return offset < -BigInt(LIMITS.stackOffset) || offset > BigInt(LIMITS.stackOffset) ? unknown(width) :
            make(width, [{kind: 'stack', base, offset: offset.toString()}]);
    };
    const moduleAddress = (width, value, moduleId, imageBase) => make(width, [{kind: 'module', moduleId,
        value: BigInt.asUintN(width, BigInt(value)).toString(), imageBase: String(imageBase),
        rva: (BigInt.asUintN(width, BigInt(value)) - BigInt(imageBase)).toString()}]);
    // Reserved for independently supplied bindings. A load from an IAT-shaped
    // address never manufactures this atom; IAT contents are mutable.
    const importReference = (width, moduleId, symbol) => make(width, [{kind: 'import', moduleId, symbol}]);
    const withSources = (v, ...values) => ({...v, ...proof([v, ...values])});
    const derived = (v, source) => ({...v, ...proof([v], [source])});
    function join(a, b) {
        if (!a) return b; if (!b) return a;
        if (a.width !== b.width) throw Error('join width mismatch');
        const mask = a.mask & b.mask & ~(a.value ^ b.value);
        return make(a.width, a.atoms && b.atoms ? [...a.atoms, ...b.atoms] : null, mask, a.value & mask, proof([a, b]));
    }
    function slice(v, offset, width) {
        if (offset === 0 && width === v.width) return v;
        const atoms = v.atoms?.every(numeric) ? v.atoms.map(a => ({kind: 'constant',
            value: BigInt.asUintN(width, BigInt(a.value) >> BigInt(offset)).toString()})) : null;
        return make(width, atoms, v.mask >> BigInt(offset), v.value >> BigInt(offset), proof([v]));
    }
    function cast(v, width, signed = false) {
        if (width === v.width) return v;
        if (width < v.width) return slice(v, 0, width);
        const atoms = v.atoms?.every(numeric) ? v.atoms.map(a => ({kind: 'constant', value: BigInt.asUintN(width,
            signed ? BigInt.asIntN(v.width, BigInt(a.value)) : BigInt(a.value)).toString()})) : null;
        const high = full(width) ^ full(v.width), sign = 1n << BigInt(v.width - 1);
        const highKnown = !signed || !!(v.mask & sign), highValue = signed && !!(v.value & sign);
        return make(width, atoms, v.mask | (highKnown ? high : 0n), v.value | (highKnown && highValue ? high : 0n), proof([v]));
    }
    function insert(old, value, offset, width) {
        value = cast(value, width);
        if (width === old.width || old.width === 64 && width === 32 && offset === 0) return cast(value, old.width);
        const changed = full(width) << BigInt(offset);
        let atoms = null;
        if (old.atoms?.every(numeric) && value.atoms?.every(numeric)) atoms = old.atoms.flatMap(a => value.atoms.map(b => ({
            kind: 'constant', value: ((BigInt(a.value) & ~changed) | (BigInt(b.value) << BigInt(offset))).toString()})));
        return make(old.width, atoms, (old.mask & ~changed) | (value.mask << BigInt(offset)),
            (old.value & ~changed) | (value.value << BigInt(offset)), proof([old, value]));
    }
    const singleNumber = v => v.atoms?.length === 1 && numeric(v.atoms[0]) ? BigInt(v.atoms[0].value) : null;
    const singleStack = v => v.atoms?.length === 1 && v.atoms[0].kind === 'stack' ? BigInt(v.atoms[0].offset) : null;
    function atomResult(op, width, a, b) {
        if (numeric(a) && numeric(b)) {
            const value = BV.integerResult(op, width, BigInt(a.value), BigInt(b.value));
            return {kind: 'constant', value: value.toString()};
        }
        if (op === '+' && numeric(a) && b.kind === 'stack') return atomResult(op, width, b, a);
        if (a.kind === 'stack' && numeric(b) && (op === '+' || op === '-')) {
            const delta = BigInt.asIntN(width, BigInt(b.value));
            return stack(width, BigInt(a.offset) + (op === '+' ? delta : -delta), a.base).atoms?.[0] || null;
        }
        if (op === '-' && a.kind === 'stack' && b.kind === 'stack' && a.base === b.base)
            return constant(width, BigInt(a.offset) - BigInt(b.offset)).atoms[0];
        return null;
    }
    function binary(operator, a, b) {
        const width = a.width, op = ({add: '+', sub: '-', imul: '*'})[operator] || operator;
        if (!['shl', 'shr', 'sar'].includes(op) && width !== b.width) throw Error('binary width mismatch');
        const ev = proof([a, b]), bnum = singleNumber(b), anum = singleNumber(a);
        if (['+', '-', 'or', 'xor'].includes(op) && bnum === 0n) return withSources(a, b);
        if (op === '+' && anum === 0n) return withSources(b, a);
        if (op === '*' && (anum === 0n || bnum === 0n)) return withSources(constant(width, 0), a, b);
        if (op === '*' && bnum === 1n || op === 'and' && bnum === full(width)) return withSources(a, b);
        if (a.atoms && b.atoms) {
            const atoms = a.atoms.flatMap(x => b.atoms.map(y => atomResult(op, width, x, y)));
            if (atoms.every(Boolean)) return make(width, atoms, 0n, 0n, ev);
        }
        let mask = 0n, value = 0n;
        if (op === 'and') {
            const ones = a.mask & a.value & b.mask & b.value;
            mask = ones | (a.mask & ~a.value) | (b.mask & ~b.value); value = ones;
        } else if (op === 'or') {
            const ones = (a.mask & a.value) | (b.mask & b.value);
            mask = ones | (a.mask & ~a.value & b.mask & ~b.value); value = ones;
        } else if (op === 'xor') {mask = a.mask & b.mask; value = (a.value ^ b.value) & mask;}
        else if (['shl', 'shr', 'sar'].includes(op) && bnum !== null) {
            const count = Number(bnum & BigInt(width === 64 ? 63 : 31));
            if (!count) return withSources(a, b);
            const n = BigInt(Math.min(count, width)), high = full(width) ^ (full(width) >> n), sign = 1n << BigInt(width - 1);
            if (op === 'shl') {mask = (a.mask << n) | ((1n << n) - 1n); value = a.value << n;}
            else {
                mask = a.mask >> n; value = a.value >> n;
                if (op === 'shr' || a.mask & sign) {mask |= high; if (op === 'sar' && a.value & sign) value |= high;}
            }
        }
        return make(width, null, mask, value, ev);
    }
    function unary(op, a) {
        if (op === 'inc' || op === 'dec') return binary(op === 'inc' ? '+' : '-', a, constant(a.width, 1));
        if (op === 'neg') return binary('-', constant(a.width, 0), a);
        if (op === 'not') {
            const atoms = a.atoms?.every(numeric) ? a.atoms.map(x => ({kind: 'constant', value: BV.integerResult(op, a.width, BigInt(x.value)).toString()})) : null;
            return make(a.width, atoms, a.mask, ~a.value, proof([a]));
        }
        return unknown(a.width);
    }
    function serialize(v) {
        return {width: v.width, atoms: v.atoms, knownMask: '0x' + v.mask.toString(16), knownValue: '0x' + v.value.toString(16),
            sources: v.sources, proofTruncated: v.proofTruncated};
    }
    const equal = (a, b) => JSON.stringify(serialize(a)) === JSON.stringify(serialize(b));
    const api = {LIMITS, unknown, constant, stack, moduleAddress, importReference, join, slice, cast, insert, binary, unary,
        singleNumber, singleStack, derived, withSources, serialize, equal};
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WEAValueDomain = api;
})(globalThis);
