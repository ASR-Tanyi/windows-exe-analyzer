'use strict';
// A bounded presentation/evaluation overlay on the original typed operations.
// SSA identities guard every register leaf; no instruction or effect is removed.
(function (root) {
    const BV = typeof module === 'object' && module.exports ? require('./bitvectors.js') : root.WEABitvectors;
    const LIMITS = Object.freeze({nodes: 64, depth: 12, sources: 64, outputNodes: 32768, work: 131072});
    const mask = n => (1n << BigInt(n)) - 1n;
    const constant = (v, width) => ({kind: 'constant', value: BigInt.asUintN(width, v).toString(), width});
    const cast = (value, width, signed = false) => ({kind: 'cast', value, width, signed});
    const integer = (operator, left, right, width) => ({kind: 'integer', operator, left, right, width});
    const pure = e => e && (['constant', 'register'].includes(e.kind) ||
        e.kind === 'cast' && pure(e.value) || e.kind === 'binary' && pure(e.left) && pure(e.right));
    const clean = e => {
        if (!e || typeof e !== 'object') return e;
        return Object.fromEntries(Object.entries(e).filter(([k]) => k !== '_definition').map(([k, v]) => [k, clean(v)]));
    };
    function analyze(ssa, liftedByBlock, options = {}) {
        const empty = (status, reason) => ({version: 1, status, reason, complete: false, rewrites: [], stats: {changedOperations: 0}});
        if (ssa?.status !== 'available') return empty('unavailable', 'Register expressions require available register SSA.');
        try {
            let work = 0, outputNodes = 0, propagatedReads = 0, cappedExpressions = 0;
            const spend = () => {if (++work > Math.min(options.work ?? LIMITS.work, LIMITS.work)) throw Error('Register-expression work budget exceeded; all rewrites discarded.');};
            const uses = new Map(ssa.uses.map(u => [u.id, u])), defs = new Map(ssa.definitions.map(d => [d.id, d]));
            const records = new Map(ssa.instructions.map(i => [i.source, i])), rewrites = [];
            function size(e, depth = 1) {
                spend();
                if (depth > LIMITS.depth) return LIMITS.nodes + 1;
                return 1 + (e.value && typeof e.value === 'object' ? size(e.value, depth + 1) : 0) +
                    (e.left ? size(e.left, depth + 1) : 0) + (e.right ? size(e.right, depth + 1) : 0);
            }
            function fold(e) {
                spend();
                if (e.kind === 'cast') {
                    if (e.value.kind === 'constant') return constant(e.signed ? BigInt.asIntN(e.value.width, BigInt(e.value.value)) : BigInt(e.value.value), e.width);
                    if (e.width === e.value.width) return e.value;
                    if (!e.signed && e.value.kind === 'cast' && !e.value.signed && e.width <= e.value.width)
                        return fold(cast(e.value.value, e.width));
                }
                if (!['binary', 'integer'].includes(e.kind)) return e;
                const a = e.left, b = e.right, op = e.operator, n = e.width;
                if (a.kind === 'constant' && (!b || b.kind === 'constant'))
                    return constant(BV.integerResult(op, n, a.value, b?.value ?? '0'), n);
                // These are data-result identities. The originating ALU operation
                // is retained separately, including its original flag behavior.
                if (b?.kind === 'constant') {
                    const v = BigInt(b.value);
                    if (v === 0n && ['+', 'add', 'sub', 'or', 'xor'].includes(op) ||
                        v === 1n && ['*', 'imul'].includes(op) || v === mask(n) && op === 'and' ||
                        ['shl', 'shr', 'sar'].includes(op) && !(v & BigInt(n === 64 ? 63 : 31))) return fold(cast(a, n));
                    if (v === 0n && ['*', 'imul', 'and'].includes(op)) return constant(0n, n);
                }
                if (b && ['xor', 'sub'].includes(op) && JSON.stringify(a) === JSON.stringify(b)) return constant(0n, n);
                if (a.kind === 'constant' && BigInt(a.value) === 0n && ['+', 'add', 'or', 'xor'].includes(op)) return fold(cast(b, n));
                return e;
            }
            for (const block of ssa.blocks) {
                // No entry facts, PHI substitution or predecessor expressions.
                const expressions = new Map(), current = new Map();
                for (const insn of liftedByBlock.get(block.id) || []) {
                    const record = records.get(insn.source);
                    if (!record) throw Error('Missing register-flow instruction.');
                    const steps = [...insn.ops, ...(insn.control ? [insn.control] : [])];
                    for (let index = 0; index < steps.length; index++) {
                        spend();
                        const op = steps[index], reads = record.reads.map(id => uses.get(id)).filter(u => u.operation === index);
                        const writes = record.writes.map(id => defs.get(id)).filter(d => d.operation === index);
                        for (const u of reads) current.set(u.register, u.definition);
                        const eligible = op.kind === 'assign' && op.target.kind === 'register' && pure(op.value) ||
                            op.kind === 'alu' && (!op.target || op.target.kind === 'register') && pure(op.left) && (!op.right || pure(op.right));
                        if (!eligible) {
                            if (op.kind !== 'nop') expressions.clear();
                            for (const d of writes) current.set(d.register, d.id);
                            continue;
                        }
                        const sources = new Set([insn.source]), definitionIds = new Set(); let expanded = 0;
                        function valid(e) {
                            spend();
                            if (e.kind === 'register') return current.get(e.name) === e._definition;
                            return (!e.value || typeof e.value !== 'object' || valid(e.value)) && (!e.left || valid(e.left)) && (!e.right || valid(e.right));
                        }
                        function substitute(e, role) {
                            spend();
                            if (e.kind === 'register') {
                                const u = reads.find(u => u.role === role && u.register === e.name && u.offset === e.offset && u.width === e.width);
                                if (!u) throw Error('Missing SSA operand binding.');
                                const candidate = expressions.get(u.definition);
                                if (candidate && valid(candidate.expression)) {
                                    let value = candidate.expression;
                                    if (e.offset) value = fold(integer('shr', value, constant(BigInt(e.offset), ssa.bits), ssa.bits));
                                    value = fold(cast(value, e.width));
                                    if (size(value) <= LIMITS.nodes && new Set([...sources, ...candidate.sources]).size <= LIMITS.sources) {
                                        candidate.sources.forEach(s => sources.add(s)); candidate.definitions.forEach(d => definitionIds.add(d));
                                        definitionIds.add(u.definition); expanded++; return value;
                                    }
                                    cappedExpressions++;
                                }
                                return {...e, _definition: u.definition};
                            }
                            if (e.kind === 'cast') return fold({...e, value: substitute(e.value, role)});
                            if (e.kind === 'binary') return fold({...e, left: substitute(e.left, role + '/left'), right: substitute(e.right, role + '/right')});
                            return e;
                        }
                        let result = null, revised;
                        if (op.kind === 'assign') {
                            result = substitute(op.value, 'value'); revised = {...op, value: result};
                        } else {
                            const left = substitute(op.left, 'left'), right = op.right ? substitute(op.right, 'right') : null;
                            revised = {...op, left, right};
                            if (op.target) result = fold(integer(op.operator, left, right, op.width));
                        }
                        const operandNodes = op.kind === 'assign' ? size(revised.value) : size(revised.left) + (revised.right ? size(revised.right) : 0);
                        if (operandNodes > LIMITS.nodes || sources.size > LIMITS.sources) {
                            cappedExpressions++; result = null; revised = op;
                        } else {
                            const exported = clean(revised);
                            if (JSON.stringify(exported) !== JSON.stringify(op)) {
                                outputNodes += operandNodes;
                                if (outputNodes > Math.min(options.outputNodes ?? LIMITS.outputNodes, LIMITS.outputNodes))
                                    throw Error('Register-expression output budget exceeded; all rewrites discarded.');
                                rewrites.push({source: insn.source, operation: index, replacement: exported,
                                    sources: [...sources], definitions: [...definitionIds].sort()});
                                propagatedReads += expanded;
                            }
                        }
                        for (const d of writes) {
                            current.set(d.register, d.id);
                            // Partial 8/16-bit writes remain insert operations;
                            // do not invent a value for their untouched bits.
                            if (result && d.kind === 'write' && d.preserveMask === '0x0') {
                                const expression = fold(cast(result, ssa.bits));
                                if (size(expression) <= LIMITS.nodes) expressions.set(d.id,
                                    {expression, sources: [...sources], definitions: [...definitionIds]});
                                else cappedExpressions++;
                            }
                        }
                    }
                }
            }
            return {version: 1, status: 'available', complete: false, rewrites,
                stats: {changedOperations: rewrites.length, propagatedReads, cappedExpressions, outputNodes, work},
                notice: 'Pure register expressions are simplified within each basic block using SSA versions. Calls, memory and flag-dependent operations stop propagation. Every instruction, flag update and machine-state write remains; source links include contributing definitions.'};
        } catch (e) {return empty('unavailable', e.message);}
    }
    const api = {LIMITS, analyze};
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WEARegisterExpressions = api;
})(globalThis);
