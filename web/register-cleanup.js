'use strict';
// Optional overlay; original operations and SSA remain intact for inspection.
(function (root) {
    const SSA = typeof module === 'object' && module.exports ? require('./register-ssa.js') : root.WEARegisterSSA;
    const LIMITS = Object.freeze({work: 131072, rewrites: 4096, depth: 32});
    const operators = new Set(['add', 'sub', 'and', 'or', 'xor', 'inc', 'dec', 'neg', 'not', 'imul', 'shl', 'shr', 'sar', 'cmp', 'test']);
    function analyze(ssa, liftedByBlock, expressions, options = {}) {
        const emptyVariant = () => ({rewrites: [], stats: {removed: 0, flagsOnly: 0}});
        const empty = reason => ({version: 1, status: 'unavailable', reason, complete: false,
            raw: emptyVariant(), simplified: emptyVariant()});
        if (ssa?.status !== 'available') return empty('Dead-write cleanup requires available register SSA.');
        try {
            let work = 0, total = 0;
            const spend = () => {if (++work > Math.min(options.work ?? LIMITS.work, LIMITS.work))
                throw Error('Dead-write work budget exceeded; all cleanup rewrites discarded.');};
            const families = SSA.families(ssa.bits), registers = new Set(families);
            const definitions = new Map();
            for (const d of ssa.definitions) if (d.kind === 'write') definitions.set(d.source + ':' + d.operation, d);
            const substitutions = new Map((expressions?.status === 'available' ? expressions.rewrites : [])
                .map(r => [r.source + ':' + r.operation, r]));
            function variant(simplified) {
                const result = emptyVariant();
                for (const block of ssa.blocks) {
                    // Preserve ALL GPRs at every block boundary. Do not infer
                    // dead exit registers from an ABI or propagate across joins.
                    let live = new Set(families);
                    const killers = new Map();
                    const instructions = liftedByBlock.get(block.id) || [];
                    for (let n = instructions.length - 1; n >= 0; n--) {
                        const insn = instructions[n];
                        const steps = [...insn.ops, ...(insn.control ? [insn.control] : [])];
                        for (let index = steps.length - 1; index >= 0; index--) {
                            spend();
                            const key = insn.source + ':' + index, substitution = simplified && substitutions.get(key);
                            const op = substitution ? substitution.replacement : steps[index], reads = new Set();
                            function pure(e, depth = 0) {
                                spend();
                                if (depth > LIMITS.depth) throw Error('Dead-write expression depth exceeded; all cleanup rewrites discarded.');
                                if (!e) return false;
                                if (e.kind === 'constant') return true;
                                if (e.kind === 'register') {
                                    if (!registers.has(e.name)) return false;
                                    reads.add(e.name); return true;
                                }
                                if (e.kind === 'cast') return pure(e.value, depth + 1);
                                if (e.kind === 'binary') return ['+', '*'].includes(e.operator) && pure(e.left, depth + 1) && pure(e.right, depth + 1);
                                if (e.kind === 'integer') return operators.has(e.operator) && pure(e.left, depth + 1) && (!e.right || pure(e.right, depth + 1));
                                return false;
                            }
                            const eligible = op.kind === 'assign' && op.target.kind === 'register' && pure(op.value) ||
                                op.kind === 'alu' && operators.has(op.operator) && (!op.target || op.target.kind === 'register') &&
                                pure(op.left) && (!op.right || pure(op.right));
                            if (!eligible) {
                                // Memory (including unused loads), calls, stack,
                                // flag-dependent operations and unknown effects
                                // observe a full boundary state, never just SSA uses.
                                if (op.kind !== 'nop') {live = new Set(families); killers.clear();}
                                continue;
                            }
                            if (op.target) {
                                const d = definitions.get(key);
                                if (!d || d.register !== op.target.name || d.slice.width !== op.target.width || d.slice.offset !== op.target.offset)
                                    throw Error('Missing or mismatched SSA write; all cleanup rewrites discarded.');
                                if (!live.has(d.register)) {
                                    const overwrittenBy = killers.get(d.register);
                                    if (!overwrittenBy) throw Error('Missing retained overwrite; all cleanup rewrites discarded.');
                                    const removed = op.kind === 'assign' || op.operator === 'not';
                                    if (++total > Math.min(options.rewrites ?? LIMITS.rewrites, LIMITS.rewrites))
                                        throw Error('Dead-write output budget exceeded; all cleanup rewrites discarded.');
                                    result.rewrites.push({source: insn.source, operation: index, definition: d.id, register: d.register,
                                        kind: removed ? 'removed' : 'flags_only', replacement: removed ? null : {...op, target: null},
                                        sources: [...new Set([insn.source, ...(substitution?.sources || []), overwrittenBy.source])], overwrittenBy});
                                    result.stats[removed ? 'removed' : 'flagsOnly']++;
                                    if (removed) continue; // Its operand reads are dead too.
                                } else {
                                    live.delete(d.register);
                                    if (d.preserveMask !== '0x0') reads.add(d.register);
                                    else killers.set(d.register, {source: insn.source, operation: index, definition: d.id});
                                }
                            }
                            // Use the chosen overlay's operands, not raw SSA use
                            // counts: expression substitution changes these reads.
                            for (const name of reads) live.add(name);
                        }
                    }
                }
                result.rewrites.reverse();
                return result;
            }
            const raw = variant(false), simplified = variant(true);
            return {version: 1, status: 'available', complete: false, raw, simplified, stats: {work},
                notice: 'Cleanup removes unused pure register writes before a retained overwrite in the same block. Arithmetic flag updates remain. Every block exit, memory access, call and unknown effect preserves its register inputs. Removed writes and overwrite evidence remain inspectable.'};
        } catch (e) {return empty(e.message);}
    }
    const api = {LIMITS, analyze};
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WEARegisterCleanup = api;
})(globalThis);
