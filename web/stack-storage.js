'use strict';
// Evidence about stack storage, not load forwarding or recovered C variables.
(function (root) {
    const CALL = typeof module === 'object' && module.exports ? require('./call-summaries.js') : root.WEACallSummaries;
    const LIMITS = Object.freeze({slots: 256, visits: 4096, work: 131072, sources: 64, pairs: 2048});
    const LABELS = Object.freeze({
        entry_return_address: 'Entry return-address region', return_access: 'Return target storage',
        call_return_address: 'Call return-address region', call_home_space: 'Callee home space',
        saved_register: 'Saved entry register', register_spill: 'Spill/reload candidate',
        outgoing_argument: 'Outgoing stack-argument candidate', candidate_local: 'Local / temporary candidate',
        push_pop: 'Unclassified PUSH/POP storage', entry_stack: 'Unclassified incoming stack storage',
        unknown: 'Unknown stack role'
    });
    const stack = value => value && !value.proofTruncated && value.atoms?.length === 1 && value.atoms[0].kind === 'stack' ?
        BigInt(value.atoms[0].offset) : null;
    const key = a => a.stackOffset + ':' + a.width;
    const end = a => BigInt(a.offset) + BigInt(a.width / 8);
    const overlaps = (a, b) => BigInt(a.offset) < end(b) && BigInt(b.offset) < end(a);
    class BudgetError extends Error {}
    function analyze(valueAnalysis, graph, lifted, options = {}) {
        const empty = (status, reason) => ({version: 1, status, reason, complete: false, slots: [], pairs: [], visits: 0, work: 0});
        if (valueAnalysis.status !== 'converged' || graph.status !== 'available')
            return empty('unavailable', 'Converged stack addresses and available register SSA are required.');
        const limits = Object.fromEntries(Object.entries(LIMITS).map(([k,v]) =>
            [k, Number.isSafeInteger(options[k]) ? Math.max(0, Math.min(v, options[k])) : v]));
        let work = 0, visits = 0;
        const spend = () => {if (++work > limits.work) throw new BudgetError('Stack storage work budget exceeded.');};
        const union = (...lists) => {
            const result = [...new Set(lists.flat())].sort();
            if (result.length > limits.sources) throw new BudgetError('Stack storage evidence budget exceeded.');
            return result;
        };
        try {
            if (valueAnalysis.slots.length > limits.slots) throw new BudgetError('Stack storage slot budget exceeded.');
            const bits = graph.bits, sp = bits === 64 ? 'rsp' : 'esp';
            const facts = new Map(valueAnalysis.facts.map(f => [f.source, f]));
            const defs = new Map(graph.definitions.map(d => [d.id, d])), uses = new Map(graph.uses.map(u => [u.id, u]));
            const records = new Map(graph.instructions.map(i => [i.source, i]));
            const accesses = new Map();
            for (const a of valueAnalysis.accesses) {
                spend(); if (!accesses.has(a.source)) accesses.set(a.source, []); accesses.get(a.source).push(a);
            }
            const slots = valueAnalysis.slots.map(s => ({id: s.id, offset: s.offset, width: s.width, roles: [],
                reasons: s.reasons.filter(r => !r.startsWith('Storage role')),
                sources: union(s.sources, s.accesses.map(n => valueAnalysis.accesses[n].source))}));
            const bySlot = new Map(slots.map(s => [s.offset + ':' + s.width, s])), pairs = [];
            function addRole(slot, kind, certainty, sources, extra = {}) {
                spend();
                let role = slot.roles.find(r => r.kind === kind && r.register === extra.register);
                if (!role) {role = {kind, label: LABELS[kind], certainty, sources: [], assumptionSources: [], ...extra}; slot.roles.push(role);}
                role.sources = union(role.sources, sources);
                role.assumptionSources = union(role.assumptionSources, sources.filter(s => valueAnalysis.assumptionSources.includes(s)));
            }
            const precise = a => a.stackOffset !== null && stack(a.address) !== null && !a.proofTruncated && a.spOffset !== null;
            const allocated = a => precise(a) && (a.allocated || a.implicit === 'push' &&
                BigInt(a.stackOffset) === BigInt(a.spOffset) - BigInt(bits / 8));
            // A state records definitely preceding stores. Joins retain only a
            // matching slice/definition present on every reachable predecessor.
            // It never supplies values to the recovery or value-analysis passes.
            const signature = x => [x.definition, x.register, x.registerOffset, x.other].join(':');
            const equal = (a,b) => !!a && !!b && a.size === b.size && [...a].every(([k,v]) => {
                const w = b.get(k); return w && signature(v) === signature(w) && v.sources.join('|') === w.sources.join('|') &&
                    v.evidence.join('|') === w.evidence.join('|');
            });
            function join(states) {
                const result = new Map(states[0]);
                for (const state of states.slice(1)) for (const [k,v] of result) {
                    spend(); const w = state.get(k);
                    if (!w || signature(v) !== signature(w)) result.delete(k);
                    else result.set(k, {...v, sources: union(v.sources, w.sources), evidence: union(v.evidence, w.evidence)});
                }
                return result;
            }
            const blocks = graph.blocks, ids = new Set(blocks.map(b => b.id));
            const predecessors = new Map(blocks.map(b => [b.id, []])), successors = new Map(blocks.map(b => [b.id, []]));
            for (const b of blocks) for (const to of b.successors) if (ids.has(to)) {
                successors.get(b.id).push(to); predecessors.get(to).push(b.id);
            }
            function transfer(id, input, collect) {
                const state = new Map(input);
                for (const i of lifted.get(id)) {
                    spend(); const f = facts.get(i.source), memory = accesses.get(i.source) || [], op = i.ops[0];
                    if (!f) {state.clear(); continue;}
                    const barrier = i.ops.length > 1 || i.ops.some(o => o.kind === 'barrier' || o.kind === 'call_summary');
                    if (collect && op?.kind === 'call_summary') {
                        const callSP = stack(f.before[sp]), profile = CALL.profile(op);
                        if (callSP !== null) for (const [k,stored] of state) {
                            spend(); const offset = BigInt(stored.offset);
                            // This is only an area candidate: no prototype gives
                            // the actual number or types of stack arguments.
                            if (offset >= callSP + BigInt(profile.homeBytes) && offset < 0n &&
                                (offset - callSP) % BigInt(bits / 8) === 0n && stored.width <= bits)
                                addRole(bySlot.get(k), 'outgoing_argument', 'candidate', union(stored.evidence, [i.source]));
                        }
                    }
                    if (barrier) {state.clear(); continue;}
                    const target = op?.kind === 'pop' ? op.value : op?.kind === 'assign' && op.value.kind === 'load' ? op.target : null;
                    if (collect && target?.kind === 'register' && target.name !== sp) {
                        const read = memory.find(a => a.access === 'read' && (op.kind === 'pop' ? a.implicit === 'pop' : a.key === JSON.stringify(op.value)));
                        const stored = read && precise(read) && state.get(key(read));
                        if (stored?.register === target.name && stored.registerOffset === target.offset && stored.width === target.width) {
                            if (pairs.length >= limits.pairs) throw new BudgetError('Stack storage pair budget exceeded.');
                            const d = defs.get(stored.definition), entryValue = d.kind === 'entry' && target.width === bits && target.offset === 0;
                            const sources = union(stored.evidence, read.sources, [i.source]);
                            pairs.push({slot: bySlot.get(key(read)).id, offset: stored.offset, width: stored.width,
                                register: target.name, registerOffset: target.offset, definition: stored.definition, entryValue,
                                saveSources: [...stored.sources], loadSource: i.source, sources});
                            addRole(bySlot.get(key(read)), entryValue ? 'saved_register' : 'register_spill', entryValue ? 'proven_pair' : 'candidate',
                                sources, {register: target.name});
                        }
                    }
                    for (const a of memory.filter(a => a.access === 'write' || a.access === 'unknown')) {
                        spend();
                        // Any write that might alias the stack invalidates all
                        // remembered stores. Known stack ranges kill overlaps.
                        if (!precise(a)) {state.clear(); continue;}
                        const range = {offset: a.stackOffset, width: a.width};
                        for (const [k,v] of state) {spend(); if (overlaps(range,v)) state.delete(k);}
                        if (!allocated(a) || !bySlot.has(key(a))) continue;
                        const value = op?.kind === 'push' ? op.value : op?.kind === 'assign' && op.target.kind === 'load' ? op.value : null;
                        const use = value?.kind === 'register' && records.get(i.source).reads.map(u => uses.get(u)).find(u =>
                            u.operation === 0 && u.role === (op.kind === 'push' ? 'pushed-value' : 'value') &&
                            u.register === value.name && u.offset === value.offset && u.width === a.width);
                        state.set(key(a), {...range, definition: use ? use.definition : null,
                            register: use ? use.register : null, registerOffset: use ? use.offset : null,
                            other: use ? null : i.source, sources: [i.source], evidence: union(a.sources, [i.source])});
                    }
                    // Deallocated/below-SP storage is volatile. Losing precise
                    // SP ends all remembered storage, even with a stable FP.
                    const afterSP = stack(f.after[sp]);
                    if (afterSP === null) state.clear();
                    else for (const [k,v] of state) {spend(); if (BigInt(v.offset) < afterSP) state.delete(k);}
                }
                return state;
            }
            const inputs = new Map(), outputs = new Map(), queue = [graph.entry], queued = new Set(queue);
            while (queue.length) {
                if (++visits > limits.visits) throw new BudgetError('Stack storage fixed-point budget exceeded.');
                const id = queue.shift(); queued.delete(id);
                const incoming = predecessors.get(id).filter(p => outputs.has(p)).map(p => outputs.get(p));
                if (id === graph.entry) incoming.unshift(new Map());
                if (!incoming.length) continue;
                const input = join(incoming), output = transfer(id, input, false); inputs.set(id, input);
                if (!equal(output, outputs.get(id))) {
                    outputs.set(id, output);
                    for (const to of successors.get(id)) if (!queued.has(to)) {queue.push(to); queued.add(to);}
                }
            }
            // Collect only from the completed fixed point, never provisional
            // paths. Empty/unknown incoming states cannot disappear at joins.
            for (const b of blocks) if (inputs.has(b.id)) transfer(b.id, inputs.get(b.id), true);
            for (const slot of slots) {
                if (BigInt(slot.offset) < BigInt(bits / 8) && end(slot) > 0n)
                    addRole(slot, 'entry_return_address', 'region', slot.sources);
            }
            for (const a of valueAnalysis.accesses) if (precise(a) && ['return','call_return_address','call_home_space'].includes(a.implicit)) {
                const range = {offset:a.stackOffset, width:a.width};
                for (const slot of slots) {spend(); if (overlaps(slot,range) && !(a.implicit === 'return' && BigInt(slot.offset) === 0n))
                    addRole(slot, a.implicit === 'return' ? 'return_access' : a.implicit,
                        a.implicit === 'return' ? 'observed' : 'assumed', a.sources);}
            }
            for (let n = 0; n < slots.length; n++) {
                const slot = slots[n], original = valueAnalysis.slots[n];
                if (!slot.roles.length) {
                    const role = original.kind === 'push_pop_storage' ? 'push_pop' : original.kind === 'entry_stack' ? 'entry_stack' :
                        original.aliasable ? 'candidate_local' : 'unknown';
                    addRole(slot, role, 'candidate', slot.sources);
                }
                slot.roles.sort((a,b) => a.kind.localeCompare(b.kind) || (a.register || '').localeCompare(b.register || ''));
                slot.mixed = slot.roles.length > 1 || slot.reasons.some(r => r.startsWith('Overlapping'));
                if (slot.roles.length > 1) slot.reasons.push('Multiple roles or candidates; storage may be reused.');
            }
            return {version:1, status:'available', complete:false, slots, pairs, visits, work,
                stats:{savedRegisters:pairs.filter(p => p.entryValue).length, spillReloads:pairs.filter(p => !p.entryValue).length,
                    mixedSlots:slots.filter(s => s.mixed).length},
                notice:'Roles describe physical storage, not original C locals, types or prototypes. Saved-entry-register pairs require a preceding full-width store on every discovered incoming path, with no intervening possible alias write or deallocation. Calls invalidate all stored contents. Spill/local/outgoing-argument roles remain candidates; ABI call areas require explicit call assumptions. Memory loads and original effects are unchanged.'};
        } catch (e) {
            if (!(e instanceof BudgetError)) throw e;
            return empty('budget_exceeded', e.message + ' Provisional roles discarded; physical accesses remain available.');
        }
    }
    const api = {LIMITS, LABELS, analyze};
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WEAStackStorage = api;
})(globalThis);
