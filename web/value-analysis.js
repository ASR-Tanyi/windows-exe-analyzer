'use strict';
// Forward analysis of the same typed operations used by C-like recovery.
// Memory contents and branch predicates are deliberately not propagated.
(function (root) {
    const V = typeof module === 'object' && module.exports ? require('./value-domain.js') : root.WEAValueDomain;
    const LIMITS = Object.freeze({blocks: 128, instructions: 2048, edges: 384, visits: 4096, operations: 65536, accesses: 8192});
    const families = bits => (bits === 64 ? ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
        ...Array.from({length: 8}, (_, i) => 'r' + (i + 8))] : ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp']);
    const newState = bits => Object.fromEntries(families(bits).map(r => [r, V.unknown(bits)]));
    const copy = state => ({...state});
    function joinStates(a, b) {
        if (!a) return b && copy(b); if (!b) return copy(a);
        return Object.fromEntries(Object.keys(a).map(r => [r, V.join(a[r], b[r])]));
    }
    const sameState = (a, b) => !!a && !!b && Object.keys(a).every(r => V.equal(a[r], b[r]));
    function evaluate(e, state) {
        if (e.kind === 'constant') return V.constant(e.width, e.value);
        if (e.kind === 'register') return V.slice(state[e.name] || V.unknown(e.familyWidth), e.offset, e.width);
        if (e.kind === 'cast') return V.cast(evaluate(e.value, state), e.width, e.signed);
        if (e.kind === 'binary') return V.binary(e.operator, evaluate(e.left, state), evaluate(e.right, state));
        // Even a file-backed, stack, or IAT load is mutable at runtime.
        if (e.kind === 'load') return V.unknown(e.width);
        if (e.kind === 'condition') return V.join(V.constant(e.width, 0), V.constant(e.width, 1));
        return V.unknown(e.width);
    }
    function apply(op, state, bits, source) {
        const write = (target, value) => {
            if (target.kind === 'register') state[target.name] = V.derived(
                V.insert(state[target.name], value, target.offset, target.width), source);
        };
        if (op.kind === 'assign') write(op.target, evaluate(op.value, state));
        else if (op.kind === 'alu' && op.target) {
            const a = evaluate(op.left, state), b = op.right && evaluate(op.right, state);
            const sameRegister = op.left.kind === 'register' && op.right?.kind === 'register' &&
                op.left.name === op.right.name && op.left.offset === op.right.offset && op.left.width === op.right.width;
            let value;
            if (sameRegister && ['sub', 'xor'].includes(op.operator)) value = V.withSources(V.constant(op.width, 0), a, b);
            else value = b ? V.binary(op.operator, a, b) : V.unary(op.operator, a);
            write(op.target, value);
        } else if (op.kind === 'select') {
            // Both outcomes remain possible; writing a 32-bit destination still
            // zero-extends in x64 on the false path.
            write(op.target, V.join(evaluate(op.value, state), evaluate(op.target, state)));
        } else if (op.kind === 'push' || op.kind === 'pop') {
            const sp = bits === 64 ? 'rsp' : 'esp';
            state[sp] = V.derived(V.binary(op.kind === 'push' ? '-' : '+', state[sp], V.constant(bits, bits / 8)), source);
            if (op.kind === 'pop') write(op.value, V.unknown(op.value.width));
        } else if (op.kind === 'barrier') Object.assign(state, newState(bits));
        return state;
    }
    function finish(instruction, state, bits) {
        if (instruction.control?.kind !== 'return') return;
        const sp = bits === 64 ? 'rsp' : 'esp';
        const adjustment = V.binary('+', V.constant(bits, bits / 8), V.cast(evaluate(instruction.control.adjustment, state), bits));
        state[sp] = V.derived(V.binary('+', state[sp], adjustment), instruction.source);
    }
    const compactState = state => Object.fromEntries(Object.entries(state)
        .filter(([, v]) => v.atoms || v.mask).map(([r, v]) => [r, V.serialize(v)]));
    const addressKey = e => JSON.stringify(e);
    function analyze(report, blocks, edges, liftedByBlock, entry, options = {}) {
        const empty = (status, reason) => ({version: 1, status, reason, facts: [], accesses: [], slots: [], visits: 0, operations: 0});
        const bits = report.module.architecture.startsWith('x64') ? 64 : 32, sp = bits === 64 ? 'rsp' : 'esp';
        if (blocks.length > LIMITS.blocks || blocks.reduce((n, b) => n + b.instructions.length, 0) > LIMITS.instructions || edges.length > LIMITS.edges)
            return empty('unavailable', 'Value-analysis size budget exceeded.');
        if (report.module.truncated || blocks.some(b => new Set(b.owners).size !== 1))
            return empty('unavailable', 'Shared blocks or truncated discovery prevent stack/value assumptions.');
        const ids = new Set(blocks.map(b => b.id));
        if (!ids.has(entry)) return empty('unavailable', 'Entry ownership unavailable.');
        if (report.edges.some(e => ids.has(e.to) && e.to !== entry && !ids.has(e.from)))
            return empty('unavailable', 'An outside edge enters the function interior.');
        if (edges.some(e => e.kind !== 'call' && !e.to))
            return empty('unavailable', 'Unresolved control flow prevents propagation.');
        const successors = new Map(blocks.map(b => [b.id, new Set()])), predecessors = new Map(blocks.map(b => [b.id, new Set()]));
        for (const e of edges) if (e.kind !== 'call' && ids.has(e.to)) {
            successors.get(e.from).add(e.to); predecessors.get(e.to).add(e.from);
        }
        const seed = newState(bits); seed[sp] = V.stack(bits);
        const inputs = new Map(), outputs = new Map(), queue = [entry], queued = new Set(queue);
        const visitLimit = Math.min(LIMITS.visits, options.visits ?? LIMITS.visits);
        const operationLimit = Math.min(LIMITS.operations, options.operations ?? LIMITS.operations);
        let visits = 0, operations = 0;
        while (queue.length) {
            if (++visits > visitLimit) return empty('budget_exceeded', 'Value fixed-point budget exhausted; provisional facts discarded.');
            const id = queue.shift(); queued.delete(id);
            let input = id === entry ? copy(seed) : null;
            for (const pred of predecessors.get(id)) input = joinStates(input, outputs.get(pred));
            if (!input) continue;
            inputs.set(id, input); const state = copy(input);
            for (const instruction of liftedByBlock.get(id)) {
                for (const op of instruction.ops) {
                    if (++operations > operationLimit) return empty('budget_exceeded', 'Value transfer budget exhausted; provisional facts discarded.');
                    apply(op, state, bits, instruction.source);
                }
                finish(instruction, state, bits);
            }
            // Accumulating the prior output also makes finite-set widening
            // sticky. Precision cannot oscillate around a loop.
            const output = joinStates(outputs.get(id), state);
            if (!sameState(output, outputs.get(id))) {
                outputs.set(id, output);
                for (const to of successors.get(id)) if (!queued.has(to)) {queue.push(to); queued.add(to);}
            }
        }
        const facts = [], accesses = [], moduleBase = BigInt(report.module.imageBase);
        const mapped = va => (report.data?.regions || []).some(r => {
            const delta = va - moduleBase;
            return Number.isSafeInteger(r.rva) && Number.isSafeInteger(r.size) && delta >= BigInt(r.rva) && delta < BigInt(r.rva) + BigInt(r.size);
        });
        function record(source, expression, width, access, state, implicit = null, addressValue = null) {
            let value = addressValue || evaluate(expression.address, state);
            const number = V.singleNumber(value);
            if (number !== null && mapped(number)) value = V.withSources(V.moduleAddress(value.width, number, report.module.id, moduleBase), value);
            const stackOffset = V.singleStack(value), spOffset = V.singleStack(state[sp]);
            const evidence = V.derived(V.withSources(value, state[sp]), source);
            accesses.push({source, key: expression ? addressKey(expression) : null, width, access, implicit,
                address: V.serialize(value), stackOffset: stackOffset?.toString() ?? null,
                spOffset: spOffset?.toString() ?? null, allocated: stackOffset !== null && spOffset !== null &&
                    stackOffset < 0n && spOffset <= stackOffset && stackOffset + BigInt(width / 8) <= 0n,
                sources: evidence.sources, proofTruncated: evidence.proofTruncated});
        }
        function read(e, state, source) {
            if (!e) return;
            if (e.kind === 'load') {record(source, e, e.width, 'read', state); read(e.address, state, source);}
            else if (e.kind === 'cast') read(e.value, state, source);
            else if (e.kind === 'binary') {read(e.left, state, source); read(e.right, state, source);}
        }
        for (const b of blocks) {
            if (!inputs.has(b.id)) continue; // no entry-relative facts for disconnected blocks
            const state = copy(inputs.get(b.id));
            for (const i of liftedByBlock.get(b.id)) {
                const before = compactState(state);
                for (const op of i.ops) {
                    if (op.kind === 'assign') read(op.value, state, i.source);
                    if (op.kind === 'alu') {read(op.left, state, i.source); read(op.right, state, i.source);}
                    if (op.target?.kind === 'load') record(i.source, op.target, op.target.width, 'write', state);
                    if (op.kind === 'push' || op.kind === 'pop') {
                        const value = op.kind === 'push' ? V.binary('-', state[sp], V.constant(bits, bits / 8)) : state[sp];
                        record(i.source, null, bits, op.kind === 'push' ? 'write' : 'read', state, op.kind, value);
                    }
                    apply(op, state, bits, i.source);
                }
                if (i.control?.kind === 'return') record(i.source, null, bits, 'read', state, 'return', state[sp]);
                finish(i, state, bits);
                facts.push({source: i.source, before, after: compactState(state)});
                if (accesses.length > LIMITS.accesses) return empty('budget_exceeded', 'Stack-access budget exceeded; facts discarded.');
            }
        }
        const slots = new Map();
        for (const [index, access] of accesses.entries()) for (const atom of access.address.atoms || []) if (atom.kind === 'stack') {
            const offset = BigInt(atom.offset), key = offset + ':' + access.width;
            if (!slots.has(key)) slots.set(key, {offset: offset.toString(), width: access.width, accesses: [], reasons: []});
            slots.get(key).accesses.push(index);
        }
        const list = [...slots.values()].sort((a, b) => Number(BigInt(a.offset) - BigInt(b.offset)) || a.width - b.width);
        for (const slot of list) {
            const offset = BigInt(slot.offset), end = offset + BigInt(slot.width / 8), uses = slot.accesses.map(i => accesses[i]);
            slot.id = 'slot_' + (offset < 0n ? 'm' : 'p') + (offset < 0n ? -offset : offset).toString(16) + '_u' + slot.width;
            slot.kind = offset < BigInt(bits / 8) && end > 0n ? 'return_address_region' :
                uses.some(a => a.implicit === 'return') ? 'return_access' :
                uses.some(a => a.implicit === 'push' || a.implicit === 'pop') ? 'push_pop_storage' :
                offset >= BigInt(bits / 8) ? 'entry_stack' : uses.every(a => a.allocated) ? 'frame_slot' : 'unclassified_stack';
            if (list.some(other => other !== slot && BigInt(other.offset) < end && BigInt(other.offset) + BigInt(other.width / 8) > offset))
                slot.reasons.push('Overlapping access widths/ranges');
            if (uses.some(a => a.address.atoms.length !== 1)) slot.reasons.push('Multiple possible addresses');
            if (uses.some(a => a.proofTruncated)) slot.reasons.push('Address proof exceeded the provenance budget');
            if (slot.kind !== 'frame_slot') slot.reasons.push('Storage role is not an allocated frame-slot candidate');
            slot.aliasable = !slot.reasons.length;
            slot.sources = [...new Set(uses.flatMap(a => a.sources))].sort();
            slot.note = slot.kind === 'entry_stack' && bits === 64 && offset >= 8n && end <= 40n ?
                'Possible Windows x64 home space; actual role unproven' :
                slot.kind === 'push_pop_storage' ? 'May hold saved registers or outgoing arguments; role unproven' :
                slot.aliasable ? 'Typed memory alias, not an independent C local or inferred type' : 'Explicit memory access retained';
            if (slot.aliasable) for (const index of slot.accesses) accesses[index].alias = slot.id;
        }
        return {version: 1, status: 'converged', visits, operations, facts, accesses, slots: list,
            reachableBlocks: inputs.size, complete: false,
            notice: 'Entry-relative facts over discovered normal-flow edges; both branch outcomes retained. Memory loads and call effects are unknown. Slot names are memory aliases, not source locals.'};
    }
    const api = {LIMITS, newState, evaluate, apply, analyze, compactState, addressKey};
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WEAValueAnalysis = api;
})(globalThis);
