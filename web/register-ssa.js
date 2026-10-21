'use strict';
// Register SSA over the preview's typed operations, before graph reduction.
// No expression substitution, flag SSA or memory SSA. Call assumptions are explicit.
(function (root) {
    const CALL = typeof module === 'object' && module.exports ? require('./call-summaries.js') : root.WEACallSummaries;
    const LIMITS = Object.freeze({blocks: 128, instructions: 2048, edges: 384, definitions: 8192, uses: 32768, work: 131072});
    const families = bits => bits === 64 ? ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
        ...Array.from({length: 8}, (_, i) => 'r' + (i + 8))] : ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'];
    const cmp = (a, b) => a < b ? -1 : a > b ? 1 : 0;
    const full = bits => (1n << BigInt(bits)) - 1n;
    // Read/write ordering and partial-register preservation come from typed
    // effects, not decoder access lists or formatted assembly text.
    function effects(instruction, bits) {
        const regs = new Set(families(bits)), sp = bits === 64 ? 'rsp' : 'esp';
        const native = name => ({kind: 'register', name, offset: 0, width: bits, familyWidth: bits});
        return [...instruction.ops, ...(instruction.control ? [instruction.control] : [])].map((op, index) => {
            const step = {index, kind: op.kind, reads: [], writes: [], memory: {read: false, write: false, unknown: false},
                flags: {read: false, write: false, unknown: false}};
            function read(e, role, depth = 0) {
                if (!e) return [];
                if (depth > 32) throw Error('Expression depth exceeds register-flow budget.');
                if (e.kind === 'register') {
                    if (!regs.has(e.name) || e.familyWidth !== bits || ![8, 16, 32, 64].includes(e.width) ||
                        e.offset < 0 || e.offset + e.width > bits) throw Error('Unsupported register slice.');
                    const id = step.reads.length;
                    step.reads.push({register: e.name, offset: e.offset, width: e.width, role,
                        mask: '0x' + (full(e.width) << BigInt(e.offset)).toString(16)});
                    return [id];
                }
                if (e.kind === 'constant') return [];
                if (e.kind === 'condition') {step.flags.read = true; return [];}
                if (e.kind === 'load') {step.memory.read = true; return read(e.address, role + '/address', depth + 1);}
                if (e.kind === 'cast') return read(e.value, role, depth + 1);
                if (e.kind === 'binary') return [...read(e.left, role + '/left', depth + 1), ...read(e.right, role + '/right', depth + 1)];
                throw Error('Unsupported typed expression.');
            }
            function write(target, inputs, memoryRead = false, kind = 'write') {
                if (target.kind === 'load') {step.memory.write = true; read(target.address, 'store/address'); return;}
                if (target.kind !== 'register' || !regs.has(target.name)) throw Error('Unsupported typed destination.');
                const zeroExtend = bits === 64 && target.width === 32 && !target.offset;
                const preserve = zeroExtend ? 0n : full(bits) ^ (full(target.width) << BigInt(target.offset));
                if (preserve) {
                    const added = read(native(target.name), 'preserve');
                    step.reads[added[0]].mask = '0x' + preserve.toString(16); inputs = [...inputs, ...added];
                }
                step.writes.push({register: target.name, width: bits, slice: {offset: target.offset, width: target.width},
                    zeroExtend, preserveMask: '0x' + preserve.toString(16), inputs, memoryRead, kind});
            }
            if (op.kind === 'assign') {
                const inputs = read(op.value, 'value'); write(op.target, inputs, step.memory.read);
            } else if (op.kind === 'alu') {
                const inputs = [...read(op.left, 'left'), ...read(op.right, 'right')];
                // Flags stay in the original typed operations, including
                // preserved/undefined bits. This marker is not flag SSA.
                step.flags.write = op.operator !== 'not';
                if (op.target) write(op.target, inputs, step.memory.read);
            } else if (op.kind === 'select') {
                step.flags.read = true;
                write(op.target, [...read(op.value, 'if-true'), ...read(op.target, 'if-false')]);
            } else if (op.kind === 'push' || op.kind === 'pop') {
                if (op.width !== bits || op.value.kind === 'load' || op.kind === 'pop' && op.value.name === sp)
                    throw Error('Unsupported typed stack form.');
                const stack = read(native(sp), 'stack');
                if (op.kind === 'push') {read(op.value, 'pushed-value'); step.memory.write = true;}
                else step.memory.read = true;
                write(native(sp), stack);
                if (op.kind === 'pop') write(op.value, stack, true);
            } else if (op.kind === 'return') {
                step.memory.read = true;
                write(native(sp), [...read(native(sp), 'return-stack'), ...read(op.adjustment, 'adjustment')]);
            } else if (op.kind === 'branch') step.flags.read = true;
            else if (op.kind === 'call_summary') {
                const profile = CALL.profile(op);
                if (bits !== 64) throw Error('Call summary requires x64.');
                read(op.target, 'call-target');
                // No prototype: conservatively retain potential uses of all
                // GPR inputs, without assigning argument positions or types.
                for (const r of regs) read(native(r), 'possible-call-input');
                step.memory.unknown = step.flags.unknown = true;
                step.memory.write = step.memory.read = true;
                for (const r of profile.clobbered) write(native(r), [], false, 'clobber');
            }
            else if (op.kind === 'barrier') {
                step.memory.unknown = step.flags.unknown = true;
                for (const r of regs) write(native(r), [], false, 'clobber');
            } else if (!['nop', 'jump'].includes(op.kind)) throw Error('Unsupported typed operation.');
            return step;
        });
    }
    class BudgetError extends Error {}
    function analyze(report, blocks, edges, liftedByBlock, entry, options = {}) {
        const empty = (status, reason) => ({version: 1, status, reason, complete: false, definitions: [], uses: [], instructions: [], blocks: []});
        const bits = report.module.architecture.startsWith('x64') ? 64 : 32, regs = families(bits);
        if (blocks.length > LIMITS.blocks || blocks.reduce((n, b) => n + b.instructions.length, 0) > LIMITS.instructions || edges.length > LIMITS.edges)
            return empty('unavailable', 'Register-flow size budget exceeded.');
        if (report.module.truncated || blocks.some(b => new Set(b.owners).size !== 1))
            return empty('unavailable', 'Shared blocks or truncated discovery prevent register SSA.');
        const owned = new Set(blocks.map(b => b.id));
        if (!owned.has(entry) || owned.size !== blocks.length) return empty('unavailable', 'Invalid entry or duplicate blocks.');
        if (report.edges.some(e => owned.has(e.to) && e.to !== entry && !owned.has(e.from)) || edges.some(e => e.kind !== 'call' && !e.to))
            return empty('unavailable', 'Unresolved control flow or an outside edge into the function interior.');
        try {
            let work = 0;
            const spend = () => {if (++work > Math.min(options.work ?? LIMITS.work, LIMITS.work)) throw new BudgetError('Register-flow work budget exceeded; provisional graph discarded.');};
            const definitionLimit = Math.min(options.definitions ?? LIMITS.definitions, LIMITS.definitions);
            const useLimit = Math.min(options.uses ?? LIMITS.uses, LIMITS.uses);
            const ordered = [...blocks].sort((a, b) => a.rva - b.rva || cmp(a.id, b.id));
            const succ = new Map(ordered.map(b => [b.id, new Set()]));
            for (const e of edges) if (e.kind !== 'call' && owned.has(e.to)) succ.get(e.from).add(e.to);
            const reachable = new Set(), queue = [entry];
            while (queue.length) {spend(); const id = queue.pop(); if (reachable.has(id)) continue;
                reachable.add(id); queue.push(...succ.get(id));}
            const real = ordered.filter(b => reachable.has(b.id)), ids = [null, ...real.map(b => b.id)];
            // A virtual incoming block gives entry-loop PHIs an explicit
            // initial value, separate from their backedge operands.
            const pred = new Map(ids.map(id => [id, new Set()])); pred.get(entry).add(null);
            succ.set(null, new Set([entry]));
            for (const b of real) for (const to of succ.get(b.id)) pred.get(to).add(b.id);
            const info = new Map(), seen = new Set();
            for (const b of real) {
                const instructions = liftedByBlock.get(b.id);
                if (!instructions || instructions.length !== b.instructions.length) throw Error('Missing typed instructions.');
                const steps = instructions.map(i => {
                    if (seen.has(i.source)) throw Error('Duplicate instruction identity.'); seen.add(i.source);
                    return {instruction: i, steps: effects(i, bits)};
                });
                const uses = new Set(), defs = new Set();
                for (const i of steps) for (const s of i.steps) {spend();
                    for (const u of s.reads) if (!defs.has(u.register)) uses.add(u.register);
                    for (const d of s.writes) defs.add(d.register);
                }
                const exit = !succ.get(b.id).size || edges.some(e => e.from === b.id && e.kind !== 'call' && !owned.has(e.to));
                info.set(b.id, {block: b, steps, uses, defs, exit, exitUses: [], liveIn: new Set(), liveOut: new Set(), phis: new Map()});
            }
            // Backwards family liveness prunes dead joins, not instructions.
            let changed = true;
            while (changed) {changed = false;
                for (const b of [...real].reverse()) {spend(); const x = info.get(b.id), out = new Set(x.exit ? regs : []);
                    for (const to of succ.get(b.id)) for (const r of info.get(to).liveIn) out.add(r);
                    const input = new Set([...x.uses, ...[...out].filter(r => !x.defs.has(r))]);
                    if (input.size !== x.liveIn.size || [...input].some(r => !x.liveIn.has(r))) changed = true;
                    x.liveIn = input; x.liveOut = out;
                }
            }
            // Bounded set-intersection dominators and iterated dominance
            // frontiers. The virtual entry is node 0 in these bit sets.
            const positions = new Map(ids.map((id, n) => [id, n])), bit = id => 1n << BigInt(positions.get(id));
            const dom = new Map(ids.map(id => [id, id === null ? 1n : (1n << BigInt(ids.length)) - 1n]));
            changed = true;
            while (changed) {changed = false;
                for (const b of real) {spend(); let value = (1n << BigInt(ids.length)) - 1n;
                    for (const p of pred.get(b.id)) {spend(); value &= dom.get(p);}
                    value |= bit(b.id);
                    if (value !== dom.get(b.id)) {dom.set(b.id, value); changed = true;}
                }
            }
            const depth = n => n.toString(2).replaceAll('0', '').length;
            const idom = new Map([[null, null]]), children = new Map(ids.map(id => [id, []])), frontier = new Map(ids.map(id => [id, new Set()]));
            for (const b of real) {
                const strict = ids.filter(id => id !== b.id && !!(dom.get(b.id) & bit(id)));
                strict.sort((a, b) => depth(dom.get(b)) - depth(dom.get(a)));
                const parent = strict[0]; idom.set(b.id, parent); children.get(parent).push(b.id);
            }
            for (const b of real) if (pred.get(b.id).size >= 2) for (const p of pred.get(b.id)) {
                let runner = p;
                while (runner !== idom.get(b.id)) {spend(); frontier.get(runner).add(b.id); runner = idom.get(runner);}
            }
            for (const r of regs) {
                const sites = new Set([null, ...real.filter(b => info.get(b.id).defs.has(r)).map(b => b.id)]), pending = [...sites];
                for (let n = 0; n < pending.length; n++) for (const to of frontier.get(pending[n])) {spend(); const x = info.get(to);
                    if (!x.liveIn.has(r) || x.phis.has(r)) continue;
                    x.phis.set(r, to + '_ssa_phi_' + r);
                    if (!sites.has(to)) {sites.add(to); pending.push(to);}
                }
            }
            const definitions = new Map(), uses = new Map(), records = new Map();
            const addDef = d => {
                if (definitions.size >= definitionLimit) throw new BudgetError('Register-definition budget exceeded; provisional graph discarded.');
                if (definitions.has(d.id)) throw Error('Duplicate register-definition identity.');
                definitions.set(d.id, {...d, inputs: [], uses: []}); return definitions.get(d.id);
            };
            const addUse = u => {
                if (uses.size >= useLimit) throw new BudgetError('Register-use budget exceeded; provisional graph discarded.');
                if (uses.has(u.id)) throw Error('Duplicate register-use identity.');
                if (!definitions.has(u.definition)) throw Error('Missing reaching definition.');
                uses.set(u.id, u); definitions.get(u.definition).uses.push(u.id); return u.id;
            };
            const stacks = Object.fromEntries(regs.map(r => [r, [addDef({id: entry + '_ssa_in_' + r, kind: 'entry', register: r,
                width: bits, block: null, source: null, label: r + '_in'}).id]]));
            for (const b of real) for (const [r, id] of info.get(b.id).phis) addDef({id, kind: 'phi', register: r,
                width: bits, block: b.id, source: null, label: r + '_phi_' + b.rva.toString(16), incoming: []});
            const current = r => stacks[r][stacks[r].length - 1];
            function rename(id) {
                spend(); const pushed = [];
                if (id !== null) {
                    const x = info.get(id);
                    for (const [r, phi] of x.phis) {stacks[r].push(phi); pushed.push(r);}
                    for (const {instruction: i, steps} of x.steps) {
                        const record = {source: i.source, block: id, reads: [], writes: [],
                            memory: {read: false, write: false, unknown: false}, flags: {read: false, write: false, unknown: false}};
                        records.set(i.source, record);
                        for (const step of steps) {spend();
                            const readIds = step.reads.map((u, n) => addUse({...u, id: i.source + '_ssa_u_' + step.index + '_' + n,
                                kind: 'instruction', source: i.source, block: id, operation: step.index, definition: current(u.register)}));
                            record.reads.push(...readIds);
                            // Bind every old operand before installing any result.
                            for (const w of step.writes) {
                                const d = addDef({...w, id: i.source + '_ssa_d_' + step.index + '_' + w.register,
                                    block: id, source: i.source, operation: step.index,
                                    label: w.register + '_' + i.rva.toString(16) + (step.index ? '_' + step.index : '')});
                                d.inputs = w.inputs.map(n => readIds[n]);
                                stacks[w.register].push(d.id); pushed.push(w.register); record.writes.push(d.id);
                            }
                            for (const group of ['memory', 'flags']) for (const k of Object.keys(step[group])) record[group][k] ||= step[group][k];
                        }
                    }
                    // All GPRs cross the machine boundary. These output uses
                    // do not infer an ABI return register or source prototype.
                    if (x.exit) for (const r of regs) x.exitUses.push(addUse({id: id + '_ssa_out_' + r, kind: 'exit',
                        register: r, width: bits, offset: 0, mask: '0x' + full(bits).toString(16), role: 'exit-state',
                        source: x.steps[x.steps.length - 1]?.instruction.source || null, block: id, definition: current(r)}));
                }
                for (const to of succ.get(id)) for (const [r, phi] of info.get(to).phis) {
                    const sourceIds = id === null ? [] : [...new Set(edges.filter(e => e.from === id && e.to === to && e.kind !== 'call').map(e => e.source))].sort(cmp);
                    const use = addUse({id: phi + '_from_' + (id === null ? 'entry' : id), kind: 'phi', register: r, offset: 0,
                        width: bits, mask: '0x' + full(bits).toString(16), role: 'incoming', source: null, block: to,
                        predecessor: id, sources: sourceIds, consumer: phi, definition: current(r)});
                    definitions.get(phi).inputs.push(use); definitions.get(phi).incoming.push(use);
                }
                for (const child of children.get(id)) rename(child);
                for (const r of pushed.reverse()) stacks[r].pop();
            }
            rename(null);
            const list = [...definitions.values()].sort((a, b) => cmp(a.id, b.id));
            for (const d of list) {d.uses.sort(cmp); if (d.kind === 'phi') {d.inputs.sort(cmp); d.incoming.sort(cmp);
                if (d.incoming.length !== pred.get(d.block).size) throw Error('Incomplete join operands.');}}
            return {version: 1, status: 'available', complete: false, bits, entry, definitions: list,
                uses: [...uses.values()].sort((a, b) => cmp(a.id, b.id)),
                instructions: real.flatMap(b => info.get(b.id).steps.map(x => records.get(x.instruction.source))),
                blocks: real.map(b => ({id: b.id, rva: b.rva, sources: b.instructions.map(i => i.id),
                    predecessors: [...pred.get(b.id)].sort(cmp), successors: [...succ.get(b.id)].sort(cmp),
                    idom: idom.get(b.id), phis: [...info.get(b.id).phis.values()].sort(cmp), exitUses: info.get(b.id).exitUses,
                    liveIn: [...info.get(b.id).liveIn].sort(cmp), liveOut: [...info.get(b.id).liveOut].sort(cmp)})),
                stats: {definitions: list.length, joins: list.filter(d => d.kind === 'phi').length, uses: uses.size,
                    reachableBlocks: real.length, disconnectedBlocks: blocks.length - real.length, work},
                assumptionSources: real.flatMap(b => info.get(b.id).steps.filter(x => x.instruction.status === 'assumed').map(x => x.instruction.source)),
                notice: 'Register versions describe machine state, not C variables. Joins select one definition per incoming edge. Memory/flags remain explicit effects outside this SSA graph. Explicit call assumptions preserve nonvolatile GPR versions; other calls clobber every register. No expressions or effects are removed.'};
        } catch (e) {return empty(e instanceof BudgetError ? 'budget_exceeded' : 'unavailable', e.message);}
    }
    const api = {LIMITS, families, effects, analyze};
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WEARegisterSSA = api;
})(globalThis);
