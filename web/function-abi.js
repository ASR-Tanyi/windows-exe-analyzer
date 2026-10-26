'use strict';
// Read-only, explicitly selected function ABI evidence. Never a prototype or
// permission to change CALL effects, memory, machine exits or rendered code.
(function (root) {
    const PROFILE = Object.freeze({id: 'windows-x64-gpr-v1', arguments: Object.freeze(['rcx', 'rdx', 'r8', 'r9']), returnRegister: 'rax'});
    const LIMITS = Object.freeze({work: 131072, sources: 64, observations: 256, callers: 8, sites: 32, moduleItems: 131072, fileBytes: 65536});
    const notice = 'Analyst-selected Windows x64 function convention. Register reads and RAX values are candidates, not a recovered C signature. Unused arguments, floating-point/stack arguments, varargs, hidden parameters and original types remain unknown. Caller observations do not assert a normal return or enable call summaries. No machine effects are changed.';
    const emptyContract = (report, id) => ({version: 1, moduleId: report.module.id, functionId: id, profile: null});
    const hex = n => '0x' + n.toString(16), full = (1n << 64n) - 1n;
    class BudgetError extends Error {}
    function analyze(report, graph, lifted, entry, manifest, loadCaller, options = {}) {
        const contract = emptyContract(report, entry);
        const eligible = report.module.architecture.startsWith('x64') && graph.status === 'available';
        const base = {version: 1, complete: false, eligible, contract, notice, arguments: [], returns: [], callers: [], conflicts: [], assumptionSources: []};
        const fail = (status, reason) => ({...base, status, reason});
        const limits = Object.fromEntries(Object.entries(LIMITS).map(([k,v]) =>
            [k, Number.isSafeInteger(options[k]) ? Math.max(0, Math.min(v, options[k])) : v]));
        if (manifest !== undefined && manifest !== null) {
            if (typeof manifest !== 'object' || Array.isArray(manifest) || Object.keys(manifest).sort().join(',') !== 'functionId,moduleId,profile,version' ||
                manifest.version !== 1 || manifest.moduleId !== report.module.id || manifest.functionId !== entry ||
                ![null, PROFILE.id].includes(manifest.profile)) return fail('invalid', 'Function contract must match this module, function and version 1 schema; only the supported profile or null is accepted.');
            if (manifest.profile && !eligible) return fail('invalid', 'This profile requires x64 and available register SSA with unambiguous ownership.');
            contract.profile = manifest.profile;
        }
        if (!eligible) return fail('unavailable', 'Function ABI evidence requires x64 and available register SSA with unambiguous ownership.');
        if (!contract.profile) return fail('default', 'Choose a function convention to inspect register argument/return candidates. No convention is inferred from PE bitness or names.');
        let work = 0, observations = 0;
        const spend = () => {if (++work > limits.work) throw new BudgetError('Function ABI work budget exceeded.');};
        const observe = () => {if (++observations > limits.observations) throw new BudgetError('Function ABI observation budget exceeded.');};
        const union = (...lists) => {
            const sources = [...new Set(lists.flat().filter(Boolean))].sort();
            if (sources.length > limits.sources) throw new BudgetError('Function ABI source budget exceeded.');
            return sources;
        };
        function context(g, l) {
            return {graph: g, defs: new Map(g.definitions.map(d => [d.id,d])), uses: new Map(g.uses.map(u => [u.id,u])),
                instructions: new Map([...l.values()].flat().map(i => [i.source,i]))};
        }
        function realRead(c, u) {
            if (u.kind !== 'instruction' || ['preserve','possible-call-input','call-observation'].includes(u.role)) return false;
            const i = c.instructions.get(u.source), op = i?.ops[u.operation];
            if (!op || i.status === 'barrier' || op.kind === 'call_summary') return false;
            // A same-slice XOR/SUB does not consume the incoming value, even
            // though both operands occur in the mechanical SSA read list.
            return !(op.kind === 'alu' && ['xor','sub'].includes(op.operator) && op.left?.kind === 'register' &&
                op.right?.kind === 'register' && op.left.name === op.right.name && op.left.width === op.right.width && op.left.offset === op.right.offset);
        }
        // May-reach unchanged bits only. PHIs union possibilities; partial
        // writes propagate only preserved bits. Ordinary computations stop
        // this identity traversal; their first operand read is the witness.
        function readOrigins(c, seedIds) {
            const seeds = new Set(seedIds), masks = new Map(c.graph.definitions.map(d => [d.id, seeds.has(d.id) ? full : 0n]));
            const parents = d => d.kind === 'phi' ? d.inputs.map(id => c.uses.get(id)) :
                d.kind === 'write' ? d.inputs.map(id => c.uses.get(id)).filter(u => u.role === 'preserve') : [];
            let changed = true;
            while (changed) {changed = false;
                for (const d of c.graph.definitions) {spend(); if (seeds.has(d.id)) continue;
                    let next = 0n;
                    for (const u of parents(d)) {spend(); next |= masks.get(u.definition) & BigInt(u.mask);}
                    if (next !== masks.get(d.id)) {masks.set(d.id,next); changed = true;}
                }
            }
            function sources(id, mask) {
                const pending = [[id,mask]], visited = new Map(); let result = [];
                while (pending.length) {spend(); const [id,mask] = pending.pop(), d = c.defs.get(id);
                    const bits = mask & masks.get(id) & ~(visited.get(id) || 0n); if (!bits) continue;
                    visited.set(id,(visited.get(id) || 0n) | bits); result = union(result,[d.source]);
                    if (!seeds.has(id)) for (const u of parents(d)) {
                        if (!(bits & BigInt(u.mask) & masks.get(u.definition))) continue;
                        result = union(result,u.sources || []); pending.push([u.definition,bits & BigInt(u.mask)]);
                    }
                }
                return result;
            }
            const reads = [];
            for (const u of c.graph.uses) {spend();
                if (!realRead(c,u)) continue;
                const mask = masks.get(u.definition) & BigInt(u.mask); if (!mask) continue;
                observe(); reads.push({source:u.source, definition:u.definition, register:u.register, offset:u.offset, width:u.width,
                    mask:hex(mask), sources:union([u.source],sources(u.definition,mask))});
            }
            return reads;
        }
        function reaching(c, id) {
            const pending = [id], seen = new Set(), alternatives = []; let sources = [];
            while (pending.length) {spend(); const id = pending.pop(); if (seen.has(id)) continue; seen.add(id);
                const d = c.defs.get(id); if (!d) throw Error('Missing function ABI definition.');
                if (d.kind === 'phi') for (const input of d.inputs) {
                    const u = c.uses.get(input); sources = union(sources,u.sources || []); pending.push(u.definition);
                }
                else {observe(); sources = union(sources,[d.source]); alternatives.push({definition:d.id,kind:d.kind,source:d.source,
                    ...(d.slice ? {slice:d.slice,zeroExtend:d.zeroExtend,preserveMask:d.preserveMask} : {})});}
            }
            alternatives.sort((a,b) => a.definition.localeCompare(b.definition));
            const kinds = new Set(alternatives.map(d => d.kind === 'write' ? 'written' : d.kind === 'entry' ? 'incoming' : 'unknown'));
            return {definition:id, status:kinds.size === 1 ? [...kinds][0] : kinds.size ? 'mixed' : 'unknown', alternatives, sources};
        }
        try {
            const c = context(graph,lifted);
            const reads = readOrigins(c,graph.definitions.filter(d => d.kind === 'entry' && PROFILE.arguments.includes(d.register)).map(d => d.id));
            const args = PROFILE.arguments.flatMap((register,n) => {
                const uses = reads.filter(u => u.register === register); if (!uses.length) return [];
                return [{position:n+1,register,certainty:'candidate',mask:hex(uses.reduce((v,u) => v | BigInt(u.mask),0n)),uses,sources:union(...uses.map(u => u.sources))}];
            });
            const returns = [], conflicts = [];
            for (const b of graph.blocks) {
                const last = lifted.get(b.id)?.at(-1); if (last?.control?.kind !== 'return') continue;
                const u = b.exitUses.map(id => c.uses.get(id)).find(u => u.register === PROFILE.returnRegister); if (!u) continue;
                const value = reaching(c,u.definition);
                returns.push({source:last.source,register:PROFILE.returnRegister,...value,sources:union([last.source],value.sources)});
                if (BigInt(last.control.adjustment.value) !== 0n) conflicts.push({source:last.source,
                    reason:'RET removes argument bytes, conflicting with the selected Windows x64 caller-cleanup convention.'});
            }
            // Index only within a hard module scan budget. Do not recursively
            // recover callees or let a large caller set multiply the work.
            let items = report.blocks.length + report.edges.length + report.functions.length;
            for (const b of report.blocks) items += b.instructions.length;
            if (items > limits.moduleItems) throw new BudgetError('Function ABI module-scan budget exceeded.');
            const blockMap = new Map(report.blocks.map(b => [b.id,b])), functionIds = new Set(report.functions.map(f => f.id));
            const fn = report.functions.find(f => f.id === entry), cache = new Map(), callers = [], seen = new Set();
            for (const edge of report.edges) {spend();
                if (edge.kind !== 'call' || edge.to !== entry || seen.has(edge.source)) continue;
                seen.add(edge.source); if (seen.size > limits.sites) throw new BudgetError('Function ABI call-site budget exceeded.');
                const b = blockMap.get(edge.from), owners = [...new Set(b?.owners || [])];
                const unavailable = reason => callers.push({source:edge.source,functionId:owners.length === 1 ? owners[0] : null,status:'unavailable',reason,arguments:[],returnUses:[]});
                if (owners.length !== 1 || !functionIds.has(owners[0])) {unavailable('Caller ownership is ambiguous.'); continue;}
                const id = owners[0];
                if (!cache.has(id)) {
                    if (cache.size >= limits.callers) throw new BudgetError('Function ABI caller budget exceeded.');
                    cache.set(id,loadCaller(id));
                }
                const caller = cache.get(id);
                if (caller.graph.status !== 'available') {unavailable(caller.graph.reason); continue;}
                const cc = context(caller.graph,caller.lifted), i = cc.instructions.get(edge.source), site = caller.calls.sites.find(s => s.source === edge.source);
                if (!site?.eligible || !caller.graph.instructions.some(r => r.source === edge.source) || i?.call?.target.kind !== 'constant' ||
                    BigInt(i.call.target.value) !== BigInt(report.module.imageBase) + BigInt(fn.rva)) {
                    unavailable('A supported direct call and unique normal continuation are required for caller observations.'); continue;
                }
                const inputs = caller.graph.uses.filter(u => u.source === edge.source && u.role === 'call-observation').map(u => ({
                    position:PROFILE.arguments.indexOf(u.register)+1,register:u.register,...reaching(cc,u.definition)}));
                const seed = caller.graph.definitions.find(d => d.source === edge.source && d.register === 'rax' && d.kind === 'clobber');
                const returnUses = seed ? readOrigins(cc,[seed.id]) : [];
                callers.push({source:edge.source,rva:i.rva,functionId:id,status:'observed',arguments:inputs,returnUses,
                    sources:union([edge.source],...inputs.map(a => a.sources),...returnUses.map(u => u.sources))});
            }
            return {...base,status:'available',arguments:args,returns,callers,conflicts,assumptionSources:[...(graph.assumptionSources || [])],work,observations};
        } catch (e) {
            return fail(e instanceof BudgetError ? 'budget_exceeded' : 'unavailable',e.message + ' Provisional ABI evidence discarded.');
        }
    }
    const api = {PROFILE,LIMITS,notice,emptyContract,analyze};
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WEAFunctionABI = api;
})(globalThis);
