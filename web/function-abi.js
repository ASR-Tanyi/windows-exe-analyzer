'use strict';
// Read-only, explicitly selected function ABI evidence. Never a prototype or
// permission to change CALL effects, memory, machine exits or rendered code.
(function (root) {
    const PROFILE = Object.freeze({id: 'windows-x64-gpr-v1', arguments: Object.freeze(['rcx', 'rdx', 'r8', 'r9']), returnRegister: 'rax'});
    const LIMITS = Object.freeze({work: 131072, sources: 64, observations: 256, callers: 8, sites: 32, moduleItems: 131072, fileBytes: 65536});
    const notice = 'Analyst-selected Windows x64 function convention. Register/stack reads and RAX values are candidates, not a recovered C signature. Unused arguments, floating-point arguments and broader stack recovery, varargs, hidden parameters and original types remain unknown. Caller observations do not assert a normal return or enable call summaries. No machine effects are changed.';
    const emptyContract = (report, id) => ({version: 1, moduleId: report.module.id, functionId: id, profile: null});
    const hex = n => '0x' + n.toString(16), full = (1n << 64n) - 1n;
    class BudgetError extends Error {}
    function analyze(report, graph, lifted, entry, manifest, loadCaller, options = {}, valueAnalysis = null) {
        const contract = emptyContract(report, entry);
        const eligible = report.module.architecture.startsWith('x64') && graph.status === 'available';
        const base = {version: 2, complete: false, eligible, contract, notice, arguments: [], stackArguments: [], stackScope: 'Entry block only; no incoming control-flow backedge; aligned 1/2/4/8-byte reads before possible alias writes or barriers. Caller stores are tracked only within the call block.', returns: [], callers: [], conflicts: [], assumptionSources: []};
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
        // Deliberately block-local memory identity. No memory values are
        // forwarded into recovery and no normal-return assumption is enabled.
        const stack = v => v && !v.proofTruncated && v.atoms?.length === 1 && v.atoms[0].kind === 'stack' ? BigInt(v.atoms[0].offset) : null;
        const precise = a => a.stackOffset !== null && !a.proofTruncated && stack(a.address) !== null && a.spOffset !== null;
        const overlap = (a,b) => {spend(); return BigInt(a.stackOffset) < BigInt(b.stackOffset) + BigInt(b.width / 8) &&
            BigInt(b.stackOffset) < BigInt(a.stackOffset) + BigInt(a.width / 8);};
        function stackScan(g, l, va, callSource = null) {
            const result = {status:'available', reason:null, reads:[], stores:[]};
            const unavailable = reason => ({...result,status:'unavailable',reason});
            if (va?.status !== 'converged') return unavailable('Converged stack addresses are required.');
            const block = callSource ? g.blocks.find(b => (l.get(b.id) || []).some(i => i.source === callSource)) : g.blocks.find(b => b.id === g.entry);
            if (!block) return unavailable('Owned block is unavailable.');
            if (!callSource && g.blocks.some(b => b.successors.includes(g.entry)))
                return unavailable('An edge re-enters the entry block; incoming stack identity is not established.');
            const facts = new Map(va.facts.map(f => [f.source,f])), accesses = new Map();
            for (const a of va.accesses) {spend(); if (!accesses.has(a.source)) accesses.set(a.source,[]); accesses.get(a.source).push(a);}
            let stored = [], written = [], intact = true;
            for (const i of l.get(block.id)) {
                spend(); const f = facts.get(i.source), memory = accesses.get(i.source) || [];
                if (i.source === callSource) {
                    const sp = stack(f?.before.rsp);
                    if (sp === null) return unavailable('Call stack pointer is not precise.');
                    result.stores = stored.filter(a => BigInt(a.stackOffset) >= sp + 32n && BigInt(a.stackOffset) + BigInt(a.width/8) <= 0n)
                        .map(a => ({...a,entryOffset:(BigInt(a.stackOffset)-sp+8n).toString(),sources:union(a.sources,f.before.rsp.sources || [],[i.source])}));
                    return result;
                }
                if (!f || i.ops.some(o => o.kind === 'barrier' || o.kind === 'call_summary')) {
                    intact = false; stored = []; continue;
                }
                const beforeSP = stack(f.before.rsp), afterSP = stack(f.after.rsp);
                if (beforeSP === null || beforeSP > 0n) intact = false;
                if (!callSource && intact) for (const a of memory) {
                    spend(); if (a.access !== 'read' || a.implicit || !precise(a) || ![8,16,32,64].includes(a.width)) continue;
                    const offset = BigInt(a.stackOffset);
                    if (offset < 40n || offset % 8n || offset > BigInt(Number.MAX_SAFE_INTEGER) || written.some(w => overlap(w,a))) continue;
                    observe(); result.reads.push({position:Number(offset/8n),entryOffset:a.stackOffset,width:a.width,source:i.source,
                        certainty:'candidate',sources:union(a.sources,[i.source])});
                }
                for (const a of memory.filter(a => a.access === 'write' || a.access === 'unknown')) {
                    spend(); if (!precise(a)) {intact = false; stored = []; continue;}
                    written.push(a); stored = stored.filter(w => !overlap(w,a));
                    const op = i.ops.length === 1 && i.ops[0];
                    if (callSource && a.allocated && [8,16,32,64].includes(a.width) && op?.kind === 'assign' &&
                        op.target.kind === 'load' && a.key === JSON.stringify(op.target)) {
                        observe(); stored.push({source:i.source,stackOffset:a.stackOffset,width:a.width,sources:union(a.sources,[i.source])});
                    }
                }
                if (afterSP === null) {intact = false; stored = [];}
                else {
                    if (afterSP > 0n) intact = false;
                    stored = stored.filter(a => BigInt(a.stackOffset) >= afterSP);
                }
            }
            return result;
        }
        try {
            const c = context(graph,lifted);
            const stackInputs = stackScan(graph,lifted,valueAnalysis);

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
                const stackStores = stackScan(caller.graph,caller.lifted,caller.values,edge.source);
                const stackArguments = stackInputs.reads.map(read => {
                    spend(); const stores = stackStores.stores.filter(s => {spend(); return s.entryOffset === read.entryOffset && s.width >= read.width;});
                    return {...read,status:stores.length ? 'matched_store' : 'unknown',stores,
                        sources:union(read.sources,...stores.map(s => s.sources))};
                });
                callers.push({stackArguments,stackStatus:stackStores.status,stackReason:stackStores.reason,source:edge.source,rva:i.rva,functionId:id,status:'observed',arguments:inputs,returnUses,
                    sources:union([edge.source],...inputs.map(a => a.sources),...returnUses.map(u => u.sources))});
            }
            return {...base,status:'available',arguments:args,stackArguments:stackInputs.reads,stackStatus:stackInputs.status,stackReason:stackInputs.reason,returns,callers,conflicts,assumptionSources:[...(graph.assumptionSources || [])],work,observations};
        } catch (e) {
            return fail(e instanceof BudgetError ? 'budget_exceeded' : 'unavailable',e.message + ' Provisional ABI evidence discarded.');
        }
    }
    const api = {PROFILE,LIMITS,notice,emptyContract,analyze};
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WEAFunctionABI = api;
})(globalThis);
