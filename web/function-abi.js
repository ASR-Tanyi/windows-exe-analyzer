'use strict';
// Read-only function ABI evidence and supplied declarations. No inferred prototype or
// permission to change CALL effects, memory, machine exits or rendered code.
(function (root) {
    const PROFILE = Object.freeze({id: 'windows-x64-gpr-v1', arguments: Object.freeze(['rcx', 'rdx', 'r8', 'r9']), returnRegister: 'rax'});
    const LIMITS = Object.freeze({work: 131072, sources: 64, observations: 256, stackSlots: 256, stackVisits: 4096, callers: 8, sites: 32, moduleItems: 131072, fileBytes: 65536});
    const notice = 'Analyst-selected Windows x64 function convention. Register/stack reads and RAX values are candidates, not a recovered C signature. Unused arguments, floating-point arguments and broader stack recovery, varargs, hidden parameters and original types remain unknown. Caller observations do not assert a normal return or enable call summaries. No machine effects are changed.';
    const emptyContract = (report, id) => ({version: 1, moduleId: report.module.id, functionId: id, profile: null});
    const hex = n => '0x' + n.toString(16), full = (1n << 64n) - 1n;
    class BudgetError extends Error {}
    const exact = (o,keys) => o !== null && typeof o === 'object' && !Array.isArray(o) && Object.keys(o).sort().join(',') === keys;
    const text = (s,n,empty=false) => typeof s === 'string' && s.length <= n && (empty || s.trim().length > 0) && !/[\x00-\x1f\x7f]/.test(s);
    const typeLabel = s => s === null || text(s,128);
    function normalizeDeclarations(list) {
        if (!Array.isArray(list) || list.length > 8) throw Error('Declarations must be an array of at most 8 records.');
        const ids = new Set();
        const result = list.map(d => {
            if (!exact(d,'hiddenParameters,id,parameters,returnType,source,variadic') || !text(d.id,64) || !/^[A-Za-z0-9_-]+$/.test(d.id) || ids.has(d.id) ||
                !text(d.source,256) || !typeLabel(d.returnType) || !['yes','no','unknown'].includes(d.variadic) || !['yes','no','unknown'].includes(d.hiddenParameters) ||
                !Array.isArray(d.parameters) || d.parameters.length > 32) throw Error('Invalid declaration: unique ID, source, type labels, at most 32 parameters and explicit uncertainty fields are required.');
            ids.add(d.id);
            const parameters = d.parameters.map(p => {
                if (!exact(p,'name,type') || !text(p.name,64,true) || !typeLabel(p.type)) throw Error('Each parameter requires a name and a type label (or null for unknown).');
                return {name:p.name,type:p.type};
            });
            return {id:d.id,source:d.source,returnType:d.returnType,parameters,variadic:d.variadic,hiddenParameters:d.hiddenParameters};
        });
        if (new TextEncoder().encode(JSON.stringify(result,null,2)).length > 49152) throw Error('Normalized declarations exceed 48 KiB.');
        return result;
    }
    function declarationConflicts(list) {
        const conflicts = [];
        for (let i=0;i<list.length;i++) for (const b of list.slice(i+1)) {
            const a=list[i], fields=[];
            if (a.returnType !== null && b.returnType !== null && a.returnType !== b.returnType) fields.push('returnType');
            if (a.parameters.length !== b.parameters.length) fields.push('parameterCount');
            for (let n=0;n<Math.min(a.parameters.length,b.parameters.length);n++)
                if (a.parameters[n].type !== null && b.parameters[n].type !== null && a.parameters[n].type !== b.parameters[n].type) fields.push('parameter['+(n+1)+'].type');
            for (const key of ['variadic','hiddenParameters']) if (a[key] !== 'unknown' && b[key] !== 'unknown' && a[key] !== b[key]) fields.push(key);
            if (fields.length) conflicts.push({declarations:[a.id,b.id],fields,
                reason:'Analyst declarations differ. Type labels are not parsed; aliases may be equivalent. Neither declaration is selected as authoritative.'});
        }
        return conflicts;
    }
    function analyze(report, graph, lifted, entry, manifest, loadCaller, options = {}, valueAnalysis = null) {
        const contract = emptyContract(report, entry);
        const eligible = report.module.architecture.startsWith('x64') && graph.status === 'available';
        const base = {version: 4, complete: false, eligible, contract, notice, arguments: [], stackArguments: [], stackScope: 'Bounded discovered normal-flow paths, including joins and loops. Aligned 1/2/4/8-byte incoming reads must remain untouched on every incoming path. Caller matches require the same covering store on every predecessor; differing stores stay unknown.', returns: [], callers: [], conflicts: [], declarationConflicts: [], declarationReviews: [], assumptionSources: []};
        const fail = (status, reason) => ({...base, status, reason});
        const limits = Object.fromEntries(Object.entries(LIMITS).map(([k,v]) =>
            [k, Number.isSafeInteger(options[k]) ? Math.max(0, Math.min(v, options[k])) : v]));
        if (manifest !== undefined && manifest !== null) {
            try {
                const keys = manifest?.version === 2 ? 'declarations,functionId,moduleId,profile,version' : 'functionId,moduleId,profile,version';
                if (!exact(manifest,keys) || ![1,2].includes(manifest.version) || manifest.moduleId !== report.module.id || manifest.functionId !== entry ||
                    ![null, PROFILE.id].includes(manifest.profile)) throw Error('Function contract must match this module, function and version 1 or 2 schema.');
                if (manifest.profile && !eligible) throw Error('This profile requires x64 and available register SSA with unambiguous ownership.');
                const declarations = manifest.version === 2 ? normalizeDeclarations(manifest.declarations) : null;
                // Commit only after validation of the entire document.
                contract.version = manifest.version; contract.profile = manifest.profile;
                if (declarations) contract.declarations = declarations;
                base.declarationConflicts = declarationConflicts(declarations || []);
            } catch (e) {return fail('invalid',e.message);}
        }
        if (!eligible) return fail('unavailable', 'Function ABI evidence requires x64 and available register SSA with unambiguous ownership.');
        if (!contract.profile) return fail('default', 'Choose a function convention to inspect register argument/return candidates. No convention is inferred from PE bitness or names.');
        let work = 0, observations = 0, stackVisits = 0;
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
        // Must-preserve memory identity over discovered normal-flow paths.
        // No memory values are forwarded and no call summary is enabled.
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
            const facts = new Map(va.facts.map(f => [f.source,f])), accesses = new Map();
            for (const a of va.accesses) {spend(); if (!accesses.has(a.source)) accesses.set(a.source,[]); accesses.get(a.source).push(a);}
            const key = a => a.stackOffset + ':' + a.width;
            const inputRead = a => {
                if (a.access !== 'read' || a.implicit || !precise(a) || ![8,16,32,64].includes(a.width)) return false;
                const offset = BigInt(a.stackOffset);
                return offset >= 40n && offset % 8n === 0n && offset <= BigInt(Number.MAX_SAFE_INTEGER);
            };
            const bounded = state => {if (state.size > limits.stackSlots) throw new BudgetError('Function ABI stack-slot budget exceeded.');};
            // A finite universe of read slices avoids tracking arbitrary memory.
            // Only the virtual initial entry supplies untouched incoming bytes.
            const seed = new Map();
            if (!callSource) for (const b of g.blocks) for (const i of l.get(b.id)) for (const a of accesses.get(i.source) || []) {
                spend(); if (inputRead(a)) seed.set(key(a),{stackOffset:a.stackOffset,width:a.width,sources:[]}); bounded(seed);
            }
            const blocks = new Map(g.blocks.map(b => [b.id,b])), edges = new Map(g.blocks.map(b => [b.id,new Map()]));
            for (const e of report.edges) {spend();
                if (e.kind !== 'call' && blocks.has(e.from) && blocks.has(e.to)) {
                    const out = edges.get(e.from); out.set(e.to,union(out.get(e.to) || [],[e.source]));
                }
            }
            const equal = (a,b) => !!a && !!b && a.size === b.size && [...a].every(([k,v]) => {
                spend(); const w = b.get(k); return w && v.source === w.source && v.sources.join('|') === w.sources.join('|');
            });
            function join(incoming) {
                const state = new Map(incoming[0].state);
                for (const [k,v] of state) {
                    let sources = union(v.sources,incoming[0].sources);
                    for (const input of incoming.slice(1)) {
                        spend(); const w = input.state.get(k);
                        if (!w || v.source !== w.source) {state.delete(k); break;}
                        sources = union(sources,w.sources,input.sources);
                    }
                    if (state.has(k)) state.set(k,{...v,sources});
                }
                return state;
            }
            function transfer(id,input,collect) {
                const state = new Map(input);
                for (const i of l.get(id)) {
                    spend(); const f = facts.get(i.source), memory = accesses.get(i.source) || [];
                    const beforeSP = stack(f?.before.rsp), afterSP = stack(f?.after.rsp);
                    if (beforeSP === null || beforeSP > 0n) state.clear();
                    if (collect && i.source === callSource) {
                        if (beforeSP === null) {result.status = 'unavailable'; result.reason = 'Call stack pointer is not precise.';}
                        else for (const a of state.values()) {spend();
                            if (BigInt(a.stackOffset) < beforeSP + 32n || BigInt(a.stackOffset) + BigInt(a.width/8) > 0n) continue;
                            observe(); result.stores.push({...a,entryOffset:(BigInt(a.stackOffset)-beforeSP+8n).toString(),
                                sources:union(a.sources,f.before.rsp.sources || [],[i.source])});
                        }
                    }
                    if (!f || i.ops.some(o => o.kind === 'barrier' || o.kind === 'call_summary')) {state.clear(); continue;}
                    if (collect && !callSource) for (const a of memory) {
                        spend(); const untouched = state.get(key(a));
                        if (!untouched || !inputRead(a)) continue;
                        observe(); result.reads.push({position:Number(BigInt(a.stackOffset)/8n),entryOffset:a.stackOffset,width:a.width,source:i.source,
                            certainty:'candidate',sources:union(untouched.sources,a.sources,[i.source])});
                    }
                    for (const a of memory.filter(a => a.access === 'write' || a.access === 'unknown')) {
                        spend(); if (!precise(a)) {state.clear(); continue;}
                        for (const [k,v] of state) if (overlap(v,a)) state.delete(k);
                        const op = i.ops.length === 1 && i.ops[0];
                        if (callSource && beforeSP !== null && a.allocated && [8,16,32,64].includes(a.width) && op?.kind === 'assign' &&
                            op.target.kind === 'load' && a.key === JSON.stringify(op.target)) {
                            state.set(key(a),{source:i.source,stackOffset:a.stackOffset,width:a.width,sources:union(a.sources,[i.source])}); bounded(state);
                        }
                    }
                    // Deallocation is irreversible evidence loss, even if SP
                    // is restored later. Calls invalidate all stored contents.
                    if (afterSP === null || afterSP > 0n) state.clear();
                    else if (callSource) for (const [k,v] of state) {spend(); if (BigInt(v.stackOffset) < afterSP) state.delete(k);}
                }
                return state;
            }
            const inputs = new Map(), outputs = new Map(), queue = [g.entry], queued = new Set(queue);
            while (queue.length) {
                if (++stackVisits > limits.stackVisits) throw new BudgetError('Function ABI stack fixed-point budget exceeded.');
                const id = queue.shift(), b = blocks.get(id); queued.delete(id);
                const incoming = b.predecessors.filter(p => outputs.has(p)).map(p => ({state:outputs.get(p),sources:edges.get(p).get(id) || []}));
                if (id === g.entry) incoming.unshift({state:seed,sources:[]});
                if (!incoming.length) continue;
                const input = join(incoming), output = transfer(id,input,false); inputs.set(id,input);
                if (!equal(output,outputs.get(id))) {
                    outputs.set(id,output);
                    for (const to of b.successors) if (!queued.has(to)) {queue.push(to); queued.add(to);}
                }
            }
            // Unknown predecessors and backedges must participate before any
            // observation is emitted. Never retain an early provisional read.
            for (const b of g.blocks) {
                if (!inputs.has(b.id)) return unavailable('Incomplete reachable stack data flow.');
                if (!callSource || b.id === block.id) transfer(b.id,inputs.get(b.id),true);
            }
            return result;
        }
        try {
            let items = report.blocks.length + report.edges.length + report.functions.length;
            for (const b of report.blocks) items += b.instructions.length;
            if (items > limits.moduleItems) throw new BudgetError('Function ABI module-scan budget exceeded.');
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
            const declarationReviews = [];
            for (const d of contract.declarations || []) {
                if (d.variadic === 'no' && d.hiddenParameters === 'no') {
                    for (const candidate of [...args,...stackInputs.reads]) if (candidate.position > d.parameters.length) {
                        observe(); declarationReviews.push({declaration:d.id,kind:'candidate_outside_declaration',position:candidate.position,sources:candidate.sources,
                            reason:'An observed input candidate is outside the declared fixed parameter list. Incidental register or stack reads are possible; this is a review hint, not a disproven prototype.'});
                    }
                }
                if (d.returnType === 'void') for (const caller of callers) if (caller.returnUses.length) {
                    observe(); declarationReviews.push({declaration:d.id,kind:'void_result_read',sources:union(...caller.returnUses.map(u => u.sources)),
                        reason:'A caller reads call-produced RAX bits despite the void annotation. Incidental register activity is possible; no return type is inferred.'});
                }
            }
            return {...base,declarationReviews,status:'available',arguments:args,stackArguments:stackInputs.reads,stackStatus:stackInputs.status,stackReason:stackInputs.reason,returns,callers,conflicts,assumptionSources:[...(graph.assumptionSources || [])],work,observations,stackVisits};
        } catch (e) {
            return fail(e instanceof BudgetError ? 'budget_exceeded' : 'unavailable',e.message + ' Provisional ABI evidence discarded.');
        }
    }
    const api = {PROFILE,LIMITS,notice,emptyContract,normalizeDeclarations,declarationConflicts,analyze};
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WEAFunctionABI = api;
})(globalThis);
