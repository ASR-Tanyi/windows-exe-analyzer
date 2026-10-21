'use strict';
// Analyst-selected call-to-continuation contracts, separate from raw CALL.
(function (root) {
    const PROFILE = Object.freeze({id: 'windows-x64-normal-return-v1',
        preserved: Object.freeze(['rbx', 'rbp', 'rsi', 'rdi', 'rsp', 'r12', 'r13', 'r14', 'r15']),
        clobbered: Object.freeze(['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11']),
        stackAlignment: 16, homeBytes: 32, returnAddressBytes: 8, netStackDelta: 0});
    const LIMITS = Object.freeze({sites: 128, fileBytes: 65536});
    const notice = 'Analyst assertion at each selected call: every possible callee follows the Windows x64 ABI and returns normally to the recorded continuation. Before CALL, RSP is 16-byte aligned with 32 bytes of writable home space and valid return-address storage. These preconditions are assumed, not verified. No prototype or return type is inferred; all memory and flags remain unknown.';
    const empty = (report, functionId) => ({version: 1, moduleId: report.module.id, functionId, sites: []});
    function profile(op) {
        if (op.kind !== 'call_summary' || op.profile !== PROFILE.id || op.width !== 64)
            throw Error('Unsupported call summary.');
        return PROFILE;
    }
    function apply(report, blocks, edges, lifted, functionId, manifest) {
        const owned = new Map(blocks.map(b => [b.id, b])), sites = [], bySource = new Map();
        const unsafe = report.module.truncated || blocks.some(b => new Set(b.owners).size !== 1) ||
            report.edges.some(e => owned.has(e.to) && e.to !== functionId && !owned.has(e.from));
        for (const b of blocks) for (const i of lifted.get(b.id)) if (i.mnemonic === 'call') {
            const native = b.instructions.find(n => n.id === i.source);
            const outgoing = edges.filter(e => e.from === b.id && e.kind !== 'call');
            const continuation = outgoing.length === 1 && outgoing[0].kind === 'continuation' &&
                outgoing[0].source === i.source && owned.get(outgoing[0].to)?.rva === native.rva + native.size &&
                b.instructions.at(-1).id === i.source;
            const reason = unsafe ? 'Shared/truncated ownership or an outside entry prevents call assumptions.' :
                !i.call ? i.reason : i.call.width !== 64 ? 'Windows x64 summaries do not apply to x86.' :
                !continuation ? 'A unique owned normal-return continuation is required.' : null;
            const site = {source: i.source, rva: i.rva, target: i.call?.target || null,
                eligible: !reason, reason, profile: null, status: 'unknown',
                continuation: continuation ? outgoing[0].to : null};
            sites.push(site); bySource.set(i.source, {site, instruction: i});
        }
        let normalized = empty(report, functionId);
        try {
            if (manifest !== undefined && manifest !== null) {
                const keys = (value, allowed) => value && typeof value === 'object' && !Array.isArray(value) &&
                    Object.keys(value).length === allowed.length && Object.keys(value).every(k => allowed.includes(k));
                if (!keys(manifest, ['version', 'moduleId', 'functionId', 'sites']) || manifest.version !== 1 ||
                    manifest.moduleId !== report.module.id || manifest.functionId !== functionId || !Array.isArray(manifest.sites))
                    throw Error('Call assumptions must match this module, function and version 1 schema.');
                if (manifest.sites.length > LIMITS.sites) throw Error('Call-assumption site budget exceeded (128).');
                const seen = new Set();
                for (const binding of manifest.sites) {
                    if (!keys(binding, ['source', 'profile']) || typeof binding.source !== 'string' ||
                        binding.profile !== PROFILE.id || seen.has(binding.source)) throw Error('Invalid, duplicate or unsupported call binding.');
                    const entry = bySource.get(binding.source);
                    if (!entry) throw Error('A call binding does not identify a call in this function.');
                    if (!entry.site.eligible) throw Error(entry.site.reason);
                    seen.add(binding.source);
                }
                normalized.sites = manifest.sites.map(b => ({source: b.source, profile: b.profile})).sort((a, b) => a.source.localeCompare(b.source));
            }
        } catch (e) {
            return {version: 1, status: 'invalid', reason: e.message, applied: 0, sites, assumptions: empty(report, functionId), notice};
        }
        // Validation is transactional: malformed files never enable a subset.
        for (const binding of normalized.sites) {
            const {site, instruction: i} = bySource.get(binding.source);
            site.profile = binding.profile; site.status = 'assumed'; i.status = 'assumed'; delete i.reason;
            i.ops = [{kind: 'call_summary', profile: binding.profile, width: 64,
                target: i.call.target, returnAddress: i.call.returnAddress, assumptionSource: i.source}];
        }
        return {version: 1, status: normalized.sites.length ? 'applied' : 'default', applied: normalized.sites.length,
            sites, assumptions: normalized, notice, profile: {...PROFILE}};
    }
    const api = {PROFILE, LIMITS, notice, empty, profile, apply};
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WEACallSummaries = api;
})(globalThis);
