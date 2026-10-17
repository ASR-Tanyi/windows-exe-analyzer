'use strict';
// Pure, presentation-only index of existing report facts. No new discovery or
// ownership inference. Usable by the offline viewer and Node regression tests.
(function (root) {
    function create(report) {
        const functions = new Map(report.functions.map(f => [f.id, f]));
        const blocks = new Map(report.blocks.map(b => [b.id, b]));
        const members = new Map([...functions.keys()].map(id => [id, []]));
        const outgoing = new Map(), incoming = new Map();
        for (const b of blocks.values()) {
            for (const owner of new Set(b.owners || [])) {
                if (members.has(owner)) members.get(owner).push(b);
            }
        }
        for (const list of members.values()) list.sort((a, b) => a.rva - b.rva);
        for (const e of report.edges) {
            if (!outgoing.has(e.from)) outgoing.set(e.from, []);
            outgoing.get(e.from).push(e);
            if (e.to) {
                if (!incoming.has(e.to)) incoming.set(e.to, []);
                incoming.get(e.to).push(e);
            }
        }
        const cache = new Map();
        function get(id) {
            if (!functions.has(id)) return null;
            if (cache.has(id)) return cache.get(id);
            const owned = members.get(id), ownedIds = new Set(owned.map(b => b.id));
            const rows = [], rowIndex = new Map(), spans = [], refs = [];
            const calls = [], callers = [], cfg = [], transfers = [], unresolved = [];
            const incomingSeen = new Set();
            for (const b of owned) {
                for (const i of b.instructions) {
                    if (rowIndex.has(i.id)) continue;
                    rowIndex.set(i.id, rows.length); rows.push({block: b, insn: i});
                    spans.push([i.rva, i.rva + i.size]);
                    for (const ref of i.dataRefs || []) refs.push({block: b, insn: i, ref});
                }
                for (const e of outgoing.get(b.id) || []) {
                    if (e.kind === 'call') calls.push(e);
                    else if (e.to && ownedIds.has(e.to)) cfg.push(e);
                    else transfers.push(e);
                    if ((!e.to || !blocks.has(e.to)) && !e.external) unresolved.push(e);
                }
                for (const e of incoming.get(b.id) || []) {
                    // Incoming calls include recursion and calls into interior
                    // blocks. Non-call transfers never become fake callers.
                    if (e.kind === 'call' && !incomingSeen.has(e)) {
                        incomingSeen.add(e); callers.push(e);
                    }
                }
            }
            spans.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
            const ranges = [];
            for (const [begin, end] of spans) {
                const last = ranges[ranges.length - 1];
                if (last && begin <= last[1]) last[1] = Math.max(last[1], end);
                else ranges.push([begin, end]);
            }
            const value = {
                function: functions.get(id), blocks: owned, ownedIds, rows, rowIndex,
                ranges, byteCount: ranges.reduce((n, r) => n + r[1] - r[0], 0),
                calls, callers, cfg, transfers, unresolved, refs,
                callSites: new Set(calls.map(e => e.source)).size,
                dataAddresses: new Set(refs.map(x => x.ref.to || x.ref.va)).size,
                sharedBlocks: owned.filter(b => new Set(b.owners || []).size > 1),
                ownershipMissing: !ownedIds.has(id),
                // False would claim complete recovery without enough evidence.
                completeness: 'not_proven'
            };
            // Bound repeated navigation's derived row/index storage; report
            // objects themselves are shared, not copied into every cache entry.
            if (cache.size >= 4) cache.delete(cache.keys().next().value);
            cache.set(id, value);
            return value;
        }
        return {functions, blocks, get};
    }
    const api = {create};
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WEAFunctionModel = api;
})(typeof globalThis === 'object' ? globalThis : this);
