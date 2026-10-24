'use strict';
// Embedded after the other viewer extensions. Existing block/annotation IDs
// remain unchanged; whole-function routes carry only a view context.
(() => {
    if (D.schema !== 2 || !globalThis.WEAFunctionModel) return;
    const index = WEAFunctionModel.create(D), prefix = D.module.id + '_fn_';
    const pageSize = 250, listLimit = 100;
    const byRva = new Map(D.functions.map(f => [f.rva, f]));
    let active = null, activeHash = '', historyMove = false, renderSerial = 0;
    function idFor(f, focus = null, page = 0) {
        return prefix + f.rva.toString(16) + (focus ? '_at_' + I.get(focus).insn.rva.toString(16) : page ? '_p' + page : '');
    }
    function parse(id) {
        if (typeof id !== 'string' || !id.startsWith(prefix)) return null;
        const match = /^([0-9a-f]{1,8})(?:_at_([0-9a-f]{1,8})|_p([1-9][0-9]{0,6}))?$/.exec(id.slice(prefix.length));
        if (!match) return null;
        const f = byRva.get(parseInt(match[1], 16));
        if (!f) return null;
        const m = index.get(f.id), focus = match[2] ? D.module.id + '_i_' + parseInt(match[2], 16).toString(16) : null;
        if (focus && !m.rowIndex.has(focus)) return null;
        const page = focus ? Math.floor(m.rowIndex.get(focus) / pageSize) : Number(match[3] || 0);
        if (page && page * pageSize >= m.rows.length) return null;
        return {f, m, page, focus, id};
    }
    const shownName = f => label(B.get(f.id) || f);
    const byteLink = (value, from) => {
        if (value === null || value === undefined) return 'unavailable';
        const rva = Number(value), id = dataId(rva);
        return isDataId(id) ? link(id, hex(rva), from) : E(hex(rva));
    };
    function target(e, view) {
        if (e.to && B.has(e.to)) {
            const b = B.get(e.to);
            // An exact, distinct function entry gets its own view; a shared
            // interior block does not silently pick an arbitrary owner.
            if (index.functions.has(b.id) && b.id !== view.f.id) return idFor(index.functions.get(b.id));
            const first = b.instructions[0];
            if (first && view.m.rowIndex.has(first.id)) return idFor(view.f, first.id);
            return b.id;
        }
        const external = targetId(e);
        return external && imports.has(external) ? external : null;
    }
    function edgeText(e, view) {
        const id = target(e, view), text = edgeName(e);
        return id ? link(id, text, e.source, 'function-target') : '<span class="muted">' + E(text) + ' (unresolved)</span>';
    }
    function section(key, title, items, render) {
        if (!items.length) return '';
        let h = '<details class="info function-detail" data-function-detail="' + key + '"><summary>' + E(title) + ' (' + items.length + ')</summary>';
        h += items.slice(0, listLimit).map(render).join('') || '<p class="muted">None in the discovered report facts.</p>';
        if (items.length > listLimit) h += '<p class="muted">First ' + listLimit + ' shown; full facts remain in the embedded report. Assembly pages retain all owned instructions.</p>';
        return h + '</details>';
    }
    function evidence(view) {
        const f = view.f;
        let h = section('evidence', 'Discovery evidence', f.evidenceRecords || [], e => {
            const s = e.source;
            let source = 'No binary source location';
            if (s) {
                source = E(s.space + ' ' + s.value);
                if (s.moduleId === D.module.id && s.space === 'rva') {
                    const iid = D.module.id + '_i_' + Number(s.value).toString(16);
                    source = I.has(iid) ? link(iid, s.value, view.id) : byteLink(s.value, view.id);
                }
            }
            return '<p><b>' + E(e.claim + ' / ' + e.status) + '</b><br>' + E(e.origin + ' / ' + e.resolution) +
                '<br>' + E(e.rule) + ' v' + E(e.ruleVersion) + '<br>' + source + '<br>' + E(e.detail) +
                (e.assumptions || []).map(a => '<br><span class="muted">' + E(a) + '</span>').join('') + '</p>';
        });
        if (!(f.evidenceRecords || []).length) h += '<p class="small muted">Legacy evidence: ' + E(f.evidence) + '</p>';
        const records = (f.metadataRecords || []).map(i => D.exceptionDirectory?.records?.[i]).filter(Boolean);
        h += section('metadata', 'Encoded metadata ranges (not decoded coverage)', records, r =>
            '<p class="mono">[' + E(r.beginRva) + ', ' + E(r.endRva) + ')<br>Table bytes ' + byteLink(r.tableRva, view.id) + '</p>');
        return h;
    }
    function connections(view) {
        const {m} = view;
        let h = section('callers', 'Incoming call references', m.callers, e => {
            const b = B.get(e.from), i = I.get(e.source)?.insn;
            const owners = [...new Set(b?.owners || [])].filter(id => index.functions.has(id));
            const sourceId = i && owners.length === 1 ? idFor(index.functions.get(owners[0]),i.id) : i?.id;
            const source = i ? link(sourceId, i.va, view.id, 'function-caller') : E(e.source);
            return '<p>' + source + ' / ' + E(b ? label(b) : 'Unknown block') +
                '<br><span class="small muted">Target ' + E(e.to) + (e.to !== view.f.id ? ' / interior block' : '') + '</span></p>';
        });
        h += section('calls', 'Outgoing call targets', m.calls, e => '<p>' +
            link(idFor(view.f, e.source), I.get(e.source)?.insn.va || e.source, view.id) + ' : ' + edgeText(e, view) + '</p>');
        h += section('transfers', 'Non-call exits / outside-owned targets', m.transfers, e => '<p>' + E(e.kind) + ' : ' + edgeText(e, view) + '</p>');
        h += section('unknown', 'Unresolved control-flow references', m.unresolved, e => '<p>' +
            link(idFor(view.f, e.source), I.get(e.source)?.insn.va || e.source, view.id) + ' / ' + E(e.kind) + '<br>' + E(e.target || 'unknown') + '</p>');
        h += '<p class="small muted">Calls and intraprocedural edges are separate. A continuation assumes the callee returns. Missing references do not prove code is unused or unreachable.</p>';
        return h + evidence(view);
    }
    function render(view) {
        active = view; selected = view.f.id; setTab('functions');
        const {m, f} = view, first = view.page * pageSize, rows = m.rows.slice(first, first + pageSize);
        const note = labels[f.id]?.note;
        let h = '<section class="blockcard function-overview"><div class="blockhead"><div class="blocktop">' +
            '<span class="eyebrow">Whole function / inferred membership</span><span class="pill blue">FUNCTION CANDIDATE</span></div>' +
            '<h2 class="blocktitle">' + E(shownName(f)) + '</h2><div class="addressmeta">Entry RVA ' + E(hex(f.rva)) +
            ' / VA ' + E(vaFor(f.rva)) + ' / ' + link(f.id, 'Open entry block', view.id, 'function-plain') + '</div></div>' +
            '<p class="function-context">Address order · inferred membership' +
            (m.sharedBlocks.length ? ' · ' + m.sharedBlocks.length + ' shared blocks' : '') +
            (note ? '<br><b>Analyst note:</b> ' + E(note) : '') + '</p>';
        if (D.module.truncated || m.unresolved.length || m.ownershipMissing) h += '<div class="datawarning">' +
            (D.module.truncated ? 'Instruction discovery hit its budget. ' : '') +
            (m.unresolved.length ? m.unresolved.length + ' unresolved control-flow reference(s). ' : '') +
            (m.ownershipMissing ? 'Entry ownership is missing; no membership has been invented. ' : '') + '</div>';
        h += '<div class="function-metrics">' + [[m.blocks.length,'Owned blocks'],[m.rows.length,'Instructions'],[m.byteCount,'Unique decoded bytes'],[m.callSites,'Call sites']]
            .filter(([n]) => n).map(([n,t]) => '<span><b>' + n.toLocaleString() + '</b> ' + t.toLowerCase() + '</span>').join('') + '</div>';
        h += '<details class="function-sections function-detail info" data-function-detail="overview"><summary>Function details</summary><p class="small muted">Gaps are not filled; decoded coverage does not prove complete function boundaries.</p>' + section('coverage','Decoded coverage spans',m.ranges,r =>
            '<p class="mono">[' + E(hex(r[0])) + ', ' + E(hex(r[1])) + ')</p>');
        h += section('blocks','Owned blocks / ' + m.sharedBlocks.length + ' shared',m.blocks,b => {
            const i = b.instructions[0];
            return '<p>' + (i ? link(idFor(f,i.id),label(b),view.id) : E(label(b))) + ' / ' + E(hex(b.rva)) +
                ((b.owners || []).length > 1 ? '<br><span class="small muted">Shared: ' + (b.owners || []).map(o =>
                    index.functions.has(o) ? link(idFor(index.functions.get(o)),shownName(index.functions.get(o)),view.id) : E(o)).join(', ') + '</span>' : '') + '</p>';
        });
        h += section('data','Data references / ' + m.dataAddresses + ' target addresses',m.refs,x =>
            '<p>' + link(idFor(f,x.insn.id),x.insn.va,view.id) + ' / ' + E(x.ref.access) +
            (x.ref.width ? ' ' + E(x.ref.width) + ' B' : '') + ' : ' +
            (x.ref.to && isDataId(x.ref.to) ? link(x.ref.to,label(dataObject(x.ref.rva)),x.insn.id,'function-data') : E(x.ref.va)) + '</p>');
        h += '</details><form id="functionGo" class="datatools"><label for="functionAddress">Go to instruction RVA</label>' +
            '<input id="functionAddress" placeholder="0x..." aria-label="Function instruction RVA"><button>Go</button>' +
            '<span class="small muted">Exact decoded instruction starts only.</span></form></section>';
        h += '<div class="function-pagebar"' + (m.rows.length <= pageSize ? ' hidden' : '') + '><button id="prevFunctionPage" ' + (view.page ? '' : 'disabled') + '>Previous instructions</button>' +
            '<span id="functionPageStatus">' + first + '-' + (first + rows.length) + ' / ' + m.rows.length + ' instructions</span>' +
            '<button id="nextFunctionPage" ' + (first + rows.length < m.rows.length ? '' : 'disabled') + '>Next instructions</button></div>';
        let group = null;
        for (const {block:b, insn:i} of rows) {
            if (group !== b.id) {
                if (group !== null) h += '</tbody></table></div></article>';
                group = b.id;
                h += '<article class="blockcard function-block ' + (showNotes ? '' : 'notes-off') + '" data-block-id="' + E(b.id) + '">' +
                    '<header class="function-block-head"><b>' + E(label(b)) + '</b> <span class="small muted">' + E(hex(b.rva)) +
                    ((b.owners || []).length > 1 ? ' / SHARED BLOCK' : '') + '</span> ' + link(b.id,'Block view',view.id,'function-plain') + '</header>' +
                    '<div class="assemblywrap" data-function-scroll="' + E(b.id) + '"><table><thead><tr><th>Address</th><th>Bytes</th><th>Instruction / successors</th>' +
                    '<th class="noteshead">Observation, not complete IR</th></tr></thead><tbody>';
            }
            h += '<tr id="' + E(i.id) + '" class="' + (view.focus === i.id ? 'focused' : '') + '"><td class="address">' +
                link(idFor(f,i.id),i.va,view.id) + '</td><td class="bytes">' + E(i.bytes) + '</td><td><span class="op">' + E(i.mnemonic) +
                '</span> <span class="operand">' + operandHtml(i) + '</span>' + dataLinksHtml(i);
            for (const e of outgoing.get(b.id) || []) if (e.source === i.id) h += '<div class="function-edge small">' + E(e.kind.replace('_',' ')) + ' : ' + edgeText(e,view) + '</div>';
            h += '</td><td class="instnote">' + E(i.notes) + '</td></tr>';
        }
        if (group !== null) h += '</tbody></table></div></article>';
        if (!rows.length) h += '<p class="info">No owned decoded instructions are available.</p>';
        $('content').innerHTML = h; $('connections').innerHTML = connections(view);
        $('renamebox').hidden = !B.has(f.id); $('labelname').value = shownName(f); $('labelnote').value = note || '';
        $('prevFunctionPage').onclick = () => navigate(idFor(f,null,view.page-1));
        $('nextFunctionPage').onclick = () => navigate(idFor(f,null,view.page+1));
        $('functionGo').onsubmit = e => {
            e.preventDefault(); const text = $('functionAddress').value.trim();
            if (!/^(0x[0-9a-f]+|[0-9]+)$/i.test(text)) return message('Enter a decimal RVA or hexadecimal with 0x.');
            const rva = Number(text), id = D.module.id + '_i_' + rva.toString(16);
            if (!Number.isSafeInteger(rva) || !m.rowIndex.has(id)) return message('Not a decoded instruction start owned by this function.');
            navigate(idFor(f,id));
        };
        renderSidebar();
    }
    function snapshot(hash = location.hash) {
        return {hash, x: scrollX, y: scrollY,
            open: [...document.querySelectorAll('[data-function-detail][open]')].map(e => e.dataset.functionDetail),
            scroll: [...document.querySelectorAll('[data-function-scroll]')].map(e => [e.dataset.functionScroll,e.scrollLeft])};
    }
    function save(hash = location.hash) {
        history.replaceState({...history.state, weaFunctionView: snapshot(hash)}, '', hash);
    }
    function restore(s, serial, focus) {
        requestAnimationFrame(() => {
            if (serial !== renderSerial) return;
            if (s && s.hash === location.hash) {
                for (const e of document.querySelectorAll('[data-function-detail]')) e.open = s.open.includes(e.dataset.functionDetail);
                for (const e of document.querySelectorAll('[data-function-scroll]')) e.scrollLeft = s.scroll.find(x => x[0] === e.dataset.functionScroll)?.[1] || 0;
                window.scrollTo(s.x,s.y);
            } else if (focus) $(focus)?.scrollIntoView({block:'center',inline:'nearest'});
            else if (active) $('content').scrollIntoView({block:'start'});
        });
    }
    const oldSidebar = renderSidebar;
    renderSidebar = function () {
        oldSidebar();
        if (tab === 'functions') for (const a of $('symbols').querySelectorAll('a.symbol')) {
            const f = index.functions.get(a.getAttribute('href').slice(1));
            if (f) a.href = '#' + idFor(f);
        }
    };
    // The original handlers captured the pre-extension function value.
    $('search').oninput = () => renderSidebar();
    document.querySelectorAll('[data-tab]').forEach(btn => btn.addEventListener('click',() => renderSidebar()));
    const button = document.createElement('button'); button.id = 'wholeFunction'; button.textContent = 'Whole function';
    const chooser = document.createElement('select'); chooser.id = 'functionOwner'; chooser.setAttribute('aria-label','Function owner');
    $('notes').before(chooser,button);
    function toolbar() {
        const b = B.get(selected), choices = active ? [active.f.id] : [...new Set([...(b?.owners || []),...(index.functions.has(selected)?[selected]:[])])].filter(id => index.functions.has(id));
        chooser.innerHTML = (choices.length > 1 ? '<option value="">Choose owner (' + choices.length + ')</option>' : '') +
            choices.map(id => '<option value="' + E(id) + '">' + E(shownName(index.functions.get(id))) + '</option>').join('');
        chooser.hidden = choices.length < 2; button.disabled = !choices.length || choices.length > 1;
        button.setAttribute('aria-pressed',String(!!active));
    }
    chooser.onchange = () => {button.disabled = !chooser.value;};
    button.onclick = () => {
        const f = index.functions.get(chooser.value); if (!f) return;
        const current = location.hash.slice(1), m = index.get(f.id);
        navigate(idFor(f,m.rowIndex.has(current)?current:null));
    };
    const oldRoute = route, oldNavigate = navigate;
    route = function () {
        if (!historyMove && activeHash === location.hash && active) save();
        const serial = ++renderSerial, view = parse(location.hash.slice(1));
        active = null;
        if (view) render(view); else oldRoute();
        activeHash = location.hash; toolbar();
        restore(history.state?.weaFunctionView, serial, view?.focus);
    };
    navigate = function (id, from, plain = false) {
        const current = active, rawFrom = from;
        if (!plain && current && (I.has(id) || B.has(id))) {
            const b = B.get(id) || I.get(id).block, i = I.get(id)?.insn || b.instructions[0];
            if (index.functions.has(b.id) && b.id !== current.f.id && i?.rva === b.rva) id = idFor(index.functions.get(b.id));
            else if (i && current.m.rowIndex.has(i.id)) id = idFor(current.f,i.id);
        }
        if (current && from && current.m.rowIndex.has(from)) from = idFor(current.f,from);
        // Save the complete originating view instead of replacing it with a
        // bare instruction hash. 'via' separately feeds RIP/data explanations.
        save(from ? '#' + from : location.hash);
        if (parse(id) || B.has(id) || I.has(id) || imports.has(id) || isDataId(id)) {
            if (location.hash !== '#' + id) history.pushState({via:rawFrom || null},'','#'+id);
            else if (rawFrom) history.replaceState({...history.state,via:rawFrom},'','#'+id);
            historyMove = true; route(); historyMove = false;
        } else {
            // Metadata extensions retain their own route validation.
            oldNavigate(id);
        }
    };
    // Capture only explicit Block-view links; ordinary links keep the viewer's
    // established handler, including modifier-key/new-tab behavior.
    document.addEventListener('click',e => {
        const a = e.target.closest('a.function-plain');
        if (!a || e.button || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
        e.preventDefault(); e.stopImmediatePropagation(); navigate(a.getAttribute('href').slice(1),a.dataset.from,true);
    },true);
    // Dispatch through the latest extension chain once. Older listeners captured
    // older route functions and otherwise erase function views on history moves.
    const onHistory = e => {e.stopImmediatePropagation(); historyMove = true; route(); historyMove = false;};
    window.addEventListener('popstate',onHistory,true); window.addEventListener('hashchange',onHistory,true);
    window.addEventListener('pagehide',() => save());
    const style = document.createElement('style');
    style.textContent = '.function-sections.function-detail{margin:0 20px 8px;padding:10px 12px}.function-detail{margin:8px 0;overflow-wrap:anywhere}.function-pagebar{display:flex;align-items:center;justify-content:space-between;gap:8px;margin:18px 0;font-size:12px}.function-pagebar button{font-size:12px}.function-block{margin:14px 0;overflow:visible}.function-block-head{position:sticky;top:0;z-index:1;background:var(--panel2);padding:12px 15px;border-bottom:1px solid var(--line);border-radius:10px 10px 0 0;font-family:var(--mono);overflow-wrap:anywhere}.function-block-head a{float:right;font:11px var(--sans)}.function-edge{margin-top:5px;color:var(--muted)}.function-target{color:var(--accent)}#functionOwner{max-width:170px;background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:7px}#functionOwner[hidden]{display:none}@media(max-width:720px){.function-sections.function-detail{margin:0 12px 8px}.function-pagebar{flex-wrap:wrap}.function-block-head{font-size:12px}}';
    document.head.appendChild(style);
    route();
})();
