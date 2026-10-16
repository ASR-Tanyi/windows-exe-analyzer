'use strict';
// Optional structural-unwind extension; old reports remain independent of it.
(() => {
    const u = D.unwindInfo;
    if (!u || u.version !== 1 || !D.exceptionDirectory) return;
    const prefix = D.module.id + '_unwind_';
    const nodes = new Map(u.nodes.map(n => [prefix + Number(n.rva).toString(16), n]));
    const assessments = new Map(u.records.map(r => [r.recordIndex, r]));
    const functions = new Map(D.functions.map(f => [f.id, f]));
    const references = new Map();
    for (const r of D.exceptionDirectory.records) {
        if (!references.has(r.unwindRva)) references.set(r.unwindRva, []);
        references.get(r.unwindRva).push(r);
    }
    const idFor = rva => prefix + Number(rva).toString(16);
    const nodeLink = (rva, from) => nodes.has(idFor(rva)) ? link(idFor(rva), rva, from, 'unwind-link') : E(rva) + ' (not parsed)';
    const dataLink = (rva, from) => isDataId(dataId(Number(rva))) ? link(dataId(Number(rva)), rva, from) : E(rva) + ' (unmapped)';
    const codeLink = (rva, from) => {
        const id = D.module.id + '_i_' + Number(rva).toString(16);
        return I.has(id) ? link(id, rva, from, 'unwind-code') : E(rva) + ' (not decoded)';
    };
    const operationNames = ['PUSH_NONVOL', 'ALLOC_LARGE', 'ALLOC_SMALL', 'SET_FPREG',
        'SAVE_NONVOL', 'SAVE_NONVOL_FAR', null, null, 'SAVE_XMM128', 'SAVE_XMM128_FAR', 'PUSH_MACHFRAME'];
    function recordDescription(r, from) {
        const a = assessments.get(r.index);
        return '<p class="unwind-assessment">Record #' + E(r.index) + ': [' + codeLink(r.beginRva, from) + ', ' + E(r.endRva) + ')<br>' +
            'Table bytes: ' + dataLink(r.tableRva, from) + ' / Unwind: ' + nodeLink(r.unwindRva, from) + '<br>' +
            (a ? E(a.status) + ' / ' + E(a.discovery) + (a.chainDepth ? '<br>Chained fragment; primary association: ' + codeLink(a.primaryBeginRva || 0, from) : '') +
                a.reasons.map(x => '<br>' + E(x)).join('') : 'No supported assessment') + '</p>';
    }
    const previousBlock = renderBlock;
    renderBlock = function (b, focus) {
        previousBlock(b, focus);
        const indices = functions.get(b.id)?.metadataRecords || [];
        if (!indices.length) return;
        let h = '<details class="unwind-ranges info"><summary>Metadata ranges (' + E(indices.length) + ' records)</summary>' +
            '<p>Encoded metadata is separate from decoded coverage. A chained range is a procedure-fragment candidate, not proof of a separate source function.</p>';
        for (const index of indices.slice(0,100)) h += recordDescription(D.exceptionDirectory.records[index], focus || b.id);
        if (indices.length > 100) h += '<p>First 100 records shown; all associations are retained in JSON.</p>';
        $('connections').insertAdjacentHTML('beforeend', h + '</details>');
    };
    function renderUnwind(id) {
        const n = nodes.get(id);
        selected = id;
        let h = '<section class="blockcard"><div class="blockhead"><div class="eyebrow">AMD64 structural validation</div>' +
            '<h2 class="blocktitle">Unwind info ' + E(n.rva) + '</h2><div class="addressmeta">Original bytes: ' + dataLink(n.rva, id) +
            ' / version ' + E(n.version) + ' / ' + E(n.status) + '</div></div>' +
            '<div class="summary">Only the documented version-1 subset is structurally checked. This does not execute unwinding, verify prolog machine code, or decode language-specific handler data.</div>' +
            '<div class="interpret">Flags: ' + E(n.flags) + ' / Prolog bytes: ' + E(n.prologSize) +
            ' / Code slots: ' + E(n.codeSlots) + ' / Frame register: ' + E(n.frameRegister) + ' / Frame offset: ' + E(n.frameOffset * 16) + '</div>';
        for (const issue of n.issues) h += '<div class="datawarning">' + E(issue) + '</div>';
        if (n.version !== 1) h += '<div class="info">Opaque unsupported version: no version-1 opcode or trailer interpretation was applied.</div>';
        if (n.chain) h += '<div class="interpret"><b>Chained runtime-function record</b><p>Record bytes: ' + dataLink(n.chain.fieldRva,id) +
            '<br>[' + codeLink(n.chain.beginRva,id) + ', ' + E(n.chain.endRva) + ')<br>Parent unwind: ' + nodeLink(n.chain.unwindRva,id) + '</p></div>';
        if (n.handlerRva !== null) h += '<div class="interpret"><b>Handler candidate</b><p>' + codeLink(n.handlerRva,id) +
            ' / target bytes: ' + dataLink(n.handlerRva,id) + ' / pointer bytes: ' + dataLink(n.handlerFieldRva,id) +
            (n.handlerDataRva !== null ? '<br>Opaque language-data start: ' + dataLink(n.handlerDataRva,id) : '') +
            '<br>This is not an ordinary call edge and does not prove a handler executed.</p></div>';
        h += '<div class="assemblywrap"><table id="unwindOperations"><thead><tr><th>Slot / bytes</th><th>Prolog offset</th><th>Operation</th><th>Info / slots / operand</th></tr></thead><tbody>';
        for (const op of n.operations) h += '<tr><td>' + E(op.slot) + ' / ' + dataLink(hex(Number(n.rva)+4+op.slot*2),id) +
            '</td><td>' + E(op.offset) + '</td><td>' + E(operationNames[op.opcode] || ('Unsupported opcode ' + op.opcode)) +
            '</td><td>' + E(op.info) + ' / ' + E(op.slots) + ' / ' + E(op.operand) + '</td></tr>';
        h += '</tbody></table></div></section>';
        $('content').innerHTML = h;
        const refs = references.get(n.rva) || [];
        $('connections').innerHTML = '<h3 class="eyebrow">Runtime records / ' + E(refs.length) + '</h3>' +
            refs.slice(0,100).map(r => recordDescription(r,id)).join('') +
            '<div class="info">Budgets: ' + E(u.chainLimit) + ' nodes per chain, ' + E(u.nodeLimit) +
            ' unique nodes, ' + E(u.slotLimit) + ' code slots. Capture is static; no input code executes.</div>';
        if (refs.length > 100) $('connections').insertAdjacentHTML('beforeend','<p>First 100 references shown; all retained in JSON.</p>');
        $('renamebox').hidden = true;
        renderSidebar();
    }
    const previousRoute = route, previousNavigate = navigate;
    route = function () {
        const id = location.hash.slice(1);
        if (nodes.has(id)) renderUnwind(id); else previousRoute();
    };
    navigate = function (id, from) {
        if (!nodes.has(id)) return previousNavigate(id,from);
        if (from && location.hash !== '#' + from) history.replaceState(null,'','#'+from);
        if (location.hash !== '#' + id) history.pushState(null,'','#'+id);
        route();
    };
    const onHistory = () => { if (nodes.has(location.hash.slice(1))) route(); };
    window.addEventListener('popstate',onHistory);
    window.addEventListener('hashchange',onHistory);
    const button = document.createElement('button');
    button.id = 'unwindInfo'; button.textContent = 'Unwind validation'; button.disabled = !nodes.size;
    button.onclick = () => navigate(nodes.keys().next().value,I.has(location.hash.slice(1)) ? location.hash.slice(1) : undefined);
    $('notes').before(button);
    route();
})();
