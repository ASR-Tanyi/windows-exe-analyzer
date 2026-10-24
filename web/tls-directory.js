'use strict';
// Optional schema-2 extension; callback metadata is not an execution trace.
(() => {
    const tls = D.tlsDirectory;
    if (!tls || tls.version !== 1) return;
    // Correct the legacy template's limitation text only for TLS-aware reports.
    for (const paragraph of document.querySelectorAll('details.info p')) {
        if (paragraph.textContent.includes('TLS discovery and semantic decompilation'))
            paragraph.textContent = paragraph.textContent.replace('TLS discovery and semantic decompilation', 'and semantic decompilation');
    }
    const prefix = D.module.id + '_tls', pageSize = 100;
    const pageId = page => page ? prefix + '_p' + page : prefix;
    const pageNumber = id => {
        if (id === prefix) return 0;
        if (typeof id !== 'string' || !id.startsWith(prefix + '_p')) return null;
        const suffix = id.slice(prefix.length + 2);
        if (!/^[1-9][0-9]{0,5}$/.test(suffix)) return null;
        const page = Number(suffix);
        return page * pageSize < tls.callbacks.length ? page : null;
    };
    const bytesLink = (rva, from) => {
        if (rva === null) return 'unavailable';
        const id = dataId(Number(rva));
        return isDataId(id) ? link(id, rva, from) : E(rva) + ' (unmapped)';
    };
    function renderTls(page) {
        const id = pageId(page), first = page * pageSize;
        selected = id;
        let h = '<section class="blockcard"><div class="blockhead">' +
            '<div class="eyebrow">TLS / independent loader callbacks</div>' +
            '<h2 class="blocktitle">TLS callback metadata</h2><div class="addressmeta">Directory RVA ' +
            bytesLink(tls.directoryRva, id) + ' / ' + E(tls.directorySize) + ' bytes / ' +
            E(tls.pointerSize * 8) + '-bit pointers / status: ' + E(tls.status) + '</div></div>' +
            '<div class="summary">Callback entries are encoded loader relationships, not calls from the PE entry point. ' +
            'Array order is not an observed execution history. No input code has been executed.</div>';
        if (tls.status === 'absent') h += '<p class="interpret">No TLS directory is declared.</p>';
        else if (tls.status === 'no_callback_array') h += '<p class="interpret">The callback-array VA is null. No array was read.</p>';
        if (tls.headerRead) {
            h += '<div class="interpret"><div class="eyebrow">Original header fields</div><p class="mono">' +
                'Template start VA: ' + E(tls.rawDataStartVa) + '<br>Template end VA: ' + E(tls.rawDataEndVa) +
                '<br>Index VA: ' + E(tls.indexVa) + '<br>Callback array VA: ' + E(tls.callbacksVa) +
                '<br>Callback pointer field RVA: ' + bytesLink(tls.callbacksFieldRva, id) +
                '<br>Array RVA: ' + bytesLink(tls.arrayRva, id) +
                '<br>Terminator RVA: ' + bytesLink(tls.terminatorRva, id) +
                '<br>Zero fill: ' + E(tls.zeroFill) + ' / characteristics: ' + E(tls.characteristics) + '</p>' +
                '<p class="small muted">Template, index, and allocation fields are recorded, not runtime-validated. ' +
                'VAs use the file\'s preferred base; relocations and live writes are not applied.</p></div>';
        }
        h += '<div class="info">Stored callbacks: ' + E(tls.callbacks.length) + ' / limit: ' + E(tls.callbackLimit) +
            '. Null terminator read: ' + E(tls.terminated) + '. Partial: ' + E(tls.partial) +
            '. Discovery enabled: ' + E(tls.discoveryEnabled) + '. Unique submitted roots: ' + E(tls.seedLocations) + '.</div>';
        for (const issue of tls.issues) h += '<div class="datawarning">' + E(issue) + '</div>';
        h += '<div class="assemblywrap"><table id="tlsCallbacks"><thead><tr>' +
            '<th>Ordinal / pointer slot</th><th>Encoded target VA / RVA</th><th>Discovery and validation</th></tr></thead><tbody>';
        const rows = tls.callbacks.slice(first, first + pageSize);
        for (const c of rows) {
            let target = c.targetRva === null ? 'outside image' : E(c.targetRva) + ' (not decoded)';
            if (c.targetRva !== null) {
                const iid = D.module.id + '_i_' + Number(c.targetRva).toString(16);
                if (I.has(iid)) target = link(iid, c.targetRva, id, 'tls-code');
            }
            h += '<tr><td>' + E(c.index) + '<br>' + bytesLink(c.slotRva, id) + '</td><td>' +
                E(c.targetVa) + '<br>' + target + '</td><td style="white-space:normal;min-width:180px">' +
                E(c.discovery) + '<br>Eligible: ' + E(c.eligible) +
                c.issues.map(x => '<br>' + E(x)).join('') +
                (c.duplicateOf !== null ? '<br>Duplicate target of #' + E(c.duplicateOf) : '') + '</td></tr>';
        }
        h += '</tbody></table></div><div class="blockfoot"><span>' + E(first) + '-' + E(first+rows.length) +
            ' / ' + E(tls.callbacks.length) + '</span><div class="btns"><button id="prevTls" ' +
            (page ? '' : 'disabled') + '>Previous callbacks</button><button id="nextTls" ' +
            (first+rows.length < tls.callbacks.length ? '' : 'disabled') + '>Next callbacks</button></div></div></section>';
        $('content').innerHTML = h;
        $('prevTls').onclick = () => navigate(pageId(page-1));
        $('nextTls').onclick = () => navigate(pageId(page+1));
        $('connections').innerHTML = '<h3 class="eyebrow">TLS provenance</h3><div class="info">' +
            'PE data directory 9 locates the header by RVA. Its callback-array pointer and array values are VAs. ' +
            'The source of each candidate is its pointer slot, not a fabricated caller. ' +
            'Incomplete arrays remain visible but add no automatic roots.</div>';
        $('renamebox').hidden = true; renderSidebar();
    }
    const oldBlock = renderBlock;
    renderBlock = function (b, focus) {
        oldBlock(b, focus);
        const entries = tls.callbacks.filter(c => c.targetRva !== null && Number(c.targetRva) === b.rva);
        if (!entries.length) return;
        let h = '<details class="tls-evidence info"><summary>TLS callback references (' + entries.length + ')</summary>' +
            '<p>Encoded loader entries; not observed runtime calls.</p>';
        for (const c of entries.slice(0,100)) h += '<p>' + link(pageId(Math.floor(c.index/pageSize)),
            'Callback #' + c.index + ' / ' + c.discovery, focus || b.id) + ' / slot ' + bytesLink(c.slotRva, focus || b.id) + '</p>';
        if (entries.length > 100) h += '<p>First 100 shown; use TLS metadata for all slots.</p>';
        $('connections').insertAdjacentHTML('beforeend', h + '</details>');
    };
    const oldRoute = route, oldNavigate = navigate;
    route = function () {
        const page = pageNumber(location.hash.slice(1));
        if (page !== null) renderTls(page); else oldRoute();
    };
    navigate = function (id, from) {
        if (pageNumber(id) === null) return oldNavigate(id, from);
        if (from && location.hash !== '#' + from) history.replaceState(null, '', '#' + from);
        if (location.hash !== '#' + id) history.pushState(null, '', '#' + id);
        route();
    };
    const onHistory = () => {if (pageNumber(location.hash.slice(1)) !== null) route();};
    window.addEventListener('popstate', onHistory); window.addEventListener('hashchange', onHistory);
    const button = document.createElement('button'); button.id = 'tlsMetadata';
    button.textContent = 'TLS callbacks (' + tls.callbacks.length + ')';
    button.onclick = () => navigate(prefix, I.has(location.hash.slice(1)) ? location.hash.slice(1) : undefined);
    $('metadataTools').append(button);
    route();
})();
