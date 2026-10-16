'use strict';
// Independent schema-2 extension. Raw metadata never becomes decoded coverage.
(() => {
    const meta = D.exceptionDirectory;
    if (!meta || meta.version !== 1) return;
    const prefix = D.module.id + '_exceptions';
    const pageSize = 100;
    const unwindNodes = new Set((D.unwindInfo?.nodes || []).map(n => n.rva));
    const unwindChecks = new Map((D.unwindInfo?.records || []).map(r => [r.recordIndex, r]));
    const pageId = page => page ? prefix + '_p' + page : prefix;
    const pageNumber = id => {
        if (id === prefix) return 0;
        if (typeof id !== 'string' || !id.startsWith(prefix + '_p')) return null;
        const suffix = id.slice(prefix.length + 2);
        if (!/^[1-9][0-9]{0,5}$/.test(suffix)) return null;
        const n = Number(suffix);
        return n * pageSize < meta.records.length ? n : null;
    };
    function dataLink(value, from) {
        const id = dataId(Number(value));
        return isDataId(id) ? link(id, value, from) : E(value);
    }
    function renderMetadata(page) {
        const id = pageId(page), first = page * pageSize;
        selected = id;
        const rows = meta.records.slice(first, first + pageSize);
        let h = '<section class="blockcard"><div class="blockhead">' +
            '<div class="eyebrow">AMD64 exception directory / metadata only</div>' +
            '<h2 class="blocktitle">Runtime-function records</h2>' +
            '<div class="addressmeta">Directory RVA ' + dataLink(meta.directoryRva, id) +
            ' / ' + E(meta.directorySize) + ' bytes / status: ' + E(meta.status) + '</div></div>' +
            '<div class="summary">These encoded ranges are not decoded coverage or proven source-function boundaries. ' +
            (D.unwindInfo ? 'Supported version-1 unwind structures are checked separately. ' + (D.unwindInfo.discoveryEnabled ? 'Only eligible records seed candidate entries. ' : 'No discovery seeds are added (disabled). ') + 'No runtime stack unwinding is performed.</div>' : 'Unwind semantics, chained records, and handlers are not decoded. No discovery seeds are added in this step.</div>') +
            '<div class="info">Read ' + E(meta.records.length) + ' of ' + E(meta.declaredRecords) +
            ' declared records; omitted: ' + E(meta.omittedRecords) + '. Record limit: ' + E(meta.recordLimit) +
            '. Trailing bytes: ' + E(meta.trailingBytes) + '.</div>';
        for (const issue of meta.issues) h += '<div class="datawarning">' + E(issue) + '</div>';
        if (meta.status === 'absent') h += '<p class="interpret">No exception directory is declared. This does not mean the image contains no functions.</p>';
        h += '<div class="assemblywrap"><table id="exceptionRecords"><thead><tr>' +
            '<th>Index / record RVA</th><th>Encoded range [begin, end)</th><th>Unwind RVA</th><th>Validation</th></tr></thead><tbody>';
        for (const r of rows) {
            const iid = D.module.id + '_i_' + Number(r.beginRva).toString(16);
            const code = I.has(iid) ? link(iid, r.beginRva, id, 'exception-code') : E(r.beginRva) + ' (not decoded)';
            h += '<tr><td>' + E(r.index) + '<br>' + dataLink(r.tableRva, id) + '</td><td>[' + code +
                ', ' + E(r.endRva) + ')</td><td>' + dataLink(r.unwindRva, id) +
                '</td><td style="white-space:normal;min-width:180px">' + E(r.validation) +
                '<br><span class="small muted">Range file-backed: ' + E(r.rangeFileBacked) +
                '; unwind header address readable: ' + E(r.unwindAddressFileBacked) + '</span>' +
                r.issues.map(x => '<br>' + E(x)).join('') +
                (r.duplicateOf !== null ? '<br>Duplicate of #' + E(r.duplicateOf) : '') +
                (r.overlapWith !== null ? '<br>Overlap witness #' + E(r.overlapWith) : '') +
                (unwindChecks.has(r.index) ? '<br>' + (unwindNodes.has(r.unwindRva) ? link(D.module.id + '_unwind_' + Number(r.unwindRva).toString(16), 'Unwind: ' + unwindChecks.get(r.index).status, id, 'unwind-link') : E('Unwind: ' + unwindChecks.get(r.index).status)) + '<br>Discovery: ' + E(unwindChecks.get(r.index).discovery) : '') + '</td></tr>';
        }
        h += '</tbody></table></div><div class="blockfoot"><span>' +
            E(first) + '-' + E(first + rows.length) + ' / ' + E(meta.records.length) +
            '</span><div class="btns"><button id="prevMetadata" ' + (page ? '' : 'disabled') +
            '>Previous records</button><button id="nextMetadata" ' +
            (first + rows.length < meta.records.length ? '' : 'disabled') + '>Next records</button></div></div></section>';
        $('content').innerHTML = h;
        $('prevMetadata').onclick = () => navigate(pageId(page - 1));
        $('nextMetadata').onclick = () => navigate(pageId(page + 1));
        $('connections').innerHTML = '<h3 class="eyebrow">Metadata provenance</h3><div class="info">PE data directory index 3. ' +
            'Each record contains three 32-bit RVAs. A readable unwind address is not validation of the unwind program. ' +
            'Links open original file bytes or instructions already decoded by the existing traversal.</div>';
        $('renamebox').hidden = true;
        renderSidebar();
    }
    const previousRoute = route, previousNavigate = navigate;
    route = function () {
        const page = pageNumber(location.hash.slice(1));
        if (page !== null) renderMetadata(page); else previousRoute();
    };
    navigate = function (id, from) {
        if (pageNumber(id) === null) return previousNavigate(id, from);
        if (from && location.hash !== '#' + from) history.replaceState(null, '', '#' + from);
        if (location.hash !== '#' + id) history.pushState(null, '', '#' + id);
        route();
    };
    // Earlier listeners captured the old route function; restore metadata after
    // those listeners on browser back/forward and manually edited deep links.
    const onMetadataHistory = () => { if (pageNumber(location.hash.slice(1)) !== null) route(); };
    window.addEventListener('popstate', onMetadataHistory);
    window.addEventListener('hashchange', onMetadataHistory);
    const button = document.createElement('button');
    button.id = 'exceptionMetadata';
    button.textContent = 'Exception metadata (' + meta.records.length + ')';
    button.onclick = () => navigate(prefix, I.has(location.hash.slice(1)) ? location.hash.slice(1) : undefined);
    $('notes').before(button);
    route();
})();
