'use strict';
(function (root) {
    function markup(analysis, E, sourceLink) {
        if (!analysis.sites.length && analysis.status !== 'invalid') return '';
        return '<details id="pseudoCalls" class="pseudo-calls"' + (analysis.applied || analysis.status === 'invalid' ? ' open' : '') +
            '><summary>Call assumptions / ' + analysis.applied + ' selected</summary><p>' + E(analysis.notice) + '</p>' +
            (analysis.status === 'invalid' ? '<p class="datawarning">No summaries applied: ' + E(analysis.reason) + '</p>' : '') +
            '<p>Selections stay in this open report. Export them to reuse in the CLI or after reloading. They are separate from display labels.</p>' +
            '<div class="pseudo-flow-table"><table><thead><tr><th>Call site</th><th>Contract</th></tr></thead><tbody>' +
            analysis.sites.map(s => '<tr><td>' + sourceLink(s.source) + '</td><td><select class="pseudo-call-profile" data-source="' + E(s.source) + '"' +
                (s.eligible ? '' : ' disabled') + ' aria-label="Call contract at 0x' + s.rva.toString(16) + '">' +
                '<option value="">Unknown / all-state barrier</option><option value="' + E(WEACallSummaries.PROFILE.id) + '"' +
                (s.profile ? ' selected' : '') + '>Assume Windows x64 / normal return</option></select>' +
                (s.reason ? '<p>' + E(s.reason) + '</p>' : '') + '</td></tr>').join('') + '</tbody></table></div>' +
            '<p>Selected contracts retain RBX, RBP, RSI, RDI, RSP and R12–R15. RAX, RCX, RDX and R8–R11 become unknown, including unused return bits. All memory may be read or modified; flags and unmodeled vector state are unknown. CALL pushes an 8-byte return address; the complete call/return boundary has net RSP change zero. Home space belongs to the callee.</p>' +
            '<button id="pseudoCallsExport">Export call assumptions</button> <button id="pseudoCallsImport">Import call assumptions</button> ' +
            '<button id="pseudoCallsReset">Clear call assumptions</button><input id="pseudoCallsFile" type="file" accept="application/json,.json" hidden></details>';
    }
    function bind(analysis, onChange, message) {
        const $ = id => document.getElementById(id), host = $('pseudoCalls');
        if (!host) return;
        for (const select of host.querySelectorAll('.pseudo-call-profile')) select.onchange = () => {
            const sites = analysis.assumptions.sites.filter(s => s.source !== select.dataset.source);
            if (select.value) sites.push({source: select.dataset.source, profile: select.value});
            onChange({...analysis.assumptions, sites});
        };
        $('pseudoCallsReset').onclick = () => onChange(null);
        $('pseudoCallsExport').onclick = () => {
            const url = URL.createObjectURL(new Blob([JSON.stringify(analysis.assumptions, null, 2) + '\n'], {type: 'application/json'}));
            const a = document.createElement('a'); a.href = url; a.download = 'call-assumptions.json'; a.click();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        };
        $('pseudoCallsImport').onclick = () => $('pseudoCallsFile').click();
        $('pseudoCallsFile').onchange = async event => {
            const file = event.target.files[0]; if (!file) return;
            try {
                if (file.size > WEACallSummaries.LIMITS.fileBytes) throw Error('Call-assumption file exceeds 64 KiB.');
                onChange(JSON.parse(await file.text()) ?? {});
            } catch (e) {onChange(null); message('Call assumptions cleared: ' + e.message);}
        };
    }
    root.WEACallSummaryView = {markup, bind};
})(globalThis);
