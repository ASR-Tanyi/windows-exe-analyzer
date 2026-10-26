'use strict';
(function (root) {
    function markup(analysis, E, sourceLink) {
        const bitRanges = mask => {
            const value = BigInt(mask), ranges = [];
            for (let n = 0; n < 64; n++) if (value & (1n << BigInt(n))) {
                const start = n;
                while (n < 63 && value & (1n << BigInt(n + 1))) n++;
                ranges.push(start === n ? String(n) : start + '–' + n);
            }
            return 'Bits ' + ranges.join(', ');
        };
        const evidence = sources => sources.length ? '<details><summary>Sources (' + sources.length + ')</summary>' +
            sources.map(s => '<p>' + sourceLink(s) + '</p>').join('') + '</details>' : '';
        const slice = a => a.kind === 'write' ?
            'Written bits ' + a.slice.offset + '–' + (a.slice.offset + a.slice.width - 1) + (a.zeroExtend ? '; upper 32 bits zeroed' : '') :
            a.kind === 'entry' ? 'Incoming register value' : 'Unknown after call / unsupported instruction';
        const values = alternatives => alternatives.length ? alternatives.map((a,n) => '<div class="pseudo-abi-value">' +
            (alternatives.length > 1 ? '<span class="muted">Alternative ' + (n + 1) + '</span><br>' : '') +
            E(slice(a)) + (a.source ? '<br>' + sourceLink(a.source) : '') + '</div>').join('') : 'Unknown';
        let h = '<details id="pseudoFunctionABI" class="pseudo-detail"><summary>Function contract and candidates</summary>' +
            '<p><label for="pseudoFunctionProfile">Function convention </label><select id="pseudoFunctionProfile"' + (analysis.eligible ? '' : ' disabled') + '>' +
            '<option value="">Unknown</option><option value="' + E(WEAFunctionABI.PROFILE.id) + '"' + (analysis.contract.profile ? ' selected' : '') +
            '>Assume Windows x64</option></select></p>';
        if (analysis.status !== 'available') h += '<p' + (analysis.status === 'invalid' || analysis.status === 'budget_exceeded' ? ' class="datawarning"' : '') + '>' + E(analysis.reason) + '</p>';
        if (analysis.contract.profile) h += '<p>' + E(analysis.notice) + '</p>';
        if (analysis.status === 'available') {
            if (analysis.conflicts.length) h += '<div class="datawarning">Observed contract conflicts:' + analysis.conflicts.map(c => '<p>' + E(c.reason) + ' ' + sourceLink(c.source) + '</p>').join('') + '</div>';
            h += '<h4>Possible register inputs</h4><p>Positions are ABI register slots, not a parameter count. Reads can be copies, spills or address calculations. Observed widths are machine accesses, not C types.</p>';
            if (analysis.arguments.length) h += '<div class="pseudo-flow-table"><table class="pseudo-abi-inputs"><thead><tr><th>Position</th><th>Register</th><th>Observed entry bits</th><th>Evidence</th></tr></thead><tbody>' +
                analysis.arguments.map(a => '<tr><td>' + a.position + '</td><td><code>' + E(a.register) + '</code></td><td>' + E(bitRanges(a.mask)) + '</td><td>' + evidence(a.sources) + '</td></tr>').join('') + '</tbody></table></div>';
            else h += '<p>No supported incoming argument-register reads found. This does not prove a zero-argument function.</p>';
            h += '<h4>Possible return values</h4><p>RAX is inspected at each reachable RET. A value can be incidental in a void function; partial writes do not establish the return width. Alternatives remain separate.</p>';
            if (analysis.returns.length) h += '<div class="pseudo-flow-table"><table class="pseudo-abi-returns"><thead><tr><th>Return</th><th>RAX evidence</th><th>Sources</th></tr></thead><tbody>' +
                analysis.returns.map(r => '<tr><td>' + sourceLink(r.source) + '</td><td>' + values(r.alternatives) + '</td><td>' + evidence(r.sources) + '</td></tr>').join('') + '</tbody></table></div>';
            else h += '<p>No supported reachable RET found. Nonreturning behavior is not established.</p>';
            if (analysis.callers.length) h += '<h4>Direct caller observations</h4><p>Each site shows all four register locations. A preceding write does not establish an argument. Return reads are conditional on reaching the recorded continuation. Caller entry conventions are unknown; indirect callers are outside this view.</p>' +
                analysis.callers.map(c => '<details class="pseudo-abi-caller"><summary>Call' + (Number.isSafeInteger(c.rva) ? ' at 0x' + c.rva.toString(16) : ' site') + '</summary><p>' + sourceLink(c.source) + '</p>' +
                    (c.status !== 'observed' ? '<p>' + E(c.reason) + '</p>' : '<div class="pseudo-flow-table"><table><thead><tr><th>Location</th><th>Reaching value</th><th>Evidence</th></tr></thead><tbody>' +
                    c.arguments.map(a => '<tr><td>' + a.position + ' · <code>' + E(a.register) + '</code></td><td>' + values(a.alternatives) + '</td><td>' + evidence(a.sources) + '</td></tr>').join('') +
                    '</tbody></table></div><p>' + (c.returnUses.length ? c.returnUses.length + ' supported read(s) of the call-produced RAX bits before overwrite.' :
                        'No supported read of call-produced RAX bits found; this does not establish a void return.') + '</p>' + evidence(c.returnUses.flatMap(u => u.sources).filter((s,n,a) => a.indexOf(s) === n))) + '</details>').join('');
            else h += '<p>No direct caller evidence is available in the discovered graph.</p>';
            if (analysis.assumptionSources.length) h += '<p>Some function evidence also depends on selected call assumptions:</p>' + evidence(analysis.assumptionSources);
        }
        h += '<p>Selections stay in this open report. Export to reuse; reloading clears them. This function contract is separate from call-site assumptions and display labels.</p>' +
            '<button id="pseudoFunctionExport">Export function contract</button> <button id="pseudoFunctionImport">Import function contract</button> ' +
            '<button id="pseudoFunctionReset">Clear function contract</button><input id="pseudoFunctionFile" type="file" accept="application/json,.json" hidden></details>';
        return h;
    }
    function bind(analysis,onChange,message) {
        const $ = id => document.getElementById(id); if (!$('pseudoFunctionABI')) return;
        $('pseudoFunctionProfile').onchange = e => onChange({...analysis.contract,profile:e.target.value || null});
        $('pseudoFunctionReset').onclick = () => onChange(null);
        $('pseudoFunctionExport').onclick = () => {
            const url = URL.createObjectURL(new Blob([JSON.stringify(analysis.contract,null,2) + '\n'],{type:'application/json'}));
            const a = document.createElement('a'); a.href = url; a.download = 'function-contract.json'; a.click();
            setTimeout(() => URL.revokeObjectURL(url),1000);
        };
        $('pseudoFunctionImport').onclick = () => $('pseudoFunctionFile').click();
        $('pseudoFunctionFile').onchange = async event => {
            const file = event.target.files[0]; if (!file) return;
            try {
                if (file.size > WEAFunctionABI.LIMITS.fileBytes) throw Error('Function-contract file exceeds 64 KiB.');
                onChange(JSON.parse(await file.text()) ?? {});
            } catch (e) {onChange(null); message('Function contract cleared: ' + e.message);}
        };
    }
    root.WEAFunctionABIView = {markup,bind};
})(globalThis);
