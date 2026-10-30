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
        const declarations = analysis.contract.declarations || [];
        const types = new Map((analysis.declarationTypes || []).map(d => [d.declaration,d]));
        const syntax = t => t ? '<span class="pseudo-type-annotation" data-type-status="' + E(t.status) + '">' + E(WEADeclarationTypes.describe(t)) + '</span>' : '';
        const aliasDefinitions=analysis.contract.typeAliases || [], aliasResults=new Map((analysis.declarationAliases || []).map(a=>[a.name,a.result]));
        const aliasMarkup='<details id="pseudoTypeAliases"><summary>Type alias definitions (' + aliasDefinitions.length + ')</summary>' +
            '<p>These supplied definitions apply to every declaration in this function contract. Source labels are analyst provenance. No headers are searched. Missing definitions, cycles and excessive expansion remain unparsed. Qualifiers apply to the aliased type: if P means int *, const P means int * const.</p>' +
            aliasDefinitions.map(a=>'<section class="pseudo-type-alias"><h4>' + E(a.name) + '</h4><p>Definition: <code>' + E(a.type) + '</code><br>Source: ' + E(a.source) + '<br>' + syntax(aliasResults.get(a.name)) + '</p></section>').join('') +
            '<label for="pseudoAliasEditor">Edit type aliases as JSON (maximum 32)</label><textarea id="pseudoAliasEditor" rows="8" style="width:100%;box-sizing:border-box" spellcheck="false">' + E(JSON.stringify(aliasDefinitions,null,2)) + '</textarea>' +
            '<p><button id="pseudoAliasExample">Add example alias</button> <button id="pseudoAliasApply">Apply type aliases</button> <button id="pseudoAliasClear">Clear type aliases</button></p></details>';
        const comparisonField = field => ({returnType:'Return annotation',parameterCount:'Supplied parameter records',variadic:'Variadic',hiddenParameters:'Hidden parameters'}[field] ||
            field.replace(/^parameter\[(\d+)\]\.type$/, 'Parameter $1 annotation'));
        const comparisonSide = (field,side) => field.kind === 'type' ?
            '<code>' + E(side.status === 'missing' ? '(no supplied record)' : side.label ?? 'unknown') + '</code><br>' + E(side.canonical ? 'Parsed: ' + side.canonical : side.reason) +
            (side.aliases?.length ? '<br>' + E(WEADeclarationTypes.aliasDescription(side)) : '') : E(String(side));
        const comparisons = (analysis.declarationComparisons || []).length ?
            '<details id="pseudoDeclarationComparisons"><summary>Parsed declaration comparisons (' + analysis.declarationComparisons.length + ')</summary>' +
            '<p>Fields compare supplied annotations. Same parsed forms do not verify a prototype; different forms do not prove machine incompatibility. Qualifiers are compared at every written level. Only supplied aliases are expanded; other names and parameter adjustments remain outside this comparison. Every declaration and textual disagreement remains retained.</p>' +
            analysis.declarationComparisons.map(c => '<details id="pseudoComparison_' + E(c.declarations.join(':')) + '" class="pseudo-declaration-comparison"><summary>' + E(c.declarations.join(' / ')) + ' · ' + E(WEADeclarationTypes.comparisonSummary(c)) + '</summary>' +
                '<div class="pseudo-flow-table" tabindex="0" role="region" aria-label="Parsed comparison ' + E(c.declarations.join(' / ')) + '"><table><thead><tr><th>Field</th><th>' + E(c.declarations[0]) + '</th><th>' + E(c.declarations[1]) + '</th><th>Comparison</th></tr></thead><tbody>' +
                c.fields.map(f => '<tr data-comparison-status="' + E(f.status) + '"><td>' + E(comparisonField(f.field)) + '</td><td>' + comparisonSide(f,f.left) + '</td><td>' + comparisonSide(f,f.right) + '</td><td>' +
                    E(WEADeclarationTypes.comparisonLabel(f)) + '<br>' + E(f.reason) + (f.differences || []).map(d => '<br>' + E(WEADeclarationTypes.describeDifference(d))).join('') + '</td></tr>').join('') +
                '</tbody></table></div></details>').join('') + '</details>' : '';
        const locations=(analysis.declarationLocations || []).length ?
            '<details id="pseudoDeclaredLocations"><summary>Declared ABI locations ('+analysis.declarationLocations.length+')</summary><p>'+E(WEADeclarationABI.NOTICE)+'</p>'+
            analysis.declarationLocations.map(d=>'<details id="pseudoDeclaredABI_'+E(d.declaration)+'" class="pseudo-declaration-locations"><summary>'+E(d.declaration)+' · '+
                (d.status==='mapped'?'conditional locations':'unresolved')+'</summary><p>Source: '+E(d.source)+'</p>'+
                (d.blockers.length?'<ul class="pseudo-location-blockers">'+d.blockers.map(b=>'<li>'+E(comparisonField(b.field))+': '+E(b.reason)+'</li>').join('')+'</ul>':'')+
                '<div class="pseudo-flow-table" tabindex="0" role="region" aria-label="Declared ABI locations '+E(d.declaration)+'"><table><thead><tr><th>Supplied annotation</th><th>Declared location</th><th>Basis</th></tr></thead><tbody>'+
                [d.returnType,...d.parameters].map((r,n)=>'<tr data-location-status="'+E(r.status)+'"><td>'+E(n?'Parameter '+n+(r.name?' · '+r.name:''):'Return')+'<br><code>'+E(r.label ?? 'unknown')+'</code>'+
                    (r.canonical?'<br>Parsed: '+E(r.canonical):'')+'</td><td>'+E(WEADeclarationABI.describe(r))+'</td><td>'+E(r.reason)+(r.aliases.length?'<br>'+E(WEADeclarationTypes.aliasDescription(r)):'')+'</td></tr>').join('')+
                '</tbody></table></div></details>').join('')+'</details>' : '';
        h += '<details id="pseudoDeclarations" style="overflow-wrap:anywhere"><summary>Analyst declarations (' + declarations.length + ')</summary>' +
            '<p>These are supplied annotations, not recovered C signatures. All original labels are retained. Supported scalar and pointer forms are parsed below; undefined names and complex declarations remain unparsed. Parsing does not infer widths, ABI locations or memory behavior. Unknown variadic/hidden-parameter status prevents fixed-count review hints.</p>' + aliasMarkup +
            declarations.map(d => '<section class="pseudo-declaration"><h4>' + E(d.id) + '</h4><p>Source: ' + E(d.source) + '</p><p>Return annotation: <code>' + E(d.returnType ?? 'unknown') + '</code><br>' + syntax(types.get(d.id)?.returnType) + '</p>' +
                '<p>Variadic: ' + E(d.variadic) + '; hidden parameters: ' + E(d.hiddenParameters) + '</p>' +
                '<ol>' + d.parameters.map((p,n) => '<li><code>' + E(p.name || '(unnamed)') + ': ' + E(p.type ?? 'unknown') + '</code><br>' + syntax(types.get(d.id)?.parameters[n]) + '</li>').join('') + '</ol></section>').join('') +
            comparisons + locations +
            (analysis.declarationConflicts || []).map(c => '<p class="datawarning pseudo-declaration-conflict">' + E(c.declarations.join(' / ')) + ': ' + E(c.fields.join(', ')) + '. ' + E(c.reason) + '</p>').join('') +
            (analysis.declarationReviews || []).map(c => '<div class="pseudo-declaration-review"><p>' + E(c.declaration) + ': ' + E(c.reason) + '</p>' + evidence(c.sources) + '</div>').join('') +
            '<p>No disagreement or review hint does not verify a declaration.</p><label for="pseudoDeclarationEditor">Edit declarations as JSON (maximum 8)</label>' +
            '<textarea id="pseudoDeclarationEditor" rows="12" style="width:100%;box-sizing:border-box" spellcheck="false">' + E(JSON.stringify(declarations,null,2)) + '</textarea>' +
            '<p><button id="pseudoDeclarationExample">Add blank declaration</button> <button id="pseudoDeclarationApply">Apply declarations</button> <button id="pseudoDeclarationClear">Clear declarations</button></p></details>';
        if (analysis.status !== 'available') h += '<p' + (analysis.status === 'invalid' || analysis.status === 'budget_exceeded' ? ' class="datawarning"' : '') + '>' + E(analysis.reason) + '</p>';
        if (analysis.contract.profile) h += '<p>' + E(analysis.notice) + '</p>';
        if (analysis.status === 'available') {
            if (analysis.conflicts.length) h += '<div class="datawarning">Observed contract conflicts:' + analysis.conflicts.map(c => '<p>' + E(c.reason) + ' ' + sourceLink(c.source) + '</p>').join('') + '</div>';
            h += '<h4>Possible register inputs</h4><p>Positions are ABI register slots, not a parameter count. Reads can be copies, spills or address calculations. Observed widths are machine accesses, not C types.</p>';
            if (analysis.arguments.length) h += '<div class="pseudo-flow-table"><table class="pseudo-abi-inputs"><thead><tr><th>Position</th><th>Register</th><th>Observed entry bits</th><th>Evidence</th></tr></thead><tbody>' +
                analysis.arguments.map(a => '<tr><td>' + a.position + '</td><td><code>' + E(a.register) + '</code></td><td>' + E(bitRanges(a.mask)) + '</td><td>' + evidence(a.sources) + '</td></tr>').join('') + '</tbody></table></div>';
            else h += '<p>No supported incoming argument-register reads found. This does not prove a zero-argument function.</p>';
            h += '<h4>Possible incoming stack inputs</h4><p>' + E(analysis.stackScope || 'Stack evidence unavailable in this report version.') + '</p>';
            if (analysis.stackReason) h += '<p>' + E(analysis.stackReason) + '</p>';
            if (analysis.stackArguments?.length) h += '<div class="pseudo-flow-table"><table class="pseudo-abi-stack"><thead><tr><th>ABI slot</th><th>Entry address</th><th>Read width</th><th>Evidence</th></tr></thead><tbody>' +
                analysis.stackArguments.map(a => '<tr><td>' + a.position + '</td><td>entry RSP + ' + E(a.entryOffset) + '</td><td>' + a.width + ' bits</td><td>' + evidence(a.sources) + '</td></tr>').join('') + '</tbody></table></div>';
            else h += '<p>No supported untouched entry-stack reads found; this does not prove the absence of stack parameters.</p>';
            h += '<h4>Possible return values</h4><p>RAX is inspected at each reachable RET. A value can be incidental in a void function; partial writes do not establish the return width. Alternatives remain separate.</p>';
            if (analysis.returns.length) h += '<div class="pseudo-flow-table"><table class="pseudo-abi-returns"><thead><tr><th>Return</th><th>RAX evidence</th><th>Sources</th></tr></thead><tbody>' +
                analysis.returns.map(r => '<tr><td>' + sourceLink(r.source) + '</td><td>' + values(r.alternatives) + '</td><td>' + evidence(r.sources) + '</td></tr>').join('') + '</tbody></table></div>';
            else h += '<p>No supported reachable RET found. Nonreturning behavior is not established.</p>';
            if (analysis.callers.length) h += '<h4>Direct caller observations</h4><p>Each site shows all four register locations. A preceding write does not establish an argument. Return reads are conditional on reaching the recorded continuation. Caller entry conventions are unknown; indirect callers are outside this view.</p>' +
                analysis.callers.map(c => '<details class="pseudo-abi-caller"><summary>Call' + (Number.isSafeInteger(c.rva) ? ' at 0x' + c.rva.toString(16) : ' site') + '</summary><p>' + sourceLink(c.source) + '</p>' +
                    (c.status !== 'observed' ? '<p>' + E(c.reason) + '</p>' : '<div class="pseudo-flow-table"><table><thead><tr><th>Location</th><th>Reaching value</th><th>Evidence</th></tr></thead><tbody>' +
                    c.arguments.map(a => '<tr><td>' + a.position + ' · <code>' + E(a.register) + '</code></td><td>' + values(a.alternatives) + '</td><td>' + evidence(a.sources) + '</td></tr>').join('') +
                    '</tbody></table></div>' + (c.stackArguments?.length ? '<h5>Stack slots read by this callee</h5><p>Matching stores cover the observed read bytes, not a recovered type or full argument. Missing evidence stays unknown.</p>' +
                    c.stackArguments.map(a => '<p class="pseudo-abi-stack-match">Slot ' + a.position + ': ' + (a.status === 'matched_store' ? 'matching preceding store' : 'unknown store') + '</p>' + evidence(a.sources)).join('') : '') +
                    (c.stackReason ? '<p>' + E(c.stackReason) + '</p>' : '') + '<p>' + (c.returnUses.length ? c.returnUses.length + ' supported read(s) of the call-produced RAX bits before overwrite.' :
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
        const applyAnnotations = patch => {
            const value={...analysis.contract,...patch};
            if (new TextEncoder().encode(JSON.stringify(value,null,2)+'\n').length>WEAFunctionABI.LIMITS.fileBytes) throw Error('Function contract exceeds 64 KiB.');
            onChange(value);
        };
        const aliasPatch = typeAliases => ({version:3,declarations:analysis.contract.declarations || [],typeAliases});
        $('pseudoAliasExample').onclick = () => {
            try {
                const list=WEADeclarationTypes.normalizeAliases(JSON.parse($('pseudoAliasEditor').value));
                let n=1; while (list.some(a=>a.name==='Pointer'+n)) n++;
                list.push({name:'Pointer'+n,source:'Analyst note',type:'int *'}); WEADeclarationTypes.normalizeAliases(list);
                $('pseudoAliasEditor').value=JSON.stringify(list,null,2);
            } catch (e) {message('Type aliases unchanged: '+e.message);}
        };
        $('pseudoAliasApply').onclick = () => {
            try {
                const input=$('pseudoAliasEditor').value;
                if (new TextEncoder().encode(input).length>WEAFunctionABI.LIMITS.fileBytes) throw Error('Type aliases exceed 64 KiB.');
                applyAnnotations(aliasPatch(WEADeclarationTypes.normalizeAliases(JSON.parse(input))));
            } catch (e) {message('Type aliases unchanged: '+e.message);}
        };
        $('pseudoAliasClear').onclick = () => applyAnnotations(aliasPatch([]));
        $('pseudoDeclarationExample').onclick = () => {
            try {
                const list = WEAFunctionABI.normalizeDeclarations(JSON.parse($('pseudoDeclarationEditor').value));
                let n=1; while (list.some(d => d.id === 'declaration-'+n)) n++;
                list.push({id:'declaration-'+n,source:'Analyst note',returnType:null,parameters:[],variadic:'unknown',hiddenParameters:'unknown'});
                WEAFunctionABI.normalizeDeclarations(list);
                $('pseudoDeclarationEditor').value = JSON.stringify(list,null,2);
            } catch (e) {message('Declarations unchanged: ' + e.message);}
        };
        $('pseudoDeclarationApply').onclick = () => {
            try {
                const input=$('pseudoDeclarationEditor').value;
                if (new TextEncoder().encode(input).length > WEAFunctionABI.LIMITS.fileBytes) throw Error('Declarations exceed 64 KiB.');
                const declarations=WEAFunctionABI.normalizeDeclarations(JSON.parse(input));
                applyAnnotations({version:Math.max(2,analysis.contract.version),declarations});
            } catch (e) {message('Declarations unchanged: ' + e.message);}
        };
        $('pseudoDeclarationClear').onclick = () => applyAnnotations({version:Math.max(2,analysis.contract.version),declarations:[]});
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
