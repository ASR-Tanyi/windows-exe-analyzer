'use strict';
(() => {
    if (D.schema !== 2 || !globalThis.WEAPseudocodeModel) return;
    const prefix = D.module.id + '_c_', fnPrefix = D.module.id + '_fn_';
    const functions = new Map(D.functions.map(f => [f.id, f]));
    const byRva = new Map(D.functions.map(f => [f.rva, f]));
    let active = null, aliasesEnabled = true, expressionsEnabled = true, cleanupEnabled = true;
    const callAssumptions = new Map();
    const functionContracts = new Map();
    const idFor = f => prefix + f.rva.toString(16);
    function parse(id) {
        if (!id.startsWith(prefix)) return null;
        const m = /^([0-9a-f]{1,8})$/.exec(id.slice(prefix.length));
        return m ? byRva.get(parseInt(m[1], 16)) || null : null;
    }
    const assembly = (f, source) => fnPrefix + f.rva.toString(16) +
        (source && I.has(source) ? '_at_' + I.get(source).insn.rva.toString(16) : '');
    function context() {
        if (active) return active;
        if (functions.has(selected)) return functions.get(selected);
        const block = B.get(selected) || I.get(location.hash.slice(1))?.block;
        const owners = [...new Set(block?.owners || [])].filter(id => functions.has(id));
        return owners.length === 1 ? functions.get(owners[0]) : null;
    }
    function valueText(value) {
        if (!value) return 'unknown';
        const atom = a => a.kind === 'stack' ? 'entry_sp ' + (BigInt(a.offset) < 0n ? '- ' : '+ ') +
            '0x' + (BigInt(a.offset) < 0n ? -BigInt(a.offset) : BigInt(a.offset)).toString(16) :
            a.kind === 'module' ? 'module RVA ' + hex(Number(a.rva)) :
            a.kind === 'import' ? a.symbol : '0x' + BigInt(a.value).toString(16);
        return (value.atoms ? value.atoms.map(atom).join(' or ') :
            'known bits ' + value.knownValue + ' / mask ' + value.knownMask) + (value.proofTruncated ? ' (proof capped)' : '');
    }
    const viewStates = new Map();
    function render(f) {
        // toggle events are queued: capture live state before replacing details
        // when a user opens a panel and immediately changes an analysis option.
        if (active?.id === f.id && viewStates.has(f.id))
            for (const detail of document.querySelectorAll('.pseudocode-overview details[id]'))
                viewStates.get(f.id).open.set(detail.id, detail.open);
        active = f; selected = f.id; setTab('functions');
        if (!viewStates.has(f.id)) viewStates.set(f.id,{tab:'code',source:null,definition:null,open:new Map()});
        const state = viewStates.get(f.id);
        const model = WEAPseudocodeModel.recover(D,f.id,{callAssumptions:callAssumptions.get(f.id),functionContract:functionContracts.get(f.id)}), s = model.stats, va = model.valueAnalysis;
        const instructionText = id => {const i = I.get(id)?.insn; return i ? hex(i.rva) + ' ' + i.mnemonic + (i.operands ? ' ' + i.operands : '') : id;};
        const sourceLink = id => {
            const record = I.get(id), owners = [...new Set(record?.block.owners || [])];
            const owner = owners.length === 1 ? functions.get(owners[0]) : null;
            return record ? link(owner ? assembly(owner,id) : id,instructionText(id),idFor(f),'pseudo-source') : E(id);
        };
        const prefix = expressionsEnabled ? (cleanupEnabled ? 'simplifiedClean' : 'simplified') : (cleanupEnabled ? 'clean' : '');
        const lines = model[prefix + (aliasesEnabled ? (prefix ? 'DisplayLines' : 'displayLines') : (prefix ? 'Lines' : 'lines'))];
        const flowAvailable = model.registerSSA?.status === 'available';
        if (!flowAvailable && state.tab === 'flow') state.tab = 'code';
        let h = '<section class="blockcard pseudocode-overview"><div class="blockhead"><div class="blocktop">' +
            '<span class="eyebrow">Function</span><span class="pill amber">C-like preview</span></div><h2 class="blocktitle">' +
            E(label(B.get(f.id) || f)) + '</h2><div class="addressmeta">Entry RVA ' + hex(f.rva) + ' · ' +
            link(assembly(f),'Assembly',idFor(f),'pseudo-assembly') + ' · ' + link(D.module.id + '_cfg_' + f.rva.toString(16),'Control-flow graph',idFor(f)) + '</div></div>';
        if (model.status === 'unavailable') h += '<p class="datawarning">' + E(model.reason) + '</p>';
        else {
            const expressions = model.registerExpressions, cleanup = model.registerCleanup;
            const variant = expressionsEnabled ? cleanup.simplified : cleanup.raw;
            h += '<div class="pseudo-context"><span>' + s.supported + ' supported instructions</span>' +
                (s.ifs ? '<span>' + s.ifs + ' if region(s)</span>' : '') + (s.loops ? '<span>' + s.loops + ' loop(s)</span>' : '') +
                '<span>Machine effects; original C types and names are not recovered.</span></div>';
            const warnings = [];
            if (s.barriers) warnings.push(s.barriers + ' instruction(s) have unknown effects.');
            if (model.callAnalysis.applied) warnings.push(model.callAnalysis.applied + ' call assumption(s) are active; these contracts are not verified.');
            if (model.functionABI.contract.profile) warnings.push('The function calling convention is assumed; argument and return roles remain candidates.');
            if (model.functionABI.conflicts.length) warnings.push('Observed instructions conflict with the selected function convention.');
            if (!model.structured) warnings.push('Shared blocks or truncated discovery: explicit transfers retained.');
            if (!flowAvailable) warnings.push(model.registerSSA.reason + ' Original effects shown; original writes retained.');
            else if (expressions.status !== 'available' || cleanup.status !== 'available') warnings.push('Some display transformations are unavailable; original effects are retained.');
            if (va.status !== 'converged') warnings.push(va.reason);
            if (warnings.length) h += '<div class="datawarning pseudo-warning">' + warnings.map(E).join(' ') +
                ' <button class="pseudo-analysis-link">View analysis details</button></div>';
            h += '<div class="pseudo-tabs" role="tablist" aria-label="Function analysis">' +
                [['code','Code'],['flow','Register flow'],['analysis','Analysis details']].map(([id,title]) => '<button id="pseudoTab' + id +
                    '" type="button" role="tab" data-panel="' + id + '" aria-controls="pseudoPanel' + id + '" aria-selected="' + (state.tab === id) +
                    '" tabindex="' + (state.tab === id ? '0' : '-1') + '"' + (id === 'flow' && !flowAvailable ? ' disabled' : '') + '>' + title + '</button>').join('') + '</div>';
            const panel = id => '<div id="pseudoPanel' + id + '" class="pseudo-panel" role="tabpanel" aria-labelledby="pseudoTab' + id + '"' + (state.tab === id ? '' : ' hidden') + '>';
            h += panel('code') + '<div class="pseudo-options" role="group" aria-label="Code display">';
            if (va.slots.some(slot => slot.aliasable)) h += '<label class="pseudo-alias-toggle"><input type="checkbox" id="pseudoAliases"' +
                (aliasesEnabled ? ' checked' : '') + '> Stack aliases</label>';
            if (expressions.status === 'available') h += '<label class="pseudo-alias-toggle"><input type="checkbox" id="pseudoExpressions"' +
                (expressionsEnabled ? ' checked' : '') + '> Simplify expressions</label>';
            if (cleanup.status === 'available') h += '<label class="pseudo-alias-toggle"><input type="checkbox" id="pseudoCleanup"' +
                (cleanupEnabled ? ' checked' : '') + '> Remove dead writes</label>';
            h += '</div><div class="pseudo-code" role="region" aria-label="C-like pseudocode"><table><thead><tr><th>Assembly</th><th>C-like effects</th><th>Inspect</th></tr></thead><tbody>';
            const flowSources = new Set((model.registerSSA.instructions || []).map(i => i.source));
            lines.forEach((line,n) => {
                const source = line.sources.find(id => I.has(id)), trace = line.sources.find(id => flowSources.has(id));
                h += '<tr><td>' + (source ? link(assembly(f,source),hex(I.get(source).insn.rva),idFor(f),'pseudo-source') : '') +
                    '</td><td><code>' + '    '.repeat(line.depth) + E(line.text) + '</code></td><td class="pseudo-actions">' +
                    (line.sources.length ? '<button class="pseudo-evidence" data-line="' + n + '">Sources (' + line.sources.length + ')</button>' : '') +
                    (trace ? '<button class="pseudo-trace" data-source="' + E(trace) + '" aria-label="Trace register values for code line ' + (n + 1) + '">Trace value</button>' : '') + '</td></tr>';
            });
            h += '</tbody></table></div></div>' + panel('flow') + WEARegisterFlowView.markup(model.registerSSA,model.instructions,E,instructionText) + '</div>' + panel('analysis');
            h += '<h3>Evidence and assumptions</h3><p class="muted">Inspect the facts behind this function and the changes made to its display.</p>';
            h += WEACallSummaryView.markup(model.callAnalysis,E,sourceLink);
            h += WEAFunctionABIView.markup(model.functionABI,E,sourceLink);
            const storage = model.stackStorage, storageSlots = new Map(storage.slots.map(s => [s.id,s]));
            const storageEvidence = slot => {
                const s = storageSlots.get(slot.id);
                if (!s) return '<p>' + E(storage.reason) + '</p>';
                return s.roles.map(r => '<div class="pseudo-storage-role" data-certainty="' + E(r.certainty) + '"><b>' + E(r.label) +
                    (r.register ? ' · <code>' + E(r.register) + '</code>' : '') + '</b>' +
                    (r.certainty === 'proven_pair' ? ' <span class="small muted">(proven pair)</span>' : r.certainty === 'assumed' ? ' <span class="small muted">(assumed)</span>' : '') +
                    '<details class="pseudo-storage-evidence"><summary>Sources (' + r.sources.length + ')</summary>' +
                    r.sources.map(id => '<p>' + sourceLink(id) + '</p>').join('') + '</details></div>').join('') +
                    (s.mixed ? '<p class="datawarning">Overlapping or mixed uses. Do not treat this as one independent local.</p>' : '');
            };
            if (va.slots.length) h += '<details id="pseudoSlots" class="pseudo-slots pseudo-detail"><summary>Stack locations (' + va.slots.length + ')</summary>' +
                '<p>Aliases name physical memory locations, not recovered C locals. ' + va.slots.filter(s => s.aliasable).length + ' location(s) can be shown as aliases.</p>' +
                '<p>Saved-entry-register pairs require matching stores/reloads with no possible overwrite; they do not prove preservation at every exit. Calls invalidate contents. Spill, local and outgoing-argument roles are candidates; original purpose is not established. ABI regions require explicit call assumptions.</p>' +
                '<div class="pseudo-slot-table"><table><thead><tr><th>Location</th><th>Width</th><th>Role and evidence</th></tr></thead><tbody>' +
                va.slots.map(slot => '<tr><td><code>' + E(slot.id) + '</code><br>entry_sp ' + E(slot.offset) + ' bytes</td><td>' + slot.width +
                    ' bits</td><td>' + storageEvidence(slot) + '<p class="muted">' + E(slot.kind.replaceAll('_',' ')) + ': ' +
                    E(slot.reasons.length ? slot.reasons.join('; ') : 'Memory alias available') + '</p></td></tr>').join('') + '</tbody></table></div></details>';
            if (variant.rewrites.length) h += '<details class="pseudo-slots pseudo-detail" id="pseudoCleanupDetails"><summary>Cleanup: ' +
                variant.rewrites.length + ' changes / ' + (cleanupEnabled ? 'applied' : 'available, disabled') + '</summary><p>' +
                variant.stats.removed + ' pure writes removed; ' + variant.stats.flagsOnly + ' operations retain flags only.</p>' +
                '<div class="pseudo-slot-table"><table><thead><tr><th>Original write</th><th>Change</th><th>Retained overwrite</th><th>Sources</th></tr></thead><tbody>' +
                variant.rewrites.map(r => '<tr><td>' + sourceLink(r.source) + '<br><code>' + E(r.register) + '</code></td><td>' +
                    (r.kind === 'removed' ? 'Pure write removed' : 'Flags retained; register write removed') + '</td><td>' + sourceLink(r.overwrittenBy.source) +
                    '</td><td>' + r.sources.map(sourceLink).join('<br>') + '</td></tr>').join('') + '</tbody></table></div></details>';
            h += '<details id="pseudoScope" class="pseudo-detail"><summary>Coverage, transformations and limits</summary><p>Preview v' + model.version +
                ' · ' + s.supported + ' supported instruction(s) · ' + s.barriers + ' unknown effect(s).</p><p>' + E(model.notice) + '</p>' +
                [['Value analysis',va],['Register flow',model.registerSSA],['Stack storage roles',storage],['Function ABI evidence',model.functionABI],['Expression simplification',expressions],['Dead-write cleanup',cleanup]].map(([title,pass]) =>
                    '<h4>' + title + '</h4><p>' + E(pass.reason || pass.notice) + '</p>').join('') +
                '<p>' + (expressions.stats.changedOperations || 0) + ' operation(s) have simplified expressions. Disable both code transformations to inspect all original effects.</p></details></div>';
        }
        h += '</section>'; $('content').innerHTML = h;
        $('connections').innerHTML = '<h3>Inspect the code</h3><p><b>Sources</b> lists the assembly behind a line. <b>Trace value</b> opens its register reads and writes.</p>' +
            '<details class="info"><summary>Reading C-like helpers</summary><p><code>read32</code> / <code>write32</code>: 32-bit memory access at a byte address.</p>' +
            '<p><code>uN</code>: truncate to N bits. <code>sext</code>: sign extension. <code>insert</code>: preserve the untouched register bits.</p>' +
            '<p>Arithmetic helpers update <code>flags</code>; branches read those flags. A <code>slot_</code> alias still reads or writes stack memory relative to <code>entry_sp</code>.</p>' +
            '<p>Registers retain machine names. The preview does not infer original variables, C return types or I/O prototypes. Source <code>for</code> loops may appear as <code>while</code>.</p></details>';
        $('renamebox').hidden = !B.has(f.id); $('labelname').value = label(B.get(f.id) || f); $('labelnote').value = labels[f.id]?.note || '';
        const tabs = [...document.querySelectorAll('.pseudo-tabs [role="tab"]')];
        function showPanel(id) {
            const target = tabs.find(t => t.dataset.panel === id && !t.disabled); if (!target) return;
            state.tab = id;
            for (const t of tabs) {const selected = t === target; t.setAttribute('aria-selected',String(selected)); t.tabIndex = selected ? 0 : -1; $('pseudoPanel' + t.dataset.panel).hidden = !selected;}
        }
        for (const t of tabs) {
            t.onclick = () => showPanel(t.dataset.panel);
            t.onkeydown = e => {
                if (!['ArrowLeft','ArrowRight','Home','End'].includes(e.key)) return;
                e.preventDefault(); const enabled = tabs.filter(t => !t.disabled), n = enabled.indexOf(t);
                const next = e.key === 'Home' ? enabled[0] : e.key === 'End' ? enabled.at(-1) : enabled[(n + (e.key === 'ArrowRight' ? 1 : -1) + enabled.length) % enabled.length];
                showPanel(next.dataset.panel); next.focus();
            };
        }
        for (const button of document.querySelectorAll('.pseudo-analysis-link')) button.onclick = () => {showPanel('analysis'); $('pseudoTabanalysis').focus();};
        if ($('pseudoAliases')) $('pseudoAliases').onchange = e => {aliasesEnabled = e.target.checked; render(f);};
        if ($('pseudoExpressions')) $('pseudoExpressions').onchange = e => {expressionsEnabled = e.target.checked; render(f);};
        if ($('pseudoCleanup')) $('pseudoCleanup').onchange = e => {cleanupEnabled = e.target.checked; render(f);};
        if (model.callAnalysis) WEACallSummaryView.bind(model.callAnalysis,value => {callAssumptions.set(f.id,value); if (active?.id === f.id) render(f);},message);
        if (model.functionABI) WEAFunctionABIView.bind(model.functionABI,value => {functionContracts.set(f.id,value); if (active?.id === f.id) render(f);},message);
        const inspectFlow = model.registerSSA ? WEARegisterFlowView.bind(model.registerSSA,{escape:E,sourceLink,instructionText,
            selection:state,onSelect:value => Object.assign(state,value)}) : () => {};
        for (const detail of document.querySelectorAll('.pseudocode-overview details[id]')) {
            if (state.open.has(detail.id)) detail.open = state.open.get(detail.id);
            detail.ontoggle = () => {if (detail.isConnected) state.open.set(detail.id,detail.open);};
        }
        const openFlow = source => {showPanel('flow'); inspectFlow(source); $('pseudoTabflow')?.focus(); $('pseudoTabflow')?.scrollIntoView({block:'nearest'});};
        for (const button of document.querySelectorAll('.pseudo-trace')) button.onclick = () => openFlow(button.dataset.source);
        const facts = new Map((va?.facts || []).map(f => [f.source,f]));
        for (const button of document.querySelectorAll('.pseudo-evidence')) button.onclick = () => {
            const line = lines[Number(button.dataset.line)], first = line.sources.find(id => facts.has(id)), fact = facts.get(first);
            let evidence = '';
            if (fact) {
                const registers = [...new Set([...Object.keys(fact.before),...Object.keys(fact.after)])];
                evidence = '<details class="info" id="pseudoValueFacts"><summary>Value facts at ' + hex(I.get(first).insn.rva) + '</summary>' +
                    '<p>Before / after the first source instruction. Unlisted registers and memory contents are unknown.</p>' +
                    registers.map(r => '<p><code>' + E(r) + '</code><br>' + E(valueText(fact.before[r])) + '<br>→ ' + E(valueText(fact.after[r])) + '</p>').join('') +
                    va.accesses.filter(a => a.source === first).map(a => '<p>' + E(a.access) + a.width + ': ' + E(valueText(a.address)) +
                        (a.alias ? ' → ' + E(a.alias) : '') + '</p>').join('') + '</details>';
            }
            $('connections').innerHTML = '<h3>Contributing instructions</h3><p><code>' + E(line.text) + '</code></p>' +
                line.sources.filter(id => I.has(id)).map(id => '<div class="pseudo-source-item">' + sourceLink(id) +
                    (flowAvailable ? '<button class="pseudo-inspect-source" data-source="' + E(id) + '">Trace values</button>' : '') + '</div>').join('') + evidence;
            for (const b of document.querySelectorAll('.pseudo-inspect-source')) b.onclick = () => openFlow(b.dataset.source);
        };
        renderSidebar();
    }
    const button = document.createElement('button'); button.id = 'functionPseudo'; button.textContent = 'C-like';
    $('functionCfg')?.after(button);
    button.onclick = () => {const f = context(); if (f) navigate(idFor(f));};
    const oldRoute = route, oldNavigate = navigate;
    route = function () {
        const f = parse(location.hash.slice(1)); active = null;
        // Reset other views' active contexts and history handlers first.
        oldRoute(); if (f) render(f);
        if (f) {
            $('wholeFunction').disabled = false; $('wholeFunction').setAttribute('aria-pressed', 'false');
            $('functionCfg').disabled = false; $('functionCfg').setAttribute('aria-pressed', 'false');
        }
        button.disabled = !context(); button.setAttribute('aria-pressed', String(!!f));
    };
    navigate = function (id, from, ...args) {
        if (!parse(id)) return oldNavigate(id, from, ...args);
        if (location.hash !== '#' + id) history.pushState({via: from || null}, '', '#' + id);
        route();
    };
    $('wholeFunction')?.addEventListener('click', e => {
        if (!active) return; e.stopImmediatePropagation(); navigate(assembly(active));
    }, true);
    const style = document.createElement('style');
    style.textContent = `
.pseudo-context{display:flex;gap:8px 16px;flex-wrap:wrap;margin:12px 20px;color:var(--muted);font-size:12px}.pseudo-context>span:last-child{flex-basis:100%}.pseudo-tabs{display:flex;gap:5px;padding:0 20px;border-bottom:1px solid var(--line)}.pseudo-tabs button{border-radius:6px 6px 0 0;border-bottom:0;background:transparent;padding:9px 12px;font-size:12px}.pseudo-tabs button[aria-selected="true"]{color:var(--accent);background:#17302e;border-color:#367d6c}.pseudo-panel{padding:16px 20px}.pseudo-panel h3{margin:0 0 8px;font-size:16px}.pseudo-panel h4{margin:16px 0 8px;font-size:13px}.pseudo-panel p{font-size:12px;line-height:1.7}.pseudo-options{display:flex;gap:10px 18px;flex-wrap:wrap;margin-bottom:14px;font-size:12px}.pseudo-alias-toggle{display:inline-flex;align-items:center;gap:7px}.pseudo-alias-toggle input{width:auto;margin:0;accent-color:var(--accent)}.pseudo-code{overflow:auto;max-height:75vh;border:1px solid var(--line);border-radius:6px}.pseudo-code table{font:12px/1.8 var(--mono)}.pseudo-code td{vertical-align:top;padding:7px 10px}.pseudo-code code{white-space:pre}.pseudo-code th{position:sticky;top:0;background:var(--panel2);z-index:2}.pseudo-code th:last-child{right:0;z-index:3}.pseudo-actions{position:sticky;right:0;background:var(--panel);box-shadow:-1px 0 var(--line);z-index:1}.pseudo-actions button{display:inline-block;font:11px var(--sans);white-space:nowrap;padding:4px 6px}.pseudo-actions button+button{margin-left:4px}.pseudo-trace{color:var(--accent)}.pseudo-slot-table,.pseudo-flow-table{overflow:auto;max-height:28em}.pseudo-slot-table table,.pseudo-flow-table table{white-space:normal;font-size:12px}.pseudo-slot-table td,.pseudo-flow-table td{overflow-wrap:anywhere;vertical-align:top}.pseudo-detail,.pseudo-calls{margin:12px 0;padding:12px;border:1px solid var(--line);border-radius:7px;font-size:12px}.pseudo-detail>summary,.pseudo-calls>summary{cursor:pointer;font-size:13px}.pseudo-flow label{display:block;margin:14px 0 5px;color:var(--muted);font-size:12px}.pseudo-flow select{width:100%;max-width:100%;background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:9px;font:12px var(--mono)}.pseudo-selected-instruction{padding:10px 12px;border-left:2px solid var(--accent);background:#122b29;overflow-wrap:anywhere}.pseudo-flow-io{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(0,1fr);gap:18px}.pseudo-flow-io>section{min-width:0}.pseudo-flow-io h4{margin-top:0}.pseudo-def,.pseudo-use{font:11px var(--mono);padding:5px 7px;margin:2px 0;white-space:normal;text-align:left}.pseudo-def{color:var(--blue)}.pseudo-def[aria-pressed="true"]{color:var(--accent);border-color:#367d6c}.pseudo-written-value{margin-bottom:10px}.pseudo-written-value p{margin:2px 0 0}.pseudo-value-trail{border-top:1px solid var(--line);margin-top:18px;padding-top:18px}.pseudo-value-trail h3{margin-top:5px}.pseudo-value-inputs>div{margin:6px 0}.pseudo-value-inputs span{font-size:12px;margin-right:5px}.pseudo-calls table{white-space:normal}.pseudo-calls select{max-width:100%;font-size:12px}.pseudo-calls button{font-size:12px;margin:3px 0}.pseudo-warning{font-size:12px;margin:12px 20px}.pseudo-warning button{font-size:11px}.pseudo-source-item{padding:9px 0;border-bottom:1px solid var(--line);font:12px/1.7 var(--mono)}.pseudo-source-item button{display:block;font:11px var(--sans);margin-top:5px}
#pseudoFunctionProfile{max-width:100%;padding:7px 9px;margin:4px 0;background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:6px;outline-offset:4px}.pseudo-abi-value+.pseudo-abi-value{border-top:1px solid var(--line);margin-top:8px;padding-top:8px}
.pseudo-declaration-comparison table{min-width:680px;table-layout:fixed}.pseudo-declaration-locations table{min-width:680px;table-layout:fixed}.pseudo-declaration-locations th:first-child{width:30%}.pseudo-declaration-locations th:last-child{width:40%}.pseudo-declaration-comparison th:first-child{width:18%}.pseudo-declaration-comparison th:last-child{width:38%}
@media(max-width:1000px){.pseudo-flow-io{grid-template-columns:1fr}}@media(max-width:720px){.pseudo-actions{position:static;box-shadow:none}.pseudo-code th:last-child{right:auto}.pseudo-panel{padding:12px}.pseudo-tabs{padding:0 12px}.pseudo-tabs button{padding:9px 8px}.pseudo-context{margin:12px}.pseudo-warning{margin:12px}}
`;
    document.head.appendChild(style); route();
})();
