'use strict';
(() => {
    if (D.schema !== 2 || !globalThis.WEAPseudocodeModel) return;
    const prefix = D.module.id + '_c_', fnPrefix = D.module.id + '_fn_';
    const functions = new Map(D.functions.map(f => [f.id, f]));
    const byRva = new Map(D.functions.map(f => [f.rva, f]));
    let active = null, aliasesEnabled = true, expressionsEnabled = true, cleanupEnabled = true;
    const callAssumptions = new Map();
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
    function render(f) {
        active = f; selected = f.id; setTab('functions');
        const model = WEAPseudocodeModel.recover(D, f.id, {callAssumptions: callAssumptions.get(f.id)}), s = model.stats, va = model.valueAnalysis;
        const sourceLink = id => I.has(id) ? link(assembly(f, id), hex(I.get(id).insn.rva) + ' ' + I.get(id).insn.mnemonic, idFor(f), 'pseudo-source') : E(id);
        const viewPrefix = expressionsEnabled ? (cleanupEnabled ? 'simplifiedClean' : 'simplified') : (cleanupEnabled ? 'clean' : '');
        const lines = model[viewPrefix + (aliasesEnabled ? (viewPrefix ? 'DisplayLines' : 'displayLines') : (viewPrefix ? 'Lines' : 'lines'))];
        let h = '<section class="blockcard pseudocode-overview"><div class="blockhead"><div class="blocktop">' +
            '<span class="eyebrow">Assembly to C-like / preview v6</span><span class="pill warn">PARTIAL RECOVERY</span></div>' +
            '<h2 class="blocktitle">' + E(label(B.get(f.id) || f)) + '</h2><div class="addressmeta">' +
            link(assembly(f), 'Whole-function assembly', idFor(f), 'pseudo-assembly') + ' / ' +
            link(D.module.id + '_cfg_' + f.rva.toString(16), 'Control-flow graph', idFor(f)) + '</div></div>';
        if (model.status === 'unavailable') h += '<p class="datawarning">' + E(model.reason) + '</p>';
        else {
            h += '<p class="summary">' + E(model.notice) + '</p><div class="function-stats">' +
                [[s.supported, 'Supported instructions'], [s.barriers, 'Unknown effects'], [s.ifs, 'If regions'], [s.loops, 'Loop regions']]
                    .map(([n, t]) => '<div class="stat"><div class="statvalue">' + n + '</div><div class="statlabel">' + t + '</div></div>').join('') + '</div>';
            if (!model.structured) h += '<p class="datawarning">Shared blocks or truncated discovery: structure recovery disabled; explicit transfers retained.</p>';
            h += WEACallSummaryView.markup(model.callAnalysis, E, sourceLink);
            if (va.status !== 'converged') h += '<p class="datawarning">' + E(va.reason) + '</p>';
            else {
                h += '<p class="summary">' + E(va.notice) + '</p>';
                if (va.slots.length) h += '<details class="pseudo-slots"><summary>' + va.slots.length + ' stack locations / ' +
                    va.slots.filter(s => s.aliasable).length + ' readable memory aliases</summary>' +
                    '<div class="pseudo-slot-table"><table><thead><tr><th>Location</th><th>Width</th><th>Evidence</th></tr></thead><tbody>' +
                    va.slots.map(slot => '<tr><td><code>' + E(slot.id) + '</code><br>entry_sp ' + E(slot.offset) +
                        ' bytes</td><td>' + slot.width + ' bits</td><td>' + E(slot.kind.replaceAll('_', ' ')) + ': ' +
                        E(slot.reasons.length ? slot.reasons.join('; ') : slot.note) + '</td></tr>').join('') + '</tbody></table></div></details>';
                if (va.slots.some(s => s.aliasable)) h += '<p><label class="pseudo-alias-toggle"><input type="checkbox" id="pseudoAliases"' +
                    (aliasesEnabled ? ' checked' : '') + '> Show stack memory aliases</label></p>';
            }
            h += WEARegisterFlowView.markup(model.registerSSA, model.instructions, E);
            const expressions = model.registerExpressions;
            if (expressions.status === 'available') h += '<p><label class="pseudo-alias-toggle"><input type="checkbox" id="pseudoExpressions"' +
                (expressionsEnabled ? ' checked' : '') + '> Simplify register expressions (' + expressions.stats.changedOperations + ' operations)</label></p>' +
                '<p class="summary">' + E(expressions.notice) + '</p>';
            else h += '<p class="datawarning">' + E(expressions.reason) + ' Original effects shown.</p>';
            const cleanup = model.registerCleanup, variant = expressionsEnabled ? cleanup.simplified : cleanup.raw;
            if (cleanup.status === 'available') {
                h += '<p><label class="pseudo-alias-toggle"><input type="checkbox" id="pseudoCleanup"' +
                    (cleanupEnabled ? ' checked' : '') + '> Remove dead register writes (' + variant.stats.removed + ' removed, ' +
                    variant.stats.flagsOnly + ' flags only)</label></p><p class="summary">' + E(cleanup.notice) + '</p>';
                if (variant.rewrites.length) h += '<details class="pseudo-slots" id="pseudoCleanupDetails"><summary>' +
                    variant.rewrites.length + ' cleanup changes / ' + (cleanupEnabled ? 'applied' : 'available, disabled') +
                    '</summary><div class="pseudo-slot-table"><table><thead><tr><th>Original write</th><th>Change</th><th>Retained overwrite</th><th>Sources</th></tr></thead><tbody>' +
                    variant.rewrites.map(r => '<tr><td>' + sourceLink(r.source) + '<br><code>' + E(r.register) + '</code></td><td>' +
                        (r.kind === 'removed' ? 'Pure write removed' : 'Flags retained; register write removed') + '</td><td>' +
                        sourceLink(r.overwrittenBy.source) + '</td><td>' + r.sources.map(sourceLink).join(' / ') + '</td></tr>').join('') +
                    '</tbody></table></div></details>';
            } else h += '<p class="datawarning">' + E(cleanup.reason) + ' Original writes retained.</p>';
            h += '<div class="pseudo-code" role="region" aria-label="C-like pseudocode"><table><thead><tr><th>Assembly</th><th>C-like effects</th><th>Evidence</th></tr></thead><tbody>';
            lines.forEach((line, n) => {
                const source = line.sources.find(id => I.has(id));
                h += '<tr><td>' + (source ? link(assembly(f, source), hex(I.get(source).insn.rva), idFor(f), 'pseudo-source') : '') +
                    '</td><td><code>' + '    '.repeat(line.depth) + E(line.text) + '</code></td><td>' +
                    (line.sources.length ? '<button class="pseudo-evidence" data-line="' + n + '">' + line.sources.length + ' source(s)</button>' : '') + '</td></tr>';
            });
            h += '</tbody></table></div>';
        }
        h += '</section>';
        $('content').innerHTML = h;
        const help = '<h3 class="eyebrow">Reading the preview</h3><p>Registers are machine-state variables, not inferred C locals. ' +
            '<code>read32(base + index * 4)</code> and <code>write32</code> are little-endian, byte-addressed memory operations; an indexed address is not proof of an array type.</p>' +
            '<p><code>entry_sp</code> is the stack pointer on entry. A <code>slot_</code> name aliases the same memory on every use; it is not a cached value, original variable name or C local. Loads and stores still occur. Turn aliases off to see each original address expression.</p>' +
            '<p><code>uN</code> truncates to N bits; <code>sext</code> sign-extends; <code>insert</code> preserves the rest of a register. Arithmetic helpers wrap to their width and update <code>flags</code>. Undefined flags remain unknown.</p>' +
            '<p>Expression simplification substitutes only pure values whose register inputs still match their SSA versions. Shift helpers ending in <code>_value</code> mask counts and compute a value without updating flags. Expression simplification and dead-write cleanup are separate toggles. Turn both off to inspect every original operation.</p>' +
            '<p>Dead-write cleanup keeps every block exit and stops at memory, calls and unknown effects. An unused arithmetic destination may disappear while its flag helper remains. The cleanup table links every removed write and its retained overwrite.</p>' +
            '<p>Comparisons update flags immediately, so later branches use a snapshot of the comparison. Loop headers stay inside the loop. Source <code>for</code> loops may appear as <code>while</code> or <code>do/while</code>.</p>' +
            '<p><code>return_to_caller</code> models the near-return boundary; no C return type is inferred. Calls, I/O APIs, exceptional paths and unsupported effects need further analysis.</p>';
        $('connections').innerHTML = help;
        $('renamebox').hidden = !B.has(f.id); $('labelname').value = label(B.get(f.id) || f); $('labelnote').value = labels[f.id]?.note || '';
        if ($('pseudoAliases')) $('pseudoAliases').onchange = e => {aliasesEnabled = e.target.checked; render(f);};
        if ($('pseudoExpressions')) $('pseudoExpressions').onchange = e => {expressionsEnabled = e.target.checked; render(f);};
        if ($('pseudoCleanup')) $('pseudoCleanup').onchange = e => {cleanupEnabled = e.target.checked; render(f);};
        if (model.callAnalysis) WEACallSummaryView.bind(model.callAnalysis, value => {
            callAssumptions.set(f.id, value);
            if (active?.id === f.id) render(f);
        }, message);
        const inspectFlow = model.registerSSA ? WEARegisterFlowView.bind(model.registerSSA, {escape: E,
            sourceLink}) : () => {};
        const facts = new Map((va?.facts || []).map(f => [f.source, f]));
        for (const button of document.querySelectorAll('.pseudo-evidence')) button.onclick = () => {
            const line = lines[Number(button.dataset.line)];
            const first = line.sources.find(id => facts.has(id)), fact = facts.get(first);
            inspectFlow(line.sources[0]);
            let evidence = '';
            if (fact) {
                const registers = [...new Set([...Object.keys(fact.before), ...Object.keys(fact.after)])];
                evidence = '<h3 class="eyebrow">Value facts at ' + hex(I.get(first).insn.rva) + '</h3>' +
                    '<p>Before / after the first contributing instruction. All unlisted registers and all memory contents are unknown. Both branch outcomes are retained.</p>' +
                    registers.map(r => '<p><code>' + E(r) + '</code><br>' + E(valueText(fact.before[r])) + '<br>→ ' + E(valueText(fact.after[r])) + '</p>').join('');
                evidence += va.accesses.filter(a => a.source === first).map(a => '<p>' + E(a.access) + a.width + ': ' +
                    E(valueText(a.address)) + (a.alias ? ' → ' + E(a.alias) : '') + '</p>').join('');
            }
            $('connections').innerHTML = '<h3 class="eyebrow">Contributing instructions</h3><p><code>' + E(line.text) + '</code></p>' +
                line.sources.filter(id => I.has(id)).map(id => '<p>' + link(assembly(f, id), hex(I.get(id).insn.rva) + ' ' + I.get(id).insn.mnemonic, idFor(f), 'pseudo-source') + '</p>').join('') + evidence;
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
    style.textContent = '.pseudo-code{overflow:auto;max-height:75vh}.pseudo-code table{width:100%;font:12px var(--mono)}.pseudo-code td{vertical-align:top}.pseudo-code code{white-space:pre}.pseudo-code th{position:sticky;top:0;background:var(--panel2)}.pseudo-evidence{font:11px var(--sans);white-space:nowrap}.pseudocode-overview .summary{line-height:1.6}.pseudo-slot-table{overflow:auto;max-height:20em}.pseudo-slots{margin:1em 0}.pseudo-slots table{width:100%}.pseudo-alias-toggle{display:inline-flex;align-items:center;gap:8px}.pseudo-alias-toggle input{width:auto;margin:0}';
    style.textContent += '.pseudo-flow{margin:1em 0}.pseudo-flow label{display:block;margin:1em 0}.pseudo-flow select{max-width:100%}.pseudo-flow-table{overflow:auto;max-height:24em}.pseudo-flow table{width:100%}.pseudo-flow td{vertical-align:top}.pseudo-def,.pseudo-use{font:11px var(--mono);padding:3px 6px;margin:2px}.pseudo-flow h3{margin-top:1em}';
    style.textContent += '.pseudo-calls{margin:1em 0}.pseudo-calls table{width:100%}.pseudo-calls td{vertical-align:top}.pseudo-calls select{max-width:100%}';
    document.head.appendChild(style); route();
})();
