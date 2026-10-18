'use strict';
(() => {
    if (D.schema !== 2 || !globalThis.WEAPseudocodeModel) return;
    const prefix = D.module.id + '_c_', fnPrefix = D.module.id + '_fn_';
    const functions = new Map(D.functions.map(f => [f.id, f]));
    const byRva = new Map(D.functions.map(f => [f.rva, f]));
    let active = null;
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
    function render(f) {
        active = f; selected = f.id; setTab('functions');
        const model = WEAPseudocodeModel.recover(D, f.id), s = model.stats;
        let h = '<section class="blockcard pseudocode-overview"><div class="blockhead"><div class="blocktop">' +
            '<span class="eyebrow">Assembly to C-like / preview v1</span><span class="pill warn">PARTIAL RECOVERY</span></div>' +
            '<h2 class="blocktitle">' + E(label(B.get(f.id) || f)) + '</h2><div class="addressmeta">' +
            link(assembly(f), 'Whole-function assembly', idFor(f), 'pseudo-assembly') + ' / ' +
            link(D.module.id + '_cfg_' + f.rva.toString(16), 'Control-flow graph', idFor(f)) + '</div></div>';
        if (model.status === 'unavailable') h += '<p class="datawarning">' + E(model.reason) + '</p>';
        else {
            h += '<p class="summary">' + E(model.notice) + '</p><div class="function-stats">' +
                [[s.supported, 'Supported instructions'], [s.barriers, 'Unknown effects'], [s.ifs, 'If regions'], [s.loops, 'Loop regions']]
                    .map(([n, t]) => '<div class="stat"><div class="statvalue">' + n + '</div><div class="statlabel">' + t + '</div></div>').join('') + '</div>';
            if (!model.structured) h += '<p class="datawarning">Shared blocks or truncated discovery: structure recovery disabled; explicit transfers retained.</p>';
            h += '<div class="pseudo-code" role="region" aria-label="C-like pseudocode"><table><thead><tr><th>Assembly</th><th>C-like effects</th><th>Evidence</th></tr></thead><tbody>';
            model.lines.forEach((line, n) => {
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
            '<p><code>uN</code> truncates to N bits; <code>sext</code> sign-extends; <code>insert</code> preserves the rest of a register. Arithmetic helpers wrap to their width and update <code>flags</code>. Undefined flags remain unknown.</p>' +
            '<p>Comparisons update flags immediately, so later branches use a snapshot of the comparison. Loop headers stay inside the loop. Source <code>for</code> loops may appear as <code>while</code> or <code>do/while</code>.</p>' +
            '<p><code>return_to_caller</code> models the near-return boundary; no C return type is inferred. Calls, I/O APIs, exceptional paths and unsupported effects need further analysis.</p>';
        $('connections').innerHTML = help;
        $('renamebox').hidden = !B.has(f.id); $('labelname').value = label(B.get(f.id) || f); $('labelnote').value = labels[f.id]?.note || '';
        for (const button of document.querySelectorAll('.pseudo-evidence')) button.onclick = () => {
            const line = model.lines[Number(button.dataset.line)];
            $('connections').innerHTML = '<h3 class="eyebrow">Contributing instructions</h3><p><code>' + E(line.text) + '</code></p>' +
                line.sources.filter(id => I.has(id)).map(id => '<p>' + link(assembly(f, id), hex(I.get(id).insn.rva) + ' ' + I.get(id).insn.mnemonic, idFor(f), 'pseudo-source') + '</p>').join('');
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
    style.textContent = '.pseudo-code{overflow:auto;max-height:75vh}.pseudo-code table{width:100%;font:12px var(--mono)}.pseudo-code td{vertical-align:top}.pseudo-code code{white-space:pre}.pseudo-code th{position:sticky;top:0;background:var(--panel2)}.pseudo-evidence{font:11px var(--sans);white-space:nowrap}.pseudocode-overview .summary{line-height:1.6}';
    document.head.appendChild(style); route();
})();
