'use strict';
// Explain the original register graph without changing any recovered effects.
(function (root) {
    const address = n => '0x' + n.toString(16);
    function markup(graph, instructions, E, instructionText) {
        if (graph.status !== 'available') return '<p class="datawarning">Register flow unavailable: ' + E(graph.reason) + '</p>';
        const sources = new Set(graph.instructions.map(i => i.source)), blocks = new Map(graph.blocks.map(b => [b.id,b]));
        const joins = graph.definitions.filter(d => d.kind === 'phi');
        return '<section id="pseudoFlow" class="pseudo-flow"><h3>Trace a register value</h3>' +
            '<p class="muted">Choose an instruction, then follow a value to its origin or to a later use. This view traces the original assembly, before display simplification.</p>' +
            '<label for="pseudoFlowInstruction">Instruction to inspect</label><select id="pseudoFlowInstruction">' +
            instructions.filter(i => sources.has(i.source)).map(i => '<option value="' + E(i.source) + '">' +
                E(instructionText(i.source)) + '</option>').join('') + '</select>' +
            '<div id="pseudoFlowInstructionDetails"></div><div id="pseudoFlowDefinition" aria-live="polite"></div>' +
            (joins.length ? '<details id="pseudoFlowMerges" class="pseudo-detail"><summary>Explore branch and loop merges (' + joins.length + ')</summary>' +
                '<p>A merge keeps the possible incoming values separate. The path taken at runtime selects one of them.</p>' +
                '<label for="pseudoFlowJoin">Register and merge location</label><select id="pseudoFlowJoin"><option value="">Choose a merge</option>' +
                joins.map(d => '<option value="' + E(d.id) + '">' + E(d.register) + ' at ' + address(blocks.get(d.block).rva) + '</option>').join('') + '</select></details>' : '') +
            '<details class="pseudo-detail"><summary>How to read register flow</summary>' +
            '<ol><li><b>Reads</b> shows the register values this instruction needs. Select a value to see where it came from.</li>' +
            '<li><b>Writes</b> shows the new values it creates. A new write is tracked separately from the previous value in the same register.</li>' +
            '<li><b>Used later</b> lists instructions that read the selected value. Trace one to continue following it.</li></ol>' +
            '<p>For <code>mov eax, ecx</code>, the input is the current value of <code>ecx</code>; the output is a new value of <code>eax</code>. ' +
            'A later <code>add eax, 1</code> reads that output and creates another value.</p>' +
            '<p>“On entry” means the value came from outside this function. A merge means it depends on an incoming branch or loop iteration. ' +
            'Memory and flags are separate effects; this view does not track their values.</p></details>' +
            '<details class="pseudo-detail"><summary>SSA terminology and analysis scope</summary><p>SSA gives each write a distinct identity (a definition). ' +
            'A use reads one of these identities; a PHI is a merge of alternative incoming identities.</p><p>' + E(graph.notice) + '</p></details></section>';
    }
    function bind(graph, {escape: E, sourceLink, instructionText, selection = {}, onSelect = () => {}}) {
        if (graph.status !== 'available') return () => {};
        const $ = id => document.getElementById(id), host = $('pseudoFlow');
        const defs = new Map(graph.definitions.map(d => [d.id,d])), uses = new Map(graph.uses.map(u => [u.id,u]));
        const instructions = new Map(graph.instructions.map(i => [i.source,i])), blocks = new Map(graph.blocks.map(b => [b.id,b]));
        const initial = {...selection}; let selectedSource = null;
        const location = source => instructionText(source).split(' ')[0];
        const name = d => d.register + (d.kind === 'entry' ? ' on entry' : d.kind === 'phi' ? ' at merge ' + address(blocks.get(d.block).rva) :
            (d.kind === 'clobber' ? ' unknown after ' : ' after ') + location(d.source));
        const defButton = id => '<button class="pseudo-def" data-definition="' + E(id) + '" title="Trace ' + E(name(defs.get(id))) + '">' + E(name(defs.get(id))) + '</button>';
        const useSources = u => u.source ? sourceLink(u.source) : (u.sources || []).map(sourceLink).join(' ');
        const sourceButton = source => '<button class="pseudo-use" data-source="' + E(source) + '" aria-label="Trace values at ' + E(location(source)) + '">Trace instruction</button>';
        const slice = u => '<code>' + E(u.register) + '</code>' + (u.width === graph.bits ? '' :
            ' <span class="muted">(' + (u.offset ? 'bits ' + u.offset + '–' + (u.offset + u.width - 1) : 'low ' + u.width + ' bits') + ')</span>');
        const role = u => u.role.includes('address') ? 'Address calculation' : ({value:'Assigned value', left:'Left operand',right:'Right operand',
            preserve:'Unchanged register bits',stack:'Stack pointer', 'return-stack':'Return stack pointer', 'pushed-value':'Value pushed',
            'if-true':'Value if the condition is true', 'if-false':'Value if the condition is false',adjustment:'Stack adjustment',
            'call-target':'Call target', 'call-stack':'Call stack pointer'}[u.role.split('/')[0]] || u.role.replaceAll('-', ' '));
        const describeWrite = d => d.kind === 'clobber' ? 'Value becomes unknown' : d.slice.width + '-bit write' +
            (d.zeroExtend ? '; clears the upper 32 bits' : d.preserveMask !== '0x0' ? '; leaves the other bits unchanged' : '');
        function definition(id) {
            const d = defs.get(id); if (!d) return;
            let h = '<div class="pseudo-value-trail"><div class="eyebrow">Selected value</div><h3>' + E(name(d)) + '</h3><h4>Where it comes from</h4>';
            if (d.kind === 'entry') h += '<p>The value was already in <code>' + E(d.register) + '</code> when this function began. ' +
                'Its initial value is unknown; this is not proof of a function argument.</p>';
            else if (d.kind === 'phi') {
                h += '<p>The value depends on the incoming path. Execution selects one row below; these values are not added together.</p>' +
                    '<div class="pseudo-flow-table"><table><thead><tr><th>Incoming block</th><th>Value carried in</th><th>Branch evidence</th></tr></thead><tbody>' +
                    d.incoming.map(id => {const u = uses.get(id); return '<tr><td>' + (u.predecessor === null ? 'Function entry' : address(blocks.get(u.predecessor).rva)) +
                        '</td><td>' + defButton(u.definition) + '</td><td>' + useSources(u) + '</td></tr>';}).join('') + '</tbody></table></div>';
            } else {
                h += '<p>' + sourceLink(d.source) + '</p><p>' + E(describeWrite(d)) + '.</p>';
                if (d.kind === 'clobber') h += '<p>This operation does not retain a known value for this register.</p>';
                else if (d.inputs.length) h += '<div class="pseudo-value-inputs">' + d.inputs.map(id => {const u = uses.get(id); return '<div>' +
                    '<span class="muted">' + E(role(u)) + '</span> ' + defButton(u.definition) + '</div>';}).join('') + '</div>';
                else if (!d.memoryRead) h += '<p>No register input. The instruction supplies an immediate value or a flag-dependent result.</p>';
                if (d.memoryRead) h += '<p>Also reads memory. The loaded value is unknown to this register analysis.</p>';
            }
            const reads = new Map(), merges = [], exits = [];
            for (const id of d.uses) {
                const u = uses.get(id);
                if (u.kind === 'phi') merges.push(u);
                else if (u.kind === 'exit') exits.push(u);
                else {if (!reads.has(u.source)) reads.set(u.source,[]); reads.get(u.source).push(u);}
            }
            h += '<h4>Used later · ' + reads.size + ' instruction' + (reads.size === 1 ? '' : 's') + '</h4>';
            if (!reads.size) h += '<p>No later instruction directly reads this value in the original graph.</p>';
            else h += '<div class="pseudo-flow-table"><table><thead><tr><th>Instruction</th><th>How it is used</th><th>Follow</th></tr></thead><tbody>' +
                [...reads].slice(0,128).map(([source,items]) => '<tr><td>' + sourceLink(source) + '</td><td>' +
                    [...new Set(items.map(role))].map(E).join(', ') + '</td><td>' + sourceButton(source) + '</td></tr>').join('') + '</tbody></table></div>';
            if (reads.size > 128) h += '<p>First 128 instructions shown; all uses remain in JSON.</p>';
            if (merges.length || exits.length) h += '<details class="pseudo-detail pseudo-flow-continuations"><summary>Carried into ' +
                [merges.length ? merges.length + ' merge input(s)' : '', exits.length ? exits.length + ' function exit(s)' : ''].filter(Boolean).join(' and ') + '</summary>' +
                '<p>These preserve machine state; they are not extra CPU instructions or proof of a C return value.</p>' +
                merges.slice(0,128).map(u => '<p>Incoming to ' + defButton(u.consumer) + ' · ' + useSources(u) + '</p>').join('') +
                exits.slice(0,128).map(u => '<p>At function exit: ' + useSources(u) + '</p>').join('') +
                (merges.length > 128 || exits.length > 128 ? '<p>First 128 of each kind shown; all remain in JSON.</p>' : '') + '</details>';
            h += '<details class="pseudo-detail"><summary>Technical identity</summary><p>SSA definition: <code>' + E(d.label) +
                '</code> · ' + E(d.kind) + '</p>' + (d.preserveMask ? '<p>Preserved-bit mask: <code>' + E(d.preserveMask) + '</code></p>' : '') + '</details></div>';
            $('pseudoFlowDefinition').innerHTML = h;
            host.querySelectorAll('.pseudo-def').forEach(b => b.setAttribute('aria-pressed',String(b.dataset.definition === id)));
            onSelect({source:selectedSource,definition:id});
        }
        function instruction(source) {
            const i = instructions.get(source); if (!i) return;
            selectedSource = source; $('pseudoFlowInstruction').value = source;
            const state = effects => effects.unknown ? 'unknown' : Object.entries(effects).filter(([,v]) => v).map(([k]) => k === 'write' ? 'may write' : k).join(', ') || 'unchanged';
            $('pseudoFlowInstructionDetails').innerHTML = '<p class="pseudo-selected-instruction">' + sourceLink(source) + '</p>' +
                '<div class="pseudo-flow-io"><section><h4>Reads · values needed</h4>' +
                (i.reads.length ? '<div class="pseudo-flow-table"><table><thead><tr><th>Read</th><th>Value to trace</th></tr></thead><tbody>' +
                    i.reads.map(id => {const u = uses.get(id); return '<tr><td>' + slice(u) + '<br><span class="muted">' + E(role(u)) + '</span></td><td>' +
                        defButton(u.definition) + '</td></tr>';}).join('') + '</tbody></table></div>' : '<p>No register inputs.</p>') +
                '</section><section><h4>Writes · new values</h4>' + (i.writes.length ? i.writes.map(id => '<div class="pseudo-written-value">' +
                    defButton(id) + '<p class="muted">' + E(describeWrite(defs.get(id))) + '</p></div>').join('') : '<p>No register writes.</p>') +
                '</section></div><p class="small muted">Other effects — memory: ' + E(state(i.memory)) + '; flags: ' + E(state(i.flags)) + '.</p>';
            const first = i.writes[0] || (i.reads[0] && uses.get(i.reads[0]).definition);
            if (first) definition(first); else {$('pseudoFlowDefinition').innerHTML = ''; onSelect({source,definition:null});}
            if ($('pseudoFlowJoin')) $('pseudoFlowJoin').value = '';
        }
        $('pseudoFlowInstruction').onchange = e => instruction(e.target.value);
        if ($('pseudoFlowJoin')) $('pseudoFlowJoin').onchange = e => {if (e.target.value) definition(e.target.value);};
        host.addEventListener('click', event => {
            const def = event.target.closest('[data-definition]'), use = event.target.closest('[data-source]');
            if (def && host.contains(def)) definition(def.dataset.definition);
            else if (use && host.contains(use)) instruction(use.dataset.source);
        });
        instruction(instructions.has(initial.source) ? initial.source : $('pseudoFlowInstruction').value);
        if (defs.has(initial.definition)) definition(initial.definition);
        return instruction;
    }
    root.WEARegisterFlowView = {markup,bind};
})(globalThis);
