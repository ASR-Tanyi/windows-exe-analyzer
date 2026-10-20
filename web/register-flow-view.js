'use strict';
// Optional inspector for the register graph. It does not rewrite pseudocode.
(function (root) {
    function markup(graph, instructions, escape) {
        const E = escape;
        if (graph.status !== 'available') return '<p class="datawarning">Register flow: ' + E(graph.reason) + '</p>';
        const sources = new Set(graph.instructions.map(i => i.source));
        const joins = graph.definitions.filter(d => d.kind === 'phi');
        return '<details id="pseudoFlow" class="pseudo-flow"><summary>Register flow / ' + graph.stats.definitions +
            ' definitions / ' + graph.stats.joins + ' joins</summary><p>' + E(graph.notice) + '</p>' +
            '<label>Instruction <select id="pseudoFlowInstruction">' + instructions.filter(i => sources.has(i.source)).map(i =>
                '<option value="' + E(i.source) + '">0x' + i.rva.toString(16) + ' ' + E(i.mnemonic) + '</option>').join('') + '</select></label>' +
            '<div id="pseudoFlowInstructionDetails"></div>' + (joins.length ? '<label>Branch / loop join <select id="pseudoFlowJoin">' +
                '<option value="">Select a join</option>' + joins.map(d => '<option value="' + E(d.id) + '">' + E(d.label) + '</option>').join('') + '</select></label>' : '') +
            '<div id="pseudoFlowDefinition" aria-live="polite"></div></details>';
    }
    function bind(graph, {escape: E, sourceLink}) {
        if (graph.status !== 'available') return () => {};
        const $ = id => document.getElementById(id), host = $('pseudoFlow');
        const defs = new Map(graph.definitions.map(d => [d.id, d])), uses = new Map(graph.uses.map(u => [u.id, u]));
        const instructions = new Map(graph.instructions.map(i => [i.source, i])), blocks = new Map(graph.blocks.map(b => [b.id, b]));
        const defButton = id => '<button class="pseudo-def" data-definition="' + E(id) + '">' + E(defs.get(id).label) + '</button>';
        const sourceButton = source => '<button class="pseudo-use" data-source="' + E(source) + '">Inspect use</button>';
        const slice = u => E(u.register) + '[' + u.offset + ':' + (u.offset + u.width - 1) + ']';
        const describeWrite = d => d.kind === 'clobber' ? 'Unknown clobber' : d.slice.width + '-bit write' +
            (d.zeroExtend ? '; upper 32 bits cleared' : d.preserveMask !== '0x0' ? '; preserves mask ' + d.preserveMask : '');
        function definition(id) {
            const d = defs.get(id); if (!d) return;
            let h = '<h3>Definition <code>' + E(d.label) + '</code></h3>';
            if (d.kind === 'entry') h += '<p>Unknown incoming register state. No argument type or calling convention is inferred.</p>';
            else if (d.kind === 'phi') {
                h += '<p>This join selects the value from the predecessor that just executed. Incoming uses occur on edges.</p>' +
                    '<div class="pseudo-flow-table"><table><thead><tr><th>Predecessor</th><th>Definition</th><th>Transfer evidence</th></tr></thead><tbody>' +
                    d.incoming.map(id => {const u = uses.get(id); return '<tr><td>' + (u.predecessor === null ? 'Function entry' : 'L_' + blocks.get(u.predecessor).rva.toString(16)) +
                        '</td><td>' + defButton(u.definition) + '</td><td>' + u.sources.map(sourceLink).join(' ') + '</td></tr>';}).join('') + '</tbody></table></div>';
            } else {
                h += '<p>' + sourceLink(d.source) + ' · ' + E(describeWrite(d)) + '</p>';
                if (d.kind === 'clobber') h += '<p>No earlier register value is retained across this unknown effect.</p>';
                else if (d.inputs.length) h += '<p>Inputs: ' + d.inputs.map(id => {const u = uses.get(id); return defButton(u.definition) + ' (' + slice(u) +
                    ', ' + E(u.role) + (u.role === 'preserve' ? ', mask ' + E(u.mask) : '') + ')';}).join(' ') + '</p>';
                else h += '<p>No register input; see the original typed operation for its immediate or condition.</p>';
                if (d.memoryRead) h += '<p>The value also depends on a memory read. No loaded memory value is propagated.</p>';
            }
            h += '<h4>Used by (' + d.uses.length + ')</h4>';
            if (!d.uses.length) h += '<p>No represented uses. The original operation is retained.</p>';
            else h += '<div class="pseudo-flow-table"><table><thead><tr><th>Use</th><th>Location</th></tr></thead><tbody>' +
                d.uses.slice(0, 128).map(id => {const u = uses.get(id); return '<tr><td>' + (u.kind === 'phi' ? 'Incoming to ' + defButton(u.consumer) :
                    u.kind === 'exit' ? 'Machine exit state' : slice(u) + ' · ' + E(u.role) + ' ' + sourceButton(u.source)) + '</td><td>' +
                    (u.source ? sourceLink(u.source) : u.sources.map(sourceLink).join(' ')) + '</td></tr>';}).join('') + '</tbody></table></div>';
            if (d.uses.length > 128) h += '<p>Showing the first 128 uses; the JSON export contains all ' + d.uses.length + '.</p>';
            $('pseudoFlowDefinition').innerHTML = h;
        }
        function instruction(source) {
            const i = instructions.get(source); if (!i) return;
            $('pseudoFlowInstruction').value = source;
            const state = effects => effects.unknown ? 'unknown' : Object.entries(effects).filter(([, v]) => v).map(([k]) => k === 'write' ? 'may write' : k).join(', ') || 'unchanged / no access';
            $('pseudoFlowInstructionDetails').innerHTML = '<p>' + sourceLink(source) + ' · Memory: ' + E(state(i.memory)) + ' · Flags: ' + E(state(i.flags)) + '</p>' +
                '<div class="pseudo-flow-table"><table><thead><tr><th>Register use</th><th>Reaching definition</th></tr></thead><tbody>' +
                (i.reads.length ? i.reads.map(id => {const u = uses.get(id); return '<tr><td>' + slice(u) + ' · ' + E(u.role) +
                    (u.role === 'preserve' ? ' · mask ' + E(u.mask) : '') + '</td><td>' + defButton(u.definition) + '</td></tr>';}).join('') : '<tr><td colspan="2">No register inputs</td></tr>') +
                '</tbody></table></div><p>New definitions: ' + (i.writes.length ? i.writes.map(id => defButton(id) + ' (' + E(describeWrite(defs.get(id))) + ')').join(' ') : 'none') + '</p>';
            const first = i.writes[0] || (i.reads[0] && uses.get(i.reads[0]).definition);
            if (first) definition(first); else $('pseudoFlowDefinition').innerHTML = '';
            if ($('pseudoFlowJoin')) $('pseudoFlowJoin').value = '';
        }
        $('pseudoFlowInstruction').onchange = e => instruction(e.target.value);
        if ($('pseudoFlowJoin')) $('pseudoFlowJoin').onchange = e => {if (e.target.value) definition(e.target.value);};
        host.addEventListener('click', event => {
            const def = event.target.closest('[data-definition]'), use = event.target.closest('[data-source]');
            if (def && host.contains(def)) definition(def.dataset.definition);
            else if (use && host.contains(use)) instruction(use.dataset.source);
        });
        instruction($('pseudoFlowInstruction').value);
        return instruction;
    }
    root.WEARegisterFlowView = {markup, bind};
})(globalThis);
