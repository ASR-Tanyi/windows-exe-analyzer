'use strict';
// Optional schema-2 extension. Facts are shown only for the selected instruction;
// old reports and annotations retain their routes and identities.
(() => {
    if (D.operandModelVersion !== 1) return;
    const info = D.module.decoderInfo;
    if (info) $('decoderinfo').textContent += info.capabilities.structuredOperands
        ? ' Structured operands are available; effects may be incomplete.'
        : ' Structured operands are unavailable in this decoder; assembly and existing references remain available.';
    const width = value => value === null || value === undefined ? 'width unknown' : value + ' bits';
    const reg = r => !r ? 'none' : r.family === null
        ? r.name + ' (alias unknown)'
        : r.name + ' = ' + r.family + '[' + r.bitOffset + ':' + (r.bitOffset + r.bitWidth - 1) + ']';
    function contents(i) {
        const d = i.operandDetails;
        if (!d || d.source === 'unavailable' || d.operands === null)
            return '<p>Structured operands unavailable. Implicit register accesses are unknown.</p>';
        let h = '<p>' + E(d.source) + ' · address size ' + E(width(d.addressWidthBits)) + '</p>';
        if (!d.operands.length) h += '<p>No operands reported. This does not establish absence of implicit effects.</p>';
        d.operands.forEach((op, index) => {
            h += '<p><b>Operand ' + index + ' · ' + E(op.kind) + '</b><br>' + E(width(op.widthBits) + ' · ' + op.access) + '<br>';
            if (op.register) h += E(reg(op.register));
            if (op.immediate) h += E(op.immediate.value + ' · ' + op.immediate.interpretation);
            if (op.memory) {
                const m = op.memory;
                h += 'Base: ' + E(reg(m.base)) + '<br>Index: ' + E(reg(m.index)) + ' × ' + E(m.scale) +
                    '<br>Displacement: ' + E(m.displacement) + '<br>Segment: ' + E(reg(m.segment));
                if (m.segment) h += '<br>Selector only; segment base unknown.';
            }
            h += '</p>';
        });
        if (d.prefixes) h += '<p>Leading legacy/REX bytes: ' + E(d.prefixes.leadingBytes.map(b => b.toString(16).padStart(2, '0')).join(' ') || 'none') + '</p>';
        for (const kind of ['immediate', 'displacement']) {
            const field = d.encoding?.[kind];
            if (field) h += '<p>Encoded ' + kind + ': ' + E(width(field.widthBits)) + ' at byte ' + E(field.offset) + '</p>';
        }
        const implicit = d.implicitRegisters;
        h += '<p><b>Implicit register effects: ' + E(implicit.status) + '</b><br>Reads: ' +
            E(implicit.reads === null ? 'unknown' : implicit.reads.map(r => r.name).join(', ') || 'none reported') +
            '<br>Writes: ' + E(implicit.writes === null ? 'unknown' : implicit.writes.map(r => r.name).join(', ') || 'none reported') + '</p>';
        h += '<p class="muted">Additional effects may be unknown. Register slices show storage overlap; they do not describe zero-extension, conditional writes, or vector lane semantics.</p>';
        return h;
    }
    const oldRoute = route;
    route = function () {
        oldRoute();
        const row = document.querySelector('#content tr.focused[id]') || document.querySelector('#content tr[id]');
        const i = row && I.get(row.id)?.insn;
        if (!i) return;
        // Route extensions may retain the panel; always replace it at most once.
        $('operandDetails')?.remove();
        $('connections').insertAdjacentHTML('beforeend', '<details id="operandDetails" class="info operand-details">' +
            '<summary>Instruction operands · RVA ' + E(hex(i.rva)) + '</summary>' +
            '<p class="mono">' + E(i.mnemonic + ' ' + i.operands) + '</p>' + contents(i) + '</details>');
    };
    const style = document.createElement('style');
    style.textContent = '.operand-details{margin-top:18px;overflow-wrap:anywhere}.operand-details p{font-size:11px}';
    document.head.appendChild(style);
    route();
})();
