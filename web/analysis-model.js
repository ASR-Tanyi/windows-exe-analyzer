'use strict';
// Optional analysisModelVersion=1 extension. CMake embeds this after the base
// viewer script; no network request is needed and old schema-2 reports work.
function analysisDetails(b) {
    if (D.analysisModelVersion !== 1) return '';
    const facts = b.evidenceRecords || [];
    const f = D.functions.find(x => x.id === b.id);
    if (!facts.length && !f?.decodedRanges?.length) return '';
    let h = '<details class="analysis-evidence info"><summary>Discovery evidence (' + facts.length + ')</summary>';
    for (const e of facts) {
        const src = e.source;
        let source = 'No binary source location recorded';
        if (src) {
            source = E(src.space + ' ' + src.value);
            if (src.moduleId === D.module.id && src.space === 'rva') {
                const suffix = src.value.replace(/^0x/, '');
                const iid = D.module.id + '_i_' + suffix;
                source = I.has(iid) ? link(iid, src.value, b.id) : source;
            }
        }
        h += '<p><b>' + E(e.claim) + ' / ' + E(e.status) + '</b><br>' +
             E(e.origin) + ' / ' + E(e.resolution) + '<br>' + E(e.rule) + ' v' +
             E(e.ruleVersion) + '<br>' + source + '<br>' + E(e.detail) + '</p>';
        for (const a of e.assumptions || []) h += '<p class="small muted">' + E(a) + '</p>';
    }
    h += '</details>';
    if (f?.decodedRanges?.length) {
        h += '<details class="analysis-ranges info"><summary>Decoded coverage (' +
             f.decodedRanges.length + ' spans)</summary><p>Half-open ranges from decoded blocks ' +
             'with inferred ownership. These are not complete function boundaries.</p>';
        for (const span of f.decodedRanges) {
            h += '<p class="mono">[' + E(span.beginRva) + ', ' + E(span.endRva) + ')</p>';
        }
        h += '</details>';
    }
    return h;
}

const renderBlockWithoutModel = renderBlock;
renderBlock = function (block, focus) {
    renderBlockWithoutModel(block, focus);
    $('connections').insertAdjacentHTML('beforeend', analysisDetails(block));
};
if (D.analysisModelVersion === 1 && D.diagnostics?.omitted) {
    $('warnings').insertAdjacentHTML('beforeend', '<div class="warning">' +
        E(D.diagnostics.omitted) + ' diagnostic details omitted; all ' +
        E(D.diagnostics.total) + ' occurrences are counted in JSON.</div>');
}
// Initial routing in the base script ran before installing the extension.
route();
