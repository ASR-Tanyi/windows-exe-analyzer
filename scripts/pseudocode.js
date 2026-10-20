#!/usr/bin/env node
'use strict';
// Offline text/JSON export using exactly the model embedded in HTML reports.
const fs = require('node:fs');
const model = require('../web/pseudocode-model.js');
function main() {
    const [path, entry, format] = process.argv.slice(2);
    if (!path || !entry || format && !['--json', '--raw', '--ssa'].includes(format))
        throw Error('Usage: node scripts/pseudocode.js report.json FUNCTION_RVA [--json|--raw|--ssa]');
    if (!/^(0x[0-9a-f]+|[0-9]+)$/i.test(entry)) throw Error('Function RVA must be decimal or 0x hexadecimal.');
    const report = JSON.parse(fs.readFileSync(path, 'utf8'));
    const f = report.functions.find(f => f.rva === Number(entry));
    if (!f) throw Error('No function candidate at that RVA.');
    const result = model.recover(report, f.id);
    if (format === '--json') console.log(JSON.stringify(result, null, 2));
    else if (result.status === 'unavailable') console.log('// ' + result.reason);
    else if (format === '--ssa') {
        const s = result.registerSSA;
        if (s.status !== 'available') {console.log('// Register SSA unavailable: ' + s.reason); process.exitCode = 2; return;}
        const defs = new Map(s.definitions.map(d => [d.id, d])), uses = new Map(s.uses.map(u => [u.id, u]));
        console.log('// Register SSA v' + s.version + '\n// ' + s.notice);
        for (const d of s.definitions) {
            const inputs = d.inputs.map(id => {const u = uses.get(id); return defs.get(u.definition).label +
                (d.kind === 'phi' ? ' from ' + (u.predecessor || 'entry') : ' [' + u.offset + ':' + (u.offset + u.width - 1) + '] ' + u.role);});
            console.log(d.label + ': ' + d.kind + ' (' + inputs.join(', ') + ')' +
                (d.source ? ' @ ' + d.source : '') + (d.kind === 'write' ? '; preserve ' + d.preserveMask + (d.zeroExtend ? '; zero upper32' : '') : '') +
                (d.memoryRead ? '; memory read' : '') + '; ' + d.uses.length + ' use(s)');
        }
    }
    else {
        console.log('// ' + f.name.replace(/[\r\n]/g, ' ') + '\n// ' + result.notice);
        if (format !== '--raw') console.log('// Stack names alias memory at entry_sp (the incoming stack pointer); they are not independent C locals.');
        for (const line of format === '--raw' ? result.lines : result.displayLines) console.log('    '.repeat(line.depth) + line.text);
    }
    if (result.status === 'unavailable') process.exitCode = 2;
}
try {main();} catch (e) {console.error(e.message); process.exitCode = 1;}
