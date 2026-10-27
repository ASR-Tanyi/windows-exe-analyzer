#!/usr/bin/env node
'use strict';
// Offline text/JSON export using exactly the model embedded in HTML reports.
const fs = require('node:fs');
const model = require('../web/pseudocode-model.js');
function main() {
    const [path, entry, ...args] = process.argv.slice(2);
    let format, calls, contract, simplified = false, clean = false;
    const usage = 'Usage: node scripts/pseudocode.js report.json FUNCTION_RVA [--json|--raw|--ssa|--storage|--abi] [--simplified] [--clean] [--calls assumptions.json] [--function-contract contract.json]';
    if (!path || !entry) throw Error(usage);
    for (let n = 0; n < args.length; n++) {
        if (['--json', '--raw', '--ssa', '--storage', '--abi'].includes(args[n]) && !format) format = args[n];
        else if (args[n] === '--simplified' && !simplified) simplified = true;
        else if (args[n] === '--clean' && !clean) clean = true;
        else if (args[n] === '--calls' && !calls && args[n + 1] && !args[n + 1].startsWith('--')) calls = args[++n];
        else if (args[n] === '--function-contract' && !contract && args[n + 1] && !args[n + 1].startsWith('--')) contract = args[++n];
        else throw Error(usage);
    }
    if ((simplified || clean) && ['--json', '--ssa', '--storage', '--abi'].includes(format)) throw Error('--simplified and --clean select code output; JSON already includes all forms.');
    if (!/^(0x[0-9a-f]+|[0-9]+)$/i.test(entry)) throw Error('Function RVA must be decimal or 0x hexadecimal.');
    const report = JSON.parse(fs.readFileSync(path, 'utf8'));
    const f = report.functions.find(f => f.rva === Number(entry));
    if (!f) throw Error('No function candidate at that RVA.');
    let callAssumptions;
    if (calls) {
        if (fs.statSync(calls).size > 65536) throw Error('Call-assumption file exceeds 64 KiB.');
        callAssumptions = JSON.parse(fs.readFileSync(calls, 'utf8')) ?? {};
    }
    let functionContract;
    if (contract) {
        if (fs.statSync(contract).size > 65536) throw Error('Function-contract file exceeds 64 KiB.');
        functionContract = JSON.parse(fs.readFileSync(contract, 'utf8')) ?? {};
    }
    const result = model.recover(report, f.id, {callAssumptions, functionContract});
    if (result.functionABI?.status === 'invalid') {
        console.error('Invalid function contract: ' + result.functionABI.reason); process.exitCode = 2;
    }
    if (result.callAnalysis?.status === 'invalid') {
        console.error('No call summaries applied: ' + result.callAnalysis.reason); process.exitCode = 2;
    }
    if (format !== '--json' && result.callAnalysis?.applied) console.log('// ' + result.callAnalysis.notice);
    if (format !== '--json' && result.functionABI?.contract.profile) console.log('// ' + result.functionABI.notice);
    if (format === '--json') console.log(JSON.stringify(result, null, 2));
    else if (result.status === 'unavailable') console.log('// ' + result.reason);
    else if (format === '--abi') {
        const a = result.functionABI;
        for (const d of a.contract?.declarations || []) console.log('Analyst declaration (not recovered): ' + JSON.stringify(d));
        for (const c of a.declarationConflicts || []) console.log('Declaration disagreement ' + c.declarations.join(' / ') + ': ' + c.fields.join(', ') + '; ' + c.reason);
        for (const r of a.declarationReviews || []) console.log('Declaration review ' + r.declaration + ': ' + r.reason + ' @ ' + r.sources.join(', '));
        if (a.status !== 'available') {console.log('// Function ABI evidence unavailable: ' + a.reason); process.exitCode = 2; return;}
        console.log('// Function ABI evidence v' + a.version);
        for (const c of a.conflicts) console.log('Contract conflict @ ' + c.source + ': ' + c.reason);
        console.log('// ' + a.stackScope);
        for (const p of a.stackArguments || []) console.log('Stack input candidate ' + p.position + ': entry RSP+' + p.entryOffset + '; ' + p.width + ' bits @ ' + p.sources.join(', '));
        for (const p of a.arguments) console.log('Input candidate ' + p.position + ': ' + p.register + '; entry-bit mask ' + p.mask + ' @ ' + p.sources.join(', '));
        for (const r of a.returns) console.log('RAX at RET ' + r.source + ': ' + r.status + '; ' + r.alternatives.map(d => d.definition).join(' or ') + ' @ ' + r.sources.join(', '));
        for (const c of a.callers) {
            console.log('Caller ' + c.functionId + ' @ ' + c.source + ': ' + c.status + (c.reason ? '; ' + c.reason : ''));
            for (const p of c.stackArguments || []) console.log('  Stack slot ' + p.position + ': ' + p.status + ' @ ' + p.sources.join(', '));
            for (const p of c.arguments) console.log('  ' + p.position + ': ' + p.register + '; ' + p.status + ' @ ' + p.sources.join(', '));
            for (const u of c.returnUses) console.log('  RAX read mask ' + u.mask + ' @ ' + u.source);
        }
    }
    else if (format === '--storage') {
        const s = result.stackStorage;
        if (s.status !== 'available') {console.log('// Stack storage unavailable: ' + s.reason); process.exitCode = 2; return;}
        console.log('// Stack storage v' + s.version + '\n// ' + s.notice);
        for (const slot of s.slots) {
            console.log(slot.id + ' (entry_sp ' + slot.offset + ', ' + slot.width + ' bits)' + (slot.mixed ? ' [mixed/overlapping]' : ''));
            for (const role of slot.roles) console.log('  ' + role.label + (role.register ? ': ' + role.register : '') + ' [' + role.certainty + '] @ ' + role.sources.join(', '));
            for (const reason of slot.reasons) console.log('  ' + reason);
        }
    }
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
        if (simplified) console.log('// ' + (result.registerExpressions.notice || result.registerExpressions.reason + ' Original effects shown.'));
        if (clean) console.log('// ' + (result.registerCleanup.notice || result.registerCleanup.reason + ' Original writes retained.'));
        const prefix = simplified ? (clean ? 'simplifiedClean' : 'simplified') : (clean ? 'clean' : '');
        const key = prefix + (format === '--raw' ? (prefix ? 'Lines' : 'lines') : (prefix ? 'DisplayLines' : 'displayLines'));
        const lines = result[key];
        for (const line of lines) console.log('    '.repeat(line.depth) + line.text);
    }
    if (result.status === 'unavailable') process.exitCode = 2;
}
try {main();} catch (e) {console.error(e.message); process.exitCode = 1;}
