#!/usr/bin/env python3
"""Decoded stack-role evidence, unsafe graphs, call assumptions and CLI parity."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import tempfile
from test_pseudocode import ROOT, models, report

# Also executed by the independent Unicorn suite. Expected classifications are
# authored from the instructions; bytes are never run as native executables.
CASES = {
    'push_save': ('53bb070000005bc3', 1, True),
    'mov_save': ('4883ec2048895c24084831db488b5c24084883c420c3', 1, True),
    'spill': ('4883ec10bb0900000048891c24bb07000000488b1c244883c410c3', 1, False),
    'partial_spill': ('4883ec1088642400b4018a6424004883c410c3', 1, False),
    'unknown_write': ('5348890f31db5bc3', 0, False),
    'overlap': ('4883ec1048891c24c644240401488b1c244883c410c3', 0, False),
    'overwrite': ('5348890c245bc3', 0, False),
    'width_change': ('4883ec1048891c248b1c244883c410c3', 0, False),
    'deallocate': ('4883ec1048891c244883c4104883ec10488b1c244883c410c3', 0, False),
    'dynamic': ('554889e54883ec2048895df84829cc488b5df84889ec5dc3', 0, False),
    'branches': ('5385c97407b801000000eb05b8020000005bc3', 1, True),
    'frame_save': ('554889e54883ec10c745fc090000008b45fc4889ec5dc3', 1, True),
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('analyzer', type=Path)
    p.add_argument('--fixtures', type=Path)
    a = p.parse_args()
    checks = 0
    def check(ok, message):
        nonlocal checks
        assert ok, message
        checks += 1
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        reports = {name: report(a.analyzer, root, code) for name, (code, _, _) in CASES.items()}
        structured = reports['push_save']['module']['decoderInfo']['capabilities']['structuredOperands']
        for (name, data), model in zip(reports.items(), models(list(reports.values()))):
            if not structured:
                check(model['status'] == 'unavailable' and 'stackStorage' not in model, name + ': no invented LLVM storage roles')
                continue
            storage = model['stackStorage']
            check(model['version'] == 8 and storage['version'] == 1 and storage['status'] == 'available', name + ': versioned storage analysis')
            check(len(storage['pairs']) == CASES[name][1], name + ': exact save/reload classification')
            if CASES[name][1]:
                check(all(p['entryValue'] == CASES[name][2] for p in storage['pairs']), name + ': whole-entry versus temporary slice')
            ids = {i['source'] for i in model['instructions']}
            check(all(set(r['sources']) <= ids for s in storage['slots'] for r in s['roles']), name + ': valid instruction evidence')
            check(any(r['kind'] == 'entry_return_address' for s in storage['slots'] for r in s['roles']), name + ': entry return region')
        if structured:
            x86 = models([report(a.analyzer, root, '53bb070000005bc3', 32)])[0]['stackStorage']
            check(len(x86['pairs']) == 1 and x86['pairs'][0]['width'] == 32 and x86['pairs'][0]['entryValue'], 'x86 full-width entry save')
            shared = copy.deepcopy(reports['push_save']); shared['blocks'][0]['owners'].append('other')
            truncated = copy.deepcopy(reports['push_save']); truncated['module']['truncated'] = True
            for m in models([shared, truncated]):
                check(m['stackStorage']['status'] == 'unavailable' and not m['stackStorage']['slots'], 'unsafe ownership discards roles')
            data = report(a.analyzer, root, '4883ec3848895c2430c744242007000000e84b000000488b5c24304883c438c3')
            script = """const fs=require('fs'),m=require('./web/pseudocode-model'),c=require('./web/call-summaries');
            const r=JSON.parse(fs.readFileSync(0,'utf8')), f=r.functions[0].id, raw=m.recover(r,f);
            const callAssumptions={version:1,moduleId:r.module.id,functionId:f,sites:raw.callAnalysis.sites.map(s=>({source:s.source,profile:c.PROFILE.id}))};
            console.log(JSON.stringify(m.recover(r,f,{callAssumptions})));"""
            selected = json.loads(subprocess.run(['node', '-e', script], cwd=ROOT, input=json.dumps(data), text=True,
                capture_output=True, check=True, timeout=10).stdout)
            roles = [r for s in selected['stackStorage']['slots'] for r in s['roles']]
            check({'call_return_address', 'call_home_space', 'outgoing_argument'} <= {r['kind'] for r in roles}, 'decoded selected call exposes regions and argument candidates')
            check(not selected['stackStorage']['pairs'], 'selected call does not prove saved memory survives')
            check(all(r['assumptionSources'] for r in roles if r['kind'].startswith('call_') or r['kind'] == 'outgoing_argument'), 'ABI claims retain explicit assumption')
            default = models([data])[0]
            check(not any(r['kind'].startswith('call_') for s in default['stackStorage']['slots'] for r in s['roles']), 'no automatic x64 ABI storage roles')
        data = reports['push_save']; path = root / 'export.json'; path.write_text(json.dumps(data))
        cli = subprocess.run(['node', str(ROOT/'scripts/pseudocode.js'), str(path), '0x1000', '--storage'], capture_output=True, text=True, timeout=10)
        check(cli.returncode == (0 if structured else 2), 'storage CLI capability status')
        check('Saved entry register' in cli.stdout if structured else 'Structured operands unavailable' in cli.stdout, 'storage CLI uses shared model')
        bad = subprocess.run(['node', str(ROOT/'scripts/pseudocode.js'), str(path), '0x1000', '--storage', '--clean'], capture_output=True, text=True, timeout=10)
        check(bad.returncode == 1, 'code-only transform flag cannot silently alter storage export')
        if a.fixtures and structured:
            for path in sorted(a.fixtures.glob('recovery*-o?.json')):
                data = json.loads(path.read_text())
                for f in data['functions']:
                    m = models([dict(data, functions=[f])])[0]
                    check(m['stackStorage']['status'] == 'available', path.name + '/' + f['name'] + ': bounded roles available')
                    if '-o0' in path.name and f['name'] == 'scalar_ops':
                        check(m['stackStorage']['stats']['savedRegisters' if '32' in path.name else 'spillReloads'] >= 1, path.name + ': compiler storage evidence')
    print('PASS: %d stack-storage decoder/CLI contracts' % checks)


if __name__ == '__main__': main()
