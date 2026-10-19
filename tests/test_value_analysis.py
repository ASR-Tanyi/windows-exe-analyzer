#!/usr/bin/env python3
"""Decoder-to-value contracts: joins, aliases, provenance and unsafe fallbacks."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import tempfile
from test_pseudocode import ROOT, models, report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('analyzer', type=Path)
    p.add_argument('--fixtures', type=Path)
    args = p.parse_args()
    checks = 0
    def check(ok, reason):
        nonlocal checks
        assert ok, reason
        checks += 1
    def aliases(model):
        return [s for s in model['valueAnalysis']['slots'] if s['aliasable']]
    def fact_at(model, rva, after=True):
        source = next(i['source'] for i in model['instructions'] if i['rva'] == rva)
        return next(f for f in model['valueAnalysis']['facts'] if f['source'] == source)['after' if after else 'before']
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        cases = {
            'fixed': '4883ec20c7442404070000008b4424044883c420c3',
            'frame': '554889e54883ec10c745fc090000008b45fc4883c4105dc3',
            'overlap': '4883ec108944240466894424064883c410c3',
            'below_sp': '894424fcc3',
            'home': '894c2408c3',
            'return': '890424c3',
            'saved': '508b042458c3',
            'dynamic': '554889e54883ec104829cc8945fc4889ec5dc3',
            'partial_sp': '4883ec10b4088904244883c410c3',  # AH does not change RSP
            'truncate_sp': '4883ec1089e4890424c3',
            'call': '4883ec1089442404e8ff000000894424084883c410c3',
            'barrier': '4883ec100f3148890424c3',  # RDTSC unsupported
            'join_sp': '4883ec1083f90074074883ec08eb01908904244883c410c3',
            'diamond': '83f9007e07b801000000eb05b802000000c3',
            'unknown_join': '83f9007405b80100000089c2c3',
            'loop': '31c0ffc0ebfc',
            'module': '488d05f9ffffff8b00c3',
            'aliasing_store': '4883ec10c704240900000089038b04244883c410c3',
            'proof_cap': '4883ec08' * 70 + '8904244881c430020000c3',
        }
        reports = {name: report(args.analyzer, root, code) for name, code in cases.items()}
        if not reports['fixed']['module']['decoderInfo']['capabilities']['structuredOperands']:
            check(all(m['status'] == 'unavailable' for m in models(list(reports.values()))), 'LLVM cannot invent value facts')
        else:
            recovered = dict(zip(cases, models(list(reports.values()))))
            for name, model in recovered.items():
                check(model['valueAnalysis']['status'] == 'converged', name + ': analysis converges')
                check(model['complete'] is False and model['valueAnalysis']['complete'] is False, 'discovery is not certified complete')
                ids = {i['source'] for i in model['instructions']}
                check(all(set(line['sources']) <= ids for line in model['displayLines']), 'alias provenance uses real instructions')
                check(len(model['lines']) + len(aliases(model)) == len(model['displayLines']), 'no effect lines removed')
            fixed = recovered['fixed']
            check([s['id'] for s in aliases(fixed)] == ['slot_m1c_u32'], 'fixed slot stable name and width')
            check(len(aliases(fixed)[0]['sources']) >= 3, 'allocation, store and load provenance')
            check(any('slot_m1c_u32 = 0x7' in x['text'] for x in fixed['displayLines']), 'store displayed as memory alias')
            check(any('write32' in x['text'] for x in fixed['lines']), 'raw memory rendering retained')
            check(fact_at(fixed, 0x100c)['rax']['atoms'] is None, 'load after store is still unknown')
            check(fixed['valueAnalysis']['facts'][-1]['after']['rsp']['atoms'][0]['offset'] == '8', 'return facts include the popped return address')
            check([s['id'] for s in aliases(recovered['frame'])] == ['slot_mc_u32'], 'frame register propagated')
            for name in ['overlap', 'below_sp', 'home', 'return', 'saved', 'dynamic', 'truncate_sp', 'barrier', 'join_sp', 'proof_cap']:
                check(not aliases(recovered[name]), name + ': no unsafe alias')
            check(bool(aliases(recovered['partial_sp'])), 'unrelated byte write preserves stack state')
            check(any('Address proof exceeded the provenance budget' in s['reasons'] for s in recovered['proof_cap']['valueAnalysis']['slots']), 'proof cap disables alias presentation')
            check(any('Possible Windows x64 home space' in s['note'] for s in recovered['home']['valueAnalysis']['slots']), 'home-space role is conditional')
            call = recovered['call']
            check(fact_at(call, 0x1008) == {}, 'call clears all register facts including SP/FP')
            check(len(aliases(call)) == 1 and all(a['source'].endswith('_1004') for a in call['valueAnalysis']['accesses'] if a.get('alias')), 'only pre-call alias survives')
            ret = recovered['diamond']['valueAnalysis']['facts'][-1]['before']['rax']
            check({a['value'] for a in ret['atoms']} == {'1', '2'}, 'both branch alternatives at join')
            check('rax' not in fact_at(recovered['unknown_join'], 0x100a, False), 'unknown branch cannot disappear')
            check(recovered['loop']['valueAnalysis']['visits'] < 100, 'unbounded counter loop widens and terminates')
            access = next(a for a in recovered['module']['valueAnalysis']['accesses'] if not a['implicit'])
            check(access['address']['atoms'][0]['kind'] == 'module' and access['address']['atoms'][0]['rva'] == '4096', 'known mapped address classified in address context')
            check(fact_at(recovered['module'], 0x1007)['rax']['atoms'] is None, 'mapped load never becomes a static constant or import binding')
            check(fact_at(recovered['aliasing_store'], 0x100d)['rax']['atoms'] is None, 'unknown pointer store cannot make later stack load a constant')
            # Fail closed for incomplete ownership/discovery, not just bad data.
            shared = copy.deepcopy(reports['fixed']); shared['blocks'][0]['owners'].append('other')
            truncated = copy.deepcopy(reports['fixed']); truncated['module']['truncated'] = True
            unresolved = copy.deepcopy(reports['diamond']); unresolved['edges'][0]['to'] = None
            external = copy.deepcopy(reports['diamond']); external['edges'].append(dict(external['edges'][0], **{'from': 'outside'}))
            for model in models([shared, truncated, unresolved, external]):
                check(model['valueAnalysis']['status'] == 'unavailable' and not model['valueAnalysis']['facts'], 'unsafe graph discards all facts')
            # Directly lower the work budget to exercise transactional fallback.
            js = """const fs=require('fs'),m=require('./web/pseudocode-model'),a=require('./web/value-analysis');
            const r=JSON.parse(fs.readFileSync(0,'utf8')), f=r.functions[0].id;
            const b=r.blocks.filter(x=>x.owners.includes(f)), ids=new Set(b.map(x=>x.id));
            const lifted=new Map(b.map(x=>[x.id,x.instructions.map(i=>m.lift(i,r))]));
            console.log(JSON.stringify(a.analyze(r,b,r.edges.filter(e=>ids.has(e.from)),lifted,f,{visits:1})));"""
            v = json.loads(subprocess.run(['node', '-e', js], cwd=ROOT, input=json.dumps(reports['loop']), text=True,
                check=True, capture_output=True, timeout=10).stdout)
            check(v['status'] == 'budget_exceeded' and not v['facts'] and not v['slots'], 'budget discards provisional output')
            # 32-bit entry stack, frame slots and pointer-size return address.
            x86 = models([report(args.analyzer, root, '5589e583ec10c745fc090000008b45fc83c4105dc3', 32)])[0]
            check([s['id'] for s in aliases(x86)] == ['slot_m8_u32'], 'x86 frame offset accounts for pushed EBP')
            check(any(s['kind'] == 'return_address_region' and s['width'] == 32 for s in x86['valueAnalysis']['slots']), 'x86 return width')
        if args.fixtures:
            for path in sorted(args.fixtures.glob('recovery*-o?.json')):
                data = json.loads(path.read_text())
                f = next(f for f in data['functions'] if f['name'] == 'transform_demo')
                model = models([dict(data, functions=[f])])[0]
                if model['status'] == 'unavailable': continue
                check(model['valueAnalysis']['status'] == 'converged', path.name + ': nested-loop fixed point')
                if '-o0' in path.name: check(len(aliases(model)) >= 4, path.name + ': source-known stack aliases')
                check(any('write32' in line['text'] for line in model['displayLines']), 'array write remains explicit')
    print(f'PASS: {checks} value-analysis contracts')


if __name__ == '__main__':
    main()
