#!/usr/bin/env python3
"""Explicit call contracts through the decoder, value analysis, SSA and CLI."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import tempfile
from test_pseudocode import ROOT, report

PROFILE = 'windows-x64-normal-return-v1'
PRESERVED = ['rbx', 'rbp', 'rsi', 'rdi', 'rsp', 'r12', 'r13', 'r14', 'r15']
VOLATILE = ['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11']


def recover(data, manifest=None, all_calls=False, function_id=None):
    script = """const fs=require('fs'),m=require('./web/pseudocode-model');
const r=JSON.parse(fs.readFileSync(0,'utf8')), id=r.id||r.data.functions[0].id;
let a=r.manifest;
if(r.all){const b=m.recover(r.data,id);a={...b.callAnalysis.assumptions,
 sites:b.callAnalysis.sites.filter(s=>s.eligible).map(s=>({source:s.source,profile:'windows-x64-normal-return-v1'}))};}
console.log(JSON.stringify(m.recover(r.data,id,{callAssumptions:a})));"""
    return json.loads(subprocess.run(['node', '-e', script], cwd=ROOT, input=json.dumps(
        {'data': data, 'manifest': manifest, 'all': all_calls, 'id': function_id}),
        text=True, capture_output=True, check=True, timeout=30).stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('analyzer', type=Path)
    parser.add_argument('--fixtures', type=Path)
    args = parser.parse_args()
    checks = 0
    def check(ok, why):
        nonlocal checks
        assert ok, why
        checks += 1
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        suffix = bytes.fromhex('89c189da4c8b04244883c428c3')
        code = bytes.fromhex('4883ec28bb2a000000b807000000') + b'\xe8' + len(suffix).to_bytes(4, 'little') + suffix + b'\xc3'
        data = report(args.analyzer, root, code.hex())
        default = recover(data)
        if default['status'] == 'unavailable':
            check('Structured operands unavailable' in default['reason'], 'backend fallback')
            print(f'PASS: {checks} call-summary contract (backend unavailable)')
            return
        model = recover(data, all_calls=True)
        manifest = model['callAnalysis']['assumptions']
        call = next(i for i in model['instructions'] if i['mnemonic'] == 'call')
        source = call['source']
        fact = next(f for f in model['valueAnalysis']['facts'] if f['source'] == source)
        unknown = next(f for f in default['valueAnalysis']['facts'] if f['source'] == source)
        check(not unknown['after'], 'unknown calls clear all known values, including SP and nonvolatile GPRs')
        check(model['status'] == 'assumed_subset' and model['stats']['assumedCalls'] == 1, 'assumptions have a distinct support status')
        check(call['call']['entryStackDelta'] == -8 and call['ops'][0]['kind'] == 'call_summary' and len(call['ops']) == 1, 'raw CALL and call/return summary are separate')
        check(call['call']['returnAddress']['value'] == str(int(data['module']['imageBase'],16) + call['rva'] + 5), 'raw next IP retained')
        for reg in ['rbx', 'rsp']:
            check(fact['before'][reg]['atoms'] == fact['after'][reg]['atoms'], 'nonvolatile value/SP unchanged at continuation')
            check(source in fact['after'][reg]['sources'], 'retained value depends on explicit call assertion')
        check(all(r not in fact['after'] for r in VOLATILE), 'all volatile bits unknown, no guessed return zero-extension')
        flow = model['registerSSA']; defs = {d['id']:d for d in flow['definitions']}
        record = next(i for i in flow['instructions'] if i['source']==source)
        check({defs[d]['register'] for d in record['writes']} == set(VOLATILE), 'SSA clobbers exactly volatile GPRs')
        check(record['memory']['unknown'] and record['flags']['unknown'], 'memory and flags not preserved')
        check(len(record['reads']) == 16, 'unknown prototype conservatively uses all input GPRs')
        check(flow['assumptionSources'] == [source], 'SSA exposes retained-version assumptions')
        check(any(s['kind']=='call_storage' and not s['aliasable'] for s in model['valueAnalysis']['slots']), 'home/return storage never becomes independent local alias')
        check(all('r8' not in f['after'] for f in model['valueAnalysis']['facts'] if f['source'] > source), 'mutable load remains unknown after summary')
        after = [i for i in model['instructions'] if i['rva'] > call['rva']]
        reads = [u for u in flow['uses'] if u['source']==after[1]['source'] and u['kind']=='instruction']
        check(reads and defs[reads[0]['definition']]['source'] != source, 'nonvolatile read keeps prior SSA definition')
        check('assume_windows_x64_call' in '\n'.join(l['text'] for l in model['lines']), 'text shows conditional summary')
        for mutate in [lambda a:a.update(version=2), lambda a:a.update(moduleId='other'), lambda a:a.update(functionId='other'),
                       lambda a:a.update(extra=True), lambda a:a['sites'].append(a['sites'][0]),
                       lambda a:a['sites'][0].update(profile='cdecl'), lambda a:a['sites'][0].update(source='not_a_call'),
                       lambda a:a['sites'][0].update(preserved=['rax']), lambda a:a.update(sites=a['sites']*129)]:
            bad = copy.deepcopy(manifest); mutate(bad); rejected = recover(data,bad)
            check(rejected['callAnalysis']['status']=='invalid' and rejected['stats']['assumedCalls']==0, 'invalid binding fails transactionally')
            check(rejected['registerSSA']==default['registerSSA'], 'invalid document retains conservative graph')
        for mutate in [lambda d:d['module'].update(truncated=True),
                       lambda d:d['blocks'][0]['owners'].append('another'),
                       lambda d:d.update(edges=[e for e in d['edges'] if e['kind']!='continuation']),
                       lambda d:d['edges'].append({'kind':'jump','from':'outside','to':model['callAnalysis']['sites'][0]['continuation'],'source':'outside'})]:
            bad=copy.deepcopy(data); mutate(bad)
            check(recover(bad,manifest)['callAnalysis']['status']=='invalid','unsafe CFG does not apply summary')
        for bits, text in [(32,'e801000000c3c3'), (64,'66e801000000c3c3')]:
            other=report(args.analyzer,root,text,bits); base=recover(other)
            check(base['callAnalysis']['sites'] and not base['callAnalysis']['sites'][0]['eligible'], 'x86/prefixed CALL unsupported')
        for text in ['4883ec28ffd34883c428c3','4883ec28ff5424104883c428c3']:
            indirect=report(args.analyzer,root,text); m=recover(indirect,all_calls=True)
            check(m['stats']['assumedCalls']==1, 'explicit summary can cover unknown indirect callee without resolving target')
            rec=next(i for i in m['registerSSA']['instructions'] if i['memory']['unknown'])
            uses={u['id']:u for u in m['registerSSA']['uses']}
            check(any(uses[id]['role'].startswith('call-target') for id in rec['reads']), 'indirect target is read before clobbers and stack changes')
        mixed=report(args.analyzer,root,'4883ec28e8070000000f314883c428c3c3')
        m=recover(mixed,all_calls=True)
        barrier=next(i for i in m['instructions'] if i['mnemonic']=='rdtsc')
        check(not next(f['after'] for f in m['valueAnalysis']['facts'] if f['source']==barrier['source']), 'unsupported operation after a summary still clears every value')
        check(len([d for d in m['registerSSA']['definitions'] if d['source']==barrier['source'] and d['kind']=='clobber'])==16, 'unsupported operation retains all-register clobbers')
        file=root/'calls.json'; file.write_text(json.dumps(manifest))
        doc=root/'input.json'; doc.write_text(json.dumps(data))
        cli=subprocess.run(['node',str(ROOT/'scripts/pseudocode.js'),str(doc),'0x1000','--calls',str(file),'--json'],capture_output=True,text=True)
        check(cli.returncode==0 and json.loads(cli.stdout)==model,'CLI and browser model use same explicit document')
        file.write_text(json.dumps(dict(manifest,moduleId='wrong')))
        cli=subprocess.run(['node',str(ROOT/'scripts/pseudocode.js'),str(doc),'0x1000','--calls',str(file)],capture_output=True,text=True)
        check(cli.returncode==2 and 'No call summaries applied' in cli.stderr, 'CLI invalid assumptions are a visible failure')
        file.write_text('null')
        cli=subprocess.run(['node',str(ROOT/'scripts/pseudocode.js'),str(doc),'0x1000','--calls',str(file)],capture_output=True,text=True)
        check(cli.returncode==2, 'a null JSON file does not bypass the binding schema')
        if args.fixtures:
            for path in sorted(args.fixtures.glob('recovery*-o?.json')):
                data=json.loads(path.read_text()); f=next(f for f in data['functions'] if f['name']=='pe_entry')
                m=recover(data,all_calls=True,function_id=f['id'])
                check(m['stats']['assumedCalls']==(6 if '64' in path.name else 0), 'source-known six-call ladder at O0/O1, separate x86 fallback')
    print(f'PASS: {checks} call-summary contracts')


if __name__=='__main__': main()
