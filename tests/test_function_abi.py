#!/usr/bin/env python3
"""Decoder, direct caller, resource fallback and CLI contracts for function ABI evidence."""
import argparse
import copy
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from test_pseudocode import ROOT, report

PROFILE = 'windows-x64-gpr-v1'


def recover(data, function_id=None, contract=True, limits=None):
    script = """const fs=require('fs'),m=require('./web/pseudocode-model'),a=require('./web/function-abi');
const q=JSON.parse(fs.readFileSync(0,'utf8')),id=q.id||q.data.functions[0].id;
const contract=q.contract===true?{...a.emptyContract(q.data,id),profile:a.PROFILE.id}:q.contract;
console.log(JSON.stringify(m.recover(q.data,id,{functionContract:contract,functionAbiLimits:q.limits})));"""
    return json.loads(subprocess.run(['node', '-e', script], cwd=ROOT, input=json.dumps(
        {'data': data, 'id': function_id, 'contract': contract, 'limits': limits or {}}),
        capture_output=True, text=True, check=True, timeout=30).stdout)


def call_program(prefix='b907000000ba09000000', suffix='89c14883c428c3', callee='89c801d0c3'):
    before = bytes.fromhex('4883ec28' + prefix)
    after = bytes.fromhex(suffix)
    return (before + b'\xe8' + struct.pack('<i', len(after)) + after + bytes.fromhex(callee)).hex()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('analyzer', type=Path)
    p.add_argument('--fixtures', type=Path)
    a = p.parse_args()
    checks = 0
    def check(ok, why):
        nonlocal checks
        assert ok, why
        checks += 1
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        data = report(a.analyzer, root, call_program())
        callee = next(f for f in data['functions'] if f['rva'] != 0x1000)
        model = recover(data, callee['id'])
        doc = root/'report.json'; doc.write_text(json.dumps(data))
        if model['status'] == 'unavailable':
            check('Structured operands unavailable' in model['reason'], 'LLVM does not invent ABI semantics')
            cli = subprocess.run(['node', str(ROOT/'scripts/pseudocode.js'), str(doc), '0x1000', '--abi'], capture_output=True, text=True)
            check(cli.returncode == 2, 'unavailable ABI CLI returns failure')
            print(f'PASS: {checks} function-ABI decoder/CLI contracts (backend unavailable)'); return
        abi = model['functionABI']
        check(model['version'] == 8 and abi['version'] == 1 and abi['status'] == 'available', 'versioned opt-in evidence')
        check([x['register'] for x in abi['arguments']] == ['rcx','rdx'], 'callee uses two ABI register locations')
        check(abi['returns'][0]['alternatives'][0]['slice']['width'] == 32, 'observed return write width is retained')
        caller = abi['callers'][0]
        check(caller['status'] == 'observed' and len(caller['arguments']) == 4, 'direct caller observes all four locations without inventing count')
        check([x['status'] for x in caller['arguments']] == ['written','written','incoming','incoming'], 'unprepared registers remain incoming caller values')
        check(len(caller['returnUses']) == 1 and caller['returnUses'][0]['mask'] == '0xffffffff', 'post-call read witnesses actual RAX slice')
        original = recover(data, callee['id'], contract=None)
        check(original['functionABI']['status'] == 'default', 'no automatic function convention')
        for key in ['instructions','lines','displayLines','simplifiedLines','cleanLines','simplifiedCleanLines',
                    'valueAnalysis','registerSSA','stackStorage','registerExpressions','registerCleanup','callAnalysis']:
            check(model[key] == original[key], 'ABI selection does not change ' + key)
        own = recover(data)
        check(own['callAnalysis']['applied'] == 0 and any(i['status']=='barrier' for i in own['instructions']), 'function contract never enables own call summaries')
        for suffix, expected in [('b80700000089c14883c428c3', 0), ('b00189c14883c428c3', 1), ('4883c428c3', 0)]:
            d = report(a.analyzer, root, call_program(suffix=suffix)); f = next(f for f in d['functions'] if f['rva'] != 0x1000)
            result = recover(d,f['id'])['functionABI']['callers'][0]
            check(len(result['returnUses']) == expected, 'full/partial overwrite and unused result')
            if suffix.startswith('b001'):
                check(result['returnUses'][0]['mask'] == '0xffffff00', 'only preserved result bits are read')
        for code, registers in [('89c8c3',['rcx']),('31c989c8c3',[]),('b1014889c8c3',['rcx']),('b9010000004889c8c3',[]),('0f314889c8c3',[])]:
            d = report(a.analyzer,root,code)
            check([x['register'] for x in recover(d)['functionABI']['arguments']] == registers, 'decoded input bit identity: ' + code)
        conflict = recover(report(a.analyzer,root,'b801000000c20800'))['functionABI']
        check(len(conflict['conflicts']) == 1 and conflict['returns'], 'contradictory RET cleanup is visible alongside observations')
        unsafe = copy.deepcopy(data); unsafe['blocks'][0]['owners'].append('another')
        check(recover(unsafe,callee['id'])['functionABI']['callers'][0]['status'] == 'unavailable', 'ambiguous caller retained as unavailable')
        no_cont = copy.deepcopy(data); no_cont['edges'] = [e for e in no_cont['edges'] if e['kind'] != 'continuation']
        check(recover(no_cont,callee['id'])['functionABI']['callers'][0]['status'] == 'unavailable', 'missing continuation rejects caller evidence')
        for mutate in [lambda d:d['module'].update(truncated=True),lambda d:next(b for b in d['blocks'] if b['id']==callee['id'])['owners'].append('other')]:
            bad=copy.deepcopy(data);mutate(bad)
            check(recover(bad,callee['id'])['functionABI']['status']=='invalid','unsafe callee cannot accept a contract')
        x86=report(a.analyzer,root,'89c8c3',32)
        check(recover(x86)['functionABI']['status']=='invalid' and recover(x86,contract=None)['functionABI']['status']=='unavailable','x86 never borrows x64 profile')
        for limit in ['sites','callers']:
            b = recover(data,callee['id'],limits={limit:0})['functionABI']
            check(b['status']=='budget_exceeded' and not b['arguments'] and not b['callers'], 'transactional caller resource limit ' + limit)
        # Actual site ceiling, not just an artificial zero limit.
        code = b''.join(b'\xe8'+struct.pack('<i',5*(33-i-1)+1) for i in range(33)) + b'\xc3\xc3'
        many = report(a.analyzer,root,code.hex()); target = next(f for f in many['functions'] if f['rva'] != 0x1000)
        for limit in [32,100000]:
            b = recover(many,target['id'],limits={'sites':limit})['functionABI']
            check(b['status']=='budget_exceeded' and not b['callers'], 'hard site cap cannot be increased')
        # Nine uniquely owned caller functions exceed the real per-function cap.
        many=copy.deepcopy(data); caller_id=next(f['id'] for f in data['functions'] if f['rva']==0x1000)
        owned=[b for b in data['blocks'] if caller_id in b['owners']]; block_ids={b['id'] for b in owned}
        for n in range(1,9):
            remap=lambda id: id+'_copy'+str(n)
            for original in owned:
                b=copy.deepcopy(original); b['id']=remap(b['id']);b['owners']=[remap(caller_id)];b['rva']+=n*4096
                for i in b['instructions']:i['id']=remap(i['id']);i['rva']+=n*4096
                many['blocks'].append(b)
            many['functions'].append(dict(next(f for f in data['functions'] if f['id']==caller_id),id=remap(caller_id),rva=0x1000+n*4096))
            for original in data['edges']:
                if original['from'] not in block_ids:continue
                e=copy.deepcopy(original);e['from']=remap(e['from']);e['source']=remap(e['source'])
                if e['to'] in block_ids:e['to']=remap(e['to'])
                many['edges'].append(e)
        for limit in [8,100000]:
            b=recover(many,callee['id'],limits={'callers':limit})['functionABI']
            check(b['status']=='budget_exceeded' and 'caller budget' in b['reason'] and not b['callers'],'hard caller cap cannot be raised')
        file = root/'function-contract.json'; file.write_text(json.dumps(abi['contract']))
        args = ['node', str(ROOT/'scripts/pseudocode.js'), str(doc), hex(callee['rva'])]
        cli = subprocess.run([*args,'--function-contract',str(file),'--json'], capture_output=True, text=True)
        check(cli.returncode == 0 and json.loads(cli.stdout) == model, 'CLI JSON uses exact shared evidence')
        cli = subprocess.run([*args,'--function-contract',str(file),'--abi'], capture_output=True, text=True)
        check(cli.returncode == 0 and 'Input candidate 1: rcx' in cli.stdout and 'Caller ' in cli.stdout, 'text ABI export')
        for flags, expected in [(['--abi'],2),(['--abi','--clean'],1),(['--abi','--ssa'],1),(['--function-contract'],1)]:
            check(subprocess.run([*args,*flags], capture_output=True).returncode == expected, 'CLI rejects unavailable evidence or conflicting flags')
        for content, status in [('null',2),('{',1),(json.dumps(dict(abi['contract'],moduleId='wrong')),2),(' '*65537,1)]:
            file.write_text(content)
            check(subprocess.run([*args,'--function-contract',str(file),'--json'],capture_output=True).returncode == status,'invalid contract file is visible failure')
        if a.fixtures:
            for path in sorted(a.fixtures.glob('recovery64-o?.json')):
                d=json.loads(path.read_text())
                expected={'scalar_ops':2,'choose_value':2,'array_read_write':3,'sum_for':2,'sum_while':2,'transform_demo':4,'pe_entry':0}
                for f in d['functions']:
                    b=recover(d,f['id'])['functionABI']
                    check(b['status']=='available' and len(b['arguments'])==expected[f['name']], path.name+'/'+f['name']+': source-known GPR reads')
                    if f['name']!='pe_entry':
                        check(len(b['callers'])==1 and b['callers'][0]['status']=='observed' and b['callers'][0]['returnUses'], 'source ladder consumes each return')
    print(f'PASS: {checks} function-ABI decoder/CLI contracts')


if __name__ == '__main__': main()
