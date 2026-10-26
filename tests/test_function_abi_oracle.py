#!/usr/bin/env python3
"""Independent concrete witnesses for ABI candidates; executes only our test corpus."""
import argparse
import json
from pathlib import Path
import tempfile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn import x86_const as reg
from test_pseudocode import report
from test_pseudocode_oracle import initial, pe_segments, registers, RETURN
from test_function_abi import recover, call_program

COUNTS = dict(executions=0, input_reads=0, returns=0, caller_values=0, result_reads=0)


def execute(data, model, segments, start_id, trial, witnesses):
    abi=model['functionABI']; assert abi['status']=='available'
    base=int(data['module']['imageBase'],16)
    functions={f['id']:f for f in data['functions']}
    target=functions[model['functionId']]; start=functions[start_id]
    uc=Uc(UC_ARCH_X86,UC_MODE_64); mapped=set()
    def memory(address,size):
        for page in range(address & ~4095,(address+size+4095)&~4095,4096):
            if page not in mapped: uc.mem_map(page,4096);mapped.add(page)
    for address,body in segments: memory(address,len(body));uc.mem_write(address,body)
    memory(RETURN,4096)
    state=initial(64);state['registers']['rsp']=str(0x300808)
    state['registers']['rcx']=str(trial)
    state['registers']['rdx']=str(0xfedcba9876543210+trial)
    for n,byte in enumerate(RETURN.to_bytes(8,'little')):state['memory'][str(0x300808+n)]=byte
    for address,byte in state['memory'].items():memory(int(address),1);uc.mem_write(int(address),bytes([byte]))
    for name,value in state['registers'].items():uc.reg_write(getattr(reg,'UC_X86_REG_'+name.upper()),int(value))
    uc.reg_write(reg.UC_X86_REG_EFLAGS,2)
    native={base+i['rva']:i['id'] for b in data['blocks'] for i in b['instructions']}
    entries={base+f['rva']:f['id'] for f in data['functions']}
    input_uses={}
    for arg in abi['arguments']:
        for u in arg['uses']:input_uses.setdefault(u['source'],[]).append(u)
    returns={r['source']:r for r in abi['returns']}
    callers={c['source']:c for c in abi['callers'] if c['status']=='observed'}
    result_uses={}
    for c in callers.values():
        for u in c['returnUses']:result_uses.setdefault(u['source'],[]).append(u)
    before_entries={}; after={}; pending=None; last_return=None
    def capture():return {r:uc.reg_read(getattr(reg,'UC_X86_REG_'+r.upper())) for r in registers(64)}
    def reaching(row,actual,register,owner):
        values=[]
        for alt in row['alternatives']:
            if alt['kind']=='entry':values.append(before_entries[owner][register])
            elif alt['kind']=='write' and alt['source'] in after:values.append(after[alt['source']][register])
            elif alt['kind']=='clobber':return False  # Unknown alternative makes no concrete claim.
        assert actual[register] in values,('reaching-definition mismatch',row,actual[register],values)
        return True
    def trace(machine,address,size,_):
        nonlocal pending,last_return
        actual=capture()
        if pending:after[pending]=actual
        if address in entries:before_entries[entries[address]]=actual
        source=native.get(address);pending=source
        if not source:return
        for u in input_uses.get(source,[]):
            mask=int(u['mask'],16)
            same=(~(actual[u['register']]^before_entries[target['id']][u['register']])) & mask
            key=(source,u['register'],u['mask']);witnesses[key]=witnesses.get(key,0)|same
            COUNTS['input_reads']+=1
        if source in returns:
            if reaching(returns[source],actual,'rax',target['id']):COUNTS['returns']+=1
            last_return=actual['rax']
        if source in callers:
            for row in callers[source]['arguments']:
                if reaching(row,actual,row['register'],callers[source]['functionId']):COUNTS['caller_values']+=1
        for u in result_uses.get(source,[]):
            assert last_return is not None
            mask=int(u['mask'],16)
            assert actual['rax'] & mask == last_return & mask,('call-result read mismatch',u)
            COUNTS['result_reads']+=1
    uc.hook_add(UC_HOOK_CODE,trace)
    uc.emu_start(base+start['rva'],RETURN,timeout=2000000,count=100000)
    assert uc.reg_read(reg.UC_X86_REG_RIP)==RETURN,'authored ABI fixture must finish within budget'
    COUNTS['executions']+=1


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('analyzer',type=Path);p.add_argument('--fixtures',required=True,type=Path);a=p.parse_args()
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp);probe=report(a.analyzer,root,'90c3')
        if not probe['module']['decoderInfo']['capabilities']['structuredOperands']:
            print('SKIP: LLVM has no typed function ABI evidence');return
        cases=['89c801d0c3','b1014889c8c3','31c989c8c3','b9010000004889c8c3',
               '85c97405b9070000004889c8c3', # entry RCX survives only one path
               '85c97407b801000000eb05b802000000c3', # distinct return definitions
               call_program(),call_program(suffix='b00189c14883c428c3')]
        for code in cases:
            data=report(a.analyzer,root,code);callee=max(data['functions'],key=lambda f:f['rva']);model=recover(data,callee['id'])
            base=int(data['module']['imageBase'],16);witnesses={}
            for trial in (0,1,2,7):execute(data,model,[(base+0x1000,bytes.fromhex(code))],data['functions'][0]['id'],trial,witnesses)
            for arg in model['functionABI']['arguments']:
                for u in arg['uses']:
                    assert witnesses.get((u['source'],u['register'],u['mask']),0)==int(u['mask'],16),('missing concrete incoming-bit witness',u)
        # The existing source-known C ladder supplies callers, joins, loops,
        # stack spills and memory I/O at O0/O1; no external binary is executed.
        for path in sorted(a.fixtures.glob('recovery64-o?.json')):
            data=json.loads(path.read_text());_,segments=pe_segments(path.with_suffix('.exe'))
            start=next(f for f in data['functions'] if f['name']=='pe_entry')
            for f in data['functions']:
                model=recover(data,f['id'])
                for trial in (0,1):execute(data,model,segments,start['id'],trial,{})
    assert all(COUNTS.values()),COUNTS
    print('PASS: ABI evidence at {executions} independent executions; {input_reads} input reads, {returns} returns, {caller_values} caller values, {result_reads} call-result reads'.format(**COUNTS))


if __name__=='__main__':main()
