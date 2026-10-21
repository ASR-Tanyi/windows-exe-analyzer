#!/usr/bin/env python3
"""Test-only Unicorn execution across selected normal-return call boundaries.

Checks the summary as an abstraction, not an executable guessed callee. Only
our authored byte stubs and source-known recovery corpus may be executed here.
"""
import argparse
import json
from pathlib import Path
import struct
import tempfile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn import x86_const as reg
from test_pseudocode import report
from test_pseudocode_oracle import initial, pe_segments, register_trace, registers, RETURN, SSA_CHECKS
from test_call_summaries import recover, PRESERVED, VOLATILE


def contains(value, concrete, entry_sp):
    mask=(1<<value['width'])-1
    if concrete & int(value['knownMask'],16) != int(value['knownValue'],16): return False
    if value['atoms'] is None: return True
    return concrete in [(entry_sp+int(a['offset'])) & mask if a['kind']=='stack' else int(a['value']) for a in value['atoms']]


def run(data, model, segments, state):
    base=int(data['module']['imageBase'],16)
    start=base+next(f['rva'] for f in data['functions'] if f['id']==model['functionId'])
    uc=Uc(UC_ARCH_X86,UC_MODE_64); mapped=set()
    def memory(address,size):
        for page in range(address & ~4095,(address+size+4095)&~4095,4096):
            if page not in mapped: uc.mem_map(page,4096); mapped.add(page)
    for address,body in segments: memory(address,len(body)); uc.mem_write(address,body)
    memory(RETURN,4096)
    for address,byte in state['memory'].items(): memory(int(address),1); uc.mem_write(int(address),bytes([byte]))
    for name,value in state['registers'].items(): uc.reg_write(getattr(reg,'UC_X86_REG_'+name.upper()),int(value))
    uc.reg_write(reg.UC_X86_REG_EFLAGS,2)
    instructions={base+i['rva']:i for i in model['instructions']}
    facts={f['source']:f for f in model['valueAnalysis']['facts']}
    stack=int(state['registers']['rsp']); pending=None; boundaries=0; states=0
    def capture(): return {r:uc.reg_read(getattr(reg,'UC_X86_REG_'+r.upper())) for r in registers(64)}
    def check_facts(fact,actual):
        for r,v in fact.items(): assert contains(v,actual[r],stack),('unsound retained fact',r,v,actual[r])
    def trace(machine,address,size,_):
        nonlocal pending,boundaries,states
        actual=capture()
        if pending:
            call,before,entered=pending
            continuation=int(call['call']['returnAddress']['value'])
            if address==continuation:
                assert entered,'callee was skipped'
                for r in PRESERVED: assert actual[r]==before[r],('ABI fixture did not preserve',r)
                check_facts(facts[call['source']]['after'],actual)
                pending=None; boundaries+=1
            elif not entered:
                assert actual['rsp']==before['rsp']-8,'CALL must push one return address'
                assert int.from_bytes(machine.mem_read(actual['rsp'],8),'little')==continuation,'wrong return address'
                pending=(call,before,True)
        insn=instructions.get(address)
        if insn is None: return
        states+=1; check_facts(facts[insn['source']]['before'],actual)
        if insn['ops'] and insn['ops'][0]['kind']=='call_summary':
            assert pending is None,'unexpected recursive fixture call'
            assert actual['rsp']%16==0,'authored fixture must meet call alignment precondition'
            machine.mem_read(actual['rsp'],32)  # home storage is mapped
            pending=(insn,actual,False)
    uc.hook_add(UC_HOOK_CODE,trace)
    finish=register_trace(uc,64,start,state,model,skip_callees=True)
    uc.emu_start(start,RETURN,timeout=2000000,count=100000)
    assert uc.reg_read(reg.UC_X86_REG_RIP)==RETURN and pending is None,'call fixture did not return within budget'
    finish(False)
    return boundaries,states,capture(),uc


def stub():
    # Save all nonvolatile GPRs other than SP, overwrite every one, and restore.
    # Change all volatile GPRs with nonzero high halves and write caller home
    # space. The register/stack preservation is checked against machine state.
    body=bytearray.fromhex('c7442408efbeadde')
    saved=[(3,'rbx'),(5,'rbp'),(6,'rsi'),(7,'rdi'),(12,'r12'),(13,'r13'),(14,'r14'),(15,'r15')]
    for n,_ in saved: body.extend(bytes(([0x41] if n>=8 else [])+[0x50+(n&7)]))
    for n,_ in saved: body.extend(bytes([0x49 if n>=8 else 0x48,0xb8+(n&7)])+struct.pack('<Q',0x123456789abcdef0+n))
    for n in [0,1,2,8,9,10,11]: body.extend(bytes([0x49 if n>=8 else 0x48,0xb8+(n&7)])+struct.pack('<Q',0xf123456700000000+n))
    for n,_ in reversed(saved): body.extend(bytes(([0x41] if n>=8 else [])+[0x58+(n&7)]))
    body.extend(b'\xc3'); return bytes(body)


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('analyzer',type=Path); p.add_argument('--fixtures',required=True,type=Path); a=p.parse_args()
    cases=boundaries=states=negatives=0
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp)
        probe=report(a.analyzer,root,'90c3')
        if not probe['module']['decoderInfo']['capabilities']['structuredOperands']:
            print('SKIP: LLVM has no typed call summaries'); return
        base=int(probe['module']['imageBase'],16); start=base+0x1000
        for form in ['direct','register','memory','loop']:
            prefix=bytearray.fromhex('534883ec20')  # save RBX; aligned call SP
            suffix=bytes.fromhex('4883c4205bc3')
            if form=='loop': prefix.extend(bytes.fromhex('bb03000000')); suffix=bytes.fromhex('ffcb75f74883c4205bc3')
            if form in ['register','memory']:
                call=b'\x41\xff\xd3' if form=='register' else b'\xff\x54\x24\x10'
                extra=0 if form=='register' else 5
                target=start+len(prefix)+10+extra+len(call)+len(suffix)
                prefix.extend(b'\x49\xbb'+struct.pack('<Q',target))
                if form=='memory': prefix.extend(bytes.fromhex('4c895c2410'))
            else:
                call=b'\xe8'+struct.pack('<i',len(suffix))
            code=bytes(prefix)+call+suffix+stub()
            data=report(a.analyzer,root,code.hex()); model=recover(data,all_calls=True)
            assert model['stats']['assumedCalls']==1, (form,model['callAnalysis'])
            for trial in range(6):
                state=initial(64); state['registers']['rsp']=str(0x300808)
                for i,byte in enumerate(RETURN.to_bytes(8,'little')): state['memory'][str(0x300808+i)]=byte
                b,s,actual,uc=run(data,model,[(start,code)],state)
                assert b==(3 if form=='loop' else 1)
                assert actual['rax']==0xf123456700000000,'upper return bits must remain unknown in summary'
                assert int.from_bytes(uc.mem_read(0x3007e0,4),'little')==0xdeadbeef,'callee home-space write must be observable'
                cases+=1; boundaries+=b; states+=s
        # Prove that a falsely selected ABI is a conditional assumption, not a
        # certification: the independent checker must reject broken callees.
        saved_counts=dict(SSA_CHECKS)
        for body,why in [(bytes.fromhex('48bb8877665544332211c3'),'ABI fixture did not preserve'),
                         (bytes.fromhex('c20800'),'ABI fixture did not preserve')]:
            prefix=bytes.fromhex('534883ec20'); suffix=bytes.fromhex('4883c4205bc3')
            code=prefix+b'\xe8'+struct.pack('<i',len(suffix))+suffix+body
            data=report(a.analyzer,root,code.hex()); model=recover(data,all_calls=True)
            state=initial(64); state['registers']['rsp']=str(0x300808)
            for i,byte in enumerate(RETURN.to_bytes(8,'little')): state['memory'][str(0x300808+i)]=byte
            try: run(data,model,[(start,code)],state)
            except AssertionError as e: assert why in str(e),str(e); negatives+=1
            else: raise AssertionError('broken ABI unexpectedly accepted by oracle')
        SSA_CHECKS.update(saved_counts)
        for path in sorted(a.fixtures.glob('recovery64-o?.json')):
            data=json.loads(path.read_text()); f=next(f for f in data['functions'] if f['name']=='pe_entry')
            model=recover(data,all_calls=True,function_id=f['id']); base,segments=pe_segments(path.with_suffix('.exe'))
            assert model['stats']['assumedCalls']==6 and model['status']=='assumed_subset'
            for trial in range(6):
                state=initial(64); state['registers']['rsp']=str(0x300808)
                for i,byte in enumerate(RETURN.to_bytes(8,'little')): state['memory'][str(0x300808+i)]=byte
                b,s,actual,uc=run(data,model,segments,state)
                assert b==6
                # Independently calculated result of recovery.c's six calls.
                values=[0,1,2,7,31,63,255,0xffffffff]; mask=0xffffffff
                v=9^0x35; expected=(((v<<2)|(v>>3))-7+11+10+sum(values)) & mask
                x=0
                for v in values: x^=v
                expected=(expected+x)&mask; checksum=7
                for i,v in enumerate(values):
                    v=(v+i*3)&mask; v=((v^0x55)+9 if v>30 else v*5+1)&mask
                    for _ in range(2): v=((v<<1)^(v>>3))&mask
                    checksum=((checksum*33)^v)&mask
                expected=(expected+checksum)&0x7fffffff
                assert actual['rax']&mask==expected,('source call-chain result',actual['rax'],expected)
                cases+=1; boundaries+=b; states+=s
    print(f'PASS: {cases} independent call executions; {boundaries} call/return boundaries; {states} caller states')
    print(f'PASS: {negatives} deliberately invalid ABI implementations rejected by the independent checker')
    print('PASS: call-path SSA at {states} states, {uses} uses, {joins} selected PHI edges and {exits} exit values'.format(**SSA_CHECKS))


if __name__=='__main__': main()
