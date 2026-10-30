#!/usr/bin/env python3
"""Independent concrete witnesses for declared locations using only authored code."""
import argparse
import copy
from pathlib import Path
import struct
import tempfile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn import x86_const as reg
from test_pseudocode import report
from test_function_abi import recover, PROFILE

# Full register/slot values deliberately contain nonzero unused high bits.
# Expected values and locations are authored from Microsoft's x64 parameter and
# return rules, independently of the model's placement calculations.
PARAMETERS=['unsigned char','unsigned short','unsigned long','P','char','short','int','unsigned long long']
EXPECTED=[0x7a,0xbeef,0x89abcdef,0x1122334455667788,0x33,0x7654,0xf1e2d3c4,0xfedcba9876543210]
REGISTERS=[0xaabbccddeeff017a,0x112233445566beef,0x2233445589abcdef,0x1122334455667788]
STACK=[0x8877665544332233,0x1122334455667654,0x22334455f1e2d3c4,0xfedcba9876543210]
RETURN_VALUE=0xfedcba987654327a
STOP=0x500000

def program():
    before=bytes.fromhex('4883ec48')
    for opcode,value in zip(('48b9','48ba','49b8','49b9'),REGISTERS):
        before+=bytes.fromhex(opcode)+struct.pack('<Q',value)
    for offset,value in zip((0x20,0x28,0x30,0x38),STACK):
        before+=bytes.fromhex('48b8')+struct.pack('<Q',value)+bytes.fromhex('48894424')+bytes([offset])
    after=bytes.fromhex('4883c448c3')
    # Independently authored reads of each full register/slot into volatile R10.
    reads=['4c8bd1','4c8bd2','4d8bd0','4d8bd1','4c8b542428','4c8b542430','4c8b542438','4c8b542440']
    entry=len(before)+5+len(after);offset=entry;read_offsets=[]
    for opcode in reads:read_offsets.append(offset);offset+=len(bytes.fromhex(opcode))
    code=before+b'\xe8'+struct.pack('<i',len(after))+after+bytes.fromhex(''.join(reads)+'48b8')+struct.pack('<Q',RETURN_VALUE)+b'\xc3'
    return code,len(before)+5,entry,read_offsets

def execute(data,code,continuation,entry,locations,expected_return,associations,read_offsets):
    base=int(data['module']['imageBase'],16)
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    uc.mem_map(base+0x1000,0x1000);uc.mem_write(base+0x1000,code)
    uc.mem_map(0x300000,0x4000);uc.mem_map(STOP,0x1000)
    uc.reg_write(reg.UC_X86_REG_RSP,0x302008);uc.mem_write(0x302008,struct.pack('<Q',STOP))
    hits=[];read_hits=[]
    source_rvas={i['id']:i['rva'] for b in data['blocks'] for i in b['instructions']}
    for n,row in enumerate(associations['parameters']):
        assert row['status']=='observed' and len(row['reads'])==1
        evidence=row['reads'][0]
        assert source_rvas[evidence['source']]==0x1000+read_offsets[n],('wrong linked instruction',evidence)
        assert evidence['relation']=='covers'
        if n<4:assert evidence['observedMask']=='0xffffffffffffffff'
        else:assert evidence['width']==64 and evidence['overlapBytes']==locations['parameters'][n]['width']//8

    def read(location):
        if location['kind']=='register':
            value=uc.reg_read(getattr(reg,'UC_X86_REG_'+location['register'].upper()))>>location['bitOffset']
        else:
            assert location['base']=='entry_rsp'
            value=int.from_bytes(uc.mem_read(uc.reg_read(reg.UC_X86_REG_RSP)+int(location['byteOffset']),location['width']//8),'little')
        return value & ((1<<location['width'])-1)
    def trace(machine,address,size,_):
        if address==base+0x1000+entry:
            assert len(locations['parameters'])==len(EXPECTED)
            for row,expected in zip(locations['parameters'],EXPECTED):
                assert row['status']=='declared' and read(row['location'])==expected,('wrong declared input location',row,expected)
            hits.append('entry')
        if address-base-0x1000 in read_offsets:
            n=read_offsets.index(address-base-0x1000);evidence=associations['parameters'][n]['reads'][0]
            if n<4:
                actual=uc.reg_read(getattr(reg,'UC_X86_REG_'+['RCX','RDX','R8','R9'][n]))
                assert actual & int(evidence['overlapMask'],16)==EXPECTED[n]
            else:
                actual=int.from_bytes(uc.mem_read(uc.reg_read(reg.UC_X86_REG_RSP)+[40,48,56,64][n-4],evidence['overlapBytes']),'little')
                assert actual==EXPECTED[n]
            read_hits.append(n)
        if address==base+0x1000+continuation:
            result=locations['returnType']
            if expected_return is None:
                assert result['status']=='none' and result['location'] is None and uc.reg_read(reg.UC_X86_REG_RAX)==RETURN_VALUE
            else:
                assert result['status']=='declared' and read(result['location'])==expected_return,('wrong declared return location',result)
            hits.append('return')
    uc.hook_add(UC_HOOK_CODE,trace)
    uc.emu_start(base+0x1000,STOP,count=1000)
    assert hits==['entry','return'],hits
    assert read_hits==list(range(8)),read_hits

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('analyzer',type=Path);a=p.parse_args()
    with tempfile.TemporaryDirectory() as temp:
        code,continuation,entry,read_offsets=program();data=report(a.analyzer,Path(temp),code.hex())
        if not data['module']['decoderInfo']['capabilities']['structuredOperands']:
            print('SKIP: LLVM has no typed declared-ABI inspector');return
        callee=next(f for f in data['functions'] if f['rva']==0x1000+entry)
        cases=[('unsigned char',0x7a),('unsigned short',0x327a),('unsigned long',0x7654327a),
               ('unsigned long long',RETURN_VALUE),('void *',RETURN_VALUE),('void',None)]
        for result,expected in cases:
            contract=dict(version=3,moduleId=data['module']['id'],functionId=callee['id'],profile=PROFILE,
                declarations=[dict(id='authored',source='independent caller fixture',returnType='Result',
                    parameters=[dict(name='p'+str(n+1),type=t) for n,t in enumerate(PARAMETERS)],variadic='no',hiddenParameters='no')],
                typeAliases=[dict(name='P',source='fixture types',type='void *'),dict(name='Result',source='fixture types',type=result)])
            model=recover(data,callee['id'],contract=contract);locations=model['functionABI']['declarationLocations'][0]
            assert locations['status']=='mapped'
            associations=model['functionABI']['declarationEvidence']['declarations'][0]
            execute(data,code,continuation,entry,locations,expected,associations,read_offsets)
        # Deliberately wrong register and stack coordinates must fail the oracle.
        for index,field,value in [(0,'register','rdx'),(4,'byteOffset','48')]:
            wrong=copy.deepcopy(locations);wrong['parameters'][index]['location'][field]=value
            try:execute(data,code,continuation,entry,wrong,None,associations,read_offsets)
            except AssertionError:pass
            else:raise AssertionError('Independent checker accepted a wrong location')
        wrong=copy.deepcopy(associations);wrong['parameters'][0]['reads'][0]['source']=associations['parameters'][1]['reads'][0]['source']
        try:execute(data,code,continuation,entry,locations,None,wrong,read_offsets)
        except AssertionError:pass
        else:raise AssertionError('Independent checker accepted a wrong source link')
    print('PASS: declared ABI locations at 6 independent executions; 48 parameter values, 5 return values, 1 void-return case; 48 source-linked reads; 2 wrong locations and 1 wrong source link rejected')

if __name__=='__main__':main()
