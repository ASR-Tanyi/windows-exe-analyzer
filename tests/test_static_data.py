#!/usr/bin/env python3
"""Static-only fixtures: positive/negative RIP targets, file data and zero fill.
Synthetic PE headers are parser fixtures, not executables intended for Windows.
No analyzed code is ever executed. No Python dependencies beyond the stdlib.
"""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parent
checks=0

def check(condition,message):
    global checks
    if not condition: raise AssertionError(message)
    checks+=1

def make_fixture(path,bits=64,base=None,large_bss=False):
    base=base if base is not None else (0x140000000 if bits==64 else 0x400000)
    b=bytearray(0xa00);b[:2]=b'MZ';struct.pack_into('<I',b,0x3c,0x80);b[0x80:0x84]=b'PE\0\0'
    opt_size=0xf0 if bits==64 else 0xe0
    struct.pack_into('<HHIIIHH',b,0x84,0x8664 if bits==64 else 0x14c,4,0,0,0,opt_size,0x102)
    opt=0x98;struct.pack_into('<H',b,opt,0x20b if bits==64 else 0x10b)
    struct.pack_into('<I',b,opt+16,0x2000)
    struct.pack_into('<Q' if bits==64 else '<I',b,opt+(24 if bits==64 else 28),base)
    struct.pack_into('<II',b,opt+32,0x1000,0x200);struct.pack_into('<II',b,opt+56,0x5000,0x400)
    for idx,(name,rva,vs,raw,rs,flags) in enumerate([
        (b'.text',0x2000,0x200,0x400,0x200,0x60000020),
        (b'.rdata',0x1000,0x1f0,0x600,0x200,0x40000040),
        (b'.data',0x3000,0x240,0x800,0x200,0xc0000040),
        (b'.bss',0x4000,0x4000000 if large_bss else 0x100,0,0,0xc0000080)]):
        off=opt+opt_size+idx*40;b[off:off+8]=name.ljust(8,b'\0')
        struct.pack_into('<IIII',b,off+8,vs,rva,rs,raw);struct.pack_into('<I',b,off+36,flags)
    code=bytearray();expected=[]
    def rip(prefix,target,access,width,suffix=b''):
        start=0x2000+len(code);length=len(prefix)+4+len(suffix)
        code.extend(prefix+struct.pack('<i',target-(start+length))+suffix)
        expected.append((start,target,access,width,'rip-relative'))
    def absolute(prefix,target,access,width,suffix=b''):
        start=0x2000+len(code);code.extend(prefix+struct.pack('<I',base+target)+suffix)
        expected.append((start,target,access,width,'absolute'))
    if bits==64:
        rip(b'\x48\x8d\x0d',0x1000,'address',0)
        rip(b'\x8b\x05',0x3000,'read',4)
        rip(b'\xc7\x05',0x3004,'write',4,struct.pack('<I',0x11223344))
        rip(b'\x83\x05',0x3004,'read-write',4,b'\x01')
        rip(b'\x0f\xb6\x05',0x1002,'read',1)
        rip(b'\x48\x8d\x15',0x1040,'address',0)
        rip(b'\x48\x8b\x05',0x1088,'read',8)
        rip(b'\xf3\x0f\x10\x05',0x1080,'read',4)
        rip(b'\xf3\x0f\x6f\x05',0x10e0,'read',16)
        rip(b'\x4c\x8d\x05',0x4000,'address',0)
        rip(b'\x8b\x05',0x3200,'read',4)
        rip(b'\x48\x8d\x0d',0x900000,'address',0)
        rip(b'\x48\x8d\x0d',0x10c0,'address',0)
        rip(b'\x48\x8d\x05',0x2000+len(code)+7,'address',0) # disp = 0
        code.extend(bytes.fromhex('8b 40 04')) # unresolved register base
        start=0x2000+len(code)
        code.extend(b'\x64\x8b\x05'+struct.pack('<i',0x1000-(start+7))) # FS base is unknown
    else:
        absolute(b'\x8d\x0d',0x1000,'address',0)
        absolute(b'\xa1',0x3000,'read',4)
        absolute(b'\xa3',0x3004,'write',4)
        absolute(b'\xc7\x05',0x3008,'write',4,struct.pack('<I',0x11223344))
        absolute(b'\x8d\x15',0x1040,'address',0)
        absolute(b'\x8b\x05',0x4000,'read',4)
        code.extend(bytes.fromhex('8b 40 04'))
        code.extend(b'\x64\xa1'+struct.pack('<I',base+0x1000))
    code.append(0xc3);b[0x400:0x400+len(code)]=code
    def put(offset,payload): b[offset:offset+len(payload)]=payload
    put(0x600,b'Hello static data\0');put(0x640,'Wide Hello\0'.encode('utf-16le'))
    put(0x680,struct.pack('<f',1.0));put(0x688,struct.pack('<Q',0xfedcba9876543210))
    put(0x6c0,b'</script><script>window.dataInjected=1</script>\0')
    put(0x800,struct.pack('<IIII',123,0x7fffffff,0x80000000,0xffffffff))
    path.write_bytes(b);return expected

def run_tests(exe):
    with tempfile.TemporaryDirectory() as tmp:
        tmp=Path(tmp)
        def invoke(path,*args):
            output=tmp/'report.json'
            p=subprocess.run([str(exe),str(path),'--json',str(output),*args],capture_output=True,text=True)
            check(p.returncode==0,p.stderr);return json.loads(output.read_text())
        for bits in (32,64):
            path=tmp/f'data{bits}.exe';expected=make_fixture(path,bits)
            d=invoke(path,'--html',str(tmp/'report.html'))
            check(d['schema']==2,'Versioned data report schema')
            insns={i['rva']:i for b in d['blocks'] for i in b['instructions']}
            refs=[r for i in insns.values() for r in i['dataRefs']]
            check(len(refs)==len(expected),'Register-based and segment-based operands stay unresolved')
            for ip,target,access,width,mode in expected:
                i=insns[ip];check(len(i['dataRefs'])==1,'One explicit static memory operand')
                ref=i['dataRefs'][0]
                check(ref['rva']==target,f'Target including full instruction length at {ip:x}')
                check(ref['access']==access,f'Access kind at {ip:x}: {ref}')
                check(ref['width']==width,f'Width at {ip:x}: {ref}')
                check(ref['mode']==mode,'Addressing mode preserved')
                text=i['operands'][ref['textBegin']:ref['textEnd']]
                check(text.startswith('[') and text.endswith(']'),'Clickable operand text span')
                check(ref['to'].endswith('_d_'+hex(target)[2:]),'Stable target identifier')
            sd=d['data'];regions={r['name']:r for r in sd['regions']}
            check(regions['.rdata']['fileSize']==0x1f0,'Raw alignment padding is not treated as virtual data')
            check(regions['.bss']['fileSize']==0 and not regions['.bss']['chunks'],'Do not invent file bytes for .bss')
            check(regions['.data']['size']==0x240 and regions['.data']['fileSize']==0x200,'Mixed raw / zero-fill section')
            chunks=regions['.rdata']['chunks'];check(bytes.fromhex(chunks[0]['hex']).startswith(b'Hello static data\0'),'Exact original file bytes')
            count=sum(len(c['hex'])//2 for r in sd['regions'] for c in r['chunks'])
            check(count==sd['embeddedBytes']==sd['fileBytes'],'Embedded byte accounting')
            text=(tmp/'report.html').read_text();check('</script><script>window.dataInjected' not in text,'Input data cannot break out of script tags')
            for budget in (0,1,64,512):
                limited=invoke(path,'--data-limit',str(budget))['data']
                actual=sum(len(c['hex'])//2 for r in limited['regions'] for c in r['chunks'])
                check(actual==limited['embeddedBytes'] and actual<=budget,'Embedding budget honored')
                check(limited['truncated'],'Partial report declared')
            named=invoke(path,'--data-name','0x1000=payload_renamed')
            check(next(t for t in named['data']['targets'] if t['rva']==0x1000)['name']=='payload_renamed','Analyst data names')
        # RIP calculation must not round large preferred VAs through floating point.
        path=tmp/'highbase.exe';base=0x2222222200000000;make_fixture(path,base=base)
        d=invoke(path);i=d['blocks'][0]['instructions'][0]
        check(i['dataRefs'][0]['va']==hex(base+0x1000),'64-bit VAs serialized exactly as strings')
        # Address-size override uses EIP + disp, zero-extended to 64 bits.
        b=bytearray(path.read_bytes());code=bytes.fromhex('67 8b 05')+struct.pack('<i',0x1000-(0x2000+7))+b'\xc3'
        b[0x400:0x400+len(code)]=code;path.write_bytes(b)
        d=invoke(path);ref=d['blocks'][0]['instructions'][0]['dataRefs'][0]
        check(ref['mode']=='eip-relative' and ref['va']=='0x1000' and ref['rva'] is None,'EIP address-size wrap is explicit')
        # Massive virtual section must not become a massive output allocation.
        make_fixture(path,large_bss=True);d=invoke(path)
        check(d['data']['embeddedBytes']<4096,'No allocation proportional to virtual zero-fill')
        check(next(r for r in d['data']['regions'] if r['name']=='.bss')['size']==0x4000000,'Large virtual extent retained')
        # Reject limits beyond bounded allowed range.
        p=subprocess.run([str(exe),str(path),'--data-limit','67108865'],capture_output=True,text=True)
        check(p.returncode!=0,'Oversized data limit rejected')
    print(f'PASS: {checks} static-data assertions')

if __name__=='__main__':run_tests(Path(sys.argv[1]).resolve())
