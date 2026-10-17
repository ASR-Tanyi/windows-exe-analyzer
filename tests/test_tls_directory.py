#!/usr/bin/env python3
"""TLS parser/discovery integration. Input Windows code is never executed."""
import argparse
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

ANALYZER = None
CLANG = None
LINKER = None


def make_tls(path, *, bits=64, targets=None, base=None, terminated=True,
             entry=0x1000, dll=False):
    w = bits // 8
    base = (0x140000000 if bits == 64 else 0x400000) if base is None else base
    targets = [base+0x1010, base+0x1020] if targets is None else list(targets)
    size = max(512, ((len(targets)+1)*w+511)//512*512)
    data = bytearray(0x800+size)
    data[:2] = b'MZ'; struct.pack_into('<I',data,0x3c,0x80)
    data[0x80:0x84] = b'PE\0\0'
    opt_size = 0xf0 if bits == 64 else 0xe0
    struct.pack_into('<HHIIIHH',data,0x84,0x8664 if bits == 64 else 0x14c,
                     3,0,0,0,opt_size,0x102 | (0x2000 if dll else 0))
    opt=0x98; sec=opt+opt_size
    struct.pack_into('<H',data,opt,0x20b if bits == 64 else 0x10b)
    struct.pack_into('<I',data,opt+16,entry)
    struct.pack_into('<Q' if bits==64 else '<I',data,opt+(24 if bits==64 else 28),base)
    struct.pack_into('<II',data,opt+32,4096,512)
    struct.pack_into('<II',data,opt+56,((0x3000+size+4095)//4096)*4096,0x400)
    struct.pack_into('<I',data,opt+(108 if bits==64 else 92),16)
    directory=opt+(112 if bits==64 else 96)+9*8
    struct.pack_into('<II',data,directory,0x2000,4*w+8)
    for k,(name,rva,raw,length,flags) in enumerate([
        (b'.code',0x1000,0x400,512,0x60000020),
        (b'.meta',0x2000,0x600,512,0x40000040),
        (b'.slots',0x3000,0x800,size,0x40000040)]):
        at=sec+k*40; data[at:at+8]=name.ljust(8,b'\0')
        struct.pack_into('<IIII',data,at+8,length,rva,length,raw)
        struct.pack_into('<I',data,at+36,flags)
    data[0x400]=data[0x410]=data[0x420]=0xc3
    fmt='<Q' if bits==64 else '<I'
    struct.pack_into(fmt,data,0x600+3*w,base+0x3000)
    for k,target in enumerate(targets):struct.pack_into(fmt,data,0x800+k*w,target)
    if not terminated:struct.pack_into('<I',data,sec+80+8,len(targets)*w)
    path.write_bytes(data)
    return data,{'base':base,'width':w,'section':sec,'directory':directory,'array':0x800,'header':0x600}


class TlsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.pe=self.root/'input.exe'

    def run_report(self,*options,path=None,ok=True):
        output=self.root/'report.json'
        proc=subprocess.run([str(ANALYZER),str(path or self.pe),'--json',str(output),*options],
                            capture_output=True,text=True,timeout=60)
        self.assertEqual(proc.returncode==0,ok,proc.stderr)
        d=json.loads(output.read_text());self.assertEqual(d,json.loads(json.dumps(d)))
        return d

    def generate(self,**kwargs):
        make_tls(self.pe,**kwargs);return self.run_report()

    def put(self,at,value,fmt='<I'):
        b=bytearray(self.pe.read_bytes());struct.pack_into(fmt,b,at,value);self.pe.write_bytes(b)

    def test_x86_and_x64_independent_roots(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                d=self.generate(bits=bits);t=d['tlsDirectory']
                self.assertEqual({f['rva'] for f in d['functions']},{0x1000,0x1010,0x1020})
                self.assertEqual(d['edges'],[]);self.assertIsNone(d['module']['mainId'])
                self.assertEqual((t['status'],t['seedLocations']),('parsed',2))
                self.assertEqual(t['relationship'],'loader_callback_not_cfg_call')
                self.assertTrue(t['terminated']);self.assertEqual(t['pointerSize'],bits//8)
                f=next(f for f in d['functions'] if f['rva']==0x1010)
                evidence=next(e for e in f['evidenceRecords'] if e['rule']=='pe.tls_callback_seed')
                self.assertEqual(evidence['source']['value'],'0x3000')
                self.assertEqual(evidence['origin'],'tls_directory')
                self.assertEqual((d['schema'],d['analysisModelVersion']),(2,1))

    def test_disable_tls_discovery_only(self):
        make_tls(self.pe);d=self.run_report('--no-tls-seeds')
        self.assertEqual(len(d['functions']),1);self.assertEqual(d['tlsDirectory']['seedLocations'],0)
        self.assertTrue(all(c['discovery']=='disabled' for c in d['tlsDirectory']['callbacks']))
        self.assertEqual(len(self.run_report('--no-unwind-seeds')['functions']),3)

    def test_duplicate_slots_preserve_evidence(self):
        d=self.generate(targets=[0x140001010]*3)
        self.assertEqual(len(d['functions']),2);self.assertEqual(d['tlsDirectory']['seedLocations'],1)
        self.assertEqual([c['duplicateOf'] for c in d['tlsDirectory']['callbacks']],[None,0,0])
        f=next(f for f in d['functions'] if f['rva']==0x1010)
        self.assertEqual([e['source']['value'] for e in f['evidenceRecords']],['0x3000','0x3008','0x3010'])

    def test_existing_direct_call_and_names_survive(self):
        b,_=make_tls(self.pe);b[0x400:0x406]=bytes.fromhex('e80b000000c3');self.pe.write_bytes(b)
        d=self.run_report('--name','0x1010=reviewed_callback')
        f=next(f for f in d['functions'] if f['rva']==0x1010)
        self.assertEqual(f['name'],'reviewed_callback')
        self.assertEqual({e['rule'] for e in f['evidenceRecords']},{'cfg.direct_call','cli.name','pe.tls_callback_seed'})
        self.assertEqual(len([e for e in d['edges'] if e['kind']=='call']),1)

    def test_callback_inside_instruction_is_not_decoded(self):
        b,_=make_tls(self.pe,targets=[0x140001001]);b[0x400:0x406]=bytes.fromhex('b801000000c3');self.pe.write_bytes(b)
        d=self.run_report();self.assertEqual([f['rva'] for f in d['functions']],[0x1000])
        self.assertEqual(d['tlsDirectory']['callbacks'][0]['discovery'],'not_decoded')
        self.assertIn('overlapping_decode',d['diagnostics']['counts'])

    def test_analyst_main_remains_explicit(self):
        make_tls(self.pe);d=self.run_report('--main-rva','0x1010')
        f=next(f for f in d['functions'] if f['rva']==0x1010)
        self.assertEqual(f['name'],'main');self.assertEqual(d['module']['mainId'],f['id'])
        self.assertIn('pe.tls_callback_seed',{e['rule'] for e in f['evidenceRecords']})

    def test_dll_without_entry(self):
        d=self.generate(entry=0,dll=True)
        self.assertIsNone(d['module']['entryId']);self.assertEqual(len(d['functions']),2)
        self.assertEqual(d['edges'],[])

    def test_absent_and_missing_directory(self):
        _,i=make_tls(self.pe);self.put(i['directory'],0);self.put(i['directory']+4,0)
        self.assertEqual(self.run_report()['tlsDirectory']['status'],'absent')
        make_tls(self.pe);self.put(0x98+108,9)
        self.assertEqual(self.run_report()['tlsDirectory']['status'],'absent')

    def test_empty_array_and_null_array_differ(self):
        d=self.generate(targets=[]);self.assertTrue(d['tlsDirectory']['terminated'])
        self.assertEqual(d['tlsDirectory']['terminatorRva'],'0x3000')
        self.put(0x618,0,'<Q');t=self.run_report()['tlsDirectory']
        self.assertEqual(t['status'],'no_callback_array');self.assertFalse(t['terminated'])
        self.assertIsNone(t['arrayRva']);self.assertEqual(t['callbacks'],[])

    def test_first_null_stops_array(self):
        d=self.generate(targets=[0x140001010,0,0x140001020])
        self.assertEqual(len(d['tlsDirectory']['callbacks']),1);self.assertEqual(len(d['functions']),2)

    def test_short_directory_and_pair_mismatch(self):
        for rva,size in [(0,40),(0x2000,0),(0x2000,39)]:
            with self.subTest(rva=rva,size=size):
                _,i=make_tls(self.pe);self.put(i['directory'],rva);self.put(i['directory']+4,size)
                t=self.run_report()['tlsDirectory'];self.assertFalse(t['headerRead']);self.assertEqual(t['callbacks'],[])

    def test_directory_overflow_and_unbacked(self):
        for rva,size in [(0xfffffff0,40),(0x1fff,40),(0x2000,0xffffffff)]:
            with self.subTest(rva=rva):
                _,i=make_tls(self.pe);self.put(i['directory'],rva);self.put(i['directory']+4,size)
                self.assertFalse(self.run_report()['tlsDirectory']['headerRead'])

    def test_directory_declared_extent_is_checked(self):
        _,i=make_tls(self.pe);self.put(i['directory']+4,513)
        t=self.run_report()['tlsDirectory'];self.assertTrue(t['headerRead']);self.assertTrue(t['partial'])
        self.assertTrue(all(not c['eligible'] for c in t['callbacks']))

    def test_array_pointer_is_va_not_rva(self):
        make_tls(self.pe);self.put(0x618,0x3000,'<Q')
        t=self.run_report()['tlsDirectory'];self.assertEqual(t['status'],'malformed');self.assertEqual(t['callbacks'],[])

    def test_array_pointer_outside_image(self):
        for pointer in [0x140000000-1,0x140004000,0xffffffffffffffff]:
            with self.subTest(pointer=pointer):
                make_tls(self.pe);self.put(0x618,pointer,'<Q')
                self.assertIsNone(self.run_report()['tlsDirectory']['arrayRva'])

    def test_valid_sibling_survives_bad_target(self):
        for pointer in [1,0x140004000,0x140002000,0x140001800]:
            with self.subTest(pointer=pointer):
                d=self.generate(targets=[pointer,0x140001020]);t=d['tlsDirectory']
                self.assertEqual(t['status'],'malformed');self.assertFalse(t['callbacks'][0]['eligible'])
                self.assertEqual({f['rva'] for f in d['functions']},{0x1000,0x1020})

    def test_partial_array_does_not_seed(self):
        d=self.generate(targets=[0x140001010],terminated=False);t=d['tlsDirectory']
        self.assertTrue(t['partial']);self.assertFalse(t['terminated']);self.assertEqual(len(t['callbacks']),1)
        self.assertFalse(t['callbacks'][0]['eligible']);self.assertEqual(len(d['functions']),1)

    def test_short_pointer_slot_is_not_zero_filled(self):
        _,i=make_tls(self.pe);self.put(i['section']+80+8,7)
        t=self.run_report()['tlsDirectory'];self.assertTrue(t['partial']);self.assertEqual(t['callbacks'],[])

    def test_zero_fill_target_is_not_decoded(self):
        _,i=make_tls(self.pe,targets=[0x140001250]);self.put(i['section']+8,0x400)
        d=self.run_report();self.assertFalse(d['tlsDirectory']['callbacks'][0]['executableFileBacked'])
        self.assertEqual(len(d['functions']),1)

    def test_high_va_precision(self):
        base=0xff00000000000000;d=self.generate(base=base)
        self.assertEqual(d['tlsDirectory']['callbacks'][0]['targetVa'],hex(base+0x1010))
        self.assertEqual(d['tlsDirectory']['arrayRva'],'0x3000')

    def test_raw_template_index_and_size_preserved_only(self):
        make_tls(self.pe);self.put(0x600,0xffffffffffffffff,'<Q');self.put(0x610,0x1111111111111111,'<Q')
        self.put(0x620,0xffffffff);self.put(0x624,0xdeadbeef)
        t=self.run_report()['tlsDirectory'];self.assertEqual(t['rawDataStartVa'],'0xffffffffffffffff')
        self.assertEqual(t['indexVa'],'0x1111111111111111');self.assertEqual(t['zeroFill'],0xffffffff)
        self.assertEqual(t['characteristics'],'0xdeadbeef')

    def test_instruction_limit_retains_pending_roots(self):
        make_tls(self.pe);d=self.run_report('--limit','1')
        self.assertTrue(d['module']['truncated']);self.assertEqual(d['tlsDirectory']['seedLocations'],2)
        self.assertTrue(all(c['discovery']=='not_decoded' for c in d['tlsDirectory']['callbacks']))
        self.assertFalse(self.run_report('--limit','3')['module']['truncated'])

    def test_exact_callback_budget_and_over_budget(self):
        d=self.generate(targets=[0x140001010]*4096);t=d['tlsDirectory']
        self.assertTrue(t['terminated']);self.assertFalse(t['partial']);self.assertEqual(t['seedLocations'],1)
        d=self.generate(targets=[0x140001010]*4097);t=d['tlsDirectory']
        self.assertTrue(t['partial']);self.assertFalse(t['terminated']);self.assertEqual(len(t['callbacks']),4096)
        self.assertEqual(t['seedLocations'],0);self.assertFalse(d['module']['truncated'])

    def test_diagnostics_count_after_cap(self):
        d=self.generate(targets=[1]*150)
        self.assertEqual(d['diagnostics']['total'],150);self.assertEqual(d['diagnostics']['omitted'],50)
        self.assertEqual(len(d['warnings']),100)

    def test_deterministic_report(self):
        d=self.generate();self.assertEqual(d,self.run_report())

    def test_source_compiled_callback_without_callers(self):
        if not CLANG or not LINKER:self.skipTest('clang/lld-link not supplied')
        source=Path(__file__).parent/'fixtures'/'tls_callbacks.c'
        for bits in (32,64):
            for dll in (False,True):
                with self.subTest(bits=bits,dll=dll):
                    binary=self.root/('compiled'+str(bits)+('.dll' if dll else '.exe'))
                    obj=self.root/f'tls{bits}.obj';mapping=self.root/f'map{bits}{dll}.txt'
                    run=lambda cmd: subprocess.run(list(map(str,cmd)),check=True,capture_output=True,text=True,timeout=60)
                    run([CLANG,'-target','x86_64-pc-windows-msvc' if bits==64 else 'i686-pc-windows-msvc',
                         '-O1','-fno-stack-protector','-c',source,'-o',obj])
                    run([LINKER,'/nodefaultlib','/timestamp:0','/machine:'+('x64' if bits==64 else 'x86'),
                         '/include:'+('_tls_used' if bits==64 else '__tls_used'),'/map:'+str(mapping),
                         '/out:'+str(binary),*(['/dll','/noentry'] if dll else ['/entry:entry_point','/subsystem:console']),obj])
                    d=self.run_report(path=binary);t=d['tlsDirectory'];self.assertEqual(t['status'],'parsed')
                    self.assertEqual(len(t['callbacks']),1);self.assertEqual(t['callbacks'][0]['discovery'],'decoded_candidate')
                    match=re.search(r'\s+_?tls_callback(?:@12)?\s+([0-9a-fA-F]{8,16})\s',mapping.read_text())
                    self.assertIsNotNone(match);self.assertEqual(int(match[1],16),int(t['callbacks'][0]['targetVa'],16))
                    old=self.run_report('--no-tls-seeds',path=binary,ok=not dll)
                    target=int(t['callbacks'][0]['targetRva'],16)
                    self.assertNotIn(target,{f['rva'] for f in old['functions']})
                    self.assertFalse(any(e['kind']=='call' for e in d['edges']))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('analyzer',type=Path)
    p.add_argument('--clang',default=shutil.which('clang'));p.add_argument('--linker',default=shutil.which('lld-link'))
    args=p.parse_args();ANALYZER=args.analyzer.resolve();CLANG=args.clang;LINKER=args.linker
    unittest.main(argv=['tls_directory'],verbosity=2)
