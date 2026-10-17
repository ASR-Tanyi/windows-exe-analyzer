#!/usr/bin/env python3
"""Real PE/CLI regressions; no generated PE is executed."""
import argparse
import json
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path


def make_image(is64=True, payload=None):
    data=bytearray(0xc00)
    struct.pack_into('<H',data,0,0x5a4d);struct.pack_into('<I',data,0x3c,0x80)
    struct.pack_into('<I',data,0x80,0x4550)
    optsize=240 if is64 else 224
    struct.pack_into('<HHIIIHH',data,0x84,0x8664 if is64 else 0x14c,2,0,0,0,optsize,0x22)
    o=0x98;struct.pack_into('<H',data,o,0x20b if is64 else 0x10b)
    struct.pack_into('<I',data,o+16,0x1000)
    if is64:struct.pack_into('<Q',data,o+24,0x140000000)
    else:struct.pack_into('<I',data,o+28,0x400000)
    struct.pack_into('<II',data,o+32,0x1000,0x200)
    struct.pack_into('<II',data,o+56,0x3000,0x400)
    struct.pack_into('<H',data,o+68,3)
    struct.pack_into('<I',data,o+(108 if is64 else 92),16)
    sh=o+optsize
    for k,(name,rva,size,raw,flags) in enumerate([(b'.text',0x1000,0x200,0x400,0x60000020),(b'.words',0x2000,0x600,0x600,0x40000040)]):
        p=sh+40*k;data[p:p+8]=name.ljust(8,b'\0');struct.pack_into('<IIII',data,p+8,size,rva,size,raw);struct.pack_into('<I',data,p+36,flags)
    code=(b'\x48\x8d\x0d'+struct.pack('<i',0x2000-0x1007)+b'\x48\x8d\x15'+struct.pack('<i',0x2002-0x100e)+b'\xc3') if is64 else b'\xa1\x00\x20\x40\x00\xa1\x02\x20\x40\x00\xc3'
    data[0x400:0x400+len(code)]=code
    if payload is None:
        payload=bytearray(0x600);payload[:11]=b'Alpha Beta\0'
        wide='\u6d4b\u8bd5\u7a0b\u5e8f\U0001f680\0'.encode('utf-16le');payload[0x41:0x41+len(wide)]=wide
        payload[0x90:0x9b]=b'Alpha Beta\0'
        unsafe=b'</script><img src=x onerror=alert(1)>\0';payload[0xd0:0xd0+len(unsafe)]=unsafe
    data[0x600:0x600+len(payload)]=payload
    return bytes(data)


class StringTests(unittest.TestCase):
    def run_image(self,is64=True,extra=(),payload=None):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);(root/'input.exe').write_bytes(make_image(is64,payload))
            result=subprocess.run([str(ANALYZER),str(root/'input.exe'),'--json',str(root/'r.json'),'--html',str(root/'r.html'),*extra],capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
            return json.loads((root/'r.json').read_text()),(root/'r.html').read_text()
    def test_architectures(self):
        for mode in (False,True):
            with self.subTest(x64=mode):
                d,_=self.run_image(mode);a=[s for s in d['strings']['candidates'] if s['encoding']=='ASCII' and s['rva']==0x2000]
                self.assertEqual(a[0]['text'],'Alpha Beta');self.assertTrue(a[0]['terminated'])
                self.assertEqual(a[0]['byteLength'],10);self.assertEqual(a[0]['fileOffset'],'0x600')
    def test_unicode_and_unaligned(self):
        d,_=self.run_image();s=next(s for s in d['strings']['candidates'] if s['rva']==0x2041 and s['encoding']=='UTF-16LE')
        self.assertEqual(s['text'],'\u6d4b\u8bd5\u7a0b\u5e8f\U0001f680');self.assertEqual((s['characters'],s['codeUnits'],s['byteLength']),(5,6,12))
    def test_distinct_addresses(self):
        d,_=self.run_image();self.assertEqual([s['rva'] for s in d['strings']['candidates'] if s['text']=='Alpha Beta'],[0x2000,0x2090])
    def test_independent_embedding_budget(self):
        d,_=self.run_image(extra=['--data-limit','0']);self.assertEqual(d['data']['embeddedBytes'],0);self.assertTrue(d['strings']['candidates'])
    def test_no_strings(self):
        d,_=self.run_image(extra=['--no-strings']);self.assertFalse(d['strings']['enabled']);self.assertEqual(d['strings']['candidates'],[])
    def test_candidate_limit(self):
        d,_=self.run_image(extra=['--strings-limit','1']);self.assertTrue(d['strings']['partial']);self.assertEqual(len(d['strings']['candidates']),1)
    def test_scan_limit(self):
        d,_=self.run_image(extra=['--strings-scan-limit','1539','--strings-min','3']);self.assertIn('scan_limit',d['strings']['reasons'])
        a=next(s for s in d['strings']['candidates'] if s['rva']==0x2000 and s['encoding']=='ASCII');self.assertEqual(a['text'],'Alp');self.assertFalse(a['terminated'])
    def test_invalid_options(self):
        for opt,v in [('--strings-min','0'),('--strings-limit','100001'),('--strings-scan-limit','268435457'),('--strings-min','-1')]:
            p=subprocess.run([str(ANALYZER),'unused.exe',opt,v],capture_output=True,text=True,timeout=10);self.assertNotEqual(p.returncode,0);self.assertNotIn('Cannot open input',p.stderr)
    def test_escaping_and_extension(self):
        d,h=self.run_image();self.assertTrue(any('</script>' in s['text'] for s in d['strings']['candidates']))
        raw=h.split('<script id="report-data" type="application/json">',1)[1].split('</script>',1)[0]
        self.assertEqual(json.loads(raw)['strings'],d['strings']);self.assertNotIn('<img',raw)
        self.assertIn('browseStrings',h);self.assertIn('WEAStringModel',h)
    def test_static_facts_unchanged(self):
        a,_=self.run_image();b,_=self.run_image(extra=['--no-strings']);a.pop('strings');b.pop('strings');self.assertEqual(a,b)
    def test_deterministic(self):
        a,_=self.run_image();b,_=self.run_image();self.assertEqual(a['strings'],b['strings'])


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('analyzer',type=Path);args=p.parse_args();ANALYZER=args.analyzer.resolve()
    unittest.main(argv=['test_strings'],verbosity=2)
