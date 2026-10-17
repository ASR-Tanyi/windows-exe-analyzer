#!/usr/bin/env python3
"""Byte-authored x86/x64 operand contracts; never execute the PE fixtures."""
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import unittest


def make_operand_pe(path, code, bits=64, base=None):
    """One bounded code section. The code/expected facts are authored in tests."""
    base = base if base is not None else (0x140000000 if bits == 64 else 0x400000)
    b = bytearray(0x400)
    b[:2] = b'MZ'
    struct.pack_into('<I', b, 0x3c, 0x80)
    b[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', b, 0x84, 0x8664 if bits == 64 else 0x14c,
                     1, 0, 0, 0, 0xf0 if bits == 64 else 0xe0, 0x102)
    struct.pack_into('<H', b, 0x98, 0x20b if bits == 64 else 0x10b)
    struct.pack_into('<I', b, 0x98 + 16, 0x1000)
    struct.pack_into('<Q' if bits == 64 else '<I', b, 0x98 + (24 if bits == 64 else 28), base)
    struct.pack_into('<II', b, 0x98 + 56, 0x2000, 0x200)
    sec = 0x98 + (0xf0 if bits == 64 else 0xe0)
    b[sec:sec+8] = b'.text\0\0\0'
    # The exact length makes truncated instructions genuinely truncated.
    struct.pack_into('<IIII', b, sec+8, len(code), 0x1000, 0x200, 0x200)
    struct.pack_into('<I', b, sec+36, 0x60000020)
    if not 0 < len(code) <= 0x200:
        raise ValueError('fixture code size')
    b[0x200:0x200+len(code)] = code
    path.write_bytes(b)


class OperandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def report(self, code, bits=64, base=None, analyzer=None, terminated=True):
        code = bytes.fromhex(code) if isinstance(code, str) else code
        src, out, html = (self.root / x for x in ('operand.exe', 'report.json', 'report.html'))
        make_operand_pe(src, code + (b'\xc3' if terminated else b''), bits, base)
        result = subprocess.run([str(analyzer or ANALYZER), str(src), '--json', str(out),
                                 '--html', str(html)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(out.read_text())
        embedded = re.search(r'<script id="report-data" type="application/json">(.*?)</script>', html.read_text(), re.S)
        self.assertEqual(json.loads(embedded[1]), data)
        first = next(i for b in data['blocks'] for i in b['instructions'] if i['rva'] == 0x1000)
        return data, first

    def structured(self, *args, **kwargs):
        if BACKEND != 'CAPSTONE':
            self.skipTest('LLVM text adapter deliberately has no structured operand capability')
        return self.report(*args, **kwargs)[1]['operandDetails']

    def test_backend_contract_and_empty_operands(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                data, insn = self.report('90', bits)
                self.assertEqual(data['schema'], 2)
                self.assertEqual(data['operandModelVersion'], 1)
                info, detail = data['module']['decoderInfo'], insn['operandDetails']
                self.assertEqual(info['name'], BACKEND.lower())
                self.assertEqual(info['capabilities']['structuredOperands'], BACKEND == 'CAPSTONE')
                self.assertFalse(info['capabilities']['instructionSemantics'])
                self.assertFalse(detail['capabilities']['completeImplicitRegisterAccess'])
                self.assertFalse(detail['implicitRegisters']['complete'])
                if BACKEND == 'CAPSTONE':
                    self.assertEqual(info['apiVersion'], '5.0')
                    self.assertEqual(detail['operands'], [])
                    self.assertEqual(detail['implicitRegisters']['status'], 'reported_partial')
                    self.assertEqual(detail['addressWidthBits'], bits)
                else:
                    self.assertIsNone(detail['operands'])
                    self.assertIsNone(detail['prefixes'])
                    self.assertIsNone(detail['encoding'])
                    self.assertIsNone(detail['addressWidthBits'])
                    self.assertIsNone(detail['implicitRegisters']['reads'])
                    self.assertIsNone(detail['implicitRegisters']['writes'])
                    self.assertEqual(detail['implicitRegisters']['status'], 'unavailable')
                    self.assertFalse(any(detail['capabilities'].values()))

    def test_partial_gpr_aliases(self):
        for bits in (32, 64):
            family = 'rax' if bits == 64 else 'eax'
            for code, names, widths, offsets in (
                    ('88 e0', ['al', 'ah'], [8, 8], [0, 8]),
                    ('66 89 d8', ['ax', 'bx'], [16, 16], [0, 0]),
                    ('89 d8', ['eax', 'ebx'], [32, 32], [0, 0])):
                with self.subTest(bits=bits, code=code):
                    d = self.structured(code, bits)
                    self.assertTrue(d['capabilities']['registerSlices'])
                    self.assertTrue(d['capabilities']['operandAccess'])
                    self.assertEqual([o['widthBits'] for o in d['operands']], widths)
                    self.assertEqual([o['register']['name'] for o in d['operands']], names)
                    self.assertEqual([o['register']['bitOffset'] for o in d['operands']], offsets)
                    self.assertEqual(d['operands'][0]['register']['family'], family)
                    self.assertEqual(d['operands'][0]['register']['familyWidth'], bits)
                    self.assertEqual([o['access'] for o in d['operands']], ['write', 'read'])

    def test_rex_and_extended_registers(self):
        d = self.structured('40 88 e0')
        self.assertEqual(d['operands'][1]['register']['name'], 'spl')
        self.assertEqual(d['operands'][1]['register']['bitOffset'], 0)
        self.assertEqual(d['prefixes']['leadingBytes'], [0x40])
        self.assertEqual(d['prefixes']['decoderRex'], 0x40)
        d = self.structured('45 89 c8')
        self.assertEqual([o['register']['family'] for o in d['operands']], ['r8', 'r9'])
        self.assertEqual([o['widthBits'] for o in d['operands']], [32, 32])
        # In 32-bit mode 0x40 decodes as INC EAX, not a REX prefix.
        d = self.structured('40', 32)
        self.assertEqual(d['prefixes']['leadingBytes'], [])

    def test_memory_expression(self):
        d = self.structured('48 8b 44 8b f0')
        op = d['operands'][1]
        self.assertEqual(op['widthBits'], 64)
        self.assertEqual(op['access'], 'read')
        self.assertIsNone(op['memory']['segment'])
        self.assertEqual(op['memory']['base']['name'], 'rbx')
        self.assertEqual(op['memory']['index']['name'], 'rcx')
        self.assertEqual(op['memory']['scale'], 4)
        self.assertEqual(op['memory']['displacement'], '-16')
        self.assertEqual(d['encoding']['displacement'], {'offset': 4, 'widthBits': 8})
        self.assertEqual(self.report('48 8b 44 8b f0')[1]['dataRefs'], [])

    def test_address_overrides(self):
        d = self.structured('67 8b 00', 32)
        self.assertEqual(d['addressWidthBits'], 16)
        self.assertEqual([d['operands'][1]['memory'][r]['name'] for r in ('base', 'index')], ['bx', 'si'])
        self.assertEqual(d['operands'][0]['widthBits'], 32)
        self.assertEqual(d['prefixes']['legacyGroups'][3], 0x67)
        d = self.structured('67 8b 00', 64)
        self.assertEqual(d['addressWidthBits'], 32)
        self.assertEqual(d['operands'][1]['memory']['base']['name'], 'eax')

    def test_lossless_immediates_and_encoding_widths(self):
        d = self.structured('48 b8 ef cd ab 89 67 45 23 f1')
        self.assertEqual(d['operands'][1]['immediate'], {'value': '0xf123456789abcdef', 'interpretation': 'bit_pattern'})
        self.assertEqual(d['encoding']['immediate'], {'offset': 2, 'widthBits': 64})
        d = self.structured('48 c7 c0 ff ff ff ff')
        self.assertEqual(d['operands'][1]['immediate']['value'], '0xffffffffffffffff')
        self.assertEqual(d['operands'][1]['widthBits'], 64)
        self.assertEqual(d['encoding']['immediate'], {'offset': 3, 'widthBits': 32})
        self.assertEqual(d['operands'][1]['access'], 'unknown')
        self.assertFalse(d['capabilities']['operandAccess'])
        d = self.structured('b8 00 00 00 00', 32)
        self.assertEqual(d['operands'][1]['immediate']['value'], '0x0')
        d = self.structured('83 c0 ff', 32)
        self.assertEqual(d['operands'][1]['immediate']['value'], '0xffffffff')
        self.assertEqual(d['encoding']['immediate']['widthBits'], 8)
        d = self.structured('c8 34 12 56')
        self.assertEqual([o['immediate']['value'] for o in d['operands']], ['0x1234', '0x56'])

    def test_segments_and_unknown_register_slices(self):
        d = self.structured('64 48 8b 03')
        self.assertEqual(d['operands'][1]['memory']['segment']['name'], 'fs')
        self.assertEqual(d['operands'][1]['memory']['segment']['bitWidth'], 16)
        self.assertEqual(self.report('64 48 8b 03')[1]['dataRefs'], [])
        d = self.structured('0f 20 c0') # MOV RAX, CR0: unsupported alias family stays opaque
        self.assertEqual(d['operands'][1]['register']['name'], 'cr0')
        self.assertIsNone(d['operands'][1]['register']['family'])
        self.assertIsNone(d['operands'][1]['register']['bitWidth'])
        self.assertFalse(d['capabilities']['registerSlices'])

    def test_prefixes_and_incomplete_implicit_effects(self):
        d = self.structured('f0 83 00 01')
        self.assertEqual(d['prefixes']['leadingBytes'], [0xf0])
        self.assertEqual(d['operands'][0]['access'], 'read-write')
        d = self.structured('f3 0f 10 c1') # mandatory prefix is absent from Capstone's effective groups
        self.assertEqual(d['prefixes']['leadingBytes'], [0xf3])
        self.assertEqual(d['operands'][0]['register']['bitWidth'], 128)
        self.assertFalse(d['prefixes']['vectorSemantics'])
        d = self.structured('f3 a4')
        self.assertEqual(d['prefixes']['legacyGroups'][0], 0xf3)
        self.assertIn('rcx', [r['name'] for r in d['implicitRegisters']['reads']])
        d = self.structured('0f a2')
        self.assertEqual({r['name'] for r in d['implicitRegisters']['writes']}, {'eax', 'ebx', 'ecx', 'edx'})
        self.assertFalse(d['implicitRegisters']['complete'])
        # Capstone reports no implicit registers for ENTER. This must never be
        # interpreted as proof that the instruction has no stack/register effects.
        d = self.structured('c8 00 00 00')
        self.assertEqual(d['implicitRegisters']['status'], 'reported_partial')
        self.assertFalse(d['implicitRegisters']['complete'])

    def test_legacy_references_and_branch_targets(self):
        # Shared expected facts in both adapter builds. No spelling comparison.
        for bits, code, mode, base in (
                (32, '8b 05 00 10 40 00', 'absolute', 0x400000),
                (64, '8b 05 fa ff ff ff', 'rip-relative', 0x2222222200000000),
                (64, '67 8b 05 f9 ff ff ff', 'eip-relative', 0x2222222200000000)):
            with self.subTest(bits=bits, code=code):
                _, i = self.report(code, bits, base)
                self.assertEqual(i['bytes'], code)
                ref = i['dataRefs'][0]
                self.assertEqual(ref['va'], hex(0x1000 if mode == 'eip-relative' else base + 0x1000))
                self.assertEqual((ref['mode'], ref['access'], ref['width']), (mode, 'read', 4))
                self.assertTrue(i['operands'][ref['textBegin']:ref['textEnd']].startswith('['))
                if COMPARE:
                    _, other = self.report(code, bits, base, analyzer=COMPARE)
                    self.assertEqual(i['size'], other['size'])
                    self.assertEqual({k: ref[k] for k in ('va', 'mode', 'access', 'width')},
                                     {k: other['dataRefs'][0][k] for k in ('va', 'mode', 'access', 'width')})
        for bits in (32, 64):
            data, i = self.report('e8 00 00 00 00', bits)
            expected = int(data['module']['imageBase'], 16) + 0x1005
            self.assertEqual(next(e['to'] for e in data['edges'] if e['kind'] == 'call'), data['module']['id'] + '_b_1005')
            if BACKEND == 'CAPSTONE':
                self.assertEqual(i['operandDetails']['operands'][0]['immediate'], {'value': hex(expected), 'interpretation': 'preferred_va'})
                self.assertEqual(i['operandDetails']['encoding']['immediate']['widthBits'], 32)
        _, i = self.report('8d 05 fa ff ff ff')
        self.assertEqual((i['dataRefs'][0]['access'], i['dataRefs'][0]['width']), ('address', 0))

    def test_determinism_and_truncated_decode(self):
        a, _ = self.report('48 8b 44 8b f0')
        b, _ = self.report('48 8b 44 8b f0')
        self.assertEqual(a, b)
        # NOP followed by an incomplete escape must preserve the first decoded
        # instruction without manufacturing structured operands for the tail.
        data, _ = self.report('90 0f', terminated=False)
        self.assertEqual(data['module']['instructionCount'], 1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('analyzer', type=Path)
    parser.add_argument('--backend', choices=['CAPSTONE', 'LLVM'], required=True)
    parser.add_argument('--compare', type=Path)
    args, rest = parser.parse_known_args()
    ANALYZER, BACKEND = args.analyzer.resolve(), args.backend
    COMPARE = args.compare.resolve() if args.compare else None
    unittest.main(argv=[__file__, *rest], verbosity=2)
