#!/usr/bin/env python3
"""Bounded AMD64 table parsing; PE fixtures are data and are never executed."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ANALYZER = None
FIXTURES = None


def align(n, boundary):
    return (n + boundary - 1) // boundary * boundary


def make_pe(path, records=None, *, bits=64, trailer=b'', directory_size=None,
            directory_rva=0x2000, table_name=b'.pdata'):
    records = [(0x1010, 0x1011, None)] if records is None else records
    raw_size = align(max(512, len(records) * 12 + len(trailer)), 512)
    unwind_rva = 0x2000 + align(raw_size, 4096)
    unwind_raw = 0x600 + raw_size
    b = bytearray(unwind_raw + 512)
    b[:2] = b'MZ'; struct.pack_into('<I', b, 0x3c, 0x80)
    b[0x80:0x84] = b'PE\0\0'
    opt_size = 0xf0 if bits == 64 else 0xe0
    struct.pack_into('<HHIIIHH', b, 0x84, 0x8664 if bits == 64 else 0x14c,
                     3, 0, 0, 0, opt_size, 0x102)
    opt = 0x98; section = opt + opt_size
    struct.pack_into('<H', b, opt, 0x20b if bits == 64 else 0x10b)
    struct.pack_into('<I', b, opt + 16, 0x1000)
    struct.pack_into('<Q' if bits == 64 else '<I', b, opt + (24 if bits == 64 else 28),
                     0x140000000 if bits == 64 else 0x400000)
    struct.pack_into('<II', b, opt + 32, 4096, 512)
    struct.pack_into('<II', b, opt + 56, unwind_rva + 4096, 0x400)
    struct.pack_into('<I', b, opt + (108 if bits == 64 else 92), 16)
    directory = opt + (112 if bits == 64 else 96) + 3 * 8
    size = len(records) * 12 + len(trailer) if directory_size is None else directory_size
    struct.pack_into('<II', b, directory, directory_rva, size)
    for i, (name, rva, virtual, raw, stored, flags) in enumerate([
        (b'.code', 0x1000, 0x200, 0x400, 512, 0x60000020),
        (table_name, 0x2000, raw_size, 0x600, raw_size, 0x40000040),
        (b'.unwind', unwind_rva, 512, unwind_raw, 512, 0x40000040),
    ]):
        p = section + i * 40
        b[p:p+8] = name[:8].ljust(8, b'\0')
        struct.pack_into('<IIII', b, p + 8, virtual, rva, stored, raw)
        struct.pack_into('<I', b, p + 36, flags)
    b[0x400] = b[0x410] = b[0x420] = 0xc3
    for i, (begin, end, unwind) in enumerate(records):
        struct.pack_into('<III', b, 0x600 + 12 * i, begin, end,
                         unwind_rva if unwind is None else unwind)
    b[0x600+12*len(records):0x600+12*len(records)+len(trailer)] = trailer
    b[unwind_raw:unwind_raw+4] = bytes([1, 0, 0, 0])
    path.write_bytes(b)
    return b, {'section': section, 'directory': directory,
               'unwind_rva': unwind_rva, 'unwind_raw': unwind_raw}


class ExceptionDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.pe = self.root / 'sample.exe'
        self.addCleanup(self.temp.cleanup)

    def analyze(self, **kwargs):
        make_pe(self.pe, **kwargs)
        return self.read()

    def read(self):
        output = self.root / 'report.json'
        p = subprocess.run([str(ANALYZER), str(self.pe), '--json', str(output),
                            '--data-limit', '0'], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(output.read_text())

    def mutate(self, offset, value):
        b = bytearray(self.pe.read_bytes())
        struct.pack_into('<I', b, offset, value)
        self.pe.write_bytes(b)

    def test_valid_record_is_metadata_not_a_new_function(self):
        d = self.analyze(); m = d['exceptionDirectory']; r = m['records'][0]
        self.assertEqual(m['status'], 'parsed')
        self.assertEqual((r['beginRva'], r['endRva'], r['unwindRva']), ('0x1010', '0x1011', '0x3000'))
        self.assertEqual(r['validation'], 'bounds_checked')
        self.assertEqual(m['unwindSemantics'], 'not_decoded')
        self.assertFalse(m['discoverySeedsAdded'])
        self.assertEqual([f['rva'] for f in d['functions']], [0x1000])
        self.assertEqual(d['module']['instructionCount'], 1)
        self.assertEqual((d['schema'], d['analysisModelVersion']), (2, 1))
        self.assertEqual(d['functions'][0]['decodedRanges'][0]['endRva'], '0x1001')

    def test_renamed_section(self):
        self.assertEqual(self.analyze(table_name=b'notpdata')['exceptionDirectory']['status'], 'parsed')

    def test_absent_directory(self):
        m = self.analyze(records=[], directory_rva=0)['exceptionDirectory']
        self.assertEqual(m['status'], 'absent'); self.assertEqual(m['records'], [])

    def test_directory_entry_not_present_in_optional_header(self):
        make_pe(self.pe); self.mutate(0x98+108, 3)
        self.assertEqual(self.read()['exceptionDirectory']['status'], 'absent')

    def test_zero_pair_mismatch(self):
        for rva, size in [(0, 12), (0x2000, 0)]:
            with self.subTest(rva=rva):
                m = self.analyze(directory_rva=rva, directory_size=size)['exceptionDirectory']
                self.assertEqual(m['status'], 'malformed'); self.assertEqual(m['records'], [])

    def test_x86_does_not_parse_amd64_records(self):
        d = self.analyze(bits=32)
        self.assertEqual(d['exceptionDirectory']['status'], 'unsupported_architecture')
        self.assertEqual(d['exceptionDirectory']['records'], [])
        self.assertEqual(d['diagnostics']['counts']['unsupported_feature'], 1)

    def test_directory_overflow(self):
        m = self.analyze(directory_rva=0xfffffff8, directory_size=24)['exceptionDirectory']
        self.assertIn('exception_directory_outside_image', m['issues'])
        self.assertEqual(m['omittedRecords'], 2)

    def test_directory_past_image(self):
        m = self.analyze(directory_size=0x4000)['exceptionDirectory']
        self.assertIn('exception_directory_outside_image', m['issues'])

    def test_trailing_bytes_are_not_a_record(self):
        m = self.analyze(trailer=b'xyz')['exceptionDirectory']
        self.assertEqual(m['trailingBytes'], 3); self.assertEqual(len(m['records']), 1)
        self.assertEqual(m['status'], 'malformed')

    def test_unbacked_trailing_byte_is_partial(self):
        _, info = make_pe(self.pe, trailer=b'x')
        self.mutate(info['section'] + 40 + 8, 12)
        m = self.read()['exceptionDirectory']
        self.assertTrue(m['partial']); self.assertEqual(m['omittedRecords'], 0)
        self.assertIn('exception_directory_not_file_backed', m['issues'])

    def test_short_directory(self):
        m = self.analyze(directory_size=8)['exceptionDirectory']
        self.assertEqual(m['records'], []); self.assertEqual(m['trailingBytes'], 8)

    def test_unaligned_directory(self):
        m = self.analyze(directory_rva=0x2001)['exceptionDirectory']
        self.assertIn('exception_directory_unaligned', m['issues'])

    def test_unmapped_directory(self):
        m = self.analyze(directory_rva=0x1500)['exceptionDirectory']
        self.assertTrue(m['partial']); self.assertEqual(m['records'], [])

    def test_readable_prefix_retained(self):
        _, info = make_pe(self.pe, [(0x1010, 0x1011, None), (0x1020, 0x1021, None)])
        self.mutate(info['section'] + 40 + 8, 12)
        m = self.read()['exceptionDirectory']
        self.assertEqual(len(m['records']), 1); self.assertEqual(m['omittedRecords'], 1)
        self.assertTrue(m['partial']); self.assertTrue(m['malformed'])

    def test_reversed_and_empty_ranges(self):
        for begin, end in [(0x1010, 0x1010), (0x1011, 0x1010), (0, 1)]:
            with self.subTest(begin=begin, end=end):
                r = self.analyze(records=[(begin, end, None)])['exceptionDirectory']['records'][0]
                self.assertIn('invalid_half_open_range', r['issues'])
                self.assertFalse(r['rangeFileBacked'])

    def test_range_past_image(self):
        r = self.analyze(records=[(0x1010, 0xffffffff, None)])['exceptionDirectory']['records'][0]
        self.assertIn('code_range_outside_image', r['issues'])

    def test_nonexecutable_range(self):
        r = self.analyze(records=[(0x2000, 0x200c, None)])['exceptionDirectory']['records'][0]
        self.assertIn('code_range_not_file_backed_executable', r['issues'])

    def test_range_with_unmapped_tail(self):
        r = self.analyze(records=[(0x11f0, 0x1300, None)])['exceptionDirectory']['records'][0]
        self.assertFalse(r['rangeFileBacked'])

    def test_range_in_virtual_zero_fill(self):
        _, info = make_pe(self.pe, [(0x1250, 0x1260, None)])
        self.mutate(info['section'] + 8, 0x400)
        r = self.read()['exceptionDirectory']['records'][0]
        self.assertFalse(r['rangeFileBacked'])

    def test_unwind_null_unaligned_unmapped_and_wrapping(self):
        for pointer, issue in [(0, 'null_unwind_rva'), (0x3001, 'unaligned_or_unsupported_unwind_rva'),
                               (0x3800, 'unwind_header_not_file_backed'), (0xfffffffc, 'unwind_header_not_file_backed')]:
            with self.subTest(pointer=pointer):
                r = self.analyze(records=[(0x1010, 0x1011, pointer)])['exceptionDirectory']['records'][0]
                self.assertIn(issue, r['issues']); self.assertFalse(r['unwindAddressFileBacked'])

    def test_short_unwind_header(self):
        _, info = make_pe(self.pe); self.mutate(info['section'] + 80 + 8, 3)
        self.assertIn('unwind_header_not_file_backed', self.read()['exceptionDirectory']['records'][0]['issues'])

    def test_unwind_version_and_flags_are_not_interpreted(self):
        for header in [b'\x07\xff\xff\xff', b'\x21\x00\x00\x00', b'\x00'*4]:
            with self.subTest(header=header):
                b, info = make_pe(self.pe); b[info['unwind_raw']:info['unwind_raw']+4] = header
                self.pe.write_bytes(b); m = self.read()['exceptionDirectory']
                self.assertEqual(m['status'], 'parsed'); self.assertEqual(m['unwindSemantics'], 'not_decoded')

    def test_sorted_adjacent_ranges_do_not_overlap(self):
        m = self.analyze(records=[(0x1010, 0x1020, None), (0x1020, 0x1021, None)])['exceptionDirectory']
        self.assertEqual(m['status'], 'parsed')

    def test_unsorted_table_preserves_order(self):
        m = self.analyze(records=[(0x1020, 0x1021, None), (0x1010, 0x1011, None)])['exceptionDirectory']
        self.assertEqual(m['records'][0]['beginRva'], '0x1020')
        self.assertIn('unsorted_begin_rva', m['records'][1]['issues'])

    def test_duplicate_entries_are_preserved(self):
        m = self.analyze(records=[(0x1010, 0x1011, None)]*2)['exceptionDirectory']
        self.assertEqual(len(m['records']), 2); self.assertEqual(m['records'][1]['duplicateOf'], 0)
        self.assertTrue(all('duplicate_runtime_function' in x['issues'] for x in m['records']))

    def test_overlap_marks_both_participants(self):
        m = self.analyze(records=[(0x1010, 0x1030, None), (0x1020, 0x1040, None)])['exceptionDirectory']
        self.assertTrue(all('overlapping_runtime_functions' in x['issues'] for x in m['records']))
        self.assertEqual([x['overlapWith'] for x in m['records']], [1, 0])

    def test_nested_overlaps_use_bounded_witnesses(self):
        m = self.analyze(records=[(0x1010, 0x1100, None), (0x1020, 0x1030, None),
                                  (0x1040, 0x1050, None)])['exceptionDirectory']
        self.assertTrue(all('overlapping_runtime_functions' in x['issues'] for x in m['records']))

    def test_same_range_different_unwind_is_conflict(self):
        m = self.analyze(records=[(0x1010, 0x1020, 0x3000), (0x1010, 0x1020, 0x3004)])['exceptionDirectory']
        self.assertIsNone(m['records'][1]['duplicateOf'])
        self.assertIn('overlapping_runtime_functions', m['records'][1]['issues'])

    def test_zero_record_is_not_a_sentinel(self):
        m = self.analyze(records=[(0, 0, 0), (0x1010, 0x1011, None)])['exceptionDirectory']
        self.assertEqual(len(m['records']), 2)
        self.assertEqual(m['records'][1]['validation'], 'bounds_checked')

    def test_table_crosses_adjacent_sections_with_disjoint_raw_bytes(self):
        b, info = make_pe(self.pe, [(0x1010, 0x1011, 0x2020), (0x1020, 0x1021, 0x2020)])
        struct.pack_into('<I', b, info['section']+40+8, 16)
        struct.pack_into('<I', b, info['section']+40+16, 16)
        struct.pack_into('<I', b, info['section']+80+12, 0x2010)
        b[info['unwind_raw']:info['unwind_raw']+8] = b[0x610:0x618]
        b[info['unwind_raw']+16:info['unwind_raw']+20] = b'\x01\x00\x00\x00'
        self.pe.write_bytes(b)
        m = self.read()['exceptionDirectory']
        self.assertEqual(m['status'], 'parsed'); self.assertEqual(len(m['records']), 2)

    def test_diagnostic_counts_survive_detail_cap(self):
        d = self.analyze(records=[(0, 0, 0)]*130)
        self.assertGreater(d['diagnostics']['total'], 100)
        self.assertGreater(d['diagnostics']['omitted'], 0)
        self.assertEqual(len(d['diagnostics']['items']), d['diagnostics']['limit'])
        self.assertEqual(sum(d['diagnostics']['counts'].values()), d['diagnostics']['total'])

    def test_record_budget_is_independent_of_instruction_budget(self):
        d = self.analyze(records=[(0x1010, 0x1011, None)]*65537)
        m = d['exceptionDirectory']
        self.assertEqual(len(m['records']), 65536); self.assertEqual(m['omittedRecords'], 1)
        self.assertTrue(m['partial']); self.assertFalse(d['module']['truncated'])
        self.assertIn('exception_record_limit_reached', m['issues'])
        self.assertIn('budget_exhausted', d['diagnostics']['counts'])

    def test_report_is_deterministic(self):
        a = self.analyze(records=[(0x1020, 0x1040, None), (0x1010, 0x1030, None)])
        self.assertEqual(a, self.read())
        self.assertEqual(a, json.loads(json.dumps(a)))

    def test_compiled_x64_demo_matches_linker_known_main(self):
        if FIXTURES is None:
            self.skipTest('compiled fixtures not supplied')
        self.pe.write_bytes((FIXTURES/'demo64.exe').read_bytes())
        d = self.read(); symbols = json.loads((FIXTURES/'demo64.symbols.json').read_text())
        m = d['exceptionDirectory']; self.assertEqual(m['status'], 'parsed')
        self.assertIn(hex(symbols['main']), [x['beginRva'] for x in m['records']])
        self.assertTrue(all(not x['issues'] for x in m['records']))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('analyzer', type=Path); p.add_argument('--fixtures', type=Path)
    args = p.parse_args(); ANALYZER = args.analyzer.resolve(); FIXTURES = args.fixtures
    unittest.main(argv=['test_exception_directory'], verbosity=2)
