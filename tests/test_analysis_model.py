#!/usr/bin/env python3
"""M0 evidence/range/diagnostic contract tests. Never execute the PE fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from make_samples import make_samples

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('analyzer', type=Path)
parser.add_argument('--fixtures', type=Path)
parser.add_argument('--baseline', type=Path, help='Optional previous analyzer for full legacy-field comparison')
args = parser.parse_args()
ANALYZER = args.analyzer.resolve()


def legacy_projection(value):
    additive = {'analysisModelVersion', 'evidenceRecords', 'decodedRanges',
                'decodedRange', 'location', 'diagnostics'}
    if isinstance(value, dict):
        return {k: legacy_projection(v) for k, v in value.items() if k not in additive}
    if isinstance(value, list):
        return [legacy_projection(v) for v in value]
    return value


class AnalysisModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        make_samples(self.root)

    def fixture(self, code, bits=64, extent=None, base=None):
        data = bytearray((self.root / f'sample{bits}.exe').read_bytes())
        data[0x200:0x400] = bytes(0x200)
        data[0x200:0x200+len(code)] = code
        sec = 0x98 + (0xf0 if bits == 64 else 0xe0)
        struct.pack_into('<I', data, sec + 8, extent or max(len(code), 1))
        if base is not None:
            struct.pack_into('<Q' if bits == 64 else '<I', data, 0x98 + (24 if bits == 64 else 28), base)
        path = self.root / f'input{bits}.exe'
        path.write_bytes(data)
        return path

    def analyze(self, path, *options, executable=ANALYZER, ok=True):
        output = self.root / 'report.json'
        proc = subprocess.run([str(executable), str(path), '--json', str(output), *options],
                              capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode == 0, ok, proc.stderr)
        report = json.loads(output.read_text())
        # Round-trip the actual producer output through a standard JSON consumer.
        # This is not a claim that the C++ analyzer implements a report importer.
        self.assertEqual(report, json.loads(json.dumps(report, ensure_ascii=True)))
        return report

    @staticmethod
    def spans(function):
        return [(int(x['beginRva'], 16), int(x['endRva'], 16)) for x in function['decodedRanges']]

    def test_tagged_entry_location_and_half_open_coverage(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                d = self.analyze(self.root / f'sample{bits}.exe')
                self.assertEqual((d['schema'], d['analysisModelVersion']), (2, 1))
                f = d['functions'][0]
                self.assertEqual(f['location'], {'moduleId': d['module']['id'], 'space': 'rva', 'value': '0x1000'})
                e = f['evidenceRecords'][0]
                self.assertEqual((e['origin'], e['claim'], e['status']), ('pe_header', 'image_entry', 'confirmed'))
                self.assertEqual(e['source']['space'], 'file_offset')
                self.assertEqual(e['source']['value'], '0xa8')
                self.assertEqual(self.spans(f), [(0x1000, 0x1009)])
                self.assertEqual(f['decodedRanges'][0]['origin'], 'decoded_instructions')
                self.assertIsNone(d['module']['mainId'])

    def test_multiple_call_sites_survive_analyst_renaming(self):
        code = bytes.fromhex('e8 0b000000 e8 06000000 c3') + bytes(5) + b'\xc3'
        p = self.fixture(code)
        plain = self.analyze(p)
        d = self.analyze(p, '--main-rva', '0x1010', '--name', '0x1010=reviewed_function')
        f = next(x for x in d['functions'] if x['rva'] == 0x1010)
        calls = [e for e in f['evidenceRecords'] if e['rule'] == 'cfg.direct_call']
        self.assertEqual([e['source']['value'] for e in calls], ['0x1000', '0x1005'])
        self.assertTrue(all(e['resolution'] == 'encoded' and e['status'] == 'candidate' for e in calls))
        self.assertEqual({e['rule'] for e in f['evidenceRecords']}, {'cfg.direct_call', 'cli.main_rva', 'cli.name'})
        self.assertEqual(f['name'], 'reviewed_function')
        old = next(x for x in plain['functions'] if x['rva'] == f['rva'])
        self.assertEqual(f['id'], old['id'])
        self.assertEqual(f['decodedRanges'], old['decodedRanges'])
        self.assertEqual(d, self.analyze(p, '--main-rva', '0x1010', '--name', '0x1010=reviewed_function'))

    def test_header_evidence_survives_main_override_and_html_escaping(self):
        evil = '</script><script>window.injected=1</script>&"'
        html = self.root / 'report.html'
        d = self.analyze(self.fixture(b'\xc3'), '--main-rva', '0x1000', '--name', '0x1000=' + evil,
                         '--html', str(html))
        records = d['functions'][0]['evidenceRecords']
        self.assertEqual({e['origin'] for e in records}, {'pe_header', 'analyst'})
        self.assertEqual([e['detail'] for e in records if e['rule'] == 'cli.name'], [evil])
        self.assertNotIn(evil, html.read_text())
        self.assertEqual(d['module']['mainId'], d['module']['entryId'])

    def test_jumped_over_bytes_are_not_function_coverage(self):
        d = self.analyze(self.fixture(bytes.fromhex('eb0e') + bytes(14) + b'\xc3'))
        self.assertEqual(self.spans(d['functions'][0]), [(0x1000, 0x1002), (0x1010, 0x1011)])
        self.assertEqual(len(d['functions']), 1)
        self.assertEqual(d['module']['instructionCount'], 2)

    def test_shared_tail_retains_two_owners_and_separate_ranges(self):
        code = bytearray(0x31)
        code[:11] = bytes.fromhex('e80b000000 e816000000 c3')
        code[0x10:0x12] = bytes.fromhex('eb1e')
        code[0x20:0x22] = bytes.fromhex('eb0e')
        code[0x30] = 0xc3
        d = self.analyze(self.fixture(code))
        shared = next(b for b in d['blocks'] if b['rva'] == 0x1030)
        self.assertEqual(len(shared['owners']), 2)
        self.assertEqual(d['diagnostics']['counts']['ambiguous_owner'], 1)
        for entry in (0x1010, 0x1020):
            f = next(f for f in d['functions'] if f['rva'] == entry)
            self.assertEqual(self.spans(f), [(entry, entry + 2), (0x1030, 0x1031)])

    def test_limit_at_terminal_instruction_is_not_exhaustion(self):
        d = self.analyze(self.fixture(b'\xc3'), '--limit', '1')
        self.assertFalse(d['module']['truncated'])
        self.assertNotIn('budget_exhausted', d['diagnostics']['counts'])
        d = self.analyze(self.root / 'sample64.exe', '--limit', '3')
        self.assertFalse(d['module']['truncated'])
        d = self.analyze(self.root / 'sample64.exe', '--limit', '2')
        self.assertTrue(d['module']['truncated'])
        self.assertEqual(d['diagnostics']['counts']['budget_exhausted'], 1)
        self.assertEqual(self.spans(d['functions'][0]), [(0x1000, 0x1008)])

    def test_decode_failure_is_not_an_unsupported_semantics_claim(self):
        d = self.analyze(self.fixture(b'\x0f', extent=1), ok=False)
        self.assertEqual(d['module']['instructionCount'], 0)
        self.assertEqual(d['diagnostics']['counts'], {'decode_failed': 1, 'unresolved_seed': 1})
        self.assertEqual(d['diagnostics']['items'][0]['location']['value'], '0x1000')

    def test_overlap_diagnostic_does_not_create_a_fake_block(self):
        d = self.analyze(self.fixture(bytes.fromhex('b800000000 ebfa')))
        self.assertEqual(d['diagnostics']['counts']['overlapping_decode'], 1)
        self.assertNotIn(0x1001, [b['rva'] for b in d['blocks']])
        self.assertIsNone(d['edges'][0]['to'])

    def test_unmapped_main_is_not_assigned(self):
        d = self.analyze(self.fixture(b'\xc3'), '--main-rva', '0x2000')
        self.assertIsNone(d['module']['mainId'])
        self.assertEqual(d['diagnostics']['counts']['unmapped_target'], 1)

    def test_diagnostic_counts_survive_detail_cap(self):
        options = []
        for i in range(107):
            options.extend(['--name', f'{hex(0x2000+i)}=unused'])
        d = self.analyze(self.fixture(b'\xc3'), *options)
        log = d['diagnostics']
        self.assertEqual((log['limit'], log['total'], log['omitted']), (100, 107, 7))
        self.assertEqual(log['counts'], {'ignored_annotation': 107})
        self.assertEqual(len(log['items']), 100)
        self.assertEqual(len(d['warnings']), 100)

    def test_malformed_import_metadata_has_typed_diagnostic(self):
        p = self.fixture(b'\xc3')
        data = bytearray(p.read_bytes())
        struct.pack_into('<I', data, 0x98 + 108, 2)
        struct.pack_into('<II', data, 0x98 + 112 + 8, 0x5000, 40)
        p.write_bytes(data)
        d = self.analyze(p)
        self.assertEqual(d['diagnostics']['counts']['invalid_metadata'], 1)
        self.assertEqual(d['diagnostics']['items'][0]['phase'], 'imports')

    def test_large_preferred_address_is_lossless(self):
        base = 0xff00000000000000
        d = self.analyze(self.fixture(bytes.fromhex('e9 00100000'), base=base))
        item = d['diagnostics']['items'][0]
        self.assertEqual(item['location']['space'], 'preferred_va')
        self.assertEqual(int(item['location']['value'], 16), base + 0x1005 + 0x1000)

    def test_register_indirect_call_remains_unresolved(self):
        d = self.analyze(self.fixture(bytes.fromhex('ffd0c3')))
        self.assertEqual(len(d['functions']), 1)
        call = next(e for e in d['edges'] if e['kind'] == 'call')
        self.assertIsNone(call['to'])
        self.assertFalse(call['external'])

    def test_compiled_corpus_manifest_and_blind_discovery(self):
        if args.fixtures is None:
            self.skipTest('Linked fixtures unavailable; pass --fixtures to check compiler-map ground truth')
        root = args.fixtures.resolve()
        manifest = json.loads((root / 'corpus.json').read_text())
        self.assertEqual(manifest['schema'], 1)
        self.assertTrue(manifest['toolchain']['compiler'])
        self.assertTrue(manifest['toolchain']['linker'])
        self.assertEqual(len(manifest['fixtures']), 2)
        source_root = Path(__file__).resolve().parent.parent
        for s in manifest['sources']:
            self.assertEqual(s['sha256'], hashlib.sha256((source_root / s['path']).read_bytes()).hexdigest())
        for item in manifest['fixtures']:
            self.assertTrue(any('-O1' in cmd for cmd in item['commands']))
            for inp in item['inputs']:
                path = root / inp['path']
                self.assertEqual(inp['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
                d = self.analyze(path)  # No --main-rva, --name, or map supplied.
                self.assertIsNone(d['module']['mainId'])
                if path.suffix == '.exe':
                    self.assertEqual({f['rva'] for f in d['functions']}, set(item['oracle']['functionEntries'].values()))
                else:
                    e = d['functions'][0]['evidenceRecords'][0]
                    self.assertEqual(e['origin'], 'export_table')
                    self.assertEqual(e['source']['space'], 'rva')
                    self.assertNotEqual(int(e['source']['value'], 16), d['functions'][0]['rva'])

    def test_old_report_fields_unchanged(self):
        if args.baseline is None:
            self.skipTest('Optional differential check requires a previous analyzer executable')
        for bits in (32, 64):
            p = self.root / f'sample{bits}.exe'
            current = self.analyze(p)
            old = self.analyze(p, executable=args.baseline.resolve())
            self.assertEqual(legacy_projection(current), old)
        if args.fixtures:
            for name in ('demo32.exe', 'demo64.exe', 'demo_math32.dll', 'demo_math64.dll'):
                p = args.fixtures.resolve() / name
                self.assertEqual(legacy_projection(self.analyze(p)), self.analyze(p, executable=args.baseline.resolve()))


if __name__ == '__main__':
    unittest.main(argv=['test_analysis_model'], verbosity=2)
