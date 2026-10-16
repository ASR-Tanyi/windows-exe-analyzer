#!/usr/bin/env python3
"""Structural v1 metadata and evidence-backed discovery. Inputs are never executed."""
import argparse
import json
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest
from unwind_fixture import info, make_unwind_pe

ANALYZER = None
FIXTURES = None


class UnwindTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.input = self.root/'fixture.exe'

    def read(self, *options):
        out = self.root/'report.json'
        p = subprocess.run([str(ANALYZER),str(self.input),'--json',str(out),'--data-limit','0',*options],
                           capture_output=True,text=True,timeout=30)
        self.assertEqual(p.returncode,0,p.stderr)
        return json.loads(out.read_text())

    def run_fixture(self, *options, **kwargs):
        make_unwind_pe(self.input, **kwargs); return self.read(*options)

    def node(self, d, rva='0x3000'):
        return next(n for n in d['unwindInfo']['nodes'] if n['rva']==rva)

    def test_discovery_without_main_or_symbol_hints(self):
        d=self.run_fixture(); self.assertEqual([f['rva'] for f in d['functions']],[0x1000,0x1010])
        self.assertIsNone(d['module']['mainId']); self.assertTrue(d['exceptionDirectory']['discoverySeedsAdded'])
        f=d['functions'][1]; self.assertEqual(f['metadataRecords'],[0])
        self.assertEqual(f['decodedRanges'][0]['endRva'],'0x1011')
        self.assertEqual(d['exceptionDirectory']['records'][0]['endRva'],'0x1030')
        self.assertEqual(f['evidenceRecords'][0]['origin'],'exception_directory')
        self.assertEqual(f['evidenceRecords'][0]['source']['value'],'0x2000')

    def test_inspection_without_seeding(self):
        d=self.run_fixture('--no-unwind-seeds')
        self.assertEqual(len(d['functions']),1); self.assertEqual(self.node(d)['status'],'supported_v1')
        self.assertEqual(d['unwindInfo']['records'][0]['discovery'],'disabled')

    def test_unknown_versions_are_opaque(self):
        for version in [0,2,3,7]:
            with self.subTest(version=version):
                d=self.run_fixture(nodes={0x3000:bytes([version,255,255,255])})
                n=self.node(d); self.assertEqual(n['version'],version); self.assertEqual(n['status'],'unsupported')
                self.assertEqual(n['operations'],[]); self.assertIsNone(n['chain'])
                self.assertEqual(len(d['functions']),1)

    def test_supported_operation_slot_lengths_and_operands(self):
        cases=[(b'\x01\x30',1,0),(b'\x01\x01\x11\x00',2,136),
               (b'\x01\x11\x00\x00\x08\x00',3,524288),(b'\x01\x32',1,32),
               (b'\x01\x34\x02\x00',2,16),(b'\x01\x35\x08\x00\x00\x00',3,8),
               (b'\x01\x68\x03\x00',2,48),(b'\x01\x69\x20\x00\x00\x00',3,32),
               (b'\x00\x0a',1,40),(b'\x00\x1a',1,48)]
        for codes,slots,operand in cases:
            with self.subTest(codes=codes):
                d=self.run_fixture(nodes={0x3000:info(prolog=1,codes=codes)})
                n=self.node(d); self.assertEqual(n['status'],'supported_v1')
                self.assertEqual((n['operations'][0]['slots'],int(n['operations'][0]['operand'],16)),(slots,operand))

    def test_frame_register(self):
        d=self.run_fixture(nodes={0x3000:info(prolog=4,frame=0x25,codes=b'\x04\x03')})
        self.assertTrue(d['unwindInfo']['records'][0]['eligible'])
        self.assertEqual(self.node(d)['operations'][0]['operand'],'0x20')

    def test_bad_frame_fields(self):
        for frame,codes in [(0x20,b''),(1,b''),(5,b''),(0,b'\x00\x03'),(5,b'\x00\x13')]:
            with self.subTest(frame=frame,codes=codes):
                d=self.run_fixture(nodes={0x3000:info(frame=frame,codes=codes)})
                self.assertFalse(d['unwindInfo']['records'][0]['eligible'])

    def test_operation_and_flag_errors(self):
        cases=[info(flags=5),info(flags=8),info(prolog=1,codes=b'\x01\x21'),
               info(prolog=1,codes=b'\x01\x2a'),info(prolog=1,codes=b'\x01\x06'),
               info(prolog=1,codes=b'\x01\x07'),info(prolog=1,codes=b'\x01\x10'),
               info(prolog=1,codes=b'\x01\x18\x00\x00')]
        for node in cases:
            with self.subTest(node=node):
                d=self.run_fixture(nodes={0x3000:node});self.assertFalse(d['unwindInfo']['records'][0]['eligible'])

    def test_continuation_slots_are_not_opcodes(self):
        d=self.run_fixture(nodes={0x3000:info(prolog=1,codes=b'\x01\x01\xff\xff')})
        self.assertEqual(len(self.node(d)['operations']),1)
        self.assertEqual(self.node(d)['operations'][0]['operand'],hex(65535*8))

    def test_truncated_operation(self):
        d=self.run_fixture(nodes={0x3000:info(prolog=1,codes=b'\x01\x34')})
        self.assertIn('truncated_multi_slot_operation',self.node(d)['issues'])
        self.assertEqual(len(d['functions']),1)

    def test_code_and_padding_bounds(self):
        for count in [1,2,255]:
            with self.subTest(count=count):
                d=self.run_fixture(records=[(0x1010,0x1030,0x3dfc)],nodes={0x3dfc:bytes([1,1,count,0])})
                self.assertIn('truncated_unwind_slots_or_padding',self.node(d,'0x3dfc')['issues'])

    def test_offset_order_and_prolog_bound(self):
        for node in [info(prolog=1,codes=b'\x02\x32'),info(prolog=3,codes=b'\x01\x32\x02\x30'),info(prolog=33)]:
            with self.subTest(node=node):
                d=self.run_fixture(nodes={0x3000:node});self.assertFalse(d['unwindInfo']['records'][0]['eligible'])

    def test_bad_stack_alignment(self):
        for codes in [b'\x01\x11\x01\x00\x00\x00',b'\x01\x35\x01\x00\x00\x00',
                      b'\x01\x69\x08\x00\x00\x00',b'\x01\x01\x00\x00']:
            with self.subTest(codes=codes):
                d=self.run_fixture(nodes={0x3000:info(prolog=1,codes=codes)})
                self.assertIn('invalid_unwind_stack_offset',self.node(d)['issues'])

    def test_handler_candidate_not_an_ordinary_call_edge(self):
        for flags in [1,2,3]:
            with self.subTest(flags=flags):
                d=self.run_fixture(nodes={0x3000:info(flags=flags,prolog=1,codes=b'\x01\x32',trailer=struct.pack('<I',0x1040))})
                n=self.node(d);self.assertEqual(n['handlerRva'],'0x1040');self.assertEqual(n['handlerFieldRva'],'0x3008')
                self.assertEqual(n['handlerDataRva'],'0x300c');self.assertTrue(d['unwindInfo']['records'][0]['eligible'])
                self.assertNotIn(0x1040,[f['rva'] for f in d['functions']]);self.assertEqual(d['edges'],[])

    def test_handler_pointer_invalid_or_truncated(self):
        for target in [0,0x2000,0xfffffff0]:
            d=self.run_fixture(nodes={0x3000:info(flags=1,trailer=struct.pack('<I',target))})
            self.assertIn('handler_not_file_backed_executable',self.node(d)['issues'])
        d=self.run_fixture(records=[(0x1010,0x1030,0x3dfc)],nodes={0x3dfc:info(flags=1)})
        self.assertIn('truncated_handler_pointer',self.node(d,'0x3dfc')['issues'])

    def test_chain_association_is_not_decoded_coverage(self):
        nodes={0x3000:info(flags=4,trailer=struct.pack('<III',0x1040,0x1050,0x3020)),0x3020:info()}
        d=self.run_fixture(nodes=nodes);a=d['unwindInfo']['records'][0]
        self.assertTrue(a['eligible']);self.assertEqual(a['primaryBeginRva'],'0x1040');self.assertEqual(a['chainDepth'],1)
        self.assertEqual(self.node(d)['chain']['fieldRva'],'0x3004')
        self.assertEqual(d['functions'][1]['evidenceRecords'][0]['claim'],'procedure_fragment_entry')
        self.assertEqual(d['functions'][1]['decodedRanges'][0]['endRva'],'0x1011')

    def test_supported_secondary_save(self):
        nodes={0x3000:info(flags=4,prolog=1,codes=b'\x01\x34\x01\x00',trailer=struct.pack('<III',0x1040,0x1050,0x3020)),0x3020:info()}
        self.assertTrue(self.run_fixture(nodes=nodes)['unwindInfo']['records'][0]['eligible'])

    def test_chain_frame_conflict(self):
        nodes={0x3000:info(flags=4,trailer=struct.pack('<III',0x1040,0x1050,0x3020)),0x3020:info(frame=5,prolog=1,codes=b'\x01\x03')}
        d=self.run_fixture(nodes=nodes);self.assertIn('chained_frame_mismatch',d['unwindInfo']['records'][0]['reasons'])

    def test_unsupported_secondary_allocation(self):
        nodes={0x3000:info(flags=4,prolog=1,codes=b'\x01\x32',trailer=struct.pack('<III',0x1040,0x1050,0x3020)),0x3020:info()}
        d=self.run_fixture(nodes=nodes);self.assertEqual(self.node(d)['status'],'unsupported');self.assertEqual(len(d['functions']),1)

    def test_chain_cycles(self):
        for second in [0x3000,0x3020]:
            nodes={0x3000:info(flags=4,trailer=struct.pack('<III',0x1040,0x1050,second))}
            if second!=0x3000:nodes[second]=info(flags=4,trailer=struct.pack('<III',0x1010,0x1030,0x3000))
            d=self.run_fixture(nodes=nodes);self.assertIn('unwind_chain_cycle',d['unwindInfo']['records'][0]['reasons'])

    def test_unknown_ancestor_blocks_descendant(self):
        nodes={0x3000:info(flags=4,trailer=struct.pack('<III',0x1040,0x1050,0x3020)),0x3020:info(version=2)}
        d=self.run_fixture(nodes=nodes);self.assertEqual(d['unwindInfo']['records'][0]['status'],'unsupported')

    def test_bad_chain_range(self):
        for begin,end in [(0x2000,0x2010),(0x1040,0x1040),(0x1040,0xffffffff)]:
            nodes={0x3000:info(flags=4,trailer=struct.pack('<III',begin,end,0x3020)),0x3020:info()}
            d=self.run_fixture(nodes=nodes);self.assertIn('unwind_context_range_invalid',d['unwindInfo']['records'][0]['reasons'])

    def test_truncated_chain(self):
        d=self.run_fixture(records=[(0x1010,0x1030,0x3df8)],nodes={0x3df8:info(flags=4)})
        self.assertIn('truncated_chained_record',self.node(d,'0x3df8')['issues'])

    def test_chain_depth_limit(self):
        for length,expected in [(32,'supported_v1'),(33,'budget_exhausted')]:
            nodes={0x3000+16*i:info(flags=4,trailer=struct.pack('<III',0x1040,0x1050,0x3000+16*(i+1))) for i in range(length-1)}
            nodes[0x3000+16*(length-1)]=info()
            d=self.run_fixture(nodes=nodes);self.assertEqual(d['unwindInfo']['records'][0]['status'],expected)
            self.assertFalse(d['module']['truncated'])

    def test_duplicates_merge_evidence_not_instructions(self):
        d=self.run_fixture(records=[(0x1010,0x1030,0x3000)]*2)
        self.assertEqual(len(d['functions']),2);self.assertEqual(d['unwindInfo']['seedLocations'],1)
        self.assertEqual(d['functions'][1]['metadataRecords'],[0,1]);self.assertEqual(len(d['functions'][1]['evidenceRecords']),2)

    def test_overlapping_records_and_duplicate_copies_are_blocked(self):
        d=self.run_fixture(records=[(0x1010,0x1030,0x3000),(0x1010,0x1030,0x3000),(0x1020,0x1040,0x3000)])
        self.assertEqual(len(d['functions']),1);self.assertFalse(any(x['eligible'] for x in d['unwindInfo']['records']))

    def test_unsorted_or_partial_directory_blocks_seeding(self):
        d=self.run_fixture(records=[(0x1040,0x1050,0x3000),(0x1010,0x1030,0x3000)])
        self.assertFalse(any(x['eligible'] for x in d['unwindInfo']['records']))
        b=make_unwind_pe(self.input);struct.pack_into('<I',b,0x98+112+24+4,13);self.input.write_bytes(b)
        self.assertFalse(self.read()['unwindInfo']['records'][0]['eligible'])

    def test_shared_header_checks_each_range_context(self):
        d=self.run_fixture(records=[(0x1010,0x1030,0x3000),(0x1040,0x1041,0x3000)],nodes={0x3000:info(prolog=2)})
        self.assertEqual(len(d['unwindInfo']['nodes']),1)
        self.assertEqual([x['eligible'] for x in d['unwindInfo']['records']],[True,False])

    def test_existing_direct_call_evidence_and_names_survive(self):
        code={0x1000:bytes.fromhex('e8 0b 00 00 00 c3'),0x1010:b'\xc3'}
        d=self.run_fixture('--name','0x1010=reviewed',code=code)
        f=d['functions'][1];self.assertEqual(f['name'],'reviewed')
        self.assertEqual({x['origin'] for x in f['evidenceRecords']},{'decoded_instruction','analyst','exception_directory'})

    def test_existing_instruction_wins_overlap(self):
        d=self.run_fixture(records=[(0x1001,0x1005,0x3000)],code={0x1000:bytes.fromhex('b8 01 00 00 00 c3')})
        self.assertEqual(len(d['functions']),1);self.assertEqual(d['unwindInfo']['records'][0]['discovery'],'not_decoded')
        self.assertIn('overlapping_decode',d['diagnostics']['counts'])

    def test_metadata_decode_does_not_fill_gaps(self):
        d=self.run_fixture(code={0x1000:b'\xc3',0x1010:bytes.fromhex('eb 0e'),0x1020:b'\xc3'})
        spans=d['functions'][1]['decodedRanges']
        self.assertEqual([(x['beginRva'],x['endRva']) for x in spans],[('0x1010','0x1012'),('0x1020','0x1021')])

    def test_no_linear_decode_past_range_end(self):
        d=self.run_fixture(records=[(0x1010,0x1012,0x3000)],code={0x1000:b'\xc3',0x1010:b'\x90\x90\xc3'})
        self.assertNotIn(0x1012,[i['rva'] for b in d['blocks'] for i in b['instructions']])
        self.assertEqual(d['functions'][1]['decodedRanges'][0]['endRva'],'0x1012')

    def test_crossing_instruction_rejected(self):
        d=self.run_fixture(records=[(0x1010,0x1011,0x3000)],code={0x1000:b'\xc3',0x1010:bytes.fromhex('b8 01 00 00 00 c3')})
        self.assertEqual(len(d['functions']),1);self.assertEqual(d['unwindInfo']['records'][0]['discovery'],'not_decoded')

    def test_instruction_limit_does_not_hide_pending_metadata_seed(self):
        d=self.run_fixture('--limit','1')
        self.assertTrue(d['module']['truncated']);self.assertEqual(d['unwindInfo']['records'][0]['discovery'],'not_decoded')
        d=self.read('--limit','2');self.assertFalse(d['module']['truncated'])

    def test_x86_no_amd64_unwind_interpretation(self):
        d=self.run_fixture(bits=32);self.assertEqual(d['unwindInfo']['nodes'],[]);self.assertEqual(len(d['functions']),1)

    def test_deterministic_serialization_and_bounded_mutations(self):
        randomizer=random.Random(817)
        for index in range(40):
            node=bytes(randomizer.randrange(256) for _ in range(64))
            make_unwind_pe(self.input,nodes={0x3000:node});d=self.read();self.assertEqual(d,self.read())
            self.assertLessEqual(len(d['unwindInfo']['nodes']),32)
            self.assertEqual(sum(d['diagnostics']['counts'].values()),d['diagnostics']['total'])

    def test_compiler_generated_demo(self):
        if FIXTURES is None:self.skipTest('Pass --fixtures for compiler-produced unwind data')
        self.input=FIXTURES/'demo64.exe';d=self.read()
        self.assertTrue(d['unwindInfo']['records']);self.assertTrue(any(x['eligible'] for x in d['unwindInfo']['records']))
        symbols=json.loads((FIXTURES/'demo64.symbols.json').read_text())
        self.assertIn(symbols['main'],[f['rva'] for f in d['functions']]);self.assertIsNone(d['module']['mainId'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('analyzer',type=Path);parser.add_argument('--fixtures',type=Path)
    args,remaining=parser.parse_known_args();ANALYZER=args.analyzer.resolve();FIXTURES=args.fixtures.resolve() if args.fixtures else None
    unittest.main(argv=[__file__,*remaining])
