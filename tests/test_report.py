#!/usr/bin/env python3
"""Executable-level regression tests, no external Python dependencies."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from make_samples import make_samples

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("analyzer", type=Path)
parser.add_argument("--fixtures", type=Path, help="Generated linked EXE/DLL fixtures")
args = parser.parse_args()
EXE = args.analyzer.resolve()
checks = 0

def check(condition, message):
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1

def invoke(path, output, *args, ok=True):
    p = subprocess.run([str(EXE), str(path), '--json', str(output), *args], capture_output=True, text=True)
    check((p.returncode == 0) == ok, f'Unexpected exit {p.returncode}: {p.stderr}')
    return json.loads(output.read_text()) if p.returncode == 0 else p

def validate(d):
    blocks = {b['id']: b for b in d['blocks']}
    insns = {i['id']: i for b in d['blocks'] for i in b['instructions']}
    check(len(insns) == d['module']['instructionCount'], 'Instructions must appear once')
    for b in d['blocks']:
        check(bool(b['instructions']), 'No empty blocks')
        for x, y in zip(b['instructions'], b['instructions'][1:]):
            check(x['rva'] + x['size'] == y['rva'], 'Instruction gap within block')
    for e in d['edges']:
        check(e['from'] in blocks and e['source'] in insns, 'Dangling edge source')
        check(e['to'] is None or e['to'] in blocks, 'Dangling edge target')
    return blocks

with tempfile.TemporaryDirectory() as directory:
    tmp = Path(directory)
    ROOT = tmp / "samples"
    make_samples(ROOT)
    for bits in (32, 64):
        d = invoke(ROOT/f'sample{bits}.exe', tmp/'out.json')
        validate(d)
        check(d['module']['instructionCount'] == 3, 'Legacy sample decoding')
        check(d['module']['mainId'] is None, 'Must not invent main')
        check(d['blocks'][0]['name'] == 'pe_entry', 'Entry recognition')

    def fixture(code, name='fixture.exe'):
        b = bytearray((ROOT/'sample64.exe').read_bytes())
        b[0x200:0x300] = bytes(256)
        b[0x200:0x200+len(code)] = code
        path = tmp/name
        path.write_bytes(b)
        return path

    # A backward conditional branch enters the middle of an initially linear stream.
    path = fixture(bytes.fromhex('B9 03 00 00 00 31 C0 83 C0 01 FF C9 75 F9 C3'))
    d = invoke(path, tmp/'out.json'); validate(d)
    check([b['rva'] for b in d['blocks']] == [0x1000, 0x1007, 0x100e], 'Split at backward target')
    taken = [e for e in d['edges'] if e['kind'] == 'taken']
    check(len(taken) == 1 and taken[0]['to'] == taken[0]['from'], 'Backward loop edge')
    check(any(e['kind'] == 'not_taken' for e in d['edges']), 'Conditional fall-through')
    d2 = invoke(path, tmp/'named.json', '--main-rva', '0x1000', '--name', '0x1007=increment_loop')
    check(d2['module']['mainId'] == d2['module']['entryId'], 'Explicit analyst main assertion')
    check(d2['blocks'][1]['name'] == 'increment_loop', 'Analyst name applied')
    check(d2['blocks'][1]['id'] == d['blocks'][1]['id'], 'Stable IDs across rename')

    # Unknown register-indirect calls retain a continuation, not a guessed target.
    d = invoke(fixture(bytes.fromhex('FF D0 C3')), tmp/'out.json')
    validate(d)
    call = next(e for e in d['edges'] if e['kind'] == 'call')
    check(call['to'] is None and not call['external'], 'Indirect call stays unknown')
    check(any(e['kind'] == 'continuation' for e in d['edges']), 'Indirect-call continuation')

    # Prefixed return must stop traversal before the following bytes.
    d = invoke(fixture(bytes.fromhex('F3 C3 B8 01 00 00 00 C3')), tmp/'out.json')
    check(d['module']['instructionCount'] == 1, 'rep ret terminates block')

    # No inferred fall-through through an unconditional indirect jump.
    d = invoke(fixture(bytes.fromhex('FF E0 B8 01 00 00 00 C3')), tmp/'out.json')
    check(d['module']['instructionCount'] == 1, 'Indirect jmp stops traversal')
    check(len(d['edges']) == 1 and d['edges'][0]['to'] is None, 'Unknown jump edge')

    # Malicious labels must never become HTML/script source.
    evil = '</script><script>window.injected=1</script>&"'
    path = fixture(bytes.fromhex('C3'))
    d = invoke(path, tmp/'out.json', '--name', '0x1000='+evil, '--html', str(tmp/'evil.html'))
    text = (tmp/'evil.html').read_text()
    check(evil not in text, 'HTML JSON escaping')
    check(d['blocks'][0]['name'] == evil, 'JSON preserves literal label')

    p = invoke(path, path, ok=False)
    check('distinct' in p.stderr, 'Refuse input overwrite')
    bad = tmp/'bad.exe'; bad.write_bytes(b'not a PE')
    invoke(bad, tmp/'out.json', ok=False)
    d = invoke(ROOT/'sample64.exe', tmp/'limited.json', '--limit', '1')
    check(d['module']['truncated'], 'Truncation is explicit')

    # Linked fixtures are generated from source, never executed.
    if args.fixtures is None:
        print("SKIP: linked EXE/DLL checks (pass --fixtures or install clang/lld-link for CTest)")
    for bits in ((32, 64) if args.fixtures else ()):
        demo = args.fixtures
        d = invoke(demo/f'demo{bits}.exe', tmp/'out.json'); validate(d)
        check(d['module']['mainId'] is None, 'No main guess on real EXE')
        external = [e for e in d['edges'] if e['external']]
        check(any(e['external'] == f'demo_math{bits}.dll!transform_score' for e in external), 'IAT resolution')
        check(len(d['functions']) == 3, 'Direct-call function discovery')
        d = invoke(demo/f'demo_math{bits}.dll', tmp/'out.json'); validate(d)
        check(d['module']['entryId'] is None, 'DLL without PE entry')
        check(d['functions'][0]['name'] == 'transform_score', 'Export-based DLL discovery')

print(f'PASS: {checks} assertions (fixture traversal, names, branches, imports, exports, safety)')
