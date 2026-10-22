#!/usr/bin/env python3
"""Decoder-to-recovery contracts, graph reductions, barriers and fixture coverage."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import tempfile
from test_decoder_operands import make_operand_pe

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / 'web/pseudocode-model.js'


def models(reports, recover=True):
    script = "const fs=require('fs'),m=require(process.argv[1]);const rs=JSON.parse(fs.readFileSync(0,'utf8'));console.log(JSON.stringify(rs.map(r=>" + (
        "m.recover(r,r.functions[0].id)" if recover else "m.lift(r.blocks[0].instructions[0],r)") + ")));"
    return json.loads(subprocess.run(['node', '-e', script, str(MODEL)], input=json.dumps(reports),
                                    capture_output=True, text=True, check=True, timeout=30).stdout)


def report(analyzer, root, code, bits=64):
    src, out = root / 'case.exe', root / 'case.json'
    make_operand_pe(src, bytes.fromhex(code), bits)
    subprocess.run([str(analyzer.resolve()), str(src), '--json', str(out)], check=True, capture_output=True, timeout=10)
    return json.loads(out.read_text())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('analyzer', type=Path)
    p.add_argument('--fixtures', type=Path)
    a = p.parse_args()
    checks = 0
    def check(ok, message):
        nonlocal checks
        if not ok:
            raise AssertionError(message)
        checks += 1
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        diamond = report(a.analyzer, root, '83f9007e07b801000000eb05b802000000c3')
        loop = report(a.analyzer, root, 'b90300000031c001c8ffc975fac3')
        available = diamond['module']['decoderInfo']['capabilities']['structuredOperands']
        # CLI inspection uses the same graph as the embedded preview, with an
        # explicit failure status for backends without typed operands.
        export = root / 'ssa-export.json'; export.write_text(json.dumps(diamond))
        cli = subprocess.run(['node', str(ROOT / 'scripts/pseudocode.js'), str(export), '0x1000', '--ssa'],
            capture_output=True, text=True, timeout=10)
        check(cli.returncode == (0 if available else 2), 'SSA export backend status')
        check(('phi' in cli.stdout and 'rax_' in cli.stdout) if available else 'Structured operands unavailable' in cli.stdout,
              'SSA text shows joined definitions or capability fallback')
        if not available:
            check(all(m['status'] == 'unavailable' for m in models([diamond, loop])), 'LLVM must not invent semantics')
        else:
            dm, lm = models([diamond, loop])
            check(dm['version'] == 5 and dm['registerExpressions']['version'] == 1, 'versioned expression overlay')
            chain = report(a.analyzer, root, 'b8ffffffff83c00289c2c3')
            cm = models([chain])[0]
            check(cm['registerExpressions']['status'] == 'available' and len(cm['registerExpressions']['rewrites']) == 2, 'constant chain rewrites two consuming operations')
            check(cm['instructions'][2]['ops'][0]['value']['kind'] == 'register', 'raw typed input retained')
            check(any('0x1' in line['text'] and len(line['sources']) == 3 for line in cm['simplifiedLines']), 'folded result carries every contributing instruction')
            export.write_text(json.dumps(chain))
            simplified_cli = subprocess.run(['node', str(ROOT / 'scripts/pseudocode.js'), str(export), '0x1000', '--raw', '--simplified'], capture_output=True, text=True, timeout=10)
            check(simplified_cli.returncode == 0 and 'rdx = u32(0x1)' in simplified_cli.stdout, 'CLI exports the simplified model')
            check([l['text'] for l in cm['lines']] != [l['text'] for l in cm['simplifiedLines']], 'both presentations available')
            check(dm['stats']['ifs'] == 1 and dm['stats']['gotos'] == 0, 'diamond becomes if/else')
            check(lm['stats']['loops'] == 1, 'backedge loop recovered')
            check('else' in '\n'.join(x['text'] for x in dm['lines']), 'else body retained')
            for data, model in ((diamond, dm), (loop, lm)):
                ids = {i['id'] for b in data['blocks'] for i in b['instructions']}
                check({s for line in model['lines'] for s in line['sources']} == ids, 'all instructions have provenance')
                check(len(model['instructions']) == len(ids), 'no duplicated lifted instruction')
                check(model['complete'] is False, 'do not claim complete function recovery')
            # Same discovered graph, but unsafe to structure it as one function.
            shared = copy.deepcopy(diamond)
            shared['blocks'][1]['owners'].append('another_owner')
            truncated = copy.deepcopy(loop)
            truncated['module']['truncated'] = True
            for model in models([shared, truncated]):
                check(not model['structured'] and model['stats']['gotos'] > 0, 'shared/truncated graph keeps transfers')
                check(model['registerSSA']['status'] == 'unavailable' and not model['registerSSA']['definitions'], 'unsafe graph cannot produce SSA')
                check(model['registerExpressions']['status'] == 'unavailable' and model['simplifiedLines'] == model['lines'], 'unsafe graph falls back transactionally to original expressions')
            unresolved = copy.deepcopy(diamond)
            unresolved['edges'][0]['to'] = None
            check(any('unknown_control_transfer' in x['text'] for x in models([unresolved])[0]['lines']), 'unresolved edge preserved')
            # Cross-entry cycle: no single-entry diamond/loop may absorb it.
            irreducible = copy.deepcopy(diamond)
            branches = [e for e in irreducible['edges'] if e['kind'] in ('taken', 'not_taken')]
            yes, no = branches[0]['to'], branches[1]['to']
            for e in irreducible['edges']:
                if e['from'] == yes: e['to'] = no
                elif e['from'] == no: e['to'] = yes
            im = models([irreducible])[0]
            check(im['stats']['loops'] == 0 and im['stats']['gotos'] >= 3, 'irreducible cycle uses gotos')
            # Unsupported instructions cannot masquerade as assignments/no-ops.
            negative = ['f00118c3', 'f3a4c3', 'f20f10c1c3', '648b03c3', '11c8c3', 'f7f1c3',
                        '0f44 03 c3', 'e800000000c3', 'ffe0', 'c8 10 00 00 c3', '66c3']
            for m in models([report(a.analyzer, root, code) for code in negative], recover=False):
                check(m['status'] == 'barrier' and m['ops'][0]['kind'] == 'barrier', 'unsupported form must invalidate all state: ' + m['mnemonic'])
            # Budgets are checked before graph reductions/lifting.
            large = copy.deepcopy(loop)
            large['blocks'][0]['instructions'] *= 2049
            check(models([large])[0]['status'] == 'unavailable', 'instruction budget')
            large = copy.deepcopy(loop)
            large['blocks'] *= 129
            check(models([large])[0]['status'] == 'unavailable', 'block budget')
            large = copy.deepcopy(loop)
            large['edges'] *= 385
            check(models([large])[0]['status'] == 'unavailable', 'edge budget')
        old = copy.deepcopy(diamond)
        del old['operandModelVersion']
        check(models([old])[0]['status'] == 'unavailable', 'legacy reports remain honest')
        if a.fixtures:
            for path in sorted(a.fixtures.glob('recovery*-o?.json')):
                data = json.loads(path.read_text())
                for f in data['functions']:
                    if f['name'] == 'pe_entry': continue
                    one = copy.deepcopy(data)
                    one['functions'] = [f]
                    m = models([one])[0]
                    if not available:
                        check(m['status'] == 'unavailable', 'LLVM fixture remains unavailable')
                        continue
                    check(m['status'] == 'supported_subset', path.name + ' ' + f['name'] + ': ' + repr([i for i in m['instructions'] if i['status'] == 'barrier']))
                    check(m['registerSSA']['status'] == 'available', path.name + ' ' + f['name'] + ': register SSA available')
                    check(m['registerExpressions']['status'] == 'available', path.name + ' ' + f['name'] + ': expressions within budget')
                    if f['name'] == 'transform_demo':
                        check(m['stats']['loops'] >= 1, 'complex demo retains loops')
                        if '-o0' in path.name:
                            check(m['stats']['loops'] == 2 and m['stats']['ifs'] >= 2, 'O0 nested loop and branches recovered')
        print('PASS: %d recovery contracts' % checks)


if __name__ == '__main__':
    main()
