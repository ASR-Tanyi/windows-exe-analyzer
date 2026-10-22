#!/usr/bin/env python3
"""Compare the test IR evaluator with Unicorn on authored bytes and our C demos.

No arbitrary input is accepted or executed natively. Unicorn is a test-only
dependency; the analyzer and offline viewer never emulate an analyzed program.
"""
import argparse
import json
from pathlib import Path
import random
import struct
import subprocess
import tempfile
from test_pseudocode import ROOT, models, report
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_HOOK_CODE
from unicorn import x86_const as uc_regs

FLAGS = {'carry': 0, 'parity': 2, 'auxiliary': 4, 'zero': 6, 'sign': 7, 'overflow': 11}
DATA, STACK, RETURN = 0x200000, 0x300800, 0x500000
RNG = random.Random(73191)
VALUE_CHECKS = {'states': 0, 'aliases': 0}
SSA_CHECKS = {'states': 0, 'uses': 0, 'joins': 0, 'exits': 0}


def registers(bits):
    return (['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp'] + [f'r{i}' for i in range(8, 16)] if bits == 64
            else ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'])


def initial(bits):
    regs = {r: str(RNG.getrandbits(bits)) for r in registers(bits)}
    p = 'r' if bits == 64 else 'e'
    regs[p + 'bx'] = str(DATA + 64)
    regs[p + 'cx'] = str(RNG.randrange(8))
    regs[p + 'sp'] = str(STACK)
    memory = {str(a): RNG.randrange(256) for lo, size in ((DATA, 256), (STACK - 512, 1024)) for a in range(lo, lo + size)}
    for i, b in enumerate(RETURN.to_bytes(bits // 8, 'little')): memory[str(STACK + i)] = b
    return {'registers': regs, 'memory': memory, 'flags': {k: bool(RNG.getrandbits(1)) for k in FLAGS}}


def write_word(state, address, value, size=4):
    for i, b in enumerate((value & ((1 << (size * 8)) - 1)).to_bytes(size, 'little')):
        state['memory'][str(address + i)] = b


def register_trace(uc, bits, start, state, model, skip_callees=False):
    """Track dynamic definition identities/values independently of SSA building.

    The emulator chooses each predecessor. Snapshot definitions after actual
    machine instructions; check each use and parallel PHI against those snapshots.
    """
    graph = model['registerSSA']
    assert graph['status'] == 'available', graph.get('reason')
    defs = {d['id']: d for d in graph['definitions']}
    uses = {u['id']: u for u in graph['uses']}
    blocks = {b['id']: b for b in graph['blocks']}
    records = {i['source']: i for i in graph['instructions']}
    base = start - blocks[graph['entry']]['rva']
    by_address = {base + i['rva']: records[i['source']] for i in model['instructions'] if i['source'] in records}
    current = {d['register']: d['id'] for d in defs.values() if d['kind'] == 'entry'}
    snapshots = {id: int(state['registers'][r]) for r, id in current.items()}
    previous = None
    previous_regs = None

    def capture():
        return {r: uc.reg_read(getattr(uc_regs, 'UC_X86_REG_' + r.upper())) for r in registers(bits)}

    def finish(regs):
        if previous is None: return
        writes = {defs[id]['register']: defs[id] for id in previous['writes']}
        for r in registers(bits):
            if r not in writes:
                assert regs[r] == previous_regs[r], ('unrepresented register write', previous['source'], r)
        for r, d in writes.items():
            preserved = int(d['preserveMask'], 16)
            assert (regs[r] & preserved) == (previous_regs[r] & preserved), ('partial-write preservation', d)
            if d['zeroExtend']: assert regs[r] >> 32 == 0, ('32-bit write did not zero extend', d)
            snapshots[d['id']] = regs[r]
            current[r] = d['id']

    def trace(machine, address, size, _):
        nonlocal previous, previous_regs
        if skip_callees and address not in by_address: return
        regs = capture()
        finish(regs)
        i = by_address[address]
        block = blocks[i['block']]
        if address == base + block['rva']:
            predecessor = previous['block'] if previous else None
            pending = {}
            for id in block['phis']:
                d = defs[id]
                incoming = [uses[u] for u in d['incoming'] if uses[u]['predecessor'] == predecessor]
                assert len(incoming) == 1, ('missing actual PHI predecessor', d, predecessor)
                u = incoming[0]
                assert current[d['register']] == u['definition'], ('wrong reaching edge definition', d, u, current[d['register']])
                assert snapshots[u['definition']] == regs[d['register']], ('wrong PHI value', d, u)
                pending[d['register']] = (id, regs[d['register']])
                SSA_CHECKS['joins'] += 1
            # PHIs read their predecessor's state simultaneously.
            for r, (id, value) in pending.items(): current[r] = id; snapshots[id] = value
        for id in i['reads']:
            u = uses[id]
            assert u['definition'] == current[u['register']], ('stale use definition', u, current[u['register']])
            mask = int(u['mask'], 16)
            assert snapshots[u['definition']] & mask == regs[u['register']] & mask, ('wrong SSA input value', u)
            SSA_CHECKS['uses'] += 1
        previous, previous_regs = i, regs
        SSA_CHECKS['states'] += 1

    uc.hook_add(UC_HOOK_CODE, trace)

    def complete(single):
        regs = capture()
        finish(regs)
        if not single:
            for id in blocks[previous['block']]['exitUses']:
                u = uses[id]
                assert current[u['register']] == u['definition'], ('wrong machine exit definition', u)
                assert snapshots[u['definition']] == regs[u['register']], ('wrong machine exit value', u)
                SSA_CHECKS['exits'] += 1
    return complete


def oracle(bits, segments, start, state, single=False, model=None):
    uc = Uc(UC_ARCH_X86, UC_MODE_64 if bits == 64 else UC_MODE_32)
    pages = set()
    def ensure(address, size):
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            if page not in pages: uc.mem_map(page, 4096); pages.add(page)
    for address, data in segments:
        ensure(address, len(data)); uc.mem_write(address, data)
    ensure(RETURN, 4096)
    for address, byte in state['memory'].items():
        ensure(int(address), 1); uc.mem_write(int(address), bytes([byte]))
    for name, value in state['registers'].items(): uc.reg_write(getattr(uc_regs, 'UC_X86_REG_' + name.upper()), int(value))
    uc.reg_write(uc_regs.UC_X86_REG_EFLAGS, 2 | sum(int(v) << FLAGS[k] for k, v in state['flags'].items()))
    if model and model['valueAnalysis']['status'] == 'converged':
        va = model['valueAnalysis']
        facts = {f['source']: f for f in va['facts']}
        # Every observed concrete state must be contained in the static facts.
        # Resolve symbolic entry_sp from the emulator's actual incoming state.
        entry_sp = int(state['registers']['rsp' if bits == 64 else 'esp'])
        image_base = start - model['instructions'][0]['rva']
        by_va = {image_base + i['rva']: i for i in model['instructions']}
        accesses = {}
        for a in va['accesses']: accesses.setdefault(a['source'], []).append(a)
        def concrete(e, regs):
            width, kind = e['width'], e['kind']
            if kind == 'constant': result = int(e['value'])
            elif kind == 'register': result = regs[e['name']] >> e['offset']
            elif kind == 'cast':
                result = concrete(e['value'], regs)
                if e['signed'] and result & (1 << (e['value']['width'] - 1)): result -= 1 << e['value']['width']
            elif kind == 'binary':
                left, right = concrete(e['left'], regs), concrete(e['right'], regs)
                result = left + right if e['operator'] == '+' else left * right
            else: raise AssertionError('unexpected address expression ' + kind)
            return result & ((1 << width) - 1)
        def contained(v, number):
            mask = (1 << v['width']) - 1
            if number & int(v['knownMask'], 16) != int(v['knownValue'], 16): return False
            if v['atoms'] is None: return True
            values = [(entry_sp + int(a['offset'])) & mask if a['kind'] == 'stack' else int(a['value'])
                      for a in v['atoms']]
            return number in values
        def trace(machine, address, size, _):
            insn = by_va.get(address)
            assert insn, ('executed instruction outside recovered function', hex(address))
            regs = {r: machine.reg_read(getattr(uc_regs, 'UC_X86_REG_' + r.upper())) for r in registers(bits)}
            for r, value in facts[insn['source']]['before'].items():
                assert contained(value, regs[r]), ('unsound abstract fact', insn['rva'], r, value, regs[r])
            VALUE_CHECKS['states'] += 1
            for access in accesses.get(insn['source'], []):
                if access['key']:
                    actual = concrete(json.loads(access['key'])['address'], regs)
                    assert contained(access['address'], actual), ('unsound address', access, actual)
                    if access.get('alias'):
                        assert actual == (entry_sp + int(access['stackOffset'])) & ((1 << bits) - 1)
                        assert access['allocated'] and not access['proofTruncated']
                        VALUE_CHECKS['aliases'] += 1
        uc.hook_add(UC_HOOK_CODE, trace)
    finish_registers = register_trace(uc, bits, start, state, model) if model else None
    uc.emu_start(start, start + len(segments[0][1]) if single else RETURN, timeout=2000000, count=1 if single else 100000)
    if finish_registers: finish_registers(single)
    if not single:
        ip = uc.reg_read(uc_regs.UC_X86_REG_RIP if bits == 64 else uc_regs.UC_X86_REG_EIP)
        assert ip == RETURN, f'oracle did not return within budget: start={start:#x}, ip={ip:#x}'
    flags = uc.reg_read(uc_regs.UC_X86_REG_EFLAGS)
    return {'registers': {name: str(uc.reg_read(getattr(uc_regs, 'UC_X86_REG_' + name.upper()))) for name in state['registers']},
            'flags': {k: bool(flags & (1 << bit)) for k, bit in FLAGS.items()},
            'memory': {address: uc.mem_read(int(address), 1)[0] for address in state['memory']}}


def evaluate(requests):
    # Execute the transformed overlay separately and compare every observable
    # result with the original, which the caller checks against Unicorn.
    expanded = [case for r in requests for case in (r, dict(r, simplified=True))]
    results = json.loads(subprocess.run(['node', str(ROOT / 'tests/pseudocode_eval.js')], input=json.dumps(expanded),
        text=True, capture_output=True, check=True, timeout=60).stdout)
    for raw, simplified in zip(results[::2], results[1::2]):
        assert raw == simplified, 'simplified effects disagree with original operations'
    return results[::2]


def compare(actual, expected, label):
    assert actual['registers'] == expected['registers'], label + ': registers ' + repr([(k, v, expected['registers'][k]) for k, v in actual['registers'].items() if v != expected['registers'][k]])
    assert actual['memory'] == expected['memory'], label + ': memory writes'
    for k, v in actual['flags'].items():
        if v is not None: assert v == expected['flags'][k], label + ': defined flag ' + k


def pe_segments(path):
    data = path.read_bytes()
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    nsec, optsize = struct.unpack_from('<H', data, pe + 6)[0], struct.unpack_from('<H', data, pe + 20)[0]
    opt = pe + 24
    is64 = struct.unpack_from('<H', data, opt)[0] == 0x20b
    base = struct.unpack_from('<Q' if is64 else '<I', data, opt + (24 if is64 else 28))[0]
    segments = []
    for i in range(nsec):
        vsize, rva, rawsize, raw = struct.unpack_from('<IIII', data, opt + optsize + i * 40 + 8)
        segments.append((base + rva, data[raw:raw + rawsize] + bytes(max(0, vsize - rawsize))))
    return base, segments


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('analyzer', type=Path)
    p.add_argument('--fixtures', required=True, type=Path)
    args = p.parse_args()
    count = 0
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        probe = report(args.analyzer, root, '90c3')
        if not probe['module']['decoderInfo']['capabilities']['structuredOperands']:
            print('SKIP: LLVM has no structured operands; unavailable contract is tested separately')
            return
        # Aliases, extensions, addresses, flags, overflow, signed multiply,
        # masked counts, zero-count shifts, stack and conditional writes.
        common = ['89c8', '88e0', '88c4', '66b8ffff', 'b878563412', '0fb6c0', '0fbec0', '0fbfc1',
                  '8d448bf0', '8b448bf0', '89448bf0', '8303ff', '01c8', '83e801', '29c8', '21c8',
                  '09c8', '31c8', '39c8', '85c0', 'ffc0', 'ffc8', 'f7d8', 'f7d0', '0fafc1', '6bc0fd',
                  'c1e002', 'd3e0', 'd3e8', 'd3f8', 'c0e020', 'c0f81f', '0f94c0', '0f9fc4',
                  '0f44c1', '50', '58', '6aff', '90', '662e0f1f840000000000']
        extra64 = ['48b8ffffffffffffffff', '4801c8', '4883e8ff', '488b448bf0', '488d448bf0',
                   '488d05f9ffffff', '678d448bf0', '4863c1', '4898', '4d89c8', '41b8ffffffff',
                   '48d3e0', '48d3e8', '48d3f8', '480fafc1', '480f44c1']
        for bits in (32, 64):
            cases = common + (extra64 if bits == 64 else [])
            reports = [report(args.analyzer, root, code + 'c3', bits) for code in cases]
            lifted = models(reports, recover=False)
            flows = models(reports)
            requests, expected, labels = [], [], []
            for code, model, flow in zip(cases, lifted, flows):
                assert model['status'] == 'supported', (bits, code, model)
                for edge in range(6):
                    state = initial(bits)
                    ax, cx = ('rax', 'rcx') if bits == 64 else ('eax', 'ecx')
                    state['registers'][ax] = str([0, (1 << bits) - 1, 0x7fffffff, 0x80000000, 0x100000000 & ((1 << bits) - 1), RNG.getrandbits(bits)][edge])
                    if code in ['d3e0', 'd3e8', 'd3f8', '48d3e0', '48d3e8', '48d3f8']:
                        state['registers'][cx] = str([0, 1, 31, 32, 63, 64][edge])
                    start = (0x140000000 if bits == 64 else 0x400000) + 0x1000
                    requests.append({'model': model, 'input': state})
                    expected.append(oracle(bits, [(start, bytes.fromhex(code))], start, state, single=True, model=flow))
                    labels.append(f'{bits}-bit {code} edge {edge}')
            for actual, want, label in zip(evaluate(requests), expected, labels):
                compare(actual, want, label); count += 1
        # Compare transformed CFG execution, including flags changed after CMP.
        for code in ['83f9007e07b801000000eb05b802000000c3', 'b90300000031c001c8ffc975fac3',
                     '83f900ffc07507b801000000eb05b802000000c3',
                     '83f9007407b4010fb6d0eb03b40290c3',  # byte definitions join whole families
                     '83c00183f8037cf8c3']:  # actual entry backedge and initial incoming definition
            data = report(args.analyzer, root, code)
            model = models([data])[0]
            for ecx in (0, 1, 0xffffffff):
                state = initial(64); state['registers']['rcx'] = str(ecx)
                state['registers']['rax'] = str(0xffffffff if ecx else 0)
                start = int(data['module']['imageBase'], 16) + 0x1000
                actual = evaluate([{'model': model, 'input': state}])[0]
                compare(actual, oracle(64, [(start, bytes.fromhex(code))], start, state, model=model), 'structured authored CFG')
                count += 1
        # Multi-instruction expression chains exercise actual substitutions,
        # stale dependencies, partial registers, sign extension and masked shifts.
        chains = ['89c8 83c005 89c2', '89c8 83c101 89c2', '89c8 b101 89c2',
                  'b8ffffffff 83c002 89c2', 'b880000000 0fbec0 89c2',
                  'b834120000 0fb6d4 b456 89c3', '31c0 89c2', '29c0 89c2',
                  '89c8 83e000 89c2', '89c8 6bc001 89c2', '89c8 c1e020 89c2',
                  '89d0 d3e8 89c3', '89d0 d3f8 89c3', '89d0 f7d8 89c3',
                  '89d0 f7d0 89c3', '89d0 ffc0 89c3', '89d0 ffc8 89c3',
                  'b8ffffffff 66ffc0 89c2', 'b834120000 b456 0fb6d4',
                  '89c8 83c005 894304 8b5304 89d0']
        extra_chains = ['48b8ffffffffffffffff 4883c002 4889c2',
                        'b8ffffffff 4889c2', '4889d0 48d3f8 4889c3',
                        '4889c8 4883c005 4889c2', '4889c8 b501 4889c2',
                        'b880000000 480fbec0 4889c2']
        expression_cases = 0
        for bits in (32, 64):
            for body in chains + (extra_chains if bits == 64 else []):
                code = body + ' c3'
                data = report(args.analyzer, root, code, bits); model = models([data])[0]
                assert model['registerExpressions']['status'] == 'available', model['registerExpressions']
                start = int(data['module']['imageBase'], 16) + 0x1000
                for edge, count_value in enumerate((0, 1, 31, 32, 63, 64)):
                    state = initial(bits)
                    state['registers']['rcx' if bits == 64 else 'ecx'] = str(count_value)
                    state['registers']['rdx' if bits == 64 else 'edx'] = str([0, (1 << bits) - 1, 0x80000000, 0x7fffffff, 128, 0xffff][edge])
                    actual = evaluate([{'model': model, 'input': state}])[0]
                    compare(actual, oracle(bits, [(start, bytes.fromhex(code))], start, state, model=model), 'expression chain ' + code)
                    count += 1; expression_cases += 1
        # O0/O1 source-known functions: compare every register, defined flag,
        # stack/data byte plus the independently written source-level result.
        values = [0, 1, 2, 7, 31, 63, 255, 0xffffffff]
        mask = 0xffffffff
        for path in sorted(args.fixtures.glob('recovery*-o?.json')):
            data = json.loads(path.read_text()); bits = 64 if '64' in path.name else 32
            base, segments = pe_segments(path.with_suffix('.exe'))
            for f in data['functions']:
                name = f['name']
                if name == 'pe_entry': continue
                d = dict(data, functions=[f]); model = models([d])[0]
                assert model['status'] == 'supported_subset', (path.name, name, model['stats'])
                for n in (0, 1, 4, 8, 10):
                    state = initial(bits); result = None; writes = None
                    for i, v in enumerate(values): write_word(state, DATA + i * 4, v)
                    if name == 'scalar_ops':
                        arguments = [0xfffffff0, n]; v = ((arguments[0] + n) & mask) ^ 0x35
                        result = (((v << 2) | (v >> 3)) - 7) & mask
                    elif name == 'choose_value': arguments = [0xffffffff if n % 2 else 20, n]; result = 11 if n % 2 else 29
                    elif name == 'array_read_write':
                        arguments = [DATA, n, 0xffffffff]; result = (values[n & 7] - 1) & mask; writes = {DATA + (n & 7) * 4: result}
                    elif name == 'sum_for': arguments = [DATA, min(n, 8)]; result = sum(values[:min(n, 8)]) & mask
                    elif name == 'sum_while':
                        arguments = [DATA, min(n, 8)]; result = 0
                        for v in values[:min(n, 8)]: result ^= v
                    elif name == 'transform_demo':
                        arguments = [DATA + 128, DATA, n, 30]; result = 7; writes = {}
                        for i, v in enumerate(values[:min(n, 8)]):
                            v = (v + i * 3) & mask
                            v = ((v ^ 0x55) + 9 if v > 30 else v * 5 + 1) & mask
                            for _ in range(2): v = ((v << 1) ^ (v >> 3)) & mask
                            writes[DATA + 128 + i * 4] = v; result = ((result * 33) ^ v) & mask
                    else: raise AssertionError('unexpected fixture function ' + name)
                    if bits == 64:
                        for r, v in zip(['rcx', 'rdx', 'r8', 'r9'], arguments): state['registers'][r] = str(v)
                    else:
                        for i, v in enumerate(arguments): write_word(state, STACK + 4 + i * 4, v)
                    actual = evaluate([{'model': model, 'input': state}])[0]
                    try:
                        expected = oracle(bits, segments, base + f['rva'], state, model=model)
                    except AssertionError as error:
                        raise AssertionError((path.name, name, n, str(error))) from error
                    compare(actual, expected, path.name + ' ' + name)
                    assert int(actual['registers']['rax' if bits == 64 else 'eax']) & mask == result, (path.name, name, n, 'source result')
                    for address, v in (writes or {}).items():
                        got = sum(actual['memory'][str(address + j)] << (8 * j) for j in range(4))
                        assert got == v, (path.name, name, n, 'source memory')
                    count += 1
    print(f'PASS: {count} independent instruction/structured-CFG/source cases (registers, defined flags, memory)')
    print(f'PASS: simplified/original evaluation parity for all cases, including {expression_cases} new expression-chain executions')
    assert VALUE_CHECKS['states'] > 0 and VALUE_CHECKS['aliases'] > 0
    print('PASS: abstract facts at %d executed instruction states; %d concrete stack-alias addresses' %
          (VALUE_CHECKS['states'], VALUE_CHECKS['aliases']))
    assert all(SSA_CHECKS.values())
    print('PASS: register SSA at {states} states, {uses} uses, {joins} selected PHI edges and {exits} exit values'.format(**SSA_CHECKS))


if __name__ == '__main__':
    main()
