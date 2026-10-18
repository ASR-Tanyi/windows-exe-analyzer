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
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64
from unicorn import x86_const as uc_regs

FLAGS = {'carry': 0, 'parity': 2, 'auxiliary': 4, 'zero': 6, 'sign': 7, 'overflow': 11}
DATA, STACK, RETURN = 0x200000, 0x300800, 0x500000
RNG = random.Random(73191)


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


def oracle(bits, segments, start, state, single=False):
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
    uc.emu_start(start, start + len(segments[0][1]) if single else RETURN, timeout=2000000, count=1 if single else 100000)
    if not single:
        ip = uc.reg_read(uc_regs.UC_X86_REG_RIP if bits == 64 else uc_regs.UC_X86_REG_EIP)
        assert ip == RETURN, 'oracle did not return within budget'
    flags = uc.reg_read(uc_regs.UC_X86_REG_EFLAGS)
    return {'registers': {name: str(uc.reg_read(getattr(uc_regs, 'UC_X86_REG_' + name.upper()))) for name in state['registers']},
            'flags': {k: bool(flags & (1 << bit)) for k, bit in FLAGS.items()},
            'memory': {address: uc.mem_read(int(address), 1)[0] for address in state['memory']}}


def evaluate(requests):
    return json.loads(subprocess.run(['node', str(ROOT / 'tests/pseudocode_eval.js')], input=json.dumps(requests),
        text=True, capture_output=True, check=True, timeout=60).stdout)


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
            requests, expected, labels = [], [], []
            for code, model in zip(cases, lifted):
                assert model['status'] == 'supported', (bits, code, model)
                for edge in range(6):
                    state = initial(bits)
                    ax, cx = ('rax', 'rcx') if bits == 64 else ('eax', 'ecx')
                    state['registers'][ax] = str([0, (1 << bits) - 1, 0x7fffffff, 0x80000000, 0x100000000 & ((1 << bits) - 1), RNG.getrandbits(bits)][edge])
                    if code in ['d3e0', 'd3e8', 'd3f8', '48d3e0', '48d3e8', '48d3f8']:
                        state['registers'][cx] = str([0, 1, 31, 32, 63, 64][edge])
                    start = (0x140000000 if bits == 64 else 0x400000) + 0x1000
                    requests.append({'model': model, 'input': state})
                    expected.append(oracle(bits, [(start, bytes.fromhex(code))], start, state, single=True))
                    labels.append(f'{bits}-bit {code} edge {edge}')
            for actual, want, label in zip(evaluate(requests), expected, labels):
                compare(actual, want, label); count += 1
        # Compare transformed CFG execution, including flags changed after CMP.
        for code in ['83f9007e07b801000000eb05b802000000c3', 'b90300000031c001c8ffc975fac3',
                     '83f900ffc07507b801000000eb05b802000000c3']:
            data = report(args.analyzer, root, code)
            model = models([data])[0]
            for ecx in (0, 1, 0xffffffff):
                state = initial(64); state['registers']['rcx'] = str(ecx)
                state['registers']['rax'] = str(0xffffffff if ecx else 0)
                start = int(data['module']['imageBase'], 16) + 0x1000
                actual = evaluate([{'model': model, 'input': state}])[0]
                compare(actual, oracle(64, [(start, bytes.fromhex(code))], start, state), 'structured authored CFG')
                count += 1
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
                    compare(actual, oracle(bits, segments, base + f['rva'], state), path.name + ' ' + name)
                    assert int(actual['registers']['rax' if bits == 64 else 'eax']) & mask == result, (path.name, name, n, 'source result')
                    for address, v in (writes or {}).items():
                        got = sum(actual['memory'][str(address + j)] << (8 * j) for j in range(4))
                        assert got == v, (path.name, name, n, 'source memory')
                    count += 1
    print(f'PASS: {count} independent instruction/structured-CFG/source cases (registers, defined flags, memory)')


if __name__ == '__main__':
    main()
