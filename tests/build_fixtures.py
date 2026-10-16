#!/usr/bin/env python3
"""Generate source-known x86/x64 EXE/DLL fixtures; never run the PE files.

All compiler/linker output and optional reports go below --output. Ground-truth
function/data labels come from this build's linker map, not hard-coded RVAs.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess

SOURCES = Path(__file__).resolve().parent / 'fixtures'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--clang', default=shutil.which('clang'))
    parser.add_argument('--linker', default=shutil.which('lld-link'))
    parser.add_argument('--analyzer', type=Path)
    args = parser.parse_args()
    if not args.clang or not args.linker:
        parser.error('clang and lld-link are required; pass their paths explicitly.')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    def run(*command):
        subprocess.run([str(x) for x in command], cwd=output, check=True)

    for bits, target, machine, base in (
        (64, 'x86_64-pc-windows-msvc', 'x64', 0x140000000),
        (32, 'i686-pc-windows-msvc', 'x86', 0x400000),
    ):
        for source in ('application', 'library'):
            run(args.clang, '-target', target, '-O1', '-fno-inline',
                '-fno-optimize-sibling-calls', '-fno-vectorize',
                '-fno-slp-vectorize', '-fno-stack-protector', '-fno-builtin',
                '-c', SOURCES / (source + '.c'), '-o', f'{source}{bits}.obj')
        run(args.linker, '/dll', '/noentry', '/nodefaultlib', '/timestamp:0',
            '/machine:' + machine, '/out:' + f'demo_math{bits}.dll',
            '/implib:' + f'demo_math{bits}.lib', f'library{bits}.obj')
        run(args.linker, '/subsystem:console', '/nodefaultlib', '/timestamp:0',
            '/entry:entry_point', '/machine:' + machine, '/base:' + hex(base),
            '/map:' + f'demo{bits}.map', '/out:' + f'demo{bits}.exe',
            f'application{bits}.obj', f'demo_math{bits}.lib')
        symbols = {}
        for line in (output / f'demo{bits}.map').read_text().splitlines():
            match = re.match(r'\s*[0-9a-fA-F]+:[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]{8,16})\s', line)
            if match:
                name = match[1].lstrip('_')
                if name in ('main', 'entry_point', 'checksum_bytes', 'main.payload', 'last_result'):
                    symbols[name] = int(match[2], 16) - base
        required = {'main', 'entry_point', 'checksum_bytes', 'main.payload', 'last_result'}
        if not required.issubset(symbols):
            raise RuntimeError(f'Incomplete linker-map ground truth: {symbols}')
        (output / f'demo{bits}.symbols.json').write_text(json.dumps(symbols, indent=2) + '\n')
        if args.analyzer:
            run(args.analyzer.resolve(), f'demo{bits}.exe',
                '--main-rva', hex(symbols['main']),
                '--name', hex(symbols['checksum_bytes']) + '=checksum_bytes',
                '--data-name', hex(symbols['main.payload']) + '=demo_payload',
                '--data-name', hex(symbols['last_result']) + '=last_result',
                '--json', f'demo{bits}.json', '--html', f'demo{bits}.html')
            run(args.analyzer.resolve(), f'demo_math{bits}.dll',
                '--json', f'dll{bits}.json', '--html', f'dll{bits}.html')
        print(f'Built {bits}-bit fixtures in {output}. Ground truth: {symbols}')


if __name__ == '__main__':
    main()
