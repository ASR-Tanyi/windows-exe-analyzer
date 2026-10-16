#!/usr/bin/env python3
"""Generate source-known x86/x64 EXE/DLL fixtures; never run the PE files.

All compiler/linker output and optional reports go below --output. Ground-truth
function/data labels come from this build's linker map, not hard-coded RVAs.
"""
import argparse
import hashlib
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

    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    # Evaluation metadata stays outside the analyzer's inputs. These two tools
    # create the fixtures; no generated EXE/DLL is ever executed here.
    def version(tool):
        return subprocess.run([str(tool), '--version'], check=True,
                              capture_output=True, text=True, timeout=10).stdout.strip()

    corpus = {'schema': 1, 'generator': 'tests/build_fixtures.py',
              'generatorSha256': digest(Path(__file__)),
              'toolchain': {'compiler': version(args.clang), 'linker': version(args.linker)},
              'sources': [{'path': 'tests/fixtures/' + path.name, 'sha256': digest(path)}
                          for path in sorted(SOURCES.glob('*.c'))],
              'fixtures': []}
    commands = []

    def run(*command):
        subprocess.run([str(x) for x in command], cwd=output, check=True)
        # Do not record machine-specific absolute source/tool paths.
        commands.append([Path(str(command[0])).name] +
                        [str(x).replace(str(SOURCES), 'tests/fixtures') for x in command[1:]])

    for bits, target, machine, base in (
        (64, 'x86_64-pc-windows-msvc', 'x64', 0x140000000),
        (32, 'i686-pc-windows-msvc', 'x86', 0x400000),
    ):
        commands.clear()
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
        corpus['fixtures'].append({
            'architecture': machine, 'target': target, 'commands': list(commands),
            'inputs': [{'path': name, 'sha256': digest(output / name)} for name in
                       (f'demo{bits}.exe', f'demo_math{bits}.dll')],
            'oracle': {'kind': 'linker_map_and_source',
                       'map': f'demo{bits}.map', 'mapSha256': digest(output / f'demo{bits}.map'),
                       'functionEntries': {key: symbols[key] for key in
                                           ('entry_point', 'main', 'checksum_bytes')},
                       'import': f'demo_math{bits}.dll!transform_score',
                       'export': 'transform_score'},
        })
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

    (output / 'corpus.json').write_text(json.dumps(corpus, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
