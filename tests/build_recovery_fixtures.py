#!/usr/bin/env python3
"""Compile the C recovery ladder at O0/O1 for x86/x64; never run the PEs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--clang', default=shutil.which('clang'))
    p.add_argument('--linker', default=shutil.which('lld-link'))
    p.add_argument('--zig', help='Optional local Zig executable in place of clang/lld-link')
    p.add_argument('--analyzer', required=True, type=Path)
    a = p.parse_args()
    if not a.zig and not (a.clang and a.linker):
        p.error('clang/lld-link or --zig is required')
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).resolve().parent / 'fixtures/recovery.c'
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    compiler = [a.zig, 'cc'] if a.zig else [a.clang]
    corpus = {'schema': 1, 'source': 'tests/fixtures/recovery.c', 'sourceSha256': digest(source),
              'toolchain': subprocess.run(compiler + ['--version'], check=True, capture_output=True, text=True).stdout.strip(),
              'fixtures': []}
    for bits, arch in ((64, 'x86_64'), (32, 'i686')):
        for opt in ('O0', 'O1'):
            stem = f'recovery{bits}-{opt.lower()}'
            obj, exe = out / (stem + '.obj'), out / (stem + '.exe')
            target_arch = 'x86' if a.zig and bits == 32 else arch
            commands = [compiler + ['-target', target_arch + '-windows-msvc', '-' + opt, '-fno-inline',
                '-fno-optimize-sibling-calls', '-fno-vectorize', '-fno-slp-vectorize',
                '-fno-unroll-loops', '-fno-stack-protector', '-fno-sanitize=all', '-fno-builtin', '-c', str(source), '-o', str(obj)]]
            if a.zig:
                commands.append([a.zig, 'build-exe', str(obj), '-target', ('x86' if bits == 32 else arch) + '-windows-msvc',
                    '-fentry=entry_point', '--subsystem', 'console', '-femit-bin=' + str(exe)])
            else:
                commands.append([a.linker, '/subsystem:console', '/nodefaultlib', '/timestamp:0', '/entry:entry_point',
                    '/machine:' + ('x64' if bits == 64 else 'x86'), '/out:' + str(exe), str(obj)])
            for command in commands:
                subprocess.run(command, check=True, timeout=120)
            # Export symbols are legitimate binary evidence; no map/source labels
            # or main-RVA hints are passed to the analyzer.
            subprocess.run([str(a.analyzer.resolve()), str(exe), '--json', str(out / (stem + '.json')),
                            '--html', str(out / (stem + '.html'))], check=True, timeout=60)
            corpus['fixtures'].append({'stem': stem, 'bits': bits, 'optimization': opt, 'sha256': digest(exe),
                'commands': [[str(x).replace(str(out), '<output>').replace(str(source), 'tests/fixtures/recovery.c')
                              for x in cmd] for cmd in commands]})
    (out / 'recovery-corpus.json').write_text(json.dumps(corpus, indent=2) + '\n')


if __name__ == '__main__':
    main()
