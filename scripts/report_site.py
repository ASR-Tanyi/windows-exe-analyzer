#!/usr/bin/env python3
"""Build a static report site. Never execute an input EXE/DLL.

All inputs must be suitable for public disclosure: reports embed binary bytes.
Custom inputs are analyzed in a restricted Docker container in GitHub Actions.
Only the Python standard library is needed by this script.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_INPUT = 64 * 1024 * 1024
MAX_API = 2 * 1024 * 1024
DEMO_REPORTS = (
    ('demo64', 'demo64.exe', 'x64 demo EXE'),
    ('demo32', 'demo32.exe', 'x86 demo EXE'),
    ('dll64', 'demo_math64.dll', 'x64 demo DLL'),
    ('dll32', 'demo_math32.dll', 'x86 demo DLL'),
)


def public_https(url: str) -> str:
    """Reject credentials, non-HTTPS endpoints and non-public resolved addresses."""
    if any(ord(c) < 33 or ord(c) == 127 for c in url) or len(url) > 8192:
        raise ValueError('Invalid download URL.')
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.port not in (None, 443)
            or parsed.fragment):
        raise ValueError('Use a public HTTPS URL without credentials, fragment or custom port.')
    addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
        raise ValueError('Download host must resolve only to public IP addresses.')
    return url


class PublicRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        public_https(newurl)
        # No credentials are used by this downloader, including release downloads.
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, destination: Path, limit: int = MAX_INPUT) -> None:
    """Bounded, credential-free download; partial files are never accepted."""
    public_https(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), PublicRedirect())
    request = urllib.request.Request(url, headers={'User-Agent': 'windows-exe-analyzer-report'})
    partial = destination.with_suffix(destination.suffix + '.part')
    deadline = time.monotonic() + 180
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with opener.open(request, timeout=30) as response, partial.open('wb') as output:
            declared = int(response.headers.get('Content-Length', '0'))
            if declared > limit:
                raise ValueError('Download exceeds the size limit.')
            size = 0
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit or time.monotonic() > deadline:
                    raise ValueError('Download exceeded its size or time limit.')
                output.write(chunk)
            if not size or (declared and size != declared):
                raise ValueError('Downloaded file is empty or incomplete.')
        partial.replace(destination)
    except (OSError, urllib.error.URLError, ValueError) as exc:
        partial.unlink(missing_ok=True)
        # Do not echo URLs: their query strings might contain credentials.
        raise ValueError('Download failed: use a public HTTPS file within the size limit.') from exc


def github_repo(value: str) -> str:
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value):
        raise ValueError('Repository must be owner/name.')
    return value


def select_url(source: str, target: str, repository: str, release_tag: str,
               file_ref: str, work: Path) -> tuple[str, str]:
    if source == 'url':
        return target, Path(urllib.parse.unquote(urllib.parse.urlsplit(target).path)).name or 'input.exe'
    repository = github_repo(repository)
    if source == 'repository':
        path = PurePosixPath(target)
        if (not target or path.is_absolute() or '\\' in target or '..' in path.parts
                or any(p.startswith('.') for p in path.parts) or not file_ref):
            raise ValueError('Use a repository-relative file path without hidden or parent segments.')
        ref = urllib.parse.quote(file_ref, safe='')
        name = urllib.parse.quote(path.as_posix(), safe='/')
        return f'https://raw.githubusercontent.com/{repository}/{ref}/{name}', path.name
    if source == 'release':
        endpoint = ('latest' if release_tag == 'latest'
                    else 'tags/' + urllib.parse.quote(release_tag, safe=''))
        metadata = work / 'release.json'
        download(f'https://api.github.com/repos/{repository}/releases/{endpoint}', metadata, MAX_API)
        release = json.loads(metadata.read_text(encoding='utf-8'))
        assets = [a for a in release.get('assets', [])
                  if isinstance(a.get('name'), str) and a['name'].lower().endswith(('.exe', '.dll'))]
        matches = [a for a in assets if a['name'] == target] if target else assets
        if len(matches) != 1:
            raise ValueError('Select one exact .exe/.dll asset name; blank requires exactly one matching asset.')
        asset = matches[0]
        if int(asset.get('size', 0)) > MAX_INPUT:
            raise ValueError('Release asset exceeds 64 MiB.')
        url = asset['browser_download_url']
        if urllib.parse.urlsplit(url).hostname != 'github.com':
            raise ValueError('Unexpected release asset host.')
        return url, asset['name']
    raise ValueError('Unsupported input source.')


def verify_pe(path: Path, expected: str = '') -> str:
    """Reject non-PE and wrong-architecture downloads before invoking the parser."""
    size = path.stat().st_size
    if size < 64 or size > MAX_INPUT:
        raise ValueError('Input must be a native PE file between 64 bytes and 64 MiB.')
    with path.open('rb') as stream:
        dos = stream.read(64)
        offset = struct.unpack_from('<I', dos, 0x3c)[0]
        if dos[:2] != b'MZ' or offset < 64 or offset + 26 > size:
            raise ValueError('Not a valid PE header location.')
        stream.seek(offset)
        pe = stream.read(26)
        machine = struct.unpack_from('<H', pe, 4)[0]
        magic = struct.unpack_from('<H', pe, 24)[0]
        if pe[:4] != b'PE\0\0' or (machine, magic) not in ((0x14c, 0x10b), (0x8664, 0x20b)):
            raise ValueError('Only native x86 PE32 and x64 PE32+ inputs are supported.')
        stream.seek(0)
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if expected and digest != expected.lower():
        raise ValueError('SHA-256 mismatch; no report was generated for this input.')
    return digest


def analyzer_command(analyzer: Path, source: Path, output: Path,
                     image: str, cidfile: Path) -> list[str]:
    flags = ['--html', 'sample.html', '--json', 'sample.json',
             '--limit', '100000', '--data-limit', '4194304']
    if not image:
        return [str(analyzer.resolve()), str(source.resolve()), *flags]
    return ['docker', 'run', '--rm', '--cidfile', str(cidfile),
            '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--pids-limit', '64',
            '--memory', '1g', '--cpus', '2', '--user', f'{os.getuid()}:{os.getgid()}',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
            '--mount', f'type=bind,src={source.parent.resolve()},dst=/input,readonly',
            '--mount', f'type=bind,src={output.resolve()},dst=/output',
            '--workdir', '/output', image, '/input/' + source.name, *flags]


def analyze_sample(analyzer: Path, source: Path, output: Path, image: str) -> None:
    output.mkdir(parents=True, exist_ok=True)
    cidfile = output.parent / 'container.cid'
    # Never pass CI credentials to the analyzer or its container.
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'LANG', 'SYSTEMROOT') if k in os.environ}
    command = analyzer_command(analyzer, source, output, image, cidfile)
    try:
        with (output.parent / 'analysis.log').open('wb') as log:
            result = subprocess.run(command, cwd=output, env=env, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=120, check=False)
        if result.returncode:
            raise ValueError('Analyzer rejected the input or could not decode reachable code.')
    except subprocess.TimeoutExpired as exc:
        raise ValueError('Analysis exceeded its 120-second limit.') from exc
    finally:
        # Killing only the Docker client does not necessarily stop its container.
        if image and cidfile.exists():
            cid = cidfile.read_text().strip()
            if re.fullmatch(r'[0-9a-f]{64}', cid):
                subprocess.run(['docker', 'rm', '-f', cid], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=30, check=False)
            cidfile.unlink(missing_ok=True)
    for name in ('sample.html', 'sample.json'):
        path = output / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError('Invalid or oversized analyzer output.')


def report_entry(directory: Path, stem: str, title: str, digest: str) -> dict:
    data = json.loads((directory / (stem + '.json')).read_text(encoding='utf-8'))
    entry = {'title': title, 'html': stem + '.html', 'json': stem + '.json',
            'sha256': digest, 'architecture': data['module']['architecture'],
            'instructions': data['module']['instructionCount'],
            'partial': bool(data['module'].get('truncated') or data.get('data', {}).get('truncated'))}
    if stem.startswith('recovery'):
        demo = next((f for f in data.get('functions', []) if f.get('name') == 'transform_demo'), None)
        if demo and isinstance(demo.get('rva'), int) and isinstance(data['module'].get('id'), str):
            entry['pseudocode'] = stem + '.html#' + data['module']['id'] + '_c_' + format(demo['rva'], 'x')
    return entry


def write_index(output: Path, entries: list[dict], source: str) -> None:
    escape = lambda value: html.escape(str(value), quote=True)
    commit = os.environ.get('GITHUB_SHA', 'local build')
    run = os.environ.get('GITHUB_RUN_ID', 'local')
    manifest = {'source': source, 'commit': commit, 'run_id': run, 'reports': entries}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    cards = []
    for entry in entries:
        cards.append('<article><h2>' + escape(entry['title']) + '</h2><p>'
                     + escape(entry['architecture']) + ' &middot; '
                     + escape(entry['instructions']) + ' instructions'
                     + (' &middot; partial report' if entry['partial'] else '')
                     + '</p><a class="button" href="' + escape(entry['html']) + '">Open report</a> '
                     + '<a href="' + escape(entry['json']) + '" download>JSON</a>'
                     + ('<p><a href="' + escape(entry['pseudocode']) + '">C-like demo</a> &middot; <a href="recovery.c">C source</a></p>' if entry.get('pseudocode') else '')
                     + '<p class="hash">Input SHA-256<br>' + escape(entry['sha256']) + '</p></article>')
    page = '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>windows-exe-analyzer | Reports</title><style>
body{font:16px/1.6 system-ui,sans-serif;margin:0;background:#0b1423;color:#e2eaf5}
main{max-width:1050px;margin:auto;padding:40px 24px}h1{font-size:32px;margin:8px 0}
h2{font-size:20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px}
article{background:#122136;border:1px solid #31445f;border-radius:12px;padding:24px}
a{color:#90c6ff}.button{display:inline-block;padding:8px 16px;background:#214637;border-radius:6px;
color:#c5ffe1;text-decoration:none;margin-right:14px}.hash{font:12px/1.8 monospace;overflow-wrap:anywhere;
color:#adbed3}.notice{border-left:3px solid #d7b174;padding:10px 16px;margin:24px 0;background:#25271f}
footer{margin-top:28px;color:#adbed3;font-size:13px;overflow-wrap:anywhere}
</style><main><p>STATIC ANALYSIS / OFFLINE REPORTS</p><h1>windows-exe-analyzer</h1>
<p>Follow assembly, calls and jumps, then click memory operands to inspect static data.</p>
<div class="notice"><b>Public reports contain original file bytes and strings.</b>
Never submit confidential executables. Input code is not executed. The latest successful
Pages deployment replaces this site; older reports remain in their workflow artifacts
until those artifacts expire.</div><div class="grid">'''
    page += ''.join(cards) + '</div><footer>Source: ' + escape(source)
    page += ' &middot; Commit: ' + escape(commit) + ' &middot; Run: ' + escape(run)
    page += '<p><a href="manifest.json">Build manifest</a></p></footer></main></html>\n'
    (output / 'index.html').write_text(page, encoding='utf-8')
    (output / '.nojekyll').touch()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analyzer', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--recovery-fixtures', type=Path,
                        help='Optional source-known C recovery reports at O0/O1')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source', choices=('demo', 'release', 'url', 'repository'), default='demo')
    parser.add_argument('--target', default='')
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY', ''))
    parser.add_argument('--release-tag', default='latest')
    parser.add_argument('--file-ref', default='main')
    parser.add_argument('--sha256', default='')
    parser.add_argument('--sandbox-image', default='')
    args = parser.parse_args()
    if args.sha256 and not re.fullmatch(r'[0-9a-fA-F]{64}', args.sha256):
        parser.error('--sha256 must be exactly 64 hexadecimal characters.')
    if args.source == 'demo' and (args.target or args.sha256):
        parser.error('target and sha256 are only applicable to custom inputs.')
    if args.source in ('url', 'repository') and not args.target:
        parser.error('This input source requires target.')
    output = args.output.resolve()
    # Refuse to overwrite a checkout, another report site, or an input directory.
    if output.exists() and any(output.iterdir()):
        parser.error('The site output directory must be empty or absent.')
    output.mkdir(parents=True, exist_ok=True)
    entries = []
    for stem, binary, title in DEMO_REPORTS:
        for suffix in ('.html', '.json'):
            shutil.copyfile(args.fixtures / (stem + suffix), output / (stem + suffix))
        entries.append(report_entry(output, stem, title, verify_pe(args.fixtures / binary)))
    if args.recovery_fixtures:
        for bits in (64, 32):
            for opt in ('o0', 'o1'):
                stem = f'recovery{bits}-{opt}'
                for suffix in ('.html', '.json'):
                    shutil.copyfile(args.recovery_fixtures / (stem + suffix), output / (stem + suffix))
                entries.append(report_entry(output, stem, f'C recovery x{bits} / {opt.upper()}',
                                            verify_pe(args.recovery_fixtures / (stem + '.exe'))))
        shutil.copyfile(args.recovery_fixtures / 'recovery-corpus.json', output / 'recovery-corpus.json')
        shutil.copyfile(Path(__file__).resolve().parents[1] / 'tests/fixtures/recovery.c', output / 'recovery.c')
    if args.source != 'demo':
        with tempfile.TemporaryDirectory(prefix='wea-report-') as temp:
            work = Path(temp)
            url, original_name = select_url(args.source, args.target, args.repository,
                                           args.release_tag, args.file_ref, work)
            if not original_name.lower().endswith(('.exe', '.dll')):
                raise ValueError('Select a direct .exe/.dll file, not an archive or a web page.')
            source = work / 'input' / ('input' + Path(original_name).suffix.lower())
            download(url, source)
            digest = verify_pe(source, args.sha256)
            reports = work / 'reports'
            analyze_sample(args.analyzer, source, reports, args.sandbox_image)
            for suffix in ('.html', '.json'):
                shutil.copyfile(reports / ('sample' + suffix), output / ('sample' + suffix))
            entries.insert(0, report_entry(output, 'sample', original_name, digest))
    write_index(output, entries, args.source)
    print(f'Generated {len(entries)} reports; open index.html after extraction or Pages deployment.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        raise SystemExit(f'Report generation failed: {error}') from None
