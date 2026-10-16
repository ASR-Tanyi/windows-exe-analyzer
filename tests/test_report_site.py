"""Report automation tests: offline, no external URLs or Docker daemon required."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('report_site', Path(__file__).resolve().parents[1] / 'scripts/report_site.py')
site = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(site)


def pe_bytes(bits=64):
    value = bytearray(512)
    value[:2] = b'MZ'
    struct.pack_into('<I', value, 0x3c, 0x80)
    value[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', value, 0x84, 0x8664 if bits == 64 else 0x14c)
    struct.pack_into('<H', value, 0x98, 0x20b if bits == 64 else 0x10b)
    return value


class ReportSiteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_pe_architectures_and_hash(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                path = self.root / 'input.exe'
                path.write_bytes(pe_bytes(bits))
                expected = hashlib.sha256(path.read_bytes()).hexdigest()
                self.assertEqual(site.verify_pe(path, expected.upper()), expected)

    def test_invalid_pe_and_checksum(self):
        path = self.root / 'input.exe'
        for data in (b'', b'MZ', b'X' * 512):
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                site.verify_pe(path)
        for field, value in ((0x84, 0xaa64), (0x98, 0x10b)):
            data = pe_bytes()
            struct.pack_into('<H', data, field, value)
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                site.verify_pe(path)
        path.write_bytes(pe_bytes())
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            site.verify_pe(path, '0' * 64)

    def test_pe_bad_offset(self):
        path = self.root / 'input.exe'
        for offset in (0, 1, 0xffffffff):
            data = pe_bytes()
            struct.pack_into('<I', data, 0x3c, offset)
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                site.verify_pe(path)

    def test_https_validation(self):
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))]
        with patch.object(site.socket, 'getaddrinfo', return_value=public):
            self.assertEqual(site.public_https('https://example.org/a.exe'), 'https://example.org/a.exe')
            for url in ('http://example.org/a', 'file:///tmp/a', 'https://u:p@example.org/a',
                        'https://example.org:8443/a', 'https://example.org/a#b',
                        'https://example.org/\na', 'https://example.org/a b'):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    site.public_https(url)

    def test_private_ips_and_redirects(self):
        for ip in ('127.0.0.1', '10.0.0.1', '169.254.169.254', '::1'):
            answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443))]
            with patch.object(site.socket, 'getaddrinfo', return_value=answer):
                with self.assertRaises(ValueError):
                    site.public_https('https://example.org/a.exe')
        handler = site.PublicRedirect()
        req = site.urllib.request.Request('https://example.org/a.exe')
        with self.assertRaises(ValueError):
            handler.redirect_request(req, None, 302, '', {}, 'file:///etc/passwd')

    def test_download_limit_and_partial_cleanup(self):
        class Response(io.BytesIO):
            headers = {}
        opener = unittest.mock.Mock()
        opener.open.return_value = Response(b'12345')
        dest = self.root / 'input.exe'
        with patch.object(site, 'public_https'), patch.object(site.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaises(ValueError):
                site.download('https://example.org/x.exe', dest, 4)
        self.assertFalse(dest.exists())
        self.assertFalse(dest.with_suffix('.exe.part').exists())

    def test_repository_path(self):
        url, name = site.select_url('repository', 'samples/a file.exe', 'owner/repo', 'latest', 'demo_exe', self.root)
        self.assertEqual(name, 'a file.exe')
        self.assertIn('/demo_exe/samples/a%20file.exe', url)
        for name in ('../a.exe', '/a.exe', '.git/config', 'a/../b.exe', 'a\\b.exe'):
            with self.assertRaises(ValueError):
                site.select_url('repository', name, 'owner/repo', '', 'main', self.root)
        with self.assertRaises(ValueError):
            site.github_repo('owner/repo/../../other')

    def test_release_selection(self):
        assets = [{'name': 'a.exe', 'browser_download_url': 'https://github.com/o/r/a.exe', 'size': 100},
                  {'name': 'b.dll', 'browser_download_url': 'https://github.com/o/r/b.dll', 'size': 100},
                  {'name': 'source.zip', 'browser_download_url': 'https://github.com/o/r/source.zip'}]
        def download(url, target, limit):
            self.assertTrue(url.endswith('/releases/tags/v1.0'))
            target.write_text(json.dumps({'assets': assets}))
        with patch.object(site, 'download', side_effect=download):
            self.assertEqual(site.select_url('release', 'a.exe', 'o/r', 'v1.0', '', self.root)[1], 'a.exe')
            for name in ('', 'no.exe', 'source.zip'):
                with self.assertRaises(ValueError):
                    site.select_url('release', name, 'o/r', 'v1.0', '', self.root)

    def test_docker_restrictions_and_no_shell(self):
        command = site.analyzer_command(self.root/'analyzer', self.root/'input'/'x.exe',
                                        self.root/'reports', 'wea:test', self.root/'cid')
        for option in ('--read-only', '--cap-drop', '--network', '--pids-limit', '--memory', '--user'):
            self.assertIn(option, command)
        self.assertEqual(command[command.index('--network') + 1], 'none')
        self.assertNotIn('-e', command)
        self.assertNotIn('--privileged', command)
        self.assertIn('/input/x.exe', command)
        self.assertNotIn('sh', command)

    def test_timeout_removes_container(self):
        source = self.root/'input'/'input.exe'
        source.parent.mkdir()
        source.write_bytes(pe_bytes())
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            if command[:2] == ['docker', 'run']:
                Path(command[command.index('--cidfile') + 1]).write_text('a' * 64)
                raise subprocess.TimeoutExpired(command, 120)
            return subprocess.CompletedProcess(command, 0)
        with patch.object(site.subprocess, 'run', side_effect=run):
            with self.assertRaisesRegex(ValueError, '120-second'):
                site.analyze_sample(self.root/'analyzer', source, self.root/'reports', 'wea:test')
        self.assertEqual(calls[-1], ['docker', 'rm', '-f', 'a' * 64])

    def test_index_escaping_and_metadata(self):
        entry = {'title': '<script>alert(1)</script>', 'html': 'sample.html', 'json': 'sample.json',
                 'sha256': 'a'*64, 'architecture': 'x64', 'instructions': 17, 'partial': True}
        with patch.dict(os.environ, {'GITHUB_SHA': 'b'*40, 'GITHUB_RUN_ID': '1234'}):
            site.write_index(self.root, [entry], 'url')
        text = (self.root/'index.html').read_text()
        self.assertNotIn('<script>', text)
        self.assertIn('&lt;script&gt;', text)
        self.assertIn('href="sample.html"', text)
        self.assertIn('partial report', text)
        self.assertEqual(json.loads((self.root/'manifest.json').read_text())['run_id'], '1234')

    def make_demo_reports(self):
        fixtures = self.root/'fixtures'
        fixtures.mkdir()
        for stem, binary, _ in site.DEMO_REPORTS:
            (fixtures/binary).write_bytes(pe_bytes(32 if '32' in stem else 64))
            (fixtures/(stem+'.html')).write_text('<!doctype html><p>Test report</p>')
            (fixtures/(stem+'.json')).write_text(json.dumps({'module': {'architecture': 'x64', 'instructionCount': 1}}))
        return fixtures

    def test_demo_site_does_not_publish_executables(self):
        fixtures = self.make_demo_reports()
        output = self.root/'site'
        argv = ['report_site.py', '--analyzer', 'unused', '--fixtures', str(fixtures), '--output', str(output)]
        with patch.object(sys, 'argv', argv), contextlib.redirect_stdout(io.StringIO()):
            site.main()
        self.assertEqual(len(json.loads((output/'manifest.json').read_text())['reports']), 4)
        self.assertFalse(list(output.glob('*.exe')))
        self.assertFalse(list(output.glob('*.dll')))
        with patch.object(sys, 'argv', argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            site.main()

    def test_custom_input_keeps_demos(self):
        fixtures = self.make_demo_reports()
        output = self.root/'site'
        data = pe_bytes()
        argv = ['report_site.py', '--analyzer', 'unused', '--fixtures', str(fixtures), '--output', str(output),
                '--source', 'url', '--target', 'https://example.org/custom.exe',
                '--sha256', hashlib.sha256(data).hexdigest()]
        def fake_download(url, path):
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
        def fake_analysis(analyzer, source, out, image):
            out.mkdir()
            shutil = site.shutil
            shutil.copyfile(fixtures/'demo64.html', out/'sample.html')
            shutil.copyfile(fixtures/'demo64.json', out/'sample.json')
        with patch.object(sys, 'argv', argv), patch.object(site, 'download', side_effect=fake_download), \
                patch.object(site, 'analyze_sample', side_effect=fake_analysis), contextlib.redirect_stdout(io.StringIO()):
            site.main()
        manifest = json.loads((output/'manifest.json').read_text())
        self.assertEqual(len(manifest['reports']), 5)
        self.assertEqual(manifest['reports'][0]['title'], 'custom.exe')
        self.assertNotIn('https://example.org', (output/'index.html').read_text())
        self.assertTrue((output/'demo64.html').exists())

    def test_cli_rejects_bad_checksum_before_download(self):
        argv = ['report_site.py', '--analyzer', 'unused', '--fixtures', 'unused', '--output', str(self.root/'site'),
                '--source', 'url', '--target', 'https://example.org/a.exe', '--sha256', 'bad']
        with patch.object(sys, 'argv', argv), patch.object(site, 'download') as download, \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            site.main()
        download.assert_not_called()


if __name__ == '__main__':
    unittest.main()
