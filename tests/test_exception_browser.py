#!/usr/bin/env python3
"""Exercise the embedded metadata viewer. No input PE is executed."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from playwright.sync_api import sync_playwright
from test_exception_directory import make_pe


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('analyzer', type=Path)
    p.add_argument('--chromium', default=shutil.which('chromium'))
    args = p.parse_args()
    checks = 0

    def check(value, message):
        nonlocal checks
        if not value:
            raise AssertionError(message)
        checks += 1

    with tempfile.TemporaryDirectory() as temp, sync_playwright() as pw:
        root = Path(temp)
        browser = pw.chromium.launch(executable_path=args.chromium, args=['--no-sandbox'])
        errors, network = [], []

        def generate(name, **kwargs):
            path = root / (name + '.exe'); make_pe(path, **kwargs)
            output = path.with_suffix('.html')
            subprocess.run([str(args.analyzer.resolve()), str(path), '--html', str(output)],
                           check=True, capture_output=True, timeout=60)
            return output.read_text()

        def open_page(html):
            page = browser.new_page(viewport={'width': 1500, 'height': 950})
            page.on('pageerror', lambda e: errors.append(str(e)))
            page.on('request', lambda r: network.append(r.url))
            page.set_content(html)
            return page

        html = generate('valid', records=[(0x1000, 0x1001, None), (0x1010, 0x1011, None)])
        page = open_page(html)
        check(page.locator('.blocktitle').inner_text() == 'pe_entry', 'default code view')
        page.locator('#exceptionMetadata').click()
        check(page.locator('#exceptionRecords tbody tr').count() == 2, 'metadata rows')
        check('not decoded' in page.locator('#exceptionRecords').inner_text(), 'unknown code stays unknown')
        check('No discovery seeds' in page.locator('.summary').inner_text(), 'scope is explicit')
        meta_hash = page.evaluate('location.hash')
        page.locator('#exceptionRecords a[href$="_d_2000"]').click()
        check(page.locator('.datacard').count() == 1, 'record to original file bytes')
        page.locator('#back').click(); page.wait_for_selector('#exceptionRecords')
        check(page.evaluate('location.hash') == meta_hash, 'back to metadata')
        page.locator('#forward').click(); page.wait_for_selector('.datacard')
        check(page.locator('.datacard').count() == 1, 'forward to bytes')
        page.locator('#back').click(); page.wait_for_selector('#exceptionRecords')
        page.locator('.exception-code').click(); page.wait_for_selector('tr.focused')
        check(page.locator('tr.focused').count() == 1, 'known metadata entry to exact instruction')
        check(page.locator('tr.focused').get_attribute('id').endswith('_i_1000'), 'instruction identity')
        page.locator('#exceptionMetadata').click()
        page.locator('#back').click(); page.wait_for_selector('tr.focused')
        check(page.locator('tr.focused').get_attribute('id').endswith('_i_1000'), 'metadata shortcut preserves instruction')
        page.locator('#forward').click(); page.wait_for_selector('#exceptionRecords')
        page.locator('#exceptionRecords a[href$="_d_3000"]').first.click()
        check(page.locator('.datacard').count() == 1, 'unwind address to bytes, not implementation')
        page.locator('#back').click(); page.wait_for_selector('#exceptionRecords')
        page.locator('#entry').click()
        check(page.locator('.blocktitle').inner_text() == 'pe_entry', 'return to entry')
        page.evaluate('(h) => { history.pushState(null, "", h); route(); }', meta_hash)
        check(page.locator('#exceptionRecords').count() == 1, 'deep-link routing')
        page.set_viewport_size({'width': 390, 'height': 844})
        check(page.locator('#exceptionMetadata').is_visible(), 'mobile toolbar')
        check(page.locator('#exceptionRecords tbody tr').count() == 2, 'mobile metadata retained')

        many = open_page(generate('many', records=[(0x1010, 0x1011, None)]*205))
        many.locator('#exceptionMetadata').click()
        check(many.locator('#exceptionRecords tbody tr').count() == 100, 'DOM row budget')
        many.locator('#nextMetadata').click()
        check(many.locator('#exceptionRecords tbody tr').count() == 100, 'second page')
        second_hash = many.evaluate('location.hash')
        many.locator('#nextMetadata').click()
        check(many.locator('#exceptionRecords tbody tr').count() == 5, 'last page')
        check(many.locator('#nextMetadata').is_disabled(), 'last page bound')
        many.locator('#back').click()
        many.wait_for_function('(h) => location.hash === h && document.querySelectorAll("#exceptionRecords tbody tr").length === 100', arg=second_hash)
        check(many.evaluate('location.hash') == second_hash, 'page history')
        many.locator('#prevMetadata').click()
        check(many.locator('#prevMetadata').is_disabled(), 'first page bound')

        bad = open_page(generate('bad', records=[(0, 0, 0)]))
        bad.locator('#exceptionMetadata').click()
        check('issues_present' in bad.locator('#exceptionRecords').inner_text(), 'invalid records are explicit')
        check(bad.locator('.exception-code').count() == 0, 'no fabricated code link')
        absent = open_page(generate('absent', records=[], directory_rva=0))
        absent.locator('#exceptionMetadata').click()
        check('No exception directory' in absent.locator('#content').inner_text(), 'absent is not no functions')
        x86 = open_page(generate('x86', bits=32)); x86.locator('#exceptionMetadata').click()
        check('unsupported_architecture' in x86.locator('#content').inner_text(), 'architecture gate')

        match = re.search(r'(<script id="report-data" type="application/json">)(.*?)(</script>)', html, re.S)
        data = json.loads(match[2]); del data['exceptionDirectory']
        legacy = html[:match.start(2)] + json.dumps(data).replace('<', '\\u003c') + html[match.end(2):]
        old = open_page(legacy)
        check(old.locator('#exceptionMetadata').count() == 0, 'old reports remain supported')
        check(old.locator('.blocktitle').inner_text() == 'pe_entry', 'legacy initial view')
        data = json.loads(match[2]); data['exceptionDirectory']['issues'] = ['<img src=x onerror="window.injected=1">']
        escaped = html[:match.start(2)] + json.dumps(data).replace('<', '\\u003c') + html[match.end(2):]
        evil = open_page(escaped); evil.locator('#exceptionMetadata').click()
        check(evil.locator('#content img').count() == 0, 'metadata escaping')
        check(evil.evaluate('window.injected === undefined'), 'no injected script')
        check(not errors, 'no JavaScript errors: ' + repr(errors))
        check(not network, 'no network requests: ' + repr(network))
        browser.close()
    print(f'PASS: {checks} exception-metadata browser checks')


if __name__ == '__main__':
    main()
