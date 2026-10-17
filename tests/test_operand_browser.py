#!/usr/bin/env python3
"""Operand inspector navigation, escaping, and legacy-report compatibility."""
import argparse
import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from playwright.sync_api import sync_playwright
from test_decoder_operands import make_operand_pe


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('analyzer', type=Path)
    parser.add_argument('--chromium', default=shutil.which('chromium'))
    args = parser.parse_args()
    checks = 0
    def check(ok, message):
        nonlocal checks
        if not ok:
            raise AssertionError(message)
        checks += 1
    with tempfile.TemporaryDirectory() as temp, sync_playwright() as pw:
        root = Path(temp)
        src, html = root/'operands.exe', root/'operands.html'
        make_operand_pe(src, bytes.fromhex('88 e0 48 8b 44 8b f0 f3 0f 10 c1 c3'))
        subprocess.run([str(args.analyzer.resolve()), str(src), '--html', str(html)], check=True, capture_output=True)
        text = html.read_text()
        match = re.search(r'<script id="report-data" type="application/json">(.*?)</script>', text, re.S)
        data = json.loads(match[1])
        structured = data['module']['decoderInfo']['capabilities']['structuredOperands']
        browser = pw.chromium.launch(executable_path=args.chromium, args=['--no-sandbox'])
        page = browser.new_page(viewport={'width':1440, 'height':1000})
        page.set_default_timeout(8000)
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.goto(html.as_uri())
        page.click('#operandDetails summary')
        panel = page.locator('#operandDetails')
        if structured:
            check('ah = rax[8:15]' in panel.inner_text(), 'high-byte alias visible')
            check('Additional effects may be unknown' in panel.inner_text(), 'partial-effects limitation visible')
        else:
            check('Structured operands unavailable' in panel.inner_text(), 'LLVM limitation visible')
        target = data['module']['id'] + '_i_1002'
        page.locator('a[href="#' + target + '"]').first.click()
        page.click('#operandDetails summary')
        check('RVA 0x1002' in panel.inner_text(), 'address selection updates inspector')
        if structured:
            check('Displacement: -16' in panel.inner_text(), 'memory expression visible')
        page.click('#wholeFunction')
        page.wait_for_selector('.function-overview')
        page.locator('a[href$="_at_1007"]').first.click()
        page.click('#operandDetails summary')
        check('RVA 0x1007' in panel.inner_text(), 'function-view instruction selection updates inspector')
        if structured:
            check('Leading legacy/REX bytes: f3' in panel.inner_text(), 'mandatory SSE prefix visible')
        page.go_back()
        page.wait_for_function("!location.hash.endsWith('_at_1007')")
        check(page.locator('#operandDetails').count() == 1, 'history keeps a single inspector')
        # Simulate an older schema-2 report with no operand extension.
        legacy = copy.deepcopy(data)
        del legacy['operandModelVersion']
        del legacy['module']['decoderInfo']
        for b in legacy['blocks']:
            for i in b['instructions']:
                del i['operandDetails']
        def patched(d):
            return text[:match.start(1)] + json.dumps(d).replace('<', '\\u003c') + text[match.end(1):]
        old = browser.new_page()
        old.on('pageerror', lambda e: errors.append(str(e)))
        old.set_content(patched(legacy))
        check(old.locator('#operandDetails').count() == 0, 'legacy reports keep working without invented metadata')
        check(old.locator('#content tr[id]').count() > 0, 'legacy assembly still rendered')
        old.close()
        if structured:
            poisoned = copy.deepcopy(data)
            poisoned['blocks'][0]['instructions'][0]['operandDetails']['operands'][0]['register']['name'] = '<img src=x onerror="window.operandInjected=1">'
            xss = browser.new_page()
            xss.set_content(patched(poisoned))
            xss.click('#operandDetails summary')
            check(xss.locator('#operandDetails img').count() == 0, 'operand metadata is escaped')
            check(xss.evaluate('window.operandInjected === undefined'), 'no operand script execution')
            xss.close()
        check(not errors, 'JavaScript errors: ' + repr(errors))
        browser.close()
    print('PASS: %d operand-browser checks' % checks)


if __name__ == '__main__':
    main()
