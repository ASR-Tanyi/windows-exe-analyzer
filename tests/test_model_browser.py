#!/usr/bin/env python3
"""Browser compatibility for optional evidence metadata and schema-1 labels."""
import argparse
import json
from pathlib import Path
import re
import shutil
from playwright.sync_api import sync_playwright

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--fixtures', type=Path, required=True)
parser.add_argument('--chromium', default=shutil.which('chromium'))
args = parser.parse_args()
text = (args.fixtures / 'demo64.html').read_text()
pattern = r'(<script id="report-data" type="application/json">)(.*?)(</script>)'
data = json.loads(re.search(pattern, text, re.S)[2])
checks = 0


def check(value, message):
    global checks
    if not value:
        raise AssertionError(message)
    checks += 1


with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=args.chromium, args=['--no-sandbox'])
    page = browser.new_page(viewport={'width': 1600, 'height': 1100})
    errors, requests = [], []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.on('request', lambda r: requests.append(r.url))
    page.set_content(text)
    page.locator('.analysis-evidence summary').click()
    check('pe.entry' in page.locator('.analysis-evidence').inner_text(), 'Header evidence shown')
    check('file_offset' in page.locator('.analysis-evidence').inner_text(), 'Header coordinate system visible')
    page.locator('.analysis-ranges summary').click()
    check('not complete function boundaries' in page.locator('.analysis-ranges').inner_text(), 'Range limitation visible')
    page.locator('#main').click()
    check(page.locator('.blocktitle').inner_text() == 'main', 'Existing main navigation retained')
    page.locator('.analysis-evidence summary').click()
    facts = page.locator('.analysis-evidence').inner_text()
    check('cli.main_rva' in facts and 'cfg.direct_call' in facts, 'Both analyst and call-site evidence retained')
    check('assertion' in facts and 'candidate' in facts, 'Status is not conflated with provenance')
    main_block = next(b for b in data['blocks'] if b['id'] == data['module']['mainId'])
    mem = next(i for i in main_block['instructions'] if i['dataRefs'])
    page.locator('.memoperand').first.click()
    check(page.locator('.hexdump').count() == 1, 'Code-to-data navigation retained')
    page.locator('#back').click()
    page.wait_for_timeout(120)
    check(page.url.endswith('#' + mem['id']), 'Back restores precise source instruction')
    check(page.locator('tr.focused').count() == 1, 'Source instruction highlighted')
    old_labels = {'schema': 1, 'moduleId': data['module']['id'], 'labels': {
        main_block['id']: {'name': 'saved_main', 'note': 'Imported old-format annotation'}}}
    page.locator('#labelFile').set_input_files({'name': 'old.labels.json', 'mimeType': 'application/json',
                                               'buffer': json.dumps(old_labels).encode()})
    page.wait_for_timeout(120)
    check(page.locator('.blocktitle').inner_text() == 'saved_main', 'Old annotation format imports')
    page.locator('.analysis-evidence summary').click()
    check('cfg.direct_call' in page.locator('.analysis-evidence').inner_text(), 'UI name does not remove static evidence')
    # The source call link must still navigate to an instruction, not a header offset.
    page.locator('.analysis-evidence a').first.click()
    check(page.locator('tr.focused').count() == 1, 'Evidence-source link reaches the call instruction')
    page.locator('#back').click()
    page.wait_for_timeout(120)
    check(page.locator('.blocktitle').inner_text() == 'saved_main', 'Evidence navigation returns to renamed block')
    # Feed this viewer an old report with all optional fields omitted.
    legacy = json.loads(json.dumps(data))
    legacy.pop('analysisModelVersion')
    legacy.pop('diagnostics')
    for entity in legacy['functions'] + legacy['blocks']:
        for key in ('location', 'evidenceRecords', 'decodedRange', 'decodedRanges'):
            entity.pop(key, None)
    legacy_text = re.sub(pattern, lambda m: m[1] + json.dumps(legacy).replace('<', '\\u003c') + m[3], text, flags=re.S)
    page.goto('about:blank')
    page.set_content(legacy_text)
    check(page.locator('.analysis-evidence').count() == 0, 'Optional extension absent without errors')
    page.locator('#main').click()
    check(page.locator('.blocktitle').inner_text() == 'main', 'Old report still navigates')
    page.locator('.memoperand').first.click()
    check(page.locator('.hexdump').count() == 1, 'Old report data links remain')
    check(not errors, str(errors))
    check(not [u for u in requests if u.startswith(('http:', 'https:'))], 'No HTTP requests')
    browser.close()
print(f'PASS: {checks} model-browser checks; no JavaScript errors or HTTP requests')
