#!/usr/bin/env python3
"""C-like view, provenance, history, labels, backend fallback and HTML escaping."""
import argparse
import copy
import json
from pathlib import Path
import re
import shutil
from playwright.sync_api import sync_playwright


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('analyzer', type=Path)
    p.add_argument('--fixtures', required=True, type=Path)
    p.add_argument('--chromium', default=shutil.which('chromium'))
    a = p.parse_args()
    path = (a.fixtures / 'recovery64-o0.html').resolve()
    text = path.read_text()
    match = re.search(r'<script id="report-data" type="application/json">(.*?)</script>', text, re.S)
    data = json.loads(match[1])
    f = next(f for f in data['functions'] if f['name'] == 'transform_demo')
    route = data['module']['id'] + '_c_' + format(f['rva'], 'x')
    structured = data['module']['decoderInfo']['capabilities']['structuredOperands']
    checks = 0
    def check(ok, message):
        nonlocal checks
        if not ok: raise AssertionError(message)
        checks += 1
    def patched(d):
        return text[:match.start(1)] + json.dumps(d).replace('<', '\\u003c') + text[match.end(1):]
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=a.chromium, args=['--no-sandbox'])
        page = browser.new_page(viewport={'width': 1440, 'height': 1000})
        page.set_default_timeout(8000)
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.goto(path.as_uri() + '#' + data['module']['id'] + '_fn_' + format(f['rva'], 'x'))
        page.click('#functionPseudo')
        page.wait_for_selector('.pseudocode-overview')
        check(page.evaluate('location.hash') == '#' + route, 'stable C-like route')
        if structured:
            code = page.locator('.pseudo-code').inner_text()
            check('while (true)' in code and 'else' in code and 'write32' in code, 'complex demo shows loops, branches and writes')
            check('Unknown effects' in page.locator('#content').text_content(), 'coverage counts visible')
            check(page.locator('.pseudo-code').bounding_box()['width'] > 600, 'code uses available content width')
            tops = page.locator('.pseudocode-overview .stat').evaluate_all('(els) => els.map(e => e.getBoundingClientRect().top)')
            check(len(tops) == 4 and len(set(tops)) == 1, 'coverage cards form one row')
            check(page.locator('#pseudoAliases').is_checked() and 'slot_' in code, 'readable stack aliases enabled')
            check(page.locator('#pseudoAliases').bounding_box()['width'] < 30, 'checkbox is sized beside its label')
            page.locator('.pseudo-slots summary').click()
            check('frame slot' in page.locator('.pseudo-slots').inner_text() and 'return address region' in page.locator('.pseudo-slots').inner_text(), 'stack candidates show classification and exclusions')
            page.uncheck('#pseudoAliases')
            raw = page.locator('.pseudo-code').inner_text()
            check('slot_' not in raw and 'write32' in raw, 'raw toggle restores original memory addresses')
            page.check('#pseudoAliases')
            check(page.locator('.pseudo-code').inner_text() == code and page.evaluate('location.hash') == '#' + route, 'alias toggle preserves code and route')
            target = page.locator('.pseudo-code .pseudo-source').nth(4).get_attribute('href')
            page.locator('.pseudo-code .pseudo-source').nth(4).click()
            page.wait_for_selector('.function-overview')
            check(page.evaluate('location.hash') == target, 'source opens exact instruction in function assembly')
            page.go_back()
            page.wait_for_selector('.pseudocode-overview')
            check(page.evaluate('location.hash') == '#' + route, 'Back restores pseudocode')
            page.go_forward()
            page.wait_for_selector('.function-overview')
            page.go_back()
            page.wait_for_selector('.pseudocode-overview')
            page.locator('.pseudo-evidence').first.click()
            check(page.locator('#connections .pseudo-source').count() > 1, 'combined region lists every contributing source')
            check('value facts at' in page.locator('#connections').inner_text().lower() and 'entry_sp' in page.locator('#connections').inner_text(), 'source evidence includes symbolic stack facts')
            check('definitions' in page.locator('#pseudoFlow summary').inner_text(), 'register-flow summary visible')
            page.locator('#pseudoFlow > summary').click()
            check(page.locator('#pseudoFlowInstruction option').count() > 20, 'instruction-level flow selector')
            page.locator('#pseudoFlowInstruction').select_option(index=0)
            check(page.locator('#pseudoFlowInstructionDetails .pseudo-def').count() > 0, 'register reads and writes link to definitions')
            page.locator('#pseudoFlowInstructionDetails .pseudo-def').first.click()
            check('Definition' in page.locator('#pseudoFlowDefinition').inner_text() and 'Used by' in page.locator('#pseudoFlowDefinition').inner_text(), 'definition and reverse uses visible')
            use = page.locator('#pseudoFlowDefinition .pseudo-use').first
            source = use.get_attribute('data-source'); use.click()
            check(page.locator('#pseudoFlowInstruction').input_value() == source, 'reverse-use navigation selects consuming instruction')
            check(page.locator('#pseudoFlowJoin option').count() > 1, 'joins available for machine exit or loop state')
            page.locator('#pseudoFlowJoin').select_option(index=1)
            check('predecessor' in page.locator('#pseudoFlowDefinition').inner_text().lower() and
                  page.locator('#pseudoFlowDefinition .pseudo-flow-table').first.locator('tbody tr').count() >= 2, 'PHI shows incoming values and predecessor transfers')
            check(page.locator('#pseudoFlowDefinition .pseudo-source').count() >= 2, 'join operands retain assembly evidence')
            page.locator('#pseudoFlowDefinition .pseudo-def').first.click()
            check('Used by' in page.locator('#pseudoFlowDefinition').inner_text(), 'join operand can be inspected without recursion')
            check(page.evaluate('location.hash') == '#' + route, 'flow inspection preserves route')
        else:
            check('Structured operands unavailable' in page.locator('#content').inner_text(), 'LLVM unavailable reason')
            check(page.locator('.pseudo-code').count() == 0, 'no invented LLVM pseudocode')
            check(page.locator('#pseudoFlow').count() == 0, 'no invented LLVM register graph')
        page.fill('#labelname', '<img src=x onerror="window.injected=1"> recovered_name')
        page.click('#saveLabel')
        check('recovered_name' in page.locator('.blocktitle').inner_text(), 'rename refreshes title')
        check(page.locator('.blocktitle img').count() == 0 and page.evaluate('window.injected === undefined'), 'labels escaped')
        check(page.evaluate('location.hash') == '#' + route, 'rename preserves evidence route')
        page.click('#wholeFunction')
        page.wait_for_selector('.function-overview')
        check(page.evaluate('location.hash').startswith('#' + data['module']['id'] + '_fn_' + format(f['rva'], 'x')), 'assembly toolbar uses correct function')
        # Deep links work without earlier navigation.
        page.goto(path.as_uri() + '#' + route)
        page.wait_for_selector('.pseudocode-overview')
        check(page.locator('#functionPseudo').get_attribute('aria-pressed') == 'true', 'deep link marks selected view')
        check(page.locator('#wholeFunction').is_enabled() and page.locator('#functionCfg').is_enabled(), 'deep link enables assembly and CFG navigation')
        old = copy.deepcopy(data)
        del old['operandModelVersion']
        legacy = browser.new_page()
        legacy.on('pageerror', lambda e: errors.append(str(e)))
        legacy.goto('about:blank#' + route)
        legacy.set_content(patched(old))
        check('Structured operands unavailable' in legacy.locator('#content').inner_text(), 'legacy capability fallback')
        check(legacy.locator('#pseudoFlow').count() == 0, 'legacy register graph unavailable')
        legacy.close()
        if structured:
            bad = copy.deepcopy(data)
            b = next(b for b in bad['blocks'] if b['id'] == f['id'])
            b['instructions'][0]['mnemonic'] = '<img src=x onerror="window.injected=1">'
            xss = browser.new_page()
            xss.on('pageerror', lambda e: errors.append(str(e)))
            xss.goto('about:blank#' + route)
            xss.set_content(patched(bad))
            check('unknown_effects' in xss.locator('.pseudo-code').inner_text(), 'unsupported form is visible')
            xss.locator('.pseudo-evidence').first.click()
            check(xss.locator('#connections img').count() == 0 and xss.evaluate('window.injected === undefined'), 'source metadata escaped')
            check(xss.locator('#pseudoFlow img').count() == 0, 'flow selectors and definition links escape metadata')
            xss.close()
            shared = copy.deepcopy(data)
            next(b for b in shared['blocks'] if b['id'] == f['id'])['owners'].append('other')
            unsafe = browser.new_page()
            unsafe.on('pageerror', lambda e: errors.append(str(e)))
            unsafe.goto('about:blank#' + route); unsafe.set_content(patched(shared))
            check(unsafe.locator('#pseudoFlow').count() == 0 and 'prevent register SSA' in unsafe.locator('#content').inner_text(), 'unsafe ownership disables register graph with reason')
            check(unsafe.locator('.pseudo-code').count() == 1, 'raw effects remain available when SSA is unavailable')
            unsafe.close()
        check(not errors, 'JavaScript errors: ' + repr(errors))
        browser.close()
    print('PASS: %d pseudocode browser checks' % checks)


if __name__ == '__main__':
    main()
