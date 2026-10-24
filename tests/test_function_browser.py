#!/usr/bin/env python3
"""Whole-function UI regressions over generated reports and synthetic report facts.

Synthetic reports test presentation contracts, not machine-code discovery.
The input Windows programs are never executed. No external server is needed.
"""
import argparse
import copy
import json
from pathlib import Path
import re
import shutil
import tempfile
from playwright.sync_api import sync_playwright


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--document-navigation', action='store_true', help='Also test a real reload via an intercepted document request')
    parser.add_argument('--chromium', default=shutil.which('chromium'))
    args = parser.parse_args()
    root = args.fixtures
    html = (root / 'demo64.html').read_text(encoding='utf-8')
    match = re.search(r'(<script id="report-data" type="application/json">)(.*?)(</script>)', html, re.S)
    data = json.loads(match[2])
    checks = 0

    def check(ok, name):
        nonlocal checks
        if not ok:
            raise AssertionError(name)
        checks += 1

    def with_data(value):
        return html[:match.start(2)] + json.dumps(value).replace('<', '\\u003c') + html[match.end(2):]

    with tempfile.TemporaryDirectory() as temp, sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=args.chromium, args=['--no-sandbox'])
        errors, requests = [], []

        def open_page(document=html, fragment=''):
            p = browser.new_page(viewport={'width': 1536, 'height': 1050})
            p.set_default_timeout(10000)
            p.on('pageerror', lambda e: errors.append(str(e)))
            p.on('request', lambda r: requests.append(r.url) if r.resource_type != 'document' else None)
            if args.document_navigation:
                p.route('https://wea.invalid/report.html', lambda route: route.fulfill(status=200, content_type='text/html', body=document))
                p.goto('https://wea.invalid/report.html' + fragment)
            else:
                # Managed browsers may block document navigation. Exercise the
                # same initial hash routing without bypassing that policy.
                if fragment:
                    document = document.replace('<head>', '<head><script>history.replaceState(null,"",' + json.dumps(fragment) + ');</script>', 1)
                p.set_content(document)
            return p

        def settle(p):
            p.evaluate('() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))')

        def back(p, selector='.function-overview'):
            # Evaluate the same History API as the toolbar without auto-scrolling
            # an off-screen toolbar button and disturbing the test's scroll state.
            p.evaluate('history.back()')
            p.wait_for_selector(selector)
            settle(p)

        def jump(p, target, plain=False):
            p.evaluate('([id, plain]) => navigate(id, undefined, plain)', [target, plain])
            settle(p)

        mid = data['module']['mainId']
        main_fn = next(f for f in data['functions'] if f['id'] == mid)
        owned = [b for b in data['blocks'] if mid in b['owners']]
        expected_rows = sum(len(b['instructions']) for b in owned)
        p = open_page()
        check(p.locator('.function-overview').count() == 0, 'legacy initial block view')
        p.locator('#main').click(); p.locator('#wholeFunction').click(); settle(p)
        check(p.locator('.function-overview .blocktitle').inner_text() == 'main', 'main whole-function heading')
        check(p.locator('.function-block').count() == len(owned), 'all owned blocks rendered')
        check(p.locator('.function-block tbody tr').count() == expected_rows, 'all owned instructions rendered')
        check(p.locator('.function-metrics b').nth(2).inner_text() == str(sum(i['size'] for b in owned for i in b['instructions'])), 'byte count, not address envelope')
        check('inferred membership' in p.locator('.function-context').inner_text(), 'uncertainty visible')
        check(not p.locator('.function-pagebar').is_visible(), 'single page has no disabled pagination clutter')
        check(p.locator('#prevFunctionPage').is_disabled() and p.locator('#nextFunctionPage').is_disabled(), 'small function page bounds')
        check(p.locator('#connections [data-function-detail="evidence"]').count() == 1, 'function evidence available')
        check(p.locator('#connections [data-function-detail="metadata"]').count() == bool(main_fn.get('metadataRecords')), 'metadata shown separately only when present')
        call = next(e for e in data['edges'] if e['from'] in {b['id'] for b in owned} and e['kind'] == 'call' and e['to'])
        p.locator('.function-block .function-target[data-from="' + call['source'] + '"]').first.click()
        check(p.locator('.function-overview .blocktitle').inner_text() == 'checksum_bytes', 'call opens callee whole function')
        back(p)
        check(p.evaluate('location.hash').endswith('_at_' + call['source'].split('_i_')[1]), 'back retains caller function and exact call')
        check(p.locator('tr.focused').get_attribute('id') == call['source'], 'call origin highlighted')
        p.evaluate('history.forward()'); p.wait_for_selector('.function-overview .blocktitle:text-is("checksum_bytes")')
        check(p.locator('.function-overview .blocktitle').inner_text() == 'checksum_bytes', 'forward returns callee')
        # Follow a branch inside the checksum: stay in its whole-function view.
        branch = p.locator('.function-block .function-edge').filter(has_text='taken :').first.locator('a')
        branch_target = branch.get_attribute('href')
        branch.click(); settle(p)
        check(p.evaluate('location.hash') == branch_target, 'branch remains function-qualified')
        check(p.locator('tr.focused').count() == 1, 'branch destination exact instruction')
        p.locator('[data-function-detail="callers"] summary').click()
        caller_link = p.locator('.function-caller').first
        check('_fn_' in caller_link.get_attribute('href'), 'unambiguous caller has function-qualified destination')
        caller_link.click(); settle(p)
        check(p.locator('.function-overview .blocktitle').inner_text() == 'main', 'caller reference opens caller function')
        back(p)
        check(p.locator('.function-overview .blocktitle').inner_text() == 'checksum_bytes', 'caller navigation returns to callee context')
        # Functions tab and search produce ordinary shareable function URLs.
        p.locator('[data-tab="functions"]').click();p.locator('#search').fill('main')
        check('_fn_' in p.locator('#symbols a.symbol').first.get_attribute('href'), 'search preserves whole-function URLs')
        p.locator('#symbols a.symbol').first.click();p.locator('#search').fill('')
        p.locator('[data-function-detail="overview"] > summary').click()
        p.locator('[data-function-detail="data"] summary').click()
        source = p.locator('.function-block .memoperand').first.get_attribute('data-from')
        p.locator('.function-block .memoperand').first.click();p.wait_for_selector('.datacard')
        check(p.locator('.calculation').count() == 1, 'RIP calculation receives raw instruction provenance')
        check(p.locator('.blocktitle').inner_text() == 'demo_payload', 'data label and bytes view')
        back(p)
        check(p.locator('tr.focused').get_attribute('id') == source, 'data back restores function instruction')
        check(p.locator('[data-function-detail="data"]').get_attribute('open') is not None, 'open details restored')
        p.evaluate('history.forward()');p.wait_for_selector('.datacard');settle(p)
        check(p.locator('.calculation').count() == 1, 'forward preserves RIP evidence')
        back(p)
        # Imported call target remains an import identity; the operand is its slot.
        imported = next(e for e in data['edges'] if e['external'] and e['from'] in {b['id'] for b in owned})
        p.locator('.function-block .function-target[data-from="' + imported['source'] + '"]').first.click();p.wait_for_selector('.importpanel')
        check('transform_score' in p.locator('.importpanel').inner_text(), 'import target opens identity not invented code')
        back(p)
        check(p.locator('tr.focused').get_attribute('id') == imported['source'], 'import back restores exact function call')
        # Test annotation compatibility using the existing block identity.
        p.locator('#labelname').fill('main_reviewed');p.locator('#saveLabel').click()
        route_before = p.evaluate('location.hash')
        check(p.locator('.function-overview .blocktitle').inner_text() == 'main_reviewed', 'rename updates function')
        p.locator('.function-overview a.function-plain').click();p.wait_for_selector('.blockcard:not(.function-overview)')
        check(p.locator('.function-overview').count() == 0 and p.locator('.blocktitle').inner_text() == 'main_reviewed', 'dedicated entry block view and shared annotation')
        back(p)
        check(p.evaluate('location.hash') == route_before, 'block-to-function back exact route')
        with p.expect_download() as event:
            p.locator('#exportLabels').click()
        path = Path(temp) / 'labels.json'; event.value.save_as(path)
        labels = json.loads(path.read_text())
        check(mid in labels['labels'] and '_fn_' not in next(iter(labels['labels'])), 'annotation IDs unchanged')
        p.locator('#resetLabel').click()
        p.locator('#labelFile').set_input_files(path)
        p.wait_for_selector('.function-overview .blocktitle:text-is("main_reviewed")')
        check(p.locator('.function-overview .blocktitle').inner_text() == 'main_reviewed', 'annotation import in function view')
        # Metadata routes retain the function origin in navigation history.
        for button, selector in [('exceptionMetadata','#exceptionRecords'),('unwindInfo','#unwindOperations'),('tlsMetadata','#tlsCallbacks')]:
            if not p.locator('#'+button).count() or p.locator('#'+button).is_disabled():
                continue
            p.locator('#reportDetails').evaluate('(e) => e.open = true')
            p.locator('#'+button).click();p.wait_for_selector(selector);back(p)
            check(p.locator('.function-overview').count() == 1, button + ' history interoperability')
        p.locator('#notes').click()
        check(p.locator('.function-block .instnote').first.is_visible(), 'instruction notes supported')
        p.locator('#notes').click()
        check(not p.locator('.function-block .instnote').first.is_visible(), 'notes hidden again')
        p.set_viewport_size({'width':390,'height':844});settle(p)
        check(p.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'mobile no page-wide overflow')
        # Direct link and a real reload through the in-memory document route.
        deep = p.evaluate('location.hash')
        direct = open_page(fragment=deep)
        check(direct.locator('.function-overview').count() == 1 and direct.locator('tr.focused').count() == 1, 'new-page exact deep link')
        if args.document_navigation:
            direct.reload();direct.wait_for_selector('.function-overview');settle(direct)
            check(direct.evaluate('location.hash') == deep and direct.locator('tr.focused').count() == 1, 'reload preserves function route')
        else:
            print('SKIP real document reload: enable --document-navigation on an unrestricted test browser')
        # Browser tests are deliberately independent of source-level recovery.
        # A very large single-block report exercises instruction-based paging.
        large = copy.deepcopy(data);base = 0x1000;bid = large['module']['id']+'_b_1000'
        instructions = [{'id':large['module']['id']+'_i_'+format(base+n,'x'), 'rva':base+n,
            'va':hex(int(large['module']['imageBase'],16)+base+n), 'size':1, 'bytes':'90',
            'mnemonic':'nop','operands':'','notes':'UI fixture','dataRefs':[]} for n in range(1201)]
        b = copy.deepcopy(large['blocks'][0]);b.update(id=bid,rva=base,name='large_ui_fixture',owners=[bid],instructions=instructions)
        f = copy.deepcopy(large['functions'][0]);f.update(id=bid,rva=base,name=b['name'],metadataRecords=[])
        large.update(blocks=[b],functions=[f],edges=[])
        large['module'].update(entryId=bid,mainId=None,instructionCount=1201)
        q = open_page(with_data(large));q.locator('#wholeFunction').click()
        check(q.locator('.function-block tbody tr').count() == 250, 'single huge block bounded to 250 instructions')
        q.locator('#nextFunctionPage').click()
        check(q.locator('.function-block tbody tr').count() == 250 and q.evaluate('location.hash').endswith('_p1'), 'second page route')
        q.locator('#functionAddress').fill(hex(base+777));q.locator('#functionGo button').click();settle(q)
        check(q.locator('tr.focused').get_attribute('id').endswith('_i_'+format(base+777,'x')), 'goto selects non-first page instruction')
        focus_hash = q.evaluate('location.hash')
        q.locator('#nextFunctionPage').click()
        check(q.locator('.function-block tbody tr').count() == 201 and q.locator('#nextFunctionPage').is_disabled(), 'last page and bound')
        back(q)
        check(q.evaluate('location.hash') == focus_hash, 'page history restores exact focused route')
        q.locator('#functionAddress').fill('0xffffffff');q.locator('#functionGo button').click()
        check(q.evaluate('location.hash') == focus_hash, 'unowned goto rejected without navigation')
        # Scroll restoration is checked after the browser has applied layout.
        q.evaluate('window.scrollTo(0,1600)');settle(q);y = q.evaluate('scrollY')
        q.evaluate('navigate(D.module.id+"_fn_1000_p4")');settle(q);back(q)
        check(abs(q.evaluate('scrollY')-y)<3, 'vertical scroll restored')
        check(len(q.locator('.function-block tbody tr').all())<=250, 'render remains bounded after history')
        q.set_viewport_size({'width':390,'height':844});settle(q)
        q.locator('.function-block .assemblywrap').evaluate('(e) => {e.scrollLeft=150}')
        left = q.locator('.function-block .assemblywrap').evaluate('(e) => e.scrollLeft')
        q.evaluate('navigate(D.module.id+"_fn_1000_p4")');settle(q);back(q)
        check(abs(q.locator('.function-block .assemblywrap').evaluate('(e) => e.scrollLeft')-left)<2, 'horizontal assembly scroll restored')
        unknown = copy.deepcopy(data)
        unknown['edges'].append({'from':mid,'source':owned[0]['instructions'][-1]['id'], 'to':None,'kind':'call','external':'','target':'rax'})
        u = open_page(with_data(unknown));u.locator('#main').click();u.locator('#wholeFunction').click()
        check('unresolved control-flow' in u.locator('.datawarning').first.inner_text(), 'unresolved call is visible in overview')
        u.locator('[data-function-detail="unknown"] summary').click()
        check('rax' in u.locator('[data-function-detail="unknown"]').inner_text(), 'unresolved expression retained')
        # A shared block requires explicit owner selection from Block view.
        shared = copy.deepcopy(data);shared_block = next(b for b in shared['blocks'] if b['id'] not in {f['id'] for f in shared['functions']})
        shared_block['owners'] = [f['id'] for f in shared['functions'][:2]]
        s = open_page(with_data(shared));jump(s,shared_block['id'],True)
        check(s.locator('#functionOwner').is_visible() and s.locator('#wholeFunction').is_disabled(), 'shared owner not silently selected')
        s.locator('#functionOwner').select_option(shared_block['owners'][0]);s.locator('#wholeFunction').click()
        check('SHARED BLOCK' in s.locator('#content').inner_text(), 'shared membership visible')
        # Old schema-2 reports need no new serialized producer fields.
        legacy = copy.deepcopy(data)
        for key in ('analysisModelVersion','unwindInfo','exceptionDirectory','tlsDirectory','diagnostics'):
            legacy.pop(key,None)
        for f in legacy['functions']:
            f.pop('evidenceRecords',None);f.pop('metadataRecords',None)
        old = open_page(with_data(legacy));old.locator('#wholeFunction').click()
        check(old.locator('.function-overview').count()==1, 'legacy schema-2 compatibility')
        legacy['functions']=[];legacy['blocks']=[];legacy['edges']=[];legacy['module'].update(entryId=None,mainId=None,instructionCount=0)
        empty = open_page(with_data(legacy))
        check(empty.locator('#wholeFunction').is_disabled(), 'empty report handled')
        evil = copy.deepcopy(data)
        evil['functions'][0]['name']=evil['blocks'][0]['name']='<img src=x onerror="window.injected=1">'
        e = open_page(with_data(evil));jump(e,evil['functions'][0]['id']);e.locator('#wholeFunction').click()
        check(e.locator('#content img').count()==0 and e.evaluate('window.injected === undefined'), 'names escaped')
        # Architecture and no-entry DLL views use the same report contracts.
        for stem in ('demo32','dll64'):
            other = open_page((root/(stem+'.html')).read_text(encoding='utf-8'))
            other.locator('#wholeFunction').click()
            check(other.locator('.function-overview').count()==1, stem+' function overview')
        check(not errors, 'no JavaScript errors: '+repr(errors))
        check(not requests, 'no external report requests: '+repr(requests))
        browser.close()
    print(f'PASS: {checks} function-browser checks')


if __name__ == '__main__':
    main()
