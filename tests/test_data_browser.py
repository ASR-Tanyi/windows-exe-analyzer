#!/usr/bin/env python3
"""Chromium integration tests for the offline static-data report.
Requires Playwright and a Chromium executable. The input code is never executed.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from playwright.sync_api import sync_playwright
from test_static_data import make_fixture

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('analyzer',type=Path)
parser.add_argument('--fixtures',type=Path,required=True)
parser.add_argument('--chromium',default=shutil.which('chromium'))
args=parser.parse_args();root=args.fixtures.resolve()
checks=0

def check(condition,message):
    global checks
    if not condition:raise AssertionError(message)
    checks+=1

with tempfile.TemporaryDirectory() as tmp,sync_playwright() as p:
    tmp=Path(tmp);browser=p.chromium.launch(executable_path=args.chromium,args=['--no-sandbox'])
    errors=[];network=[]
    def open_html(path):
        page=browser.new_page(viewport={'width':1600,'height':1080})
        page.on('pageerror',lambda e:errors.append(str(e)))
        page.on('request',lambda r:network.append(r.url))
        # Some managed test browsers block file://. Load the exact self-contained
        # document instead of weakening the browser's administrator policy.
        page.set_content(path.read_text());return page
    def go_rva(page,rva):
        page.locator('#dataAddress').fill(hex(rva));page.locator('#dataGo button').click()
    def generate(bits=64,limit=None,base=None):
        inp=tmp/f'fixture{bits}_{limit}_{base}.exe';make_fixture(inp,bits=bits,base=base)
        out=inp.with_suffix('.html');cmd=[str(args.analyzer.resolve()),str(inp),'--html',str(out)]
        if limit is not None:cmd+=['--data-limit',str(limit)]
        subprocess.run(cmd,check=True,capture_output=True);return out

    page=open_html(root/'demo64.html')
    check(page.locator('.blocktitle').inner_text()=='pe_entry','Entry view retained')
    page.locator('#main').click()
    check(page.locator('.memoperand').count()==1,'Clickable LEA operand')
    source=page.locator('.memoperand').get_attribute('data-from')
    page.locator('.memoperand').click()
    check(page.locator('.blocktitle').inner_text()=='demo_payload','Data label from CLI')
    check('Follow the code. Name the blocks.' in page.locator('.stringpreview').inner_text(),'ASCII content')
    check('0x600' in page.locator('.addressmeta').inner_text(),'Mapped file offset')
    check('0x14000104b + 0xfb5' in page.locator('.calculation').inner_text(),'Next RIP rather than current instruction')
    check('ADDRESS ONLY / LEA' in page.locator('.dataxref').inner_text(),'LEA is not a load')
    check(page.locator('.bytefocus').count()==1,'Address-only focus does not pretend to read pointer width')
    page.locator('#back').click();page.wait_for_timeout(120)
    check(page.url.endswith('#'+source),'Back to exact memory-reference instruction')
    check(page.locator('tr.focused').count()==1,'Origin highlighted after Back')
    page.locator('#forward').click();page.wait_for_timeout(120)
    check(page.locator('.blocktitle').inner_text()=='demo_payload','Forward to data')
    check(page.locator('.calculation').count()==1,'Calculation retained through history')
    page.locator('.dataxref').click()
    check(page.locator('tr.focused').count()==1,'Incoming xref jumps to instruction')
    page.locator('#back').click();page.wait_for_timeout(120)
    page.locator('#labelname').fill('input_text_reviewed');page.locator('#labelnote').fill('Test annotation. <script> is literal text.')
    page.locator('#saveLabel').click()
    check(page.locator('.blocktitle').inner_text()=='input_text_reviewed','Data rename')
    with page.expect_download() as event:page.locator('#exportLabels').click()
    label_path=tmp/'labels.json';event.value.save_as(label_path)
    check(any(x['name']=='input_text_reviewed' for x in json.loads(label_path.read_text())['labels'].values()),'Data annotations exported')
    page.locator('#main').click()
    check('input_text_reviewed' in page.locator('.datalink').inner_text(),'Renamed target shown at source')
    page.locator('.memoperand').click();page.locator('#resetLabel').click()
    check(page.locator('.blocktitle').inner_text()=='demo_payload','Data rename reset')
    page.locator('#labelFile').set_input_files(str(label_path));page.wait_for_timeout(120)
    check(page.locator('.blocktitle').inner_text()=='input_text_reviewed','Data annotations imported')
    page.locator('#resetLabel').click()
    # Inspect the pointer storage and imported identity as distinct destinations.
    go_rva(page,0x2060)
    check('IAT pointer slot, not DLL code.' in page.locator('.datawarning').inner_text(),'IAT semantics warning')
    page.locator('.datawarning a').click()
    check(page.locator('.importpanel').count()==1,'IAT bytes -> import identity')
    page.get_by_role('link',name='Inspect slot bytes').click()
    check(page.locator('.datawarning').count()==1,'Import identity -> IAT bytes')
    go_rva(page,0x3000)
    check('VIRTUAL ZERO-FILL' in page.locator('.blockhead').inner_text(),'Uninitialized global view')
    check(page.locator('.hexcell.zero-fill').count()==4,'No invented stored zeros')
    check(page.locator('.values').count()==0,'No numeric value invented from .bss')
    check(page.locator('.dataxref').count()==2,'Both global stores recorded')
    check(all('WRITE / 4 BYTES' in s for s in page.locator('.dataxref').all_text_contents()),'Store access classification')
    page.locator('.dataxref').first.click()
    check(page.locator('tr.focused').count()==1,'Global xref returns to store')

    fixture=generate();q=open_html(fixture)
    q.locator('.memoperand').first.click()
    check('0x140002007 - 0x1007' in q.locator('.calculation').inner_text(),'Negative RIP displacement')
    check('Hello static data' in q.locator('.stringpreview').inner_text(),'Fixture ASCII')
    q.locator('#back').click();q.wait_for_timeout(100);q.locator('.memoperand').nth(1).click()
    check(q.locator('.bytefocus').count()==4,'4-byte memory access highlighted')
    check('123' in q.locator('.values').inner_text(),'Initial global data shown')
    go_rva(q,0x1088)
    check(str(0xfedcba9876543210) in q.locator('.values').inner_text(),'uint64 interpretation has no precision loss')
    check(str(0xfedcba9876543210-(1<<64)) in q.locator('.values').inner_text(),'Signed int64 interpretation')
    go_rva(q,0x1040)
    check('UTF-16LE' in q.locator('.stringpreview').inner_text(),'UTF-16LE candidate')
    check('Wide Hello' in q.locator('.stringpreview').inner_text(),'Wide string content')
    go_rva(q,0x10c0)
    check('</script><script>' in q.locator('.stringpreview').inner_text(),'HTML-like data rendered literally')
    check(q.evaluate('window.dataInjected === undefined'),'No script execution from file data')
    go_rva(q,0x3000);q.locator('#nextData').click()
    check('0x3100' in q.locator('.addressmeta').inner_text(),'Next page')
    q.locator('#prevData').click()
    check('0x3000' in q.locator('.addressmeta').inner_text(),'Previous page')
    go_rva(q,0x3200)
    check('VIRTUAL ZERO-FILL' in q.locator('.blockhead').inner_text(),'Zero-fill tail of mixed section')
    go_rva(q,0x900000)
    check('UNMAPPED' in q.locator('.blockhead').inner_text(),'Unmapped effective address is explicit')
    check(q.locator('.hexcell').count()==0,'No invented bytes at unmapped address')
    go_rva(q,0x1000);q.set_viewport_size({'width':390,'height':844})
    check(q.evaluate('document.documentElement.scrollWidth <= innerWidth'),'Mobile page does not overflow horizontally')
    check(q.locator('.assemblywrap').count()>=1,'Hex overflow contained within scroll panel')

    limited=open_html(generate(limit=0));limited.locator('.memoperand').first.click()
    check('NOT EMBEDDED' in limited.locator('.blockhead').inner_text(),'Budget omission status')
    check(limited.locator('.hexcell.omitted').count()>0,'Omitted bytes rendered ??')
    check(limited.locator('.stringpreview').count()==0,'No string guesses without file bytes')
    check(limited.locator('.values').count()==0,'No numeric guesses without file bytes')
    highbase=0x2222222200000000;high=open_html(generate(base=highbase));high.locator('.memoperand').first.click()
    check(hex(highbase+0x1000) in high.locator('.addressmeta').inner_text(),'64-bit VA display exact')
    check(hex(highbase+0x2007) in high.locator('.calculation').inner_text(),'64-bit next RIP calculation exact')
    x86=open_html(generate(bits=32));x86.locator('.memoperand').first.click()
    check('Absolute effective address' in x86.locator('.calculation').inner_text(),'x86 absolute memory reference')
    check('Hello static data' in x86.locator('.stringpreview').inner_text(),'x86 data display')
    check(not errors,f'JavaScript errors: {errors}')
    check(not [url for url in network if url.startswith(('http:','https:'))],f'Unexpected network access: {network}')
    browser.close()
print(f'PASS: {checks} static-data browser assertions; no JavaScript errors or HTTP requests')
