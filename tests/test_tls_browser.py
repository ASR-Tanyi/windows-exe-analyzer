#!/usr/bin/env python3
"""TLS metadata/bytes/code navigation in the standalone report; never run a PE."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from playwright.sync_api import sync_playwright
from test_tls_directory import make_tls


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('analyzer',type=Path)
    p.add_argument('--chromium',default=shutil.which('chromium'));args=p.parse_args()
    checks=0
    def check(value,message):
        nonlocal checks
        if not value:raise AssertionError(message)
        checks+=1
    with tempfile.TemporaryDirectory() as temp,sync_playwright() as pw:
        root=Path(temp);errors=[];network=[]
        browser=pw.chromium.launch(executable_path=args.chromium,args=['--no-sandbox'])
        def generate(name,options=(),**kwargs):
            path=root/(name+'.exe');make_tls(path,**kwargs);html=path.with_suffix('.html')
            subprocess.run([str(args.analyzer.resolve()),str(path),'--html',str(html),*options],
                           check=True,capture_output=True,timeout=60)
            return html.read_text()
        def open_page(html):
            page=browser.new_page(viewport={'width':1500,'height':950})
            page.on('pageerror',lambda e:errors.append(str(e)))
            page.on('request',lambda req:network.append(req.url))
            page.set_content(html);return page
        html=generate('valid');page=open_page(html)
        check(page.locator('.blocktitle').inner_text()=='pe_entry','initial entry')
        page.locator('#tlsMetadata').click();meta_hash=page.evaluate('location.hash')
        check(page.locator('#tlsCallbacks tbody tr').count()==2,'two callback rows')
        check('not calls from the PE entry' in page.locator('.summary').inner_text(),'no synthetic caller claim')
        check('0x140003000' in page.locator('#content').inner_text(),'preferred array VA displayed')
        check('decoded_candidate' in page.locator('#tlsCallbacks').inner_text(),'discovery status')
        page.locator('#tlsCallbacks a[href$="_d_3000"]').click()
        check(page.locator('.datacard').count()==1,'slot bytes link')
        page.locator('#back').click();page.wait_for_selector('#tlsCallbacks')
        check(page.evaluate('location.hash')==meta_hash,'back to metadata')
        page.locator('#forward').click();page.wait_for_selector('.datacard')
        check(page.locator('.datacard').count()==1,'forward to bytes')
        page.locator('#back').click();page.wait_for_selector('#tlsCallbacks')
        page.locator('.tls-code').first.click();page.wait_for_selector('tr.focused')
        check(page.locator('tr.focused').get_attribute('id').endswith('_i_1010'),'exact callback instruction')
        check(page.locator('.tls-evidence').count()==1,'callback provenance in inspector')
        check(page.locator('#main').is_disabled(),'callback is not main')
        page.locator('#labelname').fill('reviewed_tls');page.locator('#saveLabel').click()
        check(page.locator('.blocktitle').inner_text()=='reviewed_tls','analyst name')
        page.locator('#tlsMetadata').click();page.locator('#back').click();page.wait_for_selector('tr.focused')
        check(page.locator('tr.focused').get_attribute('id').endswith('_i_1010'),'toolbar preserves exact instruction')
        page.locator('#forward').click();page.wait_for_selector('#tlsCallbacks')
        page.locator('#content a[href$="_d_2018"]').click()
        check(page.locator('.datacard').count()==1,'header callback field to bytes')
        page.locator('#back').click();page.wait_for_selector('#tlsCallbacks')
        page.evaluate('(h)=>{history.pushState(null,"",h);route();}',meta_hash)
        check(page.locator('#tlsCallbacks').count()==1,'deep link')
        page.set_viewport_size({'width':390,'height':844})
        check(page.locator('#tlsMetadata').is_visible(),'mobile toolbar')
        check(page.locator('#tlsCallbacks tbody tr').count()==2,'mobile data retained')
        page.close()
        many=open_page(generate('many',targets=[0x140001010]*205));many.locator('#tlsMetadata').click()
        check(many.locator('#tlsCallbacks tbody tr').count()==100,'DOM row limit')
        many.locator('#nextTls').click();second=many.evaluate('location.hash')
        check(many.locator('#tlsCallbacks tbody tr').count()==100,'second page')
        many.locator('#nextTls').click();check(many.locator('#tlsCallbacks tbody tr').count()==5,'last page')
        check(many.locator('#nextTls').is_disabled(),'page upper bound')
        many.locator('#back').click();many.wait_for_function('(h)=>location.hash===h&&document.querySelectorAll("#tlsCallbacks tbody tr").length===100',arg=second)
        check(many.evaluate('location.hash')==second,'page history');many.close()
        narrow=open_page(generate('x86',bits=32));narrow.locator('#tlsMetadata').click()
        check('32-bit pointers' in narrow.locator('#content').inner_text(),'x86 pointer size');narrow.close()
        partial=open_page(generate('partial',targets=[0x140001010],terminated=False));partial.locator('#tlsMetadata').click()
        check('partial' in partial.locator('#content').inner_text(),'partial array')
        check(partial.locator('.tls-code').count()==0,'partial array adds no roots');partial.close()
        disabled=open_page(generate('disabled',options=['--no-tls-seeds']));disabled.locator('#tlsMetadata').click()
        check('disabled' in disabled.locator('#tlsCallbacks').inner_text(),'inspection only flag');disabled.close()
        bad=open_page(generate('bad',targets=[1]));bad.locator('#tlsMetadata').click()
        check('blocked' in bad.locator('#tlsCallbacks').inner_text(),'invalid target is blocked')
        check(bad.locator('.tls-code').count()==0,'no invented code link');bad.close()
        dll=open_page(generate('dll',entry=0,dll=True))
        check(dll.locator('#entry').is_disabled(),'DLL without PE entry remains browsable');dll.close()
        match=re.search(r'(<script id="report-data" type="application/json">)(.*?)(</script>)',html,re.S)
        data=json.loads(match[2]);del data['tlsDirectory']
        old=open_page(html[:match.start(2)]+json.dumps(data).replace('<','\\u003c')+html[match.end(2):])
        check(old.locator('#tlsMetadata').count()==0,'old report compatibility');old.close()
        data=json.loads(match[2]);data['tlsDirectory']['issues']=['<img src=x onerror="window.injected=1">']
        evil=open_page(html[:match.start(2)]+json.dumps(data).replace('<','\\u003c')+html[match.end(2):])
        evil.locator('#tlsMetadata').click()
        check(evil.locator('#content img').count()==0,'metadata escaped')
        check(evil.evaluate('window.injected===undefined'),'no script injection');evil.close()
        check(not errors,'JavaScript errors: '+repr(errors));check(not network,'Network requests: '+repr(network))
        browser.close()
    print(f'PASS: {checks} TLS browser checks')


if __name__=='__main__':main()
