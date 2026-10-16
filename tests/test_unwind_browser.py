#!/usr/bin/env python3
"""Unwind/code/data navigation and compatibility; input PE files never execute."""
import argparse
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from playwright.sync_api import sync_playwright
from unwind_fixture import info, make_unwind_pe


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('analyzer',type=Path)
    parser.add_argument('--chromium',default=shutil.which('chromium'))
    args=parser.parse_args();checks=0
    def check(value,message):
        nonlocal checks
        if not value:raise AssertionError(message)
        checks+=1
    with tempfile.TemporaryDirectory() as tmp,sync_playwright() as pw:
        root=Path(tmp);browser=pw.chromium.launch(executable_path=args.chromium,args=['--no-sandbox'])
        errors=[];network=[]
        def generate(name,**kwargs):
            path=root/(name+'.exe');make_unwind_pe(path,**kwargs)
            out=path.with_suffix('.html')
            subprocess.run([str(args.analyzer.resolve()),str(path),'--html',str(out)],check=True,capture_output=True,timeout=30)
            return out.read_text()
        def open_page(html):
            p=browser.new_page(viewport={'width':1500,'height':950})
            p.on('pageerror',lambda e:errors.append(str(e)));p.on('request',lambda r:network.append(r.url));p.set_content(html);return p
        nodes={0x3000:info(flags=4,trailer=struct.pack('<III',0x1040,0x1050,0x3020)),
               0x3020:info(flags=1,prolog=1,codes=b'\x01\x32',trailer=struct.pack('<I',0x1060))}
        html=generate('chain',records=[(0x1010,0x1030,0x3000),(0x1040,0x1050,0x3020)],nodes=nodes,
                      code={0x1000:b'\xc3',0x1010:b'\xc3',0x1040:b'\xc3',0x1060:b'\xc3'})
        page=open_page(html);check(page.locator('.blocktitle').inner_text()=='pe_entry','initial entry')
        page.locator('#exceptionMetadata').click()
        check(page.locator('#exceptionRecords tbody tr').count()==2,'metadata rows retained')
        check(page.locator('.exception-code').count()==2,'newly decoded candidates linked')
        check('decoded_candidate' in page.locator('#exceptionRecords').inner_text(),'discovery result visible')
        page.locator('#exceptionRecords .unwind-link').first.click()
        check(page.locator('.blocktitle').inner_text()=='Unwind info 0x3000','node view')
        node_hash=page.evaluate('location.hash')
        page.locator('.addressmeta a').click();page.wait_for_selector('.datacard')
        check(page.locator('.datacard').count()==1,'node bytes')
        page.locator('#back').click();page.wait_for_selector('#unwindOperations')
        check(page.evaluate('location.hash')==node_hash,'return to exact node')
        page.locator('#content .unwind-link').click()
        check('0x3020' in page.locator('.blocktitle').inner_text(),'chain parent')
        check('Handler candidate' in page.locator('#content').inner_text(),'handler identified')
        check('0x1060 (not decoded)' in page.locator('#content').inner_text(),'handler is not fabricated ordinary function')
        check('ALLOC_SMALL' in page.locator('#unwindOperations').inner_text(),'opcode view')
        page.locator('#content a[href$="_d_1060"]').click();page.wait_for_selector('.datacard')
        check(page.locator('.datacard').count()==1,'handler target file bytes')
        page.locator('#back').click();page.wait_for_selector('#unwindOperations')
        check('0x3020' in page.locator('.blocktitle').inner_text(),'handler bytes back')
        page.locator('#back').click();page.wait_for_function('(h)=>location.hash===h',arg=node_hash)
        check(page.locator('.blocktitle').inner_text()=='Unwind info 0x3000','chain history')
        page.evaluate("navigate(D.module.id + '_i_1010')")
        page.locator('.unwind-ranges summary').click()
        check('0x1030' in page.locator('.unwind-ranges').inner_text(),'metadata extent retained')
        page.locator('.analysis-ranges summary').click()
        check('0x1011' in page.locator('.analysis-ranges').inner_text(),'decoded extent separate')
        page.locator('.unwind-ranges .unwind-link').click();page.locator('#back').click();page.wait_for_selector('tr.focused')
        check(page.locator('tr.focused').get_attribute('id').endswith('_i_1010'),'exact instruction history')
        page.locator('#labelname').fill('reviewed_fragment');page.locator('#saveLabel').click()
        check(page.locator('.blocktitle').inner_text()=='reviewed_fragment','rename works')
        page.locator('.unwind-ranges summary').click()
        check('supported_v1' in page.locator('.unwind-ranges').inner_text(),'rename preserves metadata')
        page.evaluate('(h)=>{history.pushState(null,"",h);route();}',node_hash)
        check(page.locator('#unwindOperations').count()==1,'deep link')
        page.set_viewport_size({'width':390,'height':844})
        check(page.locator('#unwindInfo').is_visible(),'mobile toolbar')
        check(page.locator('.blocktitle').inner_text()=='Unwind info 0x3000','mobile node retained')
        unsupported=open_page(generate('unsupported',nodes={0x3000:bytes([3,255,255,255])}))
        unsupported.locator('#unwindInfo').click()
        check('Opaque unsupported version' in unsupported.locator('#content').inner_text(),'unsupported scope')
        check(unsupported.locator('#unwindOperations tbody tr').count()==0,'no fabricated opcodes')
        cycle=open_page(generate('cycle',nodes={0x3000:info(flags=4,trailer=struct.pack('<III',0x1010,0x1030,0x3000))}))
        cycle.locator('#unwindInfo').click()
        check('unwind_chain_cycle' in cycle.locator('#connections').inner_text(),'cycle reason')
        check('blocked' in cycle.locator('#connections').inner_text(),'blocked discovery visible')
        match=re.search(r'(<script id="report-data" type="application/json">)(.*?)(</script>)',html,re.S)
        data=json.loads(match[2]);del data['unwindInfo']
        for f in data['functions']:f.pop('metadataRecords',None)
        legacy=html[:match.start(2)]+json.dumps(data).replace('<','\\u003c')+html[match.end(2):]
        old=open_page(legacy)
        check(old.locator('#unwindInfo').count()==0,'older reports require no new extension')
        old.locator('#exceptionMetadata').click();check(old.locator('#exceptionRecords').count()==1,'older metadata view')
        data=json.loads(match[2]);data['unwindInfo']['nodes'][0]['issues']=['<img src=x onerror="window.injected=1">']
        malicious=html[:match.start(2)]+json.dumps(data).replace('<','\\u003c')+html[match.end(2):]
        evil=open_page(malicious);evil.locator('#unwindInfo').click()
        check(evil.locator('#content img').count()==0,'issue escaping')
        check(evil.evaluate('window.injected === undefined'),'no script injection')
        check(not errors,'JavaScript errors: '+repr(errors));check(not network,'Network requests: '+repr(network))
        browser.close()
    print(f'PASS: {checks} unwind browser checks')


if __name__=='__main__':main()
