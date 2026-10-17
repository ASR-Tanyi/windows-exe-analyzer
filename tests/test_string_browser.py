#!/usr/bin/env python3
"""String UI integration, including whole-function history. Never executes PE."""
import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright
from test_strings import make_image


def main():
    parser=argparse.ArgumentParser();parser.add_argument('analyzer',type=Path);parser.add_argument('--document-navigation',action='store_true');args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='wea-string-browser-') as tmp:
        root=Path(tmp);exe=root/'sample.exe';exe.write_bytes(make_image())
        report=root/'report.html';metadata=root/'report.json'
        subprocess.run([str(args.analyzer.resolve()),str(exe),'--html',str(report),'--json',str(metadata)],check=True,capture_output=True,timeout=20)
        html=report.read_text();data=json.loads(metadata.read_text());module=data['module']['id']
        ascii_item=next(s for s in data['strings']['candidates'] if s['rva']==0x2000 and s['encoding']=='ASCII')
        sid=ascii_item['id'];insn=module+'_i_1000';base=module+'_strings'
        count=0;errors=[];requests=[]
        def check(ok,message):
            nonlocal count
            count+=1
            if not ok:raise AssertionError(message)
        def patched(d):
            safe=json.dumps(d,ensure_ascii=True).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
            return re.sub(r'(<script id="report-data" type="application/json">).*?(</script>)',lambda m:m[1]+safe+m[2],html,flags=re.S)
        with sync_playwright() as pw:
            executable=os.environ.get('WEA_CHROMIUM') or shutil.which('chromium')
            browser=pw.chromium.launch(headless=True,**({'executable_path':executable} if executable else {}))
            page=None;current=[html]
            def load(name,fragment=''):
                nonlocal page
                if page is None or not args.document_navigation:
                    if page is not None:page.close()
                    page=browser.new_page(viewport={'width':1440,'height':1000});page.set_default_timeout(6000)
                    page.on('pageerror',lambda e:errors.append(str(e)))
                    page.route('https://wea.test/**',lambda r:r.fulfill(status=200,content_type='text/html',body=current[0]))
                    page.on('request',lambda r:requests.append(r.url) if not r.url.startswith('https://wea.test/') else None)
                if args.document_navigation:page.goto('https://wea.test/'+name+('#'+fragment if fragment else ''))
                else:
                    page.evaluate("hash=>history.replaceState(null,'',hash?'#'+hash:'about:blank')",fragment)
                    page.set_content(current[0])
            load('report');page.wait_for_selector('#browseStrings')
            check(page.locator('#browseStrings').is_visible(),'toolbar')
            page.click('#wholeFunction');page.wait_for_selector('.function-block')
            check(page.locator('a.string-inline').count()>0,'inline candidate links in function')
            page.locator('a.string-inline[href="#'+sid+'"]').first.click();page.wait_for_selector('.string-source')
            check(page.locator('#content').inner_text().find('Alpha Beta')>=0,'detail text')
            check('1 exact / 1 interior' in page.locator('#connections').inner_text(),'exact/interior refs')
            check(page.locator('.string-owner').count()==2,'owning functions')
            page.click('#back');page.wait_for_selector('tr.focused');
            check('_fn_1000_at_1000' in page.url,'function-qualified history')
            check(page.locator('tr.focused').get_attribute('id')==insn,'exact source focus')
            page.click('#forward');page.wait_for_selector('.string-source')
            check(sid in page.url,'forward detail')
            page.click('a.string-bytes');page.wait_for_selector('.hexdump')
            check(page.locator('.string-containing').count()>0,'data links to containing strings')
            page.click('#back');page.wait_for_selector('.string-source')
            page.locator('.string-source').first.click();page.wait_for_selector('tr.focused')
            check(page.locator('tr.focused').get_attribute('id')==insn,'source instruction link')
            page.click('#back');page.wait_for_selector('.string-owner');page.locator('.string-owner').first.click()
            page.wait_for_selector('.function-block');check('_fn_1000_at_1000' in page.url,'function owner link')
            page.click('#browseStrings');page.wait_for_selector('#stringResults')
            check(page.locator('#stringResults tbody tr').count()==len(data['strings']['candidates']),'list retained candidates')
            page.fill('#stringQuery','\u6d4b\u8bd5');page.select_option('#stringEncoding','UTF-16LE');page.locator('#stringSearchForm button').click()
            check(page.locator('#stringResults tbody tr').count()==1,'Unicode search/filter')
            page.locator('#stringResults .string-open').first.click();page.wait_for_selector('.stringvalue')
            check('\U0001f680' in page.locator('.stringvalue').inner_text(),'supplementary text rendered')
            page.click('#back');page.wait_for_selector('#stringQuery');check(page.input_value('#stringQuery')=='\u6d4b\u8bd5','search history')
            check(page.input_value('#stringEncoding')=='UTF-16LE','encoding history')
            if args.document_navigation:
                page.reload();page.wait_for_selector('#stringQuery');check(page.input_value('#stringQuery')=='\u6d4b\u8bd5','reload filter deep link')
            else:print('SKIP: real document reload (use --document-navigation in unrestricted CI)')
            page.fill('#stringQuery','</script>');page.select_option('#stringEncoding','ASCII');page.locator('#stringSearchForm button').click()
            check(page.locator('#stringResults tbody tr').count()==1,'unsafe text searchable')
            page.locator('#stringResults .string-open').first.click();check(page.locator('#content img').count()==0,'HTML escaped')
            check('</script>' in page.locator('.stringvalue').inner_text(),'unsafe bytes displayed literally')
            check('No discovered' in page.locator('#connections').inner_text(),'no xref not unused')
            load('report',sid);page.wait_for_selector('.string-source')
            check('Alpha Beta' in page.locator('#content').inner_text(),'direct detail deep link')
            page.set_viewport_size({'width':390,'height':844});page.click('#browseStrings');page.wait_for_selector('#stringResults')
            check(page.locator('#stringSearchForm').is_visible(),'mobile search')
            check(page.evaluate('document.documentElement.scrollWidth <= innerWidth+1'),'mobile outer width')
            page.set_viewport_size({'width':1440,'height':1000})
            many=json.loads(json.dumps(data));many['strings']['candidates']=[dict(ascii_item,id=module+'_str_a_'+format(0x2000+k,'x'),rva=0x2000+k,text='candidate-'+str(k)) for k in range(230)]
            current[0]=patched(many);load('many',base);page.wait_for_selector('#stringResults')
            check(page.locator('#stringResults tbody tr').count()==100,'bounded first page');page.click('#stringsNext')
            check(page.locator('#stringResults tbody tr').count()==100,'second page');page.click('#stringsNext')
            check(page.locator('#stringResults tbody tr').count()==30,'last page');check(page.locator('#stringsNext').is_disabled(),'last disabled')
            partial=json.loads(json.dumps(data));partial['strings']['partial']=True;partial['strings']['reasons']=['scan_limit'];current[0]=patched(partial)
            load('partial',base);check('Partial discovery' in page.locator('#content').inner_text(),'partial clear')
            disabled=json.loads(json.dumps(data));disabled['strings']['enabled']=False;disabled['strings']['candidates']=[];current[0]=patched(disabled)
            load('disabled',base);check('disabled' in page.locator('#content').inner_text(),'disabled clear')
            old=json.loads(json.dumps(data));old.pop('strings');current[0]=patched(old);load('legacy')
            check(page.locator('#browseStrings').count()==0,'legacy UI preserved');check(page.locator('#wholeFunction').is_visible(),'legacy function UI')
            check(not errors,'JavaScript errors: '+repr(errors));check(not requests,'unexpected requests: '+repr(requests))
            browser.close()
        print(f'PASS: {count} string-browser checks document-navigation={args.document_navigation}; no external requests')

if __name__=='__main__':main()
