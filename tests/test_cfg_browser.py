#!/usr/bin/env python3
"""Interactive CFG browser regressions over generated source-known reports."""
import argparse,json,re,shutil
from pathlib import Path
from playwright.sync_api import sync_playwright

def main():
    p=argparse.ArgumentParser();p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--chromium',default=shutil.which('chromium'));args=p.parse_args()
    html=(args.fixtures/'demo64.html').read_text(encoding='utf-8')
    m=re.search(r'(<script id="report-data" type="application/json">)(.*?)(</script>)',html,re.S);data=json.loads(m[2]);checks=0
    def check(ok,name):
        nonlocal checks
        if not ok:raise AssertionError(name)
        checks+=1
    def patched(d):return html[:m.start(2)]+json.dumps(d).replace('<','\\u003c')+html[m.end(2):]
    with sync_playwright() as pw:
        browser=pw.chromium.launch(executable_path=args.chromium,args=['--no-sandbox'])
        errors=[]
        page=browser.new_page(viewport={'width':1440,'height':1000});page.set_default_timeout(8000);page.on('pageerror',lambda e:errors.append(str(e)));page.set_content(html)
        page.click('#main');page.click('#functionCfg');page.wait_for_selector('.cfg-overview')
        check(page.locator('.cfg-node').count()>0,'graph nodes')
        check(page.locator('.cfg-edge').count()>0,'graph edges')
        check('not proof' in page.locator('.cfg-overview').inner_text().lower(),'incomplete contract visible')
        first=page.locator('.cfg-node').first;first.click();check('_cfg_' in page.evaluate('location.hash'),'node selection route')
        check(page.locator('.cfg-node.selected').count()==1,'selected block')
        before=page.locator('#cfgZoomReset').inner_text();page.click('#cfgZoomIn');check(page.locator('#cfgZoomReset').inner_text()!=before,'zoom')
        page.locator('.cfg-canvas').focus()
        # Dispatch within one task so a deferred animation-frame focus cannot
        # hide a gap between replacing the canvas and accepting the next key.
        moved_and_focused=page.evaluate('''() => {
            const old = document.querySelector('.cfg-canvas');
            old.dispatchEvent(new KeyboardEvent('keydown', {key:'ArrowRight', bubbles:true}));
            const current = document.querySelector('.cfg-canvas');
            return current !== old && document.activeElement === current;
        }''')
        check(moved_and_focused,'keyboard selection immediately focuses replacement canvas')
        check('_cfg_' in page.evaluate('location.hash'),'keyboard selection')
        page.keyboard.press('Enter');page.wait_for_selector('.function-overview:not(.cfg-overview)');check('_fn_' in page.evaluate('location.hash'),'enter opens whole-function assembly')
        page.evaluate('history.back()');page.wait_for_selector('.cfg-overview');check(page.locator('.cfg-node.selected').count()==1,'back restores graph selection')
        check('outside / unknown exits' in page.locator('#connections').inner_text().lower(),'unknown exit panel')
        # Force list fallback using a synthetic function with >120 blocks.
        d=json.loads(json.dumps(data));mid=d['module']['id'];blocks=[];edges=[]
        for i in range(125):
            r=0x5000+i*0x10;bid=mid+'_b_'+format(r,'x');iid=mid+'_i_'+format(r,'x')
            blocks.append({'rva':r,'va':hex(int(d['module']['imageBase'],16)+r),'id':bid,'name':'g'+str(i),'role':'block','summary':'','evidence':'ui fixture','owners':[mid+'_b_5000'],'instructions':[{'rva':r,'va':hex(int(d['module']['imageBase'],16)+r),'id':iid,'size':1,'bytes':'90','mnemonic':'nop','operands':'','notes':'','dataRefs':[]}]})
            if i:edges.append({'from':blocks[i-1]['id'],'source':blocks[i-1]['instructions'][0]['id'],'to':bid,'kind':'jump','external':'','target':''})
        fid=mid+'_b_5000';d['functions']=[{'rva':0x5000,'id':fid,'name':'large_graph','evidence':'fixture','evidenceRecords':[],'decodedRanges':[]}];d['blocks']=blocks;d['edges']=edges;d['module']['entryId']=fid;d['module']['mainId']=fid;d['module']['instructionCount']=125
        q=browser.new_page(viewport={'width':1000,'height':800});q.set_content(patched(d));q.click('#main');q.click('#functionCfg');q.wait_for_selector('.cfg-list')
        check(q.locator('.cfg-svg').count()==0,'layout fallback hides svg');check('Graph layout limit reached' in q.locator('.cfg-overview').inner_text(),'fallback reason')
        check(q.locator('.cfg-list-node').count()==125,'fallback retains all bounded fixture blocks')
        q.close();check(not errors,'JavaScript errors: '+repr(errors));browser.close()
    print('PASS: %d cfg-browser checks'%checks)
if __name__=='__main__':main()
