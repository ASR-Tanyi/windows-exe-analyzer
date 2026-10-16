import json
import argparse
import shutil
import tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright
parser=argparse.ArgumentParser()
parser.add_argument('--fixtures', type=Path, required=True)
parser.add_argument('--chromium',default=shutil.which('chromium'))
args=parser.parse_args()
root=args.fixtures.resolve()
shots=Path(tempfile.mkdtemp(prefix='windows-exe-analyzer-browser-'))
d=json.loads((root/'demo64.json').read_text())
with sync_playwright() as p:
 browser=p.chromium.launch(executable_path=args.chromium,args=['--no-sandbox'])
 page=browser.new_page(viewport={'width':1536,'height':1120},device_scale_factor=1)
 errors=[];requests=[]
 page.on('pageerror',lambda e:errors.append(str(e)))
 page.on('request',lambda r:requests.append(r.url))
 page.set_content((root/'demo64.html').read_text())
 assert page.locator('.blocktitle').inner_text()=='pe_entry'
 page.screenshot(path=str(shots/'view-entry.png'),full_page=True)
 entry_call=next(e for e in d['edges'] if e['from']==d['module']['entryId'] and e['kind']=='call')
 page.locator('.targetlink').click()
 assert page.locator('.blocktitle').inner_text()=='main'
 page.locator('#back').click();page.wait_for_timeout(150)
 assert page.url.endswith('#'+entry_call['source']),page.url
 assert page.locator('tr.focused').count()==1
 page.locator('#forward').click();page.wait_for_timeout(150)
 assert page.locator('.blocktitle').inner_text()=='main'
 page.locator('#labelname').fill('main_reviewed');page.locator('#labelnote').fill('Reviewed from the known source; not inferred from startup.')
 page.locator('#saveLabel').click()
 assert page.locator('.blocktitle').inner_text()=='main_reviewed'
 page.locator('#entry').click()
 assert page.locator('.targetlink').inner_text().endswith('main_reviewed')
 page.locator('#main').click();page.locator('#resetLabel').click()
 page.locator('[data-tab="imports"]').click();page.locator('.symbol').click()
 assert 'transform_score' in page.locator('#content').inner_text()
 page.locator('.flowcard').first.click()
 assert page.locator('tr.focused').count()==1
 page.locator('[data-tab="all"]').click()
 page.locator('#entry').click()
 page.screenshot(path=str(shots/'view-entry-tested.png'),full_page=True)
 page.set_viewport_size({'width':390,'height':844})
 page.screenshot(path=str(shots/'view-mobile.png'),full_page=True)
 assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Page-wide overflow on mobile'
 page.set_viewport_size({'width':1536,'height':1120})
 page=browser.new_page(viewport={'width':1536,'height':1120})
 page.on('pageerror',lambda e:errors.append(str(e)))
 page.set_content((root/'dll64.html').read_text())
 assert page.locator('.blocktitle').inner_text()=='transform_score'
 assert page.locator('#entry').is_disabled()
 print('Browser assertions passed. JS errors:',errors)
 print('Screenshots:',shots)
 print('Network requests:',requests)
 assert not errors
 browser.close()
