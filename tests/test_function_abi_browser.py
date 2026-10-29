#!/usr/bin/env python3
"""Function contract controls, exact caller evidence links, export and layout."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from playwright.sync_api import sync_playwright
from test_function_abi import PROFILE, call_program, diamond
from test_pseudocode import ROOT, report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('analyzer',type=Path)
    p.add_argument('--fixtures',type=Path,required=True)
    p.add_argument('--chromium',default=shutil.which('chromium'))
    a=p.parse_args(); path=(a.fixtures/'recovery64-o1.html').resolve()
    text=path.read_text(); data=json.loads(re.search(r'<script id="report-data" type="application/json">(.*?)</script>',text,re.S)[1])
    f=next(f for f in data['functions'] if f['name']=='transform_demo')
    route='#'+data['module']['id']+'_c_'+format(f['rva'],'x')
    checks=0
    def check(ok,why):
        nonlocal checks
        assert ok,why
        checks+=1
    with tempfile.TemporaryDirectory() as temp, sync_playwright() as pw:
        browser=pw.chromium.launch(executable_path=a.chromium,args=['--no-sandbox'])
        page=browser.new_page(viewport={'width':1440,'height':1000}); errors=[]
        page.on('pageerror',lambda e:errors.append(str(e))); page.set_default_timeout(8000)
        page.goto(path.as_uri()+route)
        if not data['module']['decoderInfo']['capabilities']['structuredOperands']:
            check(not page.locator('#pseudoFunctionProfile').count(),'LLVM cannot select semantic ABI profile')
            check('Structured operands unavailable' in page.locator('.pseudocode-overview').inner_text(),'LLVM has honest fallback')
        else:
            code=page.locator('.pseudo-code tbody tr td:nth-child(2) code').all_text_contents()
            check(not page.locator('#pseudoFunctionABI').is_visible(),'ABI controls stay under Analysis details')
            page.click('#pseudoTabanalysis');page.locator('#pseudoFunctionABI > summary').click()
            check(page.locator('#pseudoFunctionProfile').input_value()=='','no automatic convention')
            check(not page.locator('.pseudo-abi-inputs').count(),'default has no guessed signature')
            page.select_option('#pseudoFunctionProfile',PROFILE)
            check(page.locator('.pseudo-abi-inputs tbody tr').count()==4,'complex source demo exposes four register input candidates')
            check('function calling convention is assumed' in page.locator('.pseudo-warning').inner_text(),'selected assumption remains visible above tabs')
            check('varargs' in page.locator('#pseudoFunctionABI').inner_text() and 'hidden parameters' in page.locator('#pseudoFunctionABI').inner_text(),'signature uncertainty is explicit')
            page.locator('#pseudoFunctionProfile').focus();page.locator('#pseudoFunctionProfile').press('Home')
            check(page.locator('#pseudoFunctionProfile').input_value()=='','keyboard clears native selection')
            page.locator('#pseudoFunctionProfile').focus();page.locator('#pseudoFunctionProfile').press('End')
            check(page.locator('#pseudoFunctionProfile').input_value()==PROFILE,'keyboard selects native profile')
            check(page.locator('.pseudo-code tbody tr td:nth-child(2) code').all_text_contents()==code,'ABI selection never changes code')
            check(page.locator('.pseudo-abi-returns tbody tr').count()>=1,'return evidence exposed')
            page.locator('.pseudo-abi-inputs details > summary').first.click()
            source=page.locator('.pseudo-abi-inputs .pseudo-source').first; target=source.get_attribute('href')
            source.click();page.wait_for_selector('.function-overview')
            check(page.evaluate('location.hash')==target,'input evidence opens exact assembly')
            page.go_back();page.wait_for_selector('#pseudoFunctionProfile')
            check(page.locator('#pseudoPanelanalysis').is_visible() and page.locator('#pseudoFunctionABI').evaluate('(e)=>e.open') and
                  page.locator('#pseudoFunctionProfile').input_value()==PROFILE,'Back restores analysis and function contract')
            page.locator('.pseudo-abi-caller > summary').first.click()
            source=page.locator('.pseudo-abi-caller > p .pseudo-source').first; target=source.get_attribute('href')
            caller=next(f for f in data['functions'] if f['name']=='pe_entry')
            check('_fn_'+format(caller['rva'],'x')+'_at_' in target,'caller evidence routes to the caller owner')
            source.click();page.wait_for_selector('.function-overview')
            check(page.evaluate('location.hash')==target,'caller instruction navigation')
            page.go_back();page.wait_for_selector('#pseudoFunctionProfile')
            check(page.evaluate('location.hash')==route and page.locator('#pseudoFunctionProfile').input_value()==PROFILE,'Back restores callee and its assumption')
            with page.expect_download() as download:
                page.click('#pseudoFunctionExport')
            file=Path(temp)/'contract.json';download.value.save_as(file);contract=json.loads(file.read_text())
            check(contract=={'version':1,'moduleId':data['module']['id'],'functionId':f['id'],'profile':PROFILE},'export binds exact report/function/profile')
            model=page.evaluate('q=>WEAPseudocodeModel.recover(D,q.id,{functionContract:q.contract})',{'id':f['id'],'contract':contract})
            cli=subprocess.run(['node',str(ROOT/'scripts/pseudocode.js'),str(a.fixtures/'recovery64-o1.json'),hex(f['rva']),
                                '--function-contract',str(file),'--json'],capture_output=True,text=True,check=True)
            check(json.loads(cli.stdout)==model,'exported contract gives identical browser/CLI model')
            page.click('#pseudoFunctionReset')
            check(page.locator('#pseudoFunctionProfile').input_value()=='' and not page.locator('.pseudo-abi-inputs').count(),'clear removes evidence')
            page.set_input_files('#pseudoFunctionFile',str(file))
            page.wait_for_function("document.querySelectorAll('.pseudo-abi-inputs tbody tr').length === 4")
            check(page.locator('.pseudo-abi-inputs tbody tr').count()==4,'valid import restores evidence')
            for payload in [dict(contract,moduleId='wrong'),dict(contract,extra='<img src=x onerror=alert(1)>'),None]:
                bad=Path(temp)/'bad.json';bad.write_text(json.dumps(payload))
                page.set_input_files('#pseudoFunctionFile',str(bad))
                page.wait_for_function("document.querySelector('#pseudoFunctionABI').textContent.includes('must match')")
                check(not page.locator('.pseudo-abi-inputs').count() and page.locator('#pseudoFunctionProfile').input_value()=='','invalid import rejects the whole contract')
            for payload in ['{',' '*65537]:
                page.select_option('#pseudoFunctionProfile',PROFILE)
                bad=Path(temp)/'bad.json';bad.write_text(payload);page.set_input_files('#pseudoFunctionFile',str(bad))
                page.wait_for_function("document.querySelector('#pseudoFunctionProfile').value === ''")
                check(not page.locator('.pseudo-abi-inputs').count(),'parse/size error clears previous contract')
            page.select_option('#pseudoFunctionProfile',PROFILE)
            page.locator('#labelname').fill('ABI demo label');page.click('#saveLabel')
            check(page.locator('#pseudoFunctionProfile').input_value()==PROFILE,'rename keeps function contract separate')
            page.set_viewport_size({'width':390,'height':844})
            check(page.evaluate('document.documentElement.scrollWidth <= innerWidth'),'phone layout has no page-wide overflow')
            page.screenshot(path=str(a.fixtures/'function-abi-mobile.png'),full_page=True)
            page.set_viewport_size({'width':1440,'height':1000})
            page.screenshot(path=str(a.fixtures/'function-abi-desktop.png'),full_page=True)
            page.reload();page.click('#pseudoTabanalysis');page.locator('#pseudoFunctionABI > summary').click()
            check(page.locator('#pseudoFunctionProfile').input_value()=='','reload clears the contract')
        if data['module']['decoderInfo']['capabilities']['structuredOperands']:
            generated=Path(temp)
            sd=report(a.analyzer,generated,call_program(prefix='c74424202a000000'+diamond(),callee=diamond(tail='8b442428c3')))
            subprocess.run([str(a.analyzer.resolve()),str(generated/'case.exe'),'--html',str(generated/'stack.html')],check=True,capture_output=True)
            sf=max(sd['functions'],key=lambda f:f['rva'])
            page.goto((generated/'stack.html').as_uri()+'#'+sd['module']['id']+'_c_'+format(sf['rva'],'x'))
            page.click('#pseudoTabanalysis')
            page.evaluate('''profile => {
                document.querySelector('#pseudoFunctionABI').open = true;
                const select = document.querySelector('#pseudoFunctionProfile');
                select.value = profile;
                select.dispatchEvent(new Event('change', {bubbles:true}));
            }''',PROFILE)
            check(page.locator('#pseudoFunctionABI').evaluate('(e)=>e.open'),'same-task contract change preserves open details')
            check(page.locator('.pseudo-abi-stack tbody tr').count()==1,'one incoming stack input in authored demo')
            check('40' in page.locator('.pseudo-abi-stack').inner_text(),'entry-relative address remains visible')
            check('every incoming path' in page.locator('#pseudoFunctionABI').inner_text(),'stack path scope is visible')
            page.locator('.pseudo-abi-stack details > summary').click()
            links=page.locator('.pseudo-abi-stack .pseudo-source')
            check(links.count()>=4,'joined incoming read exposes predecessor and read witnesses')
            source=links.first;target=source.get_attribute('href');source.click();page.wait_for_selector('.function-overview')
            check(page.evaluate('location.hash')==target,'incoming join witness opens exact assembly')
            page.go_back();page.wait_for_selector('#pseudoFunctionProfile')
            page.locator('.pseudo-abi-caller > summary').click()
            check('matching preceding store' in page.locator('.pseudo-abi-stack-match').inner_text(),'caller store evidence exposed')
            check(page.locator('.pseudo-abi-stack-match + details .pseudo-source').count()>=8,'caller match includes both joined path proofs')
            page.locator('.pseudo-abi-caller details > summary').last.click()
            source=page.locator('.pseudo-abi-caller details').last.locator('.pseudo-source').first
            target=source.get_attribute('href'); source.click();page.wait_for_selector('.function-overview')
            check(page.evaluate('location.hash')==target,'stack evidence links to exact assembly')
            page.go_back();page.wait_for_selector('#pseudoFunctionProfile')
            check(page.locator('.pseudo-abi-stack tbody tr').count()==1,'Back retains stack contract')
            page.set_viewport_size({'width':390,'height':844})
            check(page.evaluate('document.documentElement.scrollWidth <= innerWidth'),'stack table fits phone layout')
            page.set_viewport_size({'width':1440,'height':1000})
            page.locator('#pseudoDeclarations > summary').click()
            page.click('#pseudoDeclarationExample')
            draft=json.loads(page.locator('#pseudoDeclarationEditor').input_value())
            check(draft[0]['variadic']=='unknown' and draft[0]['hiddenParameters']=='unknown','blank declaration defaults to uncertainty')
            hostile='<img src=x onerror=alert(1)>'
            declarations=[{'id':'header','source':hostile,'returnType':'void','parameters':[],'variadic':'no','hiddenParameters':'no'},
                          {'id':'notes','source':'S'*256,'returnType':'T'*128,'parameters':[{'name':'x','type':'char const * volatile'},
                              {'name':'n','type':'size_t'},{'name':'cb','type':'int (*)(void)'},{'name':'unknown','type':None},
                              {'name':'text','type':hostile}],'variadic':'unknown','hiddenParameters':'unknown'}]
            page.locator('#pseudoDeclarationEditor').fill(json.dumps(declarations));page.click('#pseudoDeclarationApply')
            check(page.locator('.pseudo-declaration').count()==2,'all declarations retained')
            check(page.locator('.pseudo-declaration-conflict').count()==1,'declaration disagreements visible')
            check(page.locator('.pseudo-declaration-review').count()>=1,'stack candidate outside declared list has review evidence')
            check(hostile in page.locator('.pseudo-declaration').first.inner_text() and page.locator('.pseudo-declaration img').count()==0,'source labels escaped')
            check('Parsed annotation: const char * volatile' in page.locator('.pseudo-declaration').nth(1).inner_text(),'pointer and pointee qualifiers render separately')
            check(page.locator('.pseudo-type-annotation[data-type-status="unsupported"]').count()==4,'unresolved names and unsupported syntax visibly retained')
            check(page.locator('.pseudo-type-annotation[data-type-status="unknown"]').count()==1,'unspecified annotation remains distinct')
            check(hostile in page.locator('.pseudo-declaration').nth(1).inner_text() and not page.locator('.pseudo-declaration img').count(),'hostile type label is escaped without partial parsing')
            check(page.locator('.pseudo-declaration-comparison').count()==1,'one comparison for two supplied declarations')
            page.locator('#pseudoDeclarationComparisons > summary').click()
            page.locator('.pseudo-declaration-comparison > summary').focus();page.keyboard.press('Space')
            check(page.locator('.pseudo-declaration-comparison').evaluate('(e)=>e.open'),'comparison expands with native keyboard interaction')
            check(page.locator('.pseudo-declaration-comparison [data-comparison-status="unknown"]').count()==8,'missing and unsupported types and unknown flags remain visible')
            check(hostile in page.locator('.pseudo-declaration-comparison').inner_text() and not page.locator('.pseudo-declaration-comparison img').count(),'comparison labels are escaped')
            page.locator('#pseudoDeclarationEditor').fill('[{}]');page.click('#pseudoDeclarationApply')
            check(page.locator('.pseudo-declaration').count()==2,'invalid editor preserves applied declarations')
            with page.expect_download() as dl:page.click('#pseudoFunctionExport')
            exported=Path(temp)/'declarations.json';dl.value.save_as(exported);saved=json.loads(exported.read_text())
            check(saved['version']==2 and saved['declarations']==declarations,'version 2 export round trip')
            model=page.evaluate('q=>WEAPseudocodeModel.recover(D,q.id,{functionContract:q.contract})',{'id':sf['id'],'contract':saved})
            cli=subprocess.run(['node',str(ROOT/'scripts/pseudocode.js'),str(generated/'case.json'),hex(sf['rva']),'--function-contract',str(exported),'--json'],capture_output=True,text=True,check=True)
            check(json.loads(cli.stdout)==model,'declarations and reviews match CLI JSON')
            check(model['functionABI']['declarationTypeGrammar']=='c11-scalar-pointer-v1' and model['functionABI']['declarationTypes'][1]['parameters'][0]['canonical']=='const char * volatile','browser and CLI carry the versioned syntax tree')
            page.click('#pseudoDeclarationClear')
            check(not page.locator('.pseudo-declaration').count() and page.locator('#pseudoFunctionProfile').input_value()==PROFILE,'clearing declarations preserves convention')
            page.set_input_files('#pseudoFunctionFile',str(exported));page.wait_for_selector('.pseudo-declaration')
            check(page.locator('.pseudo-declaration').count()==2,'import restores all declarations')
            page.select_option('#pseudoFunctionProfile','')
            check(page.locator('.pseudo-declaration').count()==2 and not page.locator('.pseudo-abi-stack').count(),'declarations remain separate from machine convention')
            check(page.locator('.pseudo-type-annotation[data-type-status="parsed"]').count()==2,'parsed annotations remain when convention is unknown')
            check(page.locator('.pseudo-declaration-comparison').evaluate('(e)=>e.open'),'expanded comparison survives import and convention changes')
            page.set_viewport_size({'width':390,'height':844})
            check(page.evaluate('document.documentElement.scrollWidth <= innerWidth'),'declaration editor and conflicts fit phone')
            page.reload();page.click('#pseudoTabanalysis');page.locator('#pseudoFunctionABI > summary').click()
            check(not page.locator('.pseudo-declaration').count(),'reload clears session declarations')
            page.locator('#pseudoDeclarations > summary').click()
            pair=[{'id':'header','source':'header.h','returnType':'unsigned','parameters':[{'name':'p','type':'const int *'},{'name':'n','type':'size_t'}],'variadic':'no','hiddenParameters':'no'},
                  {'id':'notes','source':'notes','returnType':'unsigned int','parameters':[{'name':'p','type':'int *'},{'name':'n','type':'size_t'}],'variadic':'unknown','hiddenParameters':'no'}]
            before=page.locator('.pseudo-code tbody tr td:nth-child(2) code').all_text_contents()
            page.locator('#pseudoDeclarationEditor').fill(json.dumps(pair));page.click('#pseudoDeclarationApply')
            page.locator('#pseudoDeclarationComparisons > summary').click();page.locator('.pseudo-declaration-comparison > summary').click()
            comparison_text=page.locator('.pseudo-declaration-comparison').inner_text()
            check('Same parsed form' in comparison_text and 'Different parsed form' in comparison_text,'parsed agreement and differences are visible together')
            check('qualifiers at pointee depth 1: const / unqualified' in comparison_text,'qualifier difference identifies the precise pointer level')
            check(page.locator('.pseudo-declaration-comparison [data-comparison-status="unknown"]').count()==2,'matching typedef spellings and unknown flag remain unresolved')
            check(page.locator('.pseudo-declaration-conflict').count()==1,'textual differences are retained alongside matching parsed forms')
            check(page.locator('.pseudo-code tbody tr td:nth-child(2) code').all_text_contents()==before,'comparisons do not rewrite code')
            check(page.evaluate('document.documentElement.scrollWidth <= innerWidth'),'expanded comparison table fits phone layout')
            with page.expect_download() as dl:page.click('#pseudoFunctionExport')
            compared_file=Path(temp)/'comparisons.json';dl.value.save_as(compared_file);saved=json.loads(compared_file.read_text())
            check(saved['declarations']==pair and saved['profile'] is None,'comparison export retains original declarations with unknown convention')
            model=page.evaluate('q=>WEAPseudocodeModel.recover(D,q.id,{functionContract:q.contract})',{'id':sf['id'],'contract':saved})
            cli=subprocess.run(['node',str(ROOT/'scripts/pseudocode.js'),str(generated/'case.json'),hex(sf['rva']),'--function-contract',str(compared_file),'--json'],capture_output=True,text=True,check=True)
            check(json.loads(cli.stdout)==model and model['functionABI']['declarationComparisonPolicy']=='parsed-annotation-forms-v1','browser and CLI share the exact versioned comparison records')
            page.click('#pseudoDeclarationClear')
            check(not page.locator('.pseudo-declaration-comparison').count(),'clear removes all derived comparisons')
        check(not errors,'no browser errors: '+str(errors));browser.close()
    print(f'PASS: {checks} function-ABI browser checks')


if __name__=='__main__':main()
