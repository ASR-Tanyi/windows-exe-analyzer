'use strict';
// Embedded before function-view, so its function-aware history also wraps these
// routes. No candidate, annotation identity or native CFG fact is overwritten.
(() => {
    const catalog=D.strings;
    if(D.schema!==2 || catalog?.version!==1 || !globalThis.WEAStringModel)return;
    const index=WEAStringModel.create(D), prefix=D.module.id+'_strings', pageSize=100;
    const names=new Map(D.functions.map(f=>[f.id,f]));
    function listId(q='',enc='all',page=0) {
        const p=new URLSearchParams();if(q)p.set('q',q);if(enc!=='all')p.set('enc',enc);if(page)p.set('p',String(page));
        return prefix+(p.size?'?'+p.toString():'');
    }
    const detailId=(s,page=0)=>s.id+(page?'_p'+page:'');
    function parse(id) {
        if(id===prefix || id.startsWith(prefix+'?')) {
            const p=new URLSearchParams(id.slice(prefix.length+1)),q=p.get('q')||'',enc=p.get('enc')||'all',raw=p.get('p')||'0';
            if(q.length>200||!['all','ASCII','UTF-16LE'].includes(enc)||!/^(0|[1-9][0-9]{0,5})$/.test(raw))return null;
            return {kind:'list',q,enc,page:Number(raw)};
        }
        const m=/^(.*?)(?:_p([1-9][0-9]{0,5}))?$/.exec(id),entry=m&&index.entries.get(m[1]);
        if(!entry)return null;const page=Number(m[2]||0);
        if(page && page*pageSize>=entry.refs.length)return null;
        return {kind:'detail',entry,page};
    }
    function bytes(rva,from) {const id=dataId(rva);return isDataId(id)?link(id,hex(rva),from,'string-bytes'):E(hex(rva))+' (unmapped)';}
    function warnings() {
        let h='<div class="summary">Text-shaped byte runs are candidates, not proven string objects. References are statically discovered address operands, not observed reads or execution.</div>';
        if(!catalog.enabled)h+='<div class="datawarning">String discovery was disabled for this report. Regenerate without --no-strings.</div>';
        if(catalog.partial)h+='<div class="datawarning">Partial discovery: '+E(catalog.reasons.join(', '))+'. The result list is not exhaustive.</div>';
        if(index.partial)h+='<div class="datawarning">Reference indexing reached '+index.linkLimit+' associations. Counts and lists below are partial.</div>';
        return h;
    }
    const preview=s=>E(JSON.stringify(s.text))+(s.previewTruncated?' <span class="muted">[preview truncated]</span>':'');
    function renderList(view) {
        const query=view.q.toLowerCase(),items=index.candidates.filter(s=>(view.enc==='all'||s.encoding===view.enc)&&
            (!query||[s.text,s.encoding,s.section,hex(s.rva)].some(x=>x.toLowerCase().includes(query))));
        const page=Math.min(view.page,Math.max(0,Math.ceil(items.length/pageSize)-1)),start=page*pageSize,id=listId(view.q,view.enc,page);
        selected=id;
        let h='<section class="blockcard"><div class="blockhead"><div class="eyebrow">Image-wide text candidates</div><h2 class="blocktitle">Static strings</h2>'+
            '<div class="addressmeta">'+catalog.selectedBytes.toLocaleString()+' selected / '+catalog.readableBytes.toLocaleString()+' readable bytes; '+
            catalog.completedDetectorPasses+' completed detector passes</div></div>'+warnings()+
            '<form id="stringSearchForm" class="datatools"><input id="stringQuery" maxlength="200" aria-label="Search string previews or addresses" placeholder="Text, section, or RVA" value="'+E(view.q)+'">'+
            '<select id="stringEncoding" aria-label="String encoding">'+['all','ASCII','UTF-16LE'].map(x=>'<option '+(view.enc===x?'selected ':'')+'value="'+x+'">'+(x==='all'?'All encodings':x)+'</option>').join('')+
            '</select><button>Search</button></form><p class="string-hint">Search covers retained previews (up to '+catalog.previewCharacters+' Unicode scalars), section names and RVAs. Distinct addresses are not merged by text.</p>'+
            '<div class="assemblywrap"><table id="stringResults"><thead><tr><th>Address / section</th><th>Encoding / bytes</th><th>Candidate text</th><th>Refs</th></tr></thead><tbody>';
        for(const s of items.slice(start,start+pageSize)) {
            const refs=index.entries.get(s.id).refs.length;
            h+='<tr><td>'+link(s.id,hex(s.rva),id,'string-open')+'<br>'+E(s.section)+'</td><td>'+E(s.encoding)+'<br>'+s.byteLength+' B'+
                (s.terminated?' / NUL':' / prefix')+'</td><td class="string-text">'+link(s.id,JSON.stringify(s.text),id,'string-open')+
                (s.previewTruncated?' <span class="muted">[preview truncated]</span>':'')+'</td><td>'+refs+(index.partial?'*':'')+'</td></tr>';
        }
        h+='</tbody></table></div><div class="blockfoot"><span>'+items.length+' matching / '+index.candidates.length+' retained candidates</span><div class="btns">'+
            '<button id="stringsPrev" '+(page?'':'disabled')+'>Previous strings</button><button id="stringsNext" '+(start+pageSize<items.length?'':'disabled')+'>Next strings</button></div></div></section>';
        $('content').innerHTML=h;
        $('stringSearchForm').onsubmit=e=>{e.preventDefault();navigate(listId($('stringQuery').value,$('stringEncoding').value));};
        $('stringsPrev').onclick=()=>navigate(listId(view.q,view.enc,page-1));$('stringsNext').onclick=()=>navigate(listId(view.q,view.enc,page+1));
        $('connections').innerHTML='<h3 class="eyebrow">Discovery scope</h3><div class="info">File-backed headers and readable sections, in RVA order. ASCII and both UTF-16LE alignments are scanned independently; strings are not joined across sections or gaps.'+
            '<p>Minimum: '+catalog.minCharacters+' Unicode scalars. Candidate limit: '+catalog.candidateLimit+'. Scan budget: '+catalog.scanLimit+' bytes. These limits are independent of the embedded data-byte budget.</p>'+
            '<p>Printable binary data can be a false positive. UTF-16 validation rejects unpaired surrogates; it does not prove that a byte sequence was intended as text.</p></div>';
        $('renamebox').hidden=true;renderSidebar();
    }
    function refHtml(item,from) {
        const i=item.instruction,b=I.get(i.id)?.block;
        const owners=item.owners.filter(id=>names.has(id)).map(id=>{
            const f=names.get(id),fn=D.module.id+'_fn_'+f.rva.toString(16)+'_at_'+i.rva.toString(16);
            return link(fn,label(B.get(id)||f),from,'string-owner');
        }).join(', ');
        return '<div class="flowcard"><div class="flowlabel">'+E(item.kind)+' / +'+item.offset+' bytes / '+E(item.ref.access||'unknown')+'</div>'+
            '<div>'+link(i.id,i.va||hex(i.rva),from,'string-source')+' '+E(b?label(b):'unknown block')+'</div>'+
            '<div class="xrefinstruction">'+E(i.mnemonic+' '+i.operands)+'</div>'+
            '<div class="small muted">Owner candidates: '+(owners||'unknown')+'</div></div>';
    }
    function renderDetail(view) {
        const s=view.entry.candidate,refs=view.entry.refs,id=detailId(s,view.page);selected=id;
        let h='<section class="blockcard"><div class="blockhead"><div class="eyebrow">String candidate / '+E(s.encoding)+'</div><h2 class="blocktitle">'+E(hex(s.rva))+'</h2>'+
            '<div class="addressmeta"><span>VA '+E(vaFor(s.rva))+'</span><span>Section '+E(s.section)+'</span><span>File '+E(s.fileOffset)+'</span></div></div>'+warnings()+
            '<div class="stringpreview"><div class="stringvalue">'+preview(s)+'</div></div><div class="interpret">'+
            '<p>'+s.byteLength+' text bytes / '+s.codeUnits+' code units / '+s.characters+' Unicode scalars. End: <b>'+E(s.endReason)+'</b>.</p>'+
            '<p>'+bytes(s.rva,id)+' &mdash; open original bytes. '+link(prefix,'All strings',id)+'</p>'+
            '<p class="small muted">Span ['+E(hex(s.rva))+', '+E(hex(s.rva+s.byteLength))+') excludes a terminator. Interior offsets are byte offsets, not character indexes.'+
            (s.endReason==='scan_limit'?' The span is only a scanned prefix; full length is unknown.':'')+'</p></div></section>';
        $('content').innerHTML=h;
        const exact=refs.filter(x=>x.kind==='exact').length;
        let r='<h3 class="eyebrow">References / '+refs.length+(index.partial?' (partial)':'')+'</h3><div class="small muted">'+exact+' exact / '+(refs.length-exact)+' interior</div>';
        r+=refs.slice(view.page*pageSize,(view.page+1)*pageSize).map(x=>refHtml(x,id)).join('')||'<p class="empty">No discovered constant-address reference starts inside this candidate. This does not mean it is unused.</p>';
        r+='<div class="renameactions"><button id="stringRefsPrev" '+(view.page?'':'disabled')+'>Previous refs</button><button id="stringRefsNext" '+((view.page+1)*pageSize<refs.length?'':'disabled')+'>Next refs</button></div>';
        $('connections').innerHTML=r;
        $('stringRefsPrev').onclick=()=>navigate(detailId(s,view.page-1));$('stringRefsNext').onclick=()=>navigate(detailId(s,view.page+1));
        $('renamebox').hidden=true;renderSidebar();
    }
    const oldLinks=dataLinksHtml;
    dataLinksHtml=function(i) {
        let h=oldLinks(i),ids=[...(index.byInstruction.get(i.id)||[])];
        for(const id of ids.slice(0,6)) {const s=index.entries.get(id).candidate;h+=link(id,'Text candidate: '+s.encoding+' '+JSON.stringify(s.text.slice(0,45)),i.id,'datalink string-inline');}
        if(ids.length>6)h+='<span class="small muted">More candidates in Strings.</span>';return h;
    };
    const oldData=renderData;
    renderData=function(rva) {
        oldData(rva);const matches=index.at(rva);
        if(matches.length)$('connections').insertAdjacentHTML('beforeend','<h3 class="eyebrow">Containing text candidates</h3>'+matches.slice(0,20).map(s=>
            '<p>'+link(s.id,s.encoding+' '+hex(s.rva)+' +'+(rva-s.rva)+' bytes',dataId(rva),'string-containing')+'</p>').join(''));
    };
    const oldRoute=route,oldNavigate=navigate;
    route=function(){const view=parse(location.hash.slice(1));if(!view)return oldRoute();if(view.kind==='list')renderList(view);else renderDetail(view);};
    navigate=function(id,from,...args) {
        if(!parse(id))return oldNavigate(id,from,...args);
        if(from&&location.hash!=='#'+from)history.replaceState(history.state,'','#'+from);
        if(location.hash!=='#'+id)history.pushState({via:from||null},'','#'+id);route();
    };
    const button=document.createElement('button');button.id='browseStrings';button.textContent='Strings ('+index.candidates.length+')';button.onclick=()=>navigate(prefix);
    $('notes').before(button);
    const style=document.createElement('style');style.textContent='.string-text{white-space:normal;min-width:180px;max-width:520px;overflow-wrap:anywhere}.string-hint{font-size:11px;color:var(--muted);padding:0 20px}#stringQuery{width:230px;max-width:100%}.string-source{color:var(--accent)}';
    document.head.appendChild(style);route();
})();
