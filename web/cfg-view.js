'use strict';
// Interactive CFG view over existing report facts. No external layout/runtime.
(() => {
    if (D.schema !== 2 || !globalThis.WEAFunctionModel || !globalThis.WEACfgModel) return;
    const functions = WEAFunctionModel.create(D), prefix = D.module.id + '_cfg_', fnPrefix = D.module.id + '_fn_';
    const byRva = new Map(D.functions.map(f => [f.rva,f]));
    let active = null, zoom = 1, refocusGraph = false;
    function fnRoute(f, block=null) {
        if (!block) return fnPrefix + f.rva.toString(16);
        const insn = block.instructions?.[0];
        return insn ? fnPrefix + f.rva.toString(16) + '_at_' + insn.rva.toString(16) : fnPrefix + f.rva.toString(16);
    }
    function idFor(f, block=null) {return prefix + f.rva.toString(16) + (block ? '_b_' + block.rva.toString(16) : '');}
    function parse(id) {
        if (typeof id !== 'string' || !id.startsWith(prefix)) return null;
        const m=/^([0-9a-f]{1,8})(?:_b_([0-9a-f]{1,8}))?$/.exec(id.slice(prefix.length));
        if(!m)return null; const f=byRva.get(parseInt(m[1],16)); if(!f)return null;
        const graph=WEACfgModel.analyze(D,functions,f.id), selected=m[2]?B.get(D.module.id+'_b_'+parseInt(m[2],16).toString(16)):null;
        if(selected && !graph.nodes.some(b=>b.id===selected.id))return null;
        return {id,f,graph,selected:selected||graph.nodes[0]||null};
    }
    function nodeLabel(b){return label(b)+'\n'+hex(b.rva)+(b.owners?.length>1?'\nshared '+b.owners.length:'');}
    function edgeLabel(e){return e.kind==='taken'?'taken':e.kind==='not_taken'?'not taken':e.kind==='fallthrough'?'fallthrough':e.kind==='continuation'?'continuation':e.kind;}
    function graphSvg(view) {
        const g=view.graph, selected=view.selected?.id;
        if(!g.bounded)return '';
        let h='<div class="cfg-canvas" tabindex="0" aria-label="Control-flow graph"><svg class="cfg-svg" viewBox="0 0 '+g.width+' '+g.height+'" style="width:'+(g.width*zoom)+'px;height:'+(g.height*zoom)+'px" role="img">';
        h+='<defs><marker id="cfgArrow" markerWidth="8" markerHeight="8" refX="7" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z"/></marker></defs>';
        for(const e of g.edges){const a=g.positions.get(e.from),b=g.positions.get(e.to);if(!a||!b)continue;
            const x1=a.x+a.w,y1=a.y+a.h/2,x2=b.x,y2=b.y+b.h/2,mx=(x1+x2)/2;
            h+='<path class="cfg-edge" d="M '+x1+' '+y1+' C '+mx+' '+y1+', '+mx+' '+y2+', '+x2+' '+y2+'" marker-end="url(#cfgArrow)"/>';
            h+='<text class="cfg-edge-label" x="'+mx+'" y="'+((y1+y2)/2-5)+'">'+E(edgeLabel(e))+'</text>';
        }
        for(const b of g.nodes){const p=g.positions.get(b.id);if(!p)continue;const cls=['cfg-node',selected===b.id?'selected':'',g.unreachable.includes(b.id)?'unreachable':'',(b.owners||[]).length>1?'shared':''].filter(Boolean).join(' ');
            h+='<a href="#'+E(idFor(view.f,b))+'" data-cfg-node="'+E(b.id)+'"><g class="'+cls+'" tabindex="0" role="button" aria-label="'+E(nodeLabel(b).replace(/\n/g,' '))+'"><rect x="'+p.x+'" y="'+p.y+'" width="'+p.w+'" height="'+p.h+'" rx="9"/><text x="'+(p.x+10)+'" y="'+(p.y+22)+'"><tspan>'+E(label(b))+'</tspan><tspan x="'+(p.x+10)+'" dy="18">'+E(hex(b.rva))+'</tspan></text></g></a>';
        }
        return h+'</svg></div>';
    }
    function listFallback(view) {
        const g=view.graph;
        return '<div class="datawarning">Graph layout limit reached: '+g.nodes.length+' blocks / '+g.edges.length+' edges. Showing bounded list fallback; all report facts remain available.</div>'+
            '<div class="cfg-list">'+g.nodes.slice(0,500).map(b=>'<p>'+link(idFor(view.f,b),label(b)+' / '+hex(b.rva),view.id,'cfg-list-node')+
            ' <span class="small muted">out '+g.edges.filter(e=>e.from===b.id).length+' / in '+g.edges.filter(e=>e.to===b.id).length+'</span></p>').join('')+'</div>';
    }
    function analysisSummary(view){
        const g=view.graph, cyclic=g.regions.filter(r=>r.cyclic), irr=g.regions.filter(r=>r.irreducible);
        let h='<div class="function-stats">'+[[g.nodes.length,'Blocks'],[g.edges.length,'CFG edges'],[g.loops.length,'Natural loops'],[cyclic.length,'Cyclic SCCs']].map(([n,t])=>'<div class="stat"><div class="statvalue">'+n+'</div><div class="statlabel">'+E(t)+'</div></div>').join('')+'</div>';
        h+='<details open><summary>Graph analysis</summary><p class="small muted">Computed only from discovered intraprocedural edges. '+(g.incomplete?'This graph is incomplete or completeness is not proven. ':'')+(g.dominatorBudgetExceeded?'Dominator iteration budget exhausted. ':'')+'Backward addresses alone are not classified as loops.</p>';
        h+='<p><b>Reachable from entry:</b> '+g.reachable.size+' / '+g.nodes.length+'; <b>unreachable in discovered graph:</b> '+g.unreachable.length+'</p>';
        h+='<p><b>Irreducible cyclic regions:</b> '+irr.length+'</p>';
        h+='<div class="cfg-analysis-list"><b>Natural-loop candidates</b>'+(g.loops.map(loop=>'<p>'+link(idFor(view.f,B.get(loop.header)),label(B.get(loop.header)),view.id)+' &mdash; '+loop.members.length+' blocks / '+loop.backEdges.length+' back edge(s)</p>').join('')||'<p class="muted">None in the supported discovered graph.</p>')+'</div>';
        h+='<div class="cfg-analysis-list"><b>Cyclic SCCs</b>'+(cyclic.map(r=>'<p>'+(r.irreducible?'<span class="pill warn">IRREDUCIBLE</span> ':'')+r.members.map(id=>link(idFor(view.f,B.get(id)),label(B.get(id)),view.id)).join(', ')+'</p>').join('')||'<p class="muted">None.</p>')+'</div></details>';
        return h;
    }
    function render(view) {
        active=view;selected=view.selected?.id||view.f.id;setTab('functions');
        const g=view.graph,b=view.selected;
        let warning='';
        if(g.incomplete)warning+='<div class="datawarning">This CFG is a discovered subset, not proof of complete control flow.'+(g.unresolved.length?' '+g.unresolved.length+' unresolved control-flow reference(s) remain.':'')+'</div>';
        let h='<section class="blockcard function-overview cfg-overview"><div class="blockhead"><div class="blocktop"><span class="eyebrow">Function control-flow graph</span><span class="pill blue">DISCOVERED CFG</span></div><h2 class="blocktitle">'+E(label(B.get(view.f.id)||view.f))+'</h2><div class="addressmeta">Entry RVA '+E(hex(view.f.rva))+' / '+link(fnRoute(view.f,b),'Whole-function assembly',view.id,'cfg-assembly')+'</div></div>'+warning;
        h+=analysisSummary(view);
        h+='<div class="cfg-toolbar"><button id="cfgZoomOut" aria-label="Zoom out">−</button><button id="cfgZoomReset">100%</button><button id="cfgZoomIn" aria-label="Zoom in">+</button><span class="small muted">Arrow keys select a nearby block; Enter opens assembly.</span></div>';
        h+=g.bounded?graphSvg(view):listFallback(view);
        h+='</section>';$('content').innerHTML=h;
        let side='<h3 class="eyebrow">Selected block</h3>';
        if(b){side+='<div class="edgecard"><b>'+E(label(b))+'</b><br><span class="mono">'+E(hex(b.rva))+'</span><br>'+link(fnRoute(view.f,b),'Open in whole-function assembly',view.id,'cfg-open-assembly')+' &middot; '+link(b.id,'Open block view',view.id,'function-plain')+'</div>';
            const outs=g.edges.filter(e=>e.from===b.id),ins=g.edges.filter(e=>e.to===b.id);
            side+='<h3 class="eyebrow">Outgoing / '+outs.length+'</h3>'+(outs.map(e=>'<p>'+E(edgeLabel(e))+' → '+link(idFor(view.f,B.get(e.to)),label(B.get(e.to)),view.id)+'</p>').join('')||'<p class="empty">No discovered intraprocedural successor.</p>');
            side+='<h3 class="eyebrow">Incoming / '+ins.length+'</h3>'+(ins.map(e=>'<p>'+E(edgeLabel(e))+' ← '+link(idFor(view.f,B.get(e.from)),label(B.get(e.from)),view.id)+'</p>').join('')||'<p class="empty">No discovered intraprocedural predecessor.</p>');
        }
        side+='<h3 class="eyebrow">Outside / unknown exits</h3>'+(g.exits.map(e=>'<p>'+E(e.kind)+' from '+E(B.get(e.from)?label(B.get(e.from)):e.from)+' → '+E(edgeName(e))+'</p>').join('')||'<p class="empty">None reported from owned blocks.</p>');
        $('connections').innerHTML=side;$('renamebox').hidden=true;renderSidebar();
        const zi=$('cfgZoomIn'),zo=$('cfgZoomOut'),zr=$('cfgZoomReset');
        const apply=()=>{const svg=document.querySelector('.cfg-svg');if(svg){svg.style.width=(g.width*zoom)+'px';svg.style.height=(g.height*zoom)+'px';}zr.textContent=Math.round(zoom*100)+'%';};
        zi.onclick=()=>{zoom=Math.min(2,zoom+.15);apply();};zo.onclick=()=>{zoom=Math.max(.5,zoom-.15);apply();};zr.onclick=()=>{zoom=1;apply();};apply();
        const canvas=document.querySelector('.cfg-canvas');
        if(canvas)canvas.addEventListener('keydown',e=>{
            const ids=g.nodes.map(x=>x.id),cur=Math.max(0,ids.indexOf(b?.id)),p=g.positions.get(ids[cur]);let best=null,score=Infinity;
            if(e.key==='Enter'){e.preventDefault();navigate(fnRoute(view.f,b));return;}
            if(!['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(e.key))return;
            for(const id of ids){if(id===ids[cur])continue;const q=g.positions.get(id);if(!p||!q)continue;const dx=q.x-p.x,dy=q.y-p.y;
                if(e.key==='ArrowLeft'&&dx>=0||e.key==='ArrowRight'&&dx<=0||e.key==='ArrowUp'&&dy>=0||e.key==='ArrowDown'&&dy<=0)continue;
                const s=Math.abs(dx)+(2*Math.abs(dy));if(s<score){score=s;best=id;}}
            if(best){e.preventDefault();refocusGraph=true;navigate(idFor(view.f,B.get(best)));}
        });
        // The replacement canvas is already attached. Restore focus before the
        // next key event; deferring to a frame can lose rapid Arrow/Enter input.
        if(refocusGraph&&canvas){refocusGraph=false;canvas.focus({preventScroll:true});}
    }
    const button=document.createElement('button');button.id='functionCfg';button.textContent='CFG';
    $('wholeFunction')?.after(button);
    function contextFunction(){
        if(active)return active.f;
        const id=location.hash.slice(1), block=B.get(id)||I.get(id)?.block||B.get(selected);
        const owners=[...new Set(block?.owners||[])].filter(x=>functions.functions.has(x));
        if(functions.functions.has(selected))return functions.functions.get(selected);
        return owners.length===1?functions.functions.get(owners[0]):null;
    }
    button.onclick=()=>{const f=contextFunction();if(f)navigate(idFor(f));else message('Choose an unambiguous function owner first.');};
    const oldRoute=route,oldNavigate=navigate;
    route=function(){const view=parse(location.hash.slice(1));active=null;if(view)render(view);else oldRoute();const f=contextFunction();button.disabled=!f;button.setAttribute('aria-pressed',String(!!view));};
    navigate=function(id,from,...args){if(!parse(id))return oldNavigate(id,from,...args);if(from&&location.hash!=='#'+from)history.replaceState(history.state,'','#'+from);if(location.hash!=='#'+id)history.pushState({via:from||null},'','#'+id);route();};
    window.addEventListener('popstate',e=>{if(parse(location.hash.slice(1))){e.stopImmediatePropagation();route();}},true);
    window.addEventListener('hashchange',e=>{if(parse(location.hash.slice(1))){e.stopImmediatePropagation();route();}},true);
    const style=document.createElement('style');style.textContent='.cfg-toolbar{display:flex;gap:7px;align-items:center;padding:10px 20px;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}.cfg-canvas{overflow:auto;max-height:70vh;min-height:260px;background:var(--panel2);outline:none}.cfg-svg{display:block;transform-origin:0 0}.cfg-edge{fill:none;stroke:var(--muted);stroke-width:1.4;opacity:.8}.cfg-edge-label{font:10px var(--sans);fill:var(--muted);text-anchor:middle}.cfg-node rect{fill:var(--panel);stroke:var(--line);stroke-width:1.5}.cfg-node text{font:12px var(--mono);fill:var(--text)}.cfg-node.selected rect{stroke:var(--accent);stroke-width:3}.cfg-node.shared rect{stroke-dasharray:5 3}.cfg-node.unreachable{opacity:.5}.cfg-analysis-list{margin:10px 0}.cfg-list{padding:0 20px 20px}@media(max-width:720px){.cfg-toolbar{padding:8px 13px;flex-wrap:wrap}.cfg-canvas{max-height:60vh}}';document.head.appendChild(style);
    route();
})();
