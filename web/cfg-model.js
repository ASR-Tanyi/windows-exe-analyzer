'use strict';
// Pure, bounded control-flow analysis over already-discovered intraprocedural
// report edges. It never adds blocks, targets, or function ownership.
(function(root){
    const defaults={nodeLimit:120,edgeLimit:300,iterationLimit:10000};
    function analyze(report,functionIndex,functionId,limits={}){
        const cap={...defaults,...limits}, m=functionIndex.get(functionId);
        if(!m)return null;
        const nodes=m.blocks.map(b=>b.id), nodeSet=new Set(nodes);
        const edges=m.cfg.filter(e=>nodeSet.has(e.from)&&e.to&&nodeSet.has(e.to));
        const exits=m.transfers.slice(), unresolved=m.unresolved.slice();
        const bounded=nodes.length<=cap.nodeLimit&&edges.length<=cap.edgeLimit;
        const succ=new Map(nodes.map(id=>[id,[]])), pred=new Map(nodes.map(id=>[id,[]]));
        for(const e of edges){succ.get(e.from).push(e.to);pred.get(e.to).push(e.from);}
        for(const map of [succ,pred])for(const [id,list] of map)map.set(id,[...new Set(list)].sort());
        const entry=nodeSet.has(functionId)?functionId:(nodes[0]||null);
        const reachable=new Set();
        if(entry){const q=[entry];while(q.length){const n=q.shift();if(reachable.has(n))continue;reachable.add(n);for(const s of succ.get(n)||[])if(!reachable.has(s))q.push(s);}}
        const reachableNodes=nodes.filter(n=>reachable.has(n));
        let budget=0;
        const dom=new Map();
        for(const n of reachableNodes)dom.set(n,new Set(n===entry?[n]:reachableNodes));
        let changed=true;
        while(changed&&budget++<cap.iterationLimit){
            changed=false;
            for(const n of reachableNodes){if(n===entry)continue;
                const ps=(pred.get(n)||[]).filter(p=>reachable.has(p));
                let next=new Set([n]);
                if(ps.length){let common=new Set(dom.get(ps[0]));for(const p of ps.slice(1))common=new Set([...common].filter(x=>dom.get(p).has(x)));for(const x of common)next.add(x);}
                const old=dom.get(n);if(old.size!==next.size||[...next].some(x=>!old.has(x))){dom.set(n,next);changed=true;}
            }
        }
        const dominatorBudgetExceeded=changed;
        const idom=new Map();
        if(!dominatorBudgetExceeded)for(const n of reachableNodes){if(n===entry){idom.set(n,null);continue;}
            const strict=[...dom.get(n)].filter(x=>x!==n);
            strict.sort((a,b)=>dom.get(b).size-dom.get(a).size||String(a).localeCompare(String(b)));
            idom.set(n,strict[0]||null);
        }
        // Tarjan SCC, deterministic by report block order.
        let index=0;const stack=[],onStack=new Set(),idx=new Map(),low=new Map(),sccs=[];
        function strong(v){idx.set(v,index);low.set(v,index++);stack.push(v);onStack.add(v);
            for(const w of succ.get(v)||[]){if(!idx.has(w)){strong(w);low.set(v,Math.min(low.get(v),low.get(w)));}else if(onStack.has(w))low.set(v,Math.min(low.get(v),idx.get(w)));}
            if(low.get(v)===idx.get(v)){const region=[];let w;do{w=stack.pop();onStack.delete(w);region.push(w);}while(w!==v);region.sort((a,b)=>nodes.indexOf(a)-nodes.indexOf(b));sccs.push(region);}
        }
        for(const n of nodes)if(!idx.has(n))strong(n);
        const regions=sccs.map((members,i)=>{
            const set=new Set(members), cyclic=members.length>1||members.some(n=>(succ.get(n)||[]).includes(n));
            const entryTargets=new Set();for(const n of members)for(const p of pred.get(n)||[])if(!set.has(p))entryTargets.add(n);
            return {id:i,members,cyclic,entryTargets:[...entryTargets],irreducible:cyclic&&entryTargets.size>1};
        });
        const loopsByHeader=new Map();
        if(!dominatorBudgetExceeded)for(const e of edges){
            if(!reachable.has(e.from)||!reachable.has(e.to)||!dom.get(e.from).has(e.to))continue;
            const header=e.to, body=new Set([header,e.from]), work=[e.from];
            while(work.length){const n=work.pop();for(const p of pred.get(n)||[])if(reachable.has(p)&&!body.has(p)){body.add(p);if(p!==header)work.push(p);}}
            const key=header;if(!loopsByHeader.has(key))loopsByHeader.set(key,{header,members:new Set(),backEdges:[]});
            const loop=loopsByHeader.get(key);for(const n of body)loop.members.add(n);loop.backEdges.push(e);
        }
        const loops=[...loopsByHeader.values()].map(x=>({header:x.header,members:[...x.members].sort((a,b)=>nodes.indexOf(a)-nodes.indexOf(b)),backEdges:x.backEdges}));
        const depth=new Map();function d(n,seen=new Set()){if(depth.has(n))return depth.get(n);if(!idom.has(n)||idom.get(n)===null)return 0;if(seen.has(n))return 0;seen.add(n);const v=1+d(idom.get(n),seen);depth.set(n,v);return v;}
        const layers=new Map();for(const n of nodes){const layer=reachable.has(n)&&!dominatorBudgetExceeded?d(n):Math.max(1,...depth.values(),0)+1;if(!layers.has(layer))layers.set(layer,[]);layers.get(layer).push(n);}
        for(const list of layers.values())list.sort((a,b)=>nodes.indexOf(a)-nodes.indexOf(b));
        const positions=new Map(), xGap=235,yGap=105,w=180,h=64;
        let maxX=0,maxY=0;for(const [layer,list] of [...layers].sort((a,b)=>a[0]-b[0]))for(let row=0;row<list.length;row++){const p={x:25+layer*xGap,y:25+row*yGap,w,h,layer,row};positions.set(list[row],p);maxX=Math.max(maxX,p.x+w);maxY=Math.max(maxY,p.y+h);}
        return {function:m.function,nodes:m.blocks,edges,exits,unresolved,entry,reachable,unreachable:nodes.filter(n=>!reachable.has(n)),
            dominators:dom,idom,regions,loops,positions,width:maxX+80,height:maxY+80,bounded,
            limits:cap,dominatorBudgetExceeded,incomplete:report.module.truncated||m.unresolved.length>0||m.ownershipMissing||m.completeness!=='proven',
            completeness:m.completeness,shared:m.sharedBlocks};
    }
    root.WEACfgModel={analyze,defaults};
})(typeof globalThis!=='undefined'?globalThis:this);
