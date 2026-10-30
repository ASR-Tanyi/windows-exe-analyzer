'use strict';
// Relate conditional placements to existing callee-entry observations only.
(function(root) {
    const POLICY='declared-entry-read-associations-v1';
    const LIMITS=Object.freeze({work:32768,links:512,sources:64});
    const NOTICE='Location overlap only: entry reads may be copies, spills or address calculations. Coverage does not verify a type or signature; absent reads do not disprove a parameter. Paths and repeated reads remain separate. Return-value and caller-side associations are not reviewed by this policy.';
    const hex=n=>'0x'+n.toString(16), mask=width=>(1n<<BigInt(width))-1n;
    function associate(analysis,options={}) {
        const limits=Object.fromEntries(Object.entries(LIMITS).map(([k,v])=>[k,Number.isSafeInteger(options[k])?Math.max(0,Math.min(v,options[k])):v]));
        let work=0,links=0;
        const spend=()=>{if(++work>limits.work) throw Error('Association work limit exceeded.');};
        const rows=(status,reason)=>(analysis.declarationLocations || []).map(d=>({declaration:d.declaration,
            returnType:{status:'not_reviewed',reason:'Return-value associations are not reviewed by this policy.',reads:[]},
            parameters:d.parameters.map(p=>({position:p.position,status:p.status==='declared'?status:'unresolved',
                reason:p.status==='declared'?reason:'The declaration has no supported conditional location.',reads:[]}))}));
        const base={policy:POLICY,notice:NOTICE,status:'unavailable',reason:'',declarations:[],work:0,links:0,assumptionSources:[...(analysis.assumptionSources || [])]};
        if (!(analysis.declarationLocations || []).length) return {...base,status:'empty',reason:'No supplied declarations.'};
        if (analysis.status!=='available') return {...base,reason:'Function ABI observations unavailable: '+(analysis.reason || analysis.status),
            declarations:rows('unavailable','Function ABI observations are unavailable.')};
        try {
            const declarations=rows('no_observation','No supported read at this location was found. Parameter presence remains unknown.');
            for(let n=0;n<declarations.length;n++) for(let i=0;i<declarations[n].parameters.length;i++) {
                spend(); const row=declarations[n].parameters[i],p=analysis.declarationLocations[n].parameters[i];
                if(p.status!=='declared') continue;
                const location=p.location;
                if(location.kind==='stack' && analysis.stackStatus!=='available') {
                    row.status='unavailable';row.reason=analysis.stackReason || 'Incoming stack observations are unavailable.';continue;
                }
                const append=(read,extra)=>{
                    if(++links>limits.links) throw Error('Association link limit exceeded.');
                    const sources=[...new Set([read.source,...read.sources].filter(Boolean))];
                    if(sources.length>limits.sources) throw Error('Association source limit exceeded.');
                    row.reads.push({...extra,source:read.source,sources});
                };
                if(location.kind==='register') {
                    const declared=mask(location.width)<<BigInt(location.bitOffset);
                    for(const argument of analysis.arguments) {
                        spend(); if(argument.register!==location.register) continue;
                        for(const read of argument.uses) {
                            spend(); const observed=BigInt(read.mask),overlap=declared&observed;
                            append(read,{kind:'entry_register_read',register:location.register,observedMask:hex(observed),overlapMask:hex(overlap),
                                relation:overlap===declared?'covers':overlap?'partial':'disjoint'});
                        }
                    }
                } else {
                    for(const read of analysis.stackArguments) {
                        spend(); if(read.entryOffset!==location.byteOffset) continue;
                        append(read,{kind:'entry_stack_read',entryOffset:read.entryOffset,width:read.width,overlapBytes:Math.min(location.width,read.width)/8,
                            relation:read.width>=location.width?'covers':'partial'});
                    }
                }
                if(row.reads.length) {row.status='observed';row.reason='Existing entry reads at this location; each overlap is independent and is not a compatibility verdict.';}
            }
            return {...base,status:'available',reason:NOTICE,declarations,work,links};
        } catch(e) {
            // Discard all provisional associations without discarding machine
            // observations or conditional placements, which have separate limits.
            return {...base,status:'budget_exceeded',reason:e.message+' Provisional associations discarded.',
                declarations:rows('unavailable','Association budget exceeded; no provisional links retained.'),work,links:0};
        }
    }
    function describe(read) {
        const overlap={covers:'Covers declared bits',partial:'Overlaps some declared bits',disjoint:'No declared-bit overlap'}[read.relation];
        return overlap+(read.kind==='entry_register_read'?'; incoming mask '+read.observedMask+'; overlap '+read.overlapMask:
            '; '+read.width+'-bit read at entry RSP + '+read.entryOffset+'; '+read.overlapBytes+' overlapping byte(s)');
    }
    const api={POLICY,LIMITS,NOTICE,associate,describe};
    if(typeof module==='object' && module.exports) module.exports=api; else root.WEADeclarationEvidence=api;
})(globalThis);
