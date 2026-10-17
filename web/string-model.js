'use strict';
// An index of candidate spans and already-discovered constant-address operands.
// It does not scan pointers, infer object types, or turn references into reads.
((root) => {
    function create(report, linkLimit = 200000) {
        linkLimit = Number.isFinite(linkLimit) ? Math.max(0, Math.min(200000, Math.trunc(linkLimit))) : 0;
        const candidates = (report.strings?.candidates || []).slice().sort((a,b) => a.rva-b.rva || a.encoding.localeCompare(b.encoding));
        const entries = new Map(candidates.map(s => [s.id, {candidate:s, refs:[]}]));
        const byInstruction = new Map(), prefixEnd = [];
        let maximum = 0, links = 0, partial = false;
        for (const s of candidates) {maximum=Math.max(maximum,s.rva+s.byteLength);prefixEnd.push(maximum);}
        function at(rva) {
            if (!Number.isSafeInteger(rva) || rva<0 || rva>0xffffffff) return [];
            let low=0, high=candidates.length;
            while(low<high) {const m=(low+high)>>>1;if(candidates[m].rva<=rva)low=m+1;else high=m;}
            const result=[];
            for(let k=low-1;k>=0 && prefixEnd[k]>rva;--k) {
                const s=candidates[k];if(s.rva+s.byteLength>rva)result.push(s);
            }
            return result.reverse();
        }
        outer: for (const block of report.blocks || []) for (const instruction of block.instructions || []) {
            for (const ref of instruction.dataRefs || []) {
                for (const s of at(ref.rva)) {
                    if (links >= linkLimit) {partial=true;break outer;}
                    ++links;
                    const item={source:instruction.id,block:block.id,owners:[...(block.owners||[])],
                        instruction,ref,offset:ref.rva-s.rva,kind:ref.rva===s.rva?'exact':'interior'};
                    entries.get(s.id).refs.push(item);
                    if(!byInstruction.has(instruction.id))byInstruction.set(instruction.id,new Set());
                    byInstruction.get(instruction.id).add(s.id);
                }
            }
        }
        return {candidates,entries,byInstruction,at,links,linkLimit,partial};
    }
    root.WEAStringModel={create};
    if(typeof module!=='undefined' && module.exports)module.exports=root.WEAStringModel;
})(globalThis);
