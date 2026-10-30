'use strict';
// Conditional locations for supplied types; never observations or CALL effects.
// Microsoft x64 calling convention: parameter passing and return values.
// https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
// https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions
// https://learn.microsoft.com/en-us/cpp/c-language/storage-of-basic-types
(function (root) {
    const POLICY='windows-x64-declared-integer-pointer-v1';
    const PROFILE='windows-x64-gpr-v1';
    const NOTICE='Conditional locations for supplied declarations under the selected Windows x64 convention and LLP64 integer sizes. Each list is assumed complete and fixed, with no hidden parameters. These are not observed inputs, recovered signatures or compatibility verdicts. Upper register bits and stack-slot padding are unspecified; register home-space contents are not inferred. Machine effects and call assumptions remain unchanged.';
    const widths=new Map([['char',8],['signed char',8],['unsigned char',8],['short int',16],['unsigned short int',16],
        ['int',32],['unsigned int',32],['long int',32],['unsigned long int',32],['long long int',64],['unsigned long long int',64]]);
    function classify(result,isReturn) {
        if (result?.status!=='parsed') return {reason:'A fully parsed annotation is required; unresolved names and aliases have no declared location.'};
        const t=result.type;
        if (t.kind==='pointer') return {category:'pointer',width:64};
        if (widths.has(t.name)) return {category:'integer',width:widths.get(t.name)};
        if (t.name==='void') return isReturn ? {category:'void',width:null} : {reason:'A void parameter record is not a scalar argument or an empty parameter list.'};
        return {reason:'This policy covers char/short/int/long/long long and pointers; Boolean and floating-point ABI types are not reviewed.'};
    }
    function declarations(list,parsed,profile) {
        // Full contract/type validation precedes this pure mapping. Repeat the
        // cardinality caps so no caller can request more than 264 field rows.
        if (!Array.isArray(list) || list.length>8 || list.some(d=>!Array.isArray(d?.parameters) || d.parameters.length>32) ||
            !Array.isArray(parsed) || parsed.length!==list.length) throw Error('Declared ABI locations require at most 8 validated declarations and matching type results.');
        return list.map((d,index)=>{
            const types=parsed[index], blockers=[];
            if (!types || types.declaration!==d.id || !Array.isArray(types.parameters) || types.parameters.length!==d.parameters.length)
                throw Error('Declared ABI locations require matching declaration IDs and parameter type results.');
            if (profile!==PROFILE) blockers.push({field:'profile',reason:'Explicit Windows x64 function convention is required.'});
            for (const field of ['variadic','hiddenParameters']) if (d[field]!=='no')
                blockers.push({field,reason:field==='variadic'?'Variadic status must explicitly be no; varargs and unprototyped calls are outside this policy.':'Hidden-parameter status must explicitly be no; implicit parameters can shift locations.'});
            const info=[classify(types.returnType,true),...types.parameters.map(t=>classify(t,false))];
            info.forEach((t,n)=>{if(t.reason) blockers.push({field:n?'parameter['+n+'].type':'returnType',reason:t.reason});});
            const mapped=blockers.length===0;
            const row=(label,type,t,position)=>{
                const result={label,canonical:type.canonical,aliases:[...(type.aliases || [])],status:'unknown',category:null,width:null,location:null,
                    reason:t.reason || 'Locations are withheld for this entire declaration until every prerequisite is supported.'};
                if (!mapped) return result;
                result.category=t.category;result.width=t.width;
                if (t.category==='void') return {...result,status:'none',reason:'The supplied declaration has no return value; this does not classify observed RAX values.'};
                const location=position===0 || position<=4 ?
                    {kind:'register',register:position===0?'rax':['rcx','rdx','r8','r9'][position-1],bitOffset:0,width:t.width,containerWidth:64} :
                    // Return address (8) + four home slots (32) precede slot 5.
                    {kind:'stack',base:'entry_rsp',byteOffset:String(position*8),width:t.width,slotBytes:8};
                return {...result,status:'declared',location,reason:'Conditional declared placement; no extension, padding value or matching machine use is inferred.'};
            };
            return {declaration:d.id,source:d.source,profile:profile || null,status:mapped?'mapped':'unknown',blockers,
                returnType:row(d.returnType,types.returnType,info[0],0),
                parameters:d.parameters.map((p,n)=>({position:n+1,name:p.name,...row(p.type,types.parameters[n],info[n+1],n+1)}))};
        });
    }
    function describe(row) {
        if (row.status==='none') return 'No declared return value';
        if (row.status!=='declared') return 'Unknown';
        const l=row.location;
        return l.kind==='register' ? l.register.toUpperCase()+' bits '+l.bitOffset+'–'+(l.bitOffset+l.width-1) :
            'entry RSP + '+l.byteOffset+' bytes · '+l.width+' bits in an '+l.slotBytes+'-byte slot';
    }
    const api={POLICY,PROFILE,NOTICE,declarations,describe};
    if (typeof module==='object' && module.exports) module.exports=api;
    else root.WEADeclarationABI=api;
})(globalThis);
