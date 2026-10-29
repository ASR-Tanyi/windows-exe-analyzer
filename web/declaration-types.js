'use strict';
// Bounded C type-name syntax for analyst annotations, never machine semantics.
// Reviewed subset: WG14 N1570 6.7.2, 6.7.3, 6.7.6.1 and 6.7.7.
// https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf
(function (root) {
    const GRAMMAR = 'c11-scalar-pointer-v1';
    const COMPARISON_POLICY = 'parsed-annotation-forms-v1';
    const LIMITS = Object.freeze({characters:128,tokens:32,pointers:4});
    const qualifiers = new Set(['const','volatile']);
    const specifiers = new Set(['void','_Bool','char','short','int','long','signed','unsigned','float','double']);
    // Match whole multisets, not substrings: repetitions and incompatible
    // combinations must not be silently dropped. Plain char stays distinct.
    const builtins = new Map();
    for (const [name,forms] of [
        ['void',['void']],['_Bool',['_Bool']],['char',['char']],
        ['signed char',['signed char']],['unsigned char',['unsigned char']],
        ['short int',['short','short int','signed short','signed short int']],
        ['unsigned short int',['unsigned short','unsigned short int']],
        ['int',['int','signed','signed int']],['unsigned int',['unsigned','unsigned int']],
        ['long int',['long','long int','signed long','signed long int']],
        ['unsigned long int',['unsigned long','unsigned long int']],
        ['long long int',['long long','long long int','signed long long','signed long long int']],
        ['unsigned long long int',['unsigned long long','unsigned long long int']],
        ['float',['float']],['double',['double']],['long double',['long double']]
    ]) for (const form of forms) builtins.set(form.split(' ').sort().join(' '),name);

    const ALIAS_POLICY = 'explicit-scalar-pointer-aliases-v1';
    const ALIAS_LIMITS = Object.freeze({definitions:32,bytes:8192,depth:8,tokens:128});
    const keywords = new Set(('auto break case char const continue default do double else enum extern float for goto if inline int long register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while ' +
        '_Alignas _Alignof _Atomic _Bool _Complex _Generic _Imaginary _Noreturn _Static_assert _Thread_local').split(' '));
    const uniqueQualifiers = list => [...new Set(list.filter(t => qualifiers.has(t)))].sort();
    const empty = (status,reason) => ({status,canonical:null,type:null,reason});
    function form(label,allowAlias=false) {
        const fail = reason => ({error:empty('unsupported',reason)});
        if (label === null) return {error:empty('unknown','No type annotation supplied.')};
        if (typeof label !== 'string' || !label.length || label.length > LIMITS.characters || /[\x00-\x1f\x7f]/.test(label))
            return fail('Type syntax requires a nonempty label of at most 128 characters without control characters.');
        const tokens = label.match(/[A-Za-z_][A-Za-z0-9_]*|\*|[^ ]/g) || [];
        if (tokens.length > LIMITS.tokens) return fail('Type syntax exceeds the 32-token limit.');
        if (tokens.filter(t => t === '*').length > LIMITS.pointers) return fail('Type syntax exceeds four pointer levels.');
        if (!tokens.length || tokens.some(t => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(t) && t !== '*'))
            return fail('Only scalar specifiers, const/volatile and plain pointer stars are supported.');
        const first = tokens.indexOf('*'), base = first < 0 ? tokens : tokens.slice(0,first);
        const words = base.filter(t => !qualifiers.has(t)), name = builtins.get([...words].sort().join(' '));
        const alias = !name && allowAlias && words.length === 1 && !keywords.has(words[0]) ? words[0] : null;
        if (!name && !alias) return fail(words.some(t => !specifiers.has(t)) ?
            'Unrecognized name or specifier; typedefs, declarator names and extensions are not resolved.' : 'Missing or unsupported combination of scalar specifiers.');
        const pointers = [];
        if (first >= 0) for (let n = first; n < tokens.length;) {
            if (tokens[n++] !== '*') return fail('Each pointer level accepts only const/volatile after its star.');
            const q = [];
            while (n < tokens.length && tokens[n] !== '*') {
                if (!qualifiers.has(tokens[n])) return fail('Each pointer level accepts only const/volatile after its star.');
                q.push(tokens[n++]);
            }
            pointers.push(uniqueQualifiers(q));
        }
        return {name,alias,qualifiers:uniqueQualifiers(base),pointers,tokens:tokens.length};
    }
    function applyForm(f,type=null) {
        // N1570 6.7.6.1 p4: qualifiers on a pointer typedef qualify that
        // pointer, not its pointee. Never substitute the definition as text.
        if (!type) type = {kind:'builtin',name:f.name,qualifiers:[]};
        type.qualifiers = uniqueQualifiers([...type.qualifiers,...f.qualifiers]);
        for (const q of f.pointers) type = {kind:'pointer',qualifiers:[...q],to:type};
        return type;
    }
    function parsed(type) {
        const pointers=[]; let base=type;
        while (base.kind === 'pointer') {pointers.push(' *' + (base.qualifiers.length ? ' ' + base.qualifiers.join(' ') : '')); base=base.to;}
        return {status:'parsed',canonical:[...base.qualifiers,base.name].join(' ') + pointers.reverse().join(''),type,reason:null};
    }
    function parse(label) {
        const f=form(label); return f.error || parsed(applyForm(f));
    }
    function normalizeAliases(list) {
        if (!Array.isArray(list) || list.length > ALIAS_LIMITS.definitions) throw Error('Type aliases must be an array of at most 32 definitions.');
        const seen=new Set(), validText=(s,n)=>typeof s==='string' && s.length<=n && s.trim().length>0 && !/[\x00-\x1f\x7f]/.test(s);
        const result=list.map(a=>{
            if (!a || Array.isArray(a) || Object.keys(a).sort().join(',')!=='name,source,type' ||
                !validText(a.name,64) || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(a.name) || keywords.has(a.name) || seen.has(a.name) ||
                !validText(a.source,256) || !validText(a.type,128)) throw Error('Each type alias requires a unique non-keyword ASCII name, source label and type label.');
            seen.add(a.name); return {name:a.name,source:a.source,type:a.type};
        });
        if (new TextEncoder().encode(JSON.stringify(result,null,2)).length > ALIAS_LIMITS.bytes) throw Error('Normalized type aliases exceed 8 KiB.');
        return result;
    }
    function aliasContext(list) {
        const definitions=normalizeAliases(list), byName=new Map(definitions.map(a=>[a.name,{...a}]));
        function resolve(label) {
            const aliases=[], frames=[]; let current=label, tokens=0, pointers=0;
            const fail=reason=>({...empty('unsupported',reason),aliases});
            for (;;) {
                const f=form(current,true);
                if (f.error) return {...f.error,aliases};
                tokens+=f.tokens; pointers+=f.pointers.length;
                if (tokens>ALIAS_LIMITS.tokens) return fail('Alias expansion exceeds 128 total tokens.');
                if (pointers>LIMITS.pointers) return fail('Expanded type exceeds four pointer levels.');
                frames.push(f);
                if (f.name) break;
                if (!byName.has(f.alias)) return fail('No supplied definition for type alias '+f.alias+'.');
                if (aliases.includes(f.alias)) return fail('Type alias cycle: '+[...aliases,f.alias].join(' → ')+'.');
                if (aliases.length>=ALIAS_LIMITS.depth) return fail('Alias expansion exceeds eight definitions.');
                aliases.push(f.alias); current=byName.get(f.alias).type;
            }
            let type=null;
            for (const f of frames.reverse()) type=applyForm(f,type);
            return {...parsed(type),aliases};
        }
        return {definitions,parse:resolve,results:definitions.map(a=>({name:a.name,result:resolve(a.name)}))};
    }
    function declarations(list,context=null) {
        // Full contract validation bounds this to 264 independently resolved labels.
        const read=context ? context.parse : parse;
        return list.map(d => ({declaration:d.id,returnType:read(d.returnType),parameters:d.parameters.map(p => read(p.type))}));
    }
    function compareDeclarations(list, parsed = null) {
        // The caller validates the entire contract first. Repeat its cardinality
        // caps here so this pairwise operation always has at most 28 * 36 rows.
        if (!Array.isArray(list) || list.length > 8 || list.some(d => !Array.isArray(d?.parameters) || d.parameters.length > 32))
            throw Error('Declaration comparisons require at most 8 declarations with at most 32 parameters each.');
        const types = parsed || declarations(list), result = [];
        const side = (label,t) => t ? {label,status:t.status,canonical:t.canonical,reason:t.reason,...(t.aliases ? {aliases:[...t.aliases]} : {})} :
            {label:null,status:'missing',canonical:null,reason:'No supplied parameter record at this position.'};
        function typeField(field,leftLabel,rightLabel,a,b) {
            const row = {field,kind:'type',status:'unknown',left:side(leftLabel,a),right:side(rightLabel,b),differences:[],
                reason:'At least one annotation is missing, unspecified or outside the reviewed grammar.'};
            // Even identical unresolved names are unknown; no typedef or
            // structural prefix is promoted into an equality claim.
            if (a?.status !== 'parsed' || b?.status !== 'parsed') return row;
            let left = a.type, right = b.type;
            for (let depth=0;depth<=LIMITS.pointers;depth++) {
                if (left.qualifiers.join(',') !== right.qualifiers.join(','))
                    row.differences.push({kind:'qualifiers',depth,left:[...left.qualifiers],right:[...right.qualifiers]});
                if (left.kind !== right.kind) {
                    row.differences.push({kind:'shape',depth,left:left.kind,right:right.kind}); break;
                }
                if (left.kind === 'builtin') {
                    if (left.name !== right.name) row.differences.push({kind:'base',depth,left:left.name,right:right.name});
                    break;
                }
                left = left.to; right = right.to;
            }
            row.status = row.differences.length ? 'different' : 'same';
            row.reason = row.differences.length ? 'Parsed annotation forms differ; this is not a prototype or machine-compatibility verdict.' :
                'Same parsed annotation form under the reviewed grammar and any supplied alias assumptions; full prototype compatibility is not established.';
            return row;
        }
        for (let i=0;i<list.length;i++) for (let j=i+1;j<list.length;j++) {
            const a=list[i],b=list[j],ta=types[i],tb=types[j];
            const fields = [typeField('returnType',a.returnType,b.returnType,ta.returnType,tb.returnType),
                {field:'parameterCount',kind:'count',status:a.parameters.length===b.parameters.length?'same':'different',
                    left:a.parameters.length,right:b.parameters.length,reason:'Counts of supplied parameter records, not inferred machine arity.'}];
            for (let n=0;n<Math.max(a.parameters.length,b.parameters.length);n++) fields.push(typeField('parameter['+(n+1)+'].type',
                a.parameters[n]?.type,b.parameters[n]?.type,ta.parameters[n],tb.parameters[n]));
            for (const field of ['variadic','hiddenParameters']) {
                const unknown = a[field]==='unknown' || b[field]==='unknown';
                fields.push({field,kind:'flag',status:unknown?'unknown':a[field]===b[field]?'same':'different',left:a[field],right:b[field],
                    reason:unknown?'At least one declaration leaves this flag unknown.':'Comparison of explicit analyst flags; machine behavior is not inferred.'});
            }
            const counts = {same:0,different:0,unknown:0};
            for (const f of fields) counts[f.status]++;
            result.push({declarations:[a.id,b.id],counts,fields});
        }
        return result;
    }
    const comparisonSummary = c => c.counts.same + ' same, ' + c.counts.different + ' different, ' + c.counts.unknown + ' unknown fields';
    const comparisonLabel = f => f.status === 'unknown' ? 'Unknown' :
        (f.status === 'same' ? 'Same ' : 'Different ') + (f.kind === 'type' ? 'parsed form' : f.kind === 'count' ? 'supplied count' : 'supplied flag');
    const describeDifference = d => {
        const at = d.depth === 0 ? 'outer type' : 'pointee depth ' + d.depth;
        const value = x => Array.isArray(x) ? x.join(' ') || 'unqualified' : x;
        return d.kind + ' at ' + at + ': ' + value(d.left) + ' / ' + value(d.right);
    };
    const aliasDescription = result => result.aliases?.length ? 'Supplied aliases: ' + result.aliases.join(' → ') : '';
    const describe = result => (result.status === 'parsed' ? 'Parsed annotation: ' + result.canonical :
        result.status === 'unknown' ? result.reason : 'Unparsed annotation: ' + result.reason) + (result.aliases?.length ? ' · ' + aliasDescription(result) : '');
    const api = {GRAMMAR,COMPARISON_POLICY,LIMITS,ALIAS_POLICY,ALIAS_LIMITS,normalizeAliases,aliasContext,aliasDescription,parse,declarations,describe,compareDeclarations,comparisonSummary,comparisonLabel,describeDifference};
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WEADeclarationTypes = api;
})(globalThis);
