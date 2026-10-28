'use strict';
// Bounded C type-name syntax for analyst annotations, never machine semantics.
// Reviewed subset: WG14 N1570 6.7.2, 6.7.3, 6.7.6.1 and 6.7.7.
// https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf
(function (root) {
    const GRAMMAR = 'c11-scalar-pointer-v1';
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

    function parse(label) {
        const empty = (status,reason) => ({status,canonical:null,type:null,reason});
        if (label === null) return empty('unknown','No type annotation supplied.');
        if (typeof label !== 'string' || !label.length || label.length > LIMITS.characters || /[\x00-\x1f\x7f]/.test(label))
            return empty('unsupported','Type syntax requires a nonempty label of at most 128 characters without control characters.');
        // Consume every non-space character. No comments, macros, escapes,
        // identifier lookup, implicit int or partial parse of complex types.
        const tokens = label.match(/[A-Za-z_][A-Za-z0-9_]*|\*|[^ ]/g) || [];
        if (tokens.length > LIMITS.tokens) return empty('unsupported','Type syntax exceeds the 32-token limit.');
        const depth = tokens.filter(t => t === '*').length;
        if (depth > LIMITS.pointers) return empty('unsupported','Type syntax exceeds four pointer levels.');
        if (!tokens.length || tokens.some(t => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(t) && t !== '*'))
            return empty('unsupported','Only scalar specifiers, const/volatile and plain pointer stars are supported.');
        if (tokens.some(t => t !== '*' && !specifiers.has(t) && !qualifiers.has(t)))
            return empty('unsupported','Unrecognized name or specifier; typedefs, declarator names and extensions are not resolved.');
        const first = tokens.indexOf('*'), base = first < 0 ? tokens : tokens.slice(0,first);
        const name = builtins.get(base.filter(t => !qualifiers.has(t)).sort().join(' '));
        if (!name) return empty('unsupported','Missing or unsupported combination of scalar specifiers.');
        const uniqueQualifiers = list => [...new Set(list.filter(t => qualifiers.has(t)))].sort();
        let type = {kind:'builtin',name,qualifiers:uniqueQualifiers(base)};
        let canonical = [...type.qualifiers,name].join(' ');
        if (first >= 0) for (let n = first; n < tokens.length;) {
            if (tokens[n++] !== '*') return empty('unsupported','Each pointer level accepts only const/volatile after its star.');
            const q = [];
            while (n < tokens.length && tokens[n] !== '*') {
                if (!qualifiers.has(tokens[n])) return empty('unsupported','Each pointer level accepts only const/volatile after its star.');
                q.push(tokens[n++]);
            }
            type = {kind:'pointer',qualifiers:uniqueQualifiers(q),to:type};
            canonical += ' *' + (type.qualifiers.length ? ' ' + type.qualifiers.join(' ') : '');
        }
        return {status:'parsed',canonical,type,reason:null};
    }
    function declarations(list) {
        // Called only after full contract validation (8 declarations, 32
        // parameters each). Syntax failure never rejects or rewrites a label.
        return list.map(d => ({declaration:d.id,returnType:parse(d.returnType),parameters:d.parameters.map(p => parse(p.type))}));
    }
    const describe = result => result.status === 'parsed' ? 'Parsed annotation: ' + result.canonical :
        result.status === 'unknown' ? result.reason : 'Unparsed annotation: ' + result.reason;
    const api = {GRAMMAR,LIMITS,parse,declarations,describe};
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WEADeclarationTypes = api;
})(globalThis);
