'use strict';
// Data-result semantics shared by abstract transfers and the concrete test
// evaluator. Flags remain a separate effect of the typed ALU operation.
(function (root) {
    function integerResult(operator, width, left, right = 0n) {
        if (![8, 16, 32, 64].includes(width)) throw Error('unsupported integer width');
        const u = v => BigInt.asUintN(width, v), a = u(BigInt(left)), b = u(BigInt(right));
        const count = b & BigInt(width === 64 ? 63 : 31);
        switch (operator) {
        case '+': case 'add': return u(a + b);
        case '-': case 'sub': case 'cmp': return u(a - b);
        case '*': case 'imul': return u(a * b);
        case 'and': case 'test': return a & b;
        case 'or': return a | b;
        case 'xor': return a ^ b;
        case 'not': return u(~a);
        case 'neg': return u(-a);
        case 'inc': return u(a + 1n);
        case 'dec': return u(a - 1n);
        case 'shl': return u(a << count);
        case 'shr': return a >> count;
        case 'sar': return u(BigInt.asIntN(width, a) >> count);
        default: throw Error('unsupported integer operator');
        }
    }
    const api = {integerResult};
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WEABitvectors = api;
})(globalThis);
