'use strict';
// Versioned, bounded preview. Operands are decoder facts, never parsed assembly
// strings. The typed operations are shared by the renderer and semantic tests.
(function (root) {
    const VA = typeof module === 'object' && module.exports ? require('./value-analysis.js') : root.WEAValueAnalysis;
    const SSA = typeof module === 'object' && module.exports ? require('./register-ssa.js') : root.WEARegisterSSA;
    const CALL = typeof module === 'object' && module.exports ? require('./call-summaries.js') : root.WEACallSummaries;
    const EXPR = typeof module === 'object' && module.exports ? require('./register-expressions.js') : root.WEARegisterExpressions;
    const VERSION = 5, LIMITS = Object.freeze({blocks: 128, instructions: 2048, edges: 384});
    const widths = new Set([8, 16, 32, 64]);
    const conditions = {
        e: 'zero', z: 'zero', ne: '!zero', nz: '!zero',
        b: 'carry', c: 'carry', nae: 'carry', ae: '!carry', nb: '!carry', nc: '!carry',
        be: 'carry || zero', na: 'carry || zero', a: '!carry && !zero', nbe: '!carry && !zero',
        l: 'sign != overflow', nge: 'sign != overflow', ge: 'sign == overflow', nl: 'sign == overflow',
        le: 'zero || (sign != overflow)', ng: 'zero || (sign != overflow)',
        g: '!zero && (sign == overflow)', nle: '!zero && (sign == overflow)',
        s: 'sign', ns: '!sign', o: 'overflow', no: '!overflow', p: 'parity', pe: 'parity', np: '!parity', po: '!parity'
    };
    const constant = (value, width) => ({kind: 'constant', value: BigInt.asUintN(width, BigInt(value)).toString(), width});
    const binary = (operator, left, right, width) => ({kind: 'binary', operator, left, right, width});
    const cast = (value, width, signed = false) => ({kind: 'cast', value, width, signed});
    function register(r, bits) {
        const family = bits === 64 ? /^(r[abcd]x|r[sd]i|r[bs]p|r(?:[89]|1[0-5]))$/ : /^(e[abcd]x|e[sd]i|e[bs]p)$/;
        if (!r || !family.test(r.family) || r.familyWidth !== bits || !widths.has(r.bitWidth) ||
            r.bitWidth > bits || ![0, 8].includes(r.bitOffset) || r.bitOffset && r.bitWidth !== 8)
            throw Error('unsupported register slice');
        return {kind: 'register', name: r.family, offset: r.bitOffset, width: r.bitWidth, familyWidth: bits};
    }
    function address(op, detail, insn, report, bits) {
        const m = op.memory, width = detail.addressWidthBits;
        if (!m || m.segment || ![32, bits].includes(width) || ![1, 2, 4, 8].includes(m.scale))
            throw Error('unsupported address size or segment');
        const part = r => {
            if (r?.family === 'rip' || r?.family === 'eip') {
                if (bits !== 64 || m.index || r.bitWidth !== width) throw Error('unsupported IP-relative address');
                return constant(BigInt(report.module.imageBase) + BigInt(insn.rva + insn.size), width);
            }
            const value = register(r, bits);
            if (value.width !== width || value.offset) throw Error('address register width mismatch');
            return value;
        };
        let result = m.base ? part(m.base) : constant(0, width);
        if (m.index) result = binary('+', result, binary('*', part(m.index), constant(m.scale, width), width), width);
        if (BigInt(m.displacement)) result = binary('+', result, constant(m.displacement, width), width);
        return cast(result, width);
    }
    function lift(insn, report) {
        const bits = /^x64(?: \/ PE32\+)?$/.test(report.module.architecture) ? 64 : /^x86(?: \/ PE32)?$/.test(report.module.architecture) ? 32 : 0;
        const result = {source: insn.id, rva: insn.rva, mnemonic: insn.mnemonic, status: 'supported', ops: []};
        try {
            const d = insn.operandDetails, m = insn.mnemonic, args = d?.operands;
            if (!bits || d?.source !== 'capstone_detail' || !Array.isArray(args) || args.length > 3)
                throw Error('structured operands unavailable');
            // LOCK, REP, segment overrides, vector prefixes and 16-bit address
            // modes require separate semantics. Do not strip them to fit a rule.
            if (!Array.isArray(d.prefixes?.leadingBytes) || d.prefixes.leadingBytes.some(p =>
                p !== 0x66 && p !== 0x67 && !(bits === 64 && p >= 0x40 && p <= 0x4f) &&
                !(m === 'nop' && [0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65].includes(p))))
                throw Error('unsupported instruction prefix');
            const read = o => {
                if (!o || !widths.has(o.widthBits)) throw Error('unsupported operand width');
                if (o.kind === 'register') {
                    const r = register(o.register, bits);
                    if (r.width !== o.widthBits) throw Error('register width mismatch');
                    return r;
                }
                if (o.kind === 'immediate' && o.immediate?.interpretation === 'bit_pattern')
                    return constant(o.immediate.value, o.widthBits);
                if (o.kind === 'memory') return {kind: 'load', address: address(o, d, insn, report, bits), width: o.widthBits};
                throw Error('unsupported operand kind');
            };
            const dest = o => {
                const v = read(o);
                if (!['register', 'load'].includes(v.kind)) throw Error('destination is not writable');
                return v;
            };
            const arity = n => {if (args.length !== n) throw Error('unsupported operand form');};
            const pair = () => {
                arity(2); const a = read(args[0]), b = read(args[1]);
                if (a.width !== b.width || a.kind === 'load' && b.kind === 'load') throw Error('operand width/form mismatch');
                return [a, b];
            };
            const set = (target, value) => result.ops.push({kind: 'assign', target, value});
            if (m === 'mov' || m === 'movabs') {const [a, b] = pair(); set(dest(args[0]), b);}
            else if (['movzx', 'movsx', 'movsxd'].includes(m)) {
                arity(2); const a = dest(args[0]), b = read(args[1]);
                if (a.kind !== 'register' || a.width <= b.width || b.kind === 'constant' ||
                    (m === 'movsxd' ? b.width !== 32 || a.width !== 64 : ![8, 16].includes(b.width)))
                    throw Error('unsupported extension form');
                set(a, cast(b, a.width, m !== 'movzx'));
            } else if (m === 'lea') {
                arity(2); const a = dest(args[0]);
                if (a.kind !== 'register' || ![16, 32, 64].includes(a.width) || args[1].kind !== 'memory')
                    throw Error('unsupported LEA form');
                set(a, cast(address(args[1], d, insn, report, bits), a.width));
            } else if (['add', 'sub', 'and', 'or', 'xor', 'cmp', 'test'].includes(m)) {
                const [a, b] = pair();
                if (a.kind === 'constant') throw Error('invalid arithmetic destination');
                result.ops.push({kind: 'alu', operator: m, target: ['cmp', 'test'].includes(m) ? null : dest(args[0]),
                    left: a, right: b, width: a.width});
            } else if (['inc', 'dec', 'neg', 'not'].includes(m)) {
                arity(1); const a = dest(args[0]);
                result.ops.push({kind: 'alu', operator: m, target: a, left: a, right: null, width: a.width});
            } else if (['shl', 'sal', 'shr', 'sar'].includes(m)) {
                arity(2); const a = dest(args[0]), b = read(args[1]);
                if (b.kind !== 'constant' && !(b.kind === 'register' && b.name === (bits === 64 ? 'rcx' : 'ecx') && b.width === 8 && b.offset === 0))
                    throw Error('unsupported shift count');
                result.ops.push({kind: 'alu', operator: m === 'sal' ? 'shl' : m, target: a, left: a, right: b, width: a.width});
            } else if (m === 'imul') {
                if (![2, 3].includes(args.length)) throw Error('implicit product form not supported');
                const a = dest(args[0]), b = read(args[args.length === 3 ? 1 : 0]), c = read(args[args.length - 1]);
                if (a.kind !== 'register' || a.width === 8 || a.width !== b.width || a.width !== c.width ||
                    args.length === 3 && c.kind !== 'constant') throw Error('unsupported multiply form');
                result.ops.push({kind: 'alu', operator: m, target: a, left: b, right: c, width: a.width});
            } else if (m === 'cdqe' || m === 'cwde') {
                arity(0); const width = m === 'cdqe' ? 64 : 32;
                if (width > bits) throw Error('invalid extension mode');
                const r = {kind: 'register', name: bits === 64 ? 'rax' : 'eax', offset: 0, width, familyWidth: bits};
                set(r, cast({...r, width: width / 2}, width, true));
            } else if (m.startsWith('set') && conditions[m.slice(3)]) {
                arity(1); const a = dest(args[0]);
                if (a.width !== 8) throw Error('invalid SETcc width');
                set(a, {kind: 'condition', code: m.slice(3), width: 8});
            } else if (m.startsWith('cmov') && conditions[m.slice(4)]) {
                const [a, b] = pair();
                // Memory CMOV reads even on the false path; leave it a barrier
                // until the view has an explicit unconditional-read operation.
                if (a.kind !== 'register' || b.kind !== 'register' || a.width === 8) throw Error('unsupported CMOV form');
                result.ops.push({kind: 'select', target: a, value: b, condition: m.slice(4)});
            } else if (m === 'push' || m === 'pop') {
                arity(1); const a = m === 'pop' ? dest(args[0]) : read(args[0]);
                if (a.width !== bits || a.kind === 'load' || m === 'pop' && a.name === (bits === 64 ? 'rsp' : 'esp'))
                    throw Error('unsupported stack form');
                result.ops.push({kind: m, value: a, width: bits});
            } else if (m === 'call') {
                arity(1);
                // Keep raw near-CALL facts even when the default effect is a
                // barrier. Never execute these facts and a summary together.
                if (d.prefixes.leadingBytes.some(p => p === 0x66)) throw Error('unsupported CALL operand-size prefix');
                const target = args[0].kind === 'immediate' && args[0].immediate?.interpretation === 'preferred_va' ?
                    constant(args[0].immediate.value, bits) : read(args[0]);
                if (target.width !== bits || !['constant', 'register', 'load'].includes(target.kind)) throw Error('unsupported near CALL target');
                result.call = {kind: 'near_call', width: bits, target,
                    returnAddress: constant(BigInt(report.module.imageBase) + BigInt(insn.rva + insn.size), bits),
                    entryStackDelta: -bits / 8, returnAddressBytes: bits / 8};
                throw Error('call effects and signature unknown');
            } else if (m === 'ret') {
                if (args.length > 1 || args.length && args[0].kind !== 'immediate' || d.prefixes.leadingBytes.length)
                    throw Error('unsupported return form');
                result.control = {kind: 'return', width: bits, adjustment: args.length ? read(args[0]) : constant(0, 16)};
            } else if (m === 'jmp' || m.startsWith('j') && conditions[m.slice(1)]) {
                arity(1);
                if (args[0].kind !== 'immediate' || args[0].immediate?.interpretation !== 'preferred_va')
                    throw Error('indirect control transfer');
                result.control = {kind: m === 'jmp' ? 'jump' : 'branch', condition: m.slice(1)};
            } else if (m === 'nop') {
                if (args.length > 1) throw Error('unsupported NOP form');
                result.ops.push({kind: 'nop'});
            } else throw Error(m === 'call' ? 'call effects and signature unknown' : 'instruction form not supported');
        } catch (error) {
            result.status = 'barrier'; result.reason = error.message;
            result.ops = [{kind: 'barrier', reason: error.message}]; delete result.control;
        }
        return result;
    }
    function expr(e, alias = () => null) {
        const child = e => expr(e, alias);
        if (e.kind === 'constant') return '0x' + BigInt(e.value).toString(16);
        if (e.kind === 'register') {
            let value = e.name;
            if (e.offset) value = '(' + value + ' >> ' + e.offset + ')';
            return e.width === e.familyWidth ? value : 'u' + e.width + '(' + value + ')';
        }
        if (e.kind === 'load') return alias(e) || 'read' + e.width + '(' + child(e.address) + ')';
        if (e.kind === 'cast') return (e.signed ? 'sext' + e.value.width + '_to_' : 'u') + e.width + '(' + child(e.value) + ')';
        if (e.kind === 'binary') {
            // Render modular negative displacements as subtraction. Arithmetic
            // remains explicitly truncated by the enclosing address cast.
            if (e.operator === '+' && e.right.kind === 'constant' && BigInt.asIntN(e.width, BigInt(e.right.value)) < 0n)
                return '(' + child(e.left) + ' - 0x' + (-BigInt.asIntN(e.width, BigInt(e.right.value))).toString(16) + ')';
            return '(' + child(e.left) + ' ' + e.operator + ' ' + child(e.right) + ')';
        }
        if (e.kind === 'condition') return condition(e.code);
        if (e.kind === 'integer') {
            const symbols = {add: '+', sub: '-', imul: '*', and: '&', or: '|', xor: '^'};
            let value;
            if (symbols[e.operator]) value = '(' + child(e.left) + ' ' + symbols[e.operator] + ' ' + child(e.right) + ')';
            else if (['not', 'neg'].includes(e.operator)) value = '(' + (e.operator === 'not' ? '~' : '-') + child(e.left) + ')';
            else if (['inc', 'dec'].includes(e.operator)) value = '(' + child(e.left) + (e.operator === 'inc' ? ' + 1)' : ' - 1)');
            // Shift helpers apply x86 count masking and signed SAR explicitly.
            else return e.operator + e.width + '_value(' + child(e.left) + ', ' + child(e.right) + ')';
            return 'u' + e.width + '(' + value + ')';
        }
        throw Error('unknown expression');
    }
    function condition(code) {
        return (conditions[code] || 'unknown_condition').replace(/\b(zero|carry|sign|overflow|parity)\b/g, 'flags.$1');
    }
    function assignment(target, value, alias = () => null) {
        if (target.kind === 'load' && alias(target)) return alias(target) + ' = ' + value + ';';
        if (target.kind === 'load') return 'write' + target.width + '(' + expr(target.address) + ', ' + value + ');';
        if (target.width === target.familyWidth || target.familyWidth === 64 && target.width === 32)
            return target.name + ' = ' + (target.width === 32 ? 'u32(' + value + ')' : value) + ';';
        return target.name + ' = insert' + target.width + '(' + target.name + ', ' + target.offset + ', ' + value + ');';
    }
    function operation(op, source, alias = () => null) {
        const read = e => expr(e, alias), write = (target, value) => assignment(target, value, alias);
        if (op.kind === 'assign') return write(op.target, read(op.value));
        // A 32-bit CMOV in long mode clears the upper half even when false.
        if (op.kind === 'select') return write(op.target, '(' + condition(op.condition) + ' ? ' + read(op.value) + ' : ' + read(op.target) + ')');
        if (op.kind === 'alu') {
            const args = [read(op.left)]; if (op.right) args.push(read(op.right));
            if (op.operator !== 'not') args.push('&flags');
            const value = op.operator + op.width + '(' + args.join(', ') + ')';
            return op.target ? write(op.target, value) : value + ';';
        }
        if (op.kind === 'push') return 'push' + op.width + '(' + read(op.value) + ');';
        if (op.kind === 'pop') return write(op.value, 'pop' + op.width + '()');
        if (op.kind === 'call_summary') return 'assume_windows_x64_call(' + read(op.target) +
            '); /* normal return; preserve nonvolatile GPRs/RSP; volatile GPRs, flags and memory unknown */';
        if (op.kind === 'nop') return '/* nop */';
        return 'unknown_effects("' + source.replace(/[^a-zA-Z0-9_]/g, '_') + '"); /* ' + op.reason + '; registers, flags, memory invalidated */';
    }
    const refs = nodes => [...new Set(nodes.flatMap(n => n.sources || []))];
    function recover(report, functionId, options = {}) {
        const unavailable = reason => ({version: VERSION, status: 'unavailable', reason, lines: [], instructions: [], regions: [], stats: {}});
        if (report.schema !== 2 || report.operandModelVersion !== 1 || !report.module?.decoderInfo?.capabilities?.structuredOperands)
            return unavailable('Structured operands unavailable; use the Capstone backend.');
        const f = report.functions.find(f => f.id === functionId);
        if (!f) return unavailable('Function candidate unavailable.');
        const blocks = [], owned = new Set(); let count = 0;
        for (const b of report.blocks) if (b.owners?.includes(functionId)) {
            blocks.push(b); owned.add(b.id); count += b.instructions.length;
            if (blocks.length > LIMITS.blocks || count > LIMITS.instructions)
                return unavailable('Recovery budget exceeded (128 blocks / 2048 instructions); assembly remains available.');
        }
        if (!owned.has(functionId)) return unavailable('Entry ownership is missing.');
        const edges = report.edges.filter(e => owned.has(e.from));
        if (edges.length > LIMITS.edges) return unavailable('Recovery edge budget exceeded (384 edges).');
        const outgoing = new Map(blocks.map(b => [b.id, []]));
        for (const e of edges) if (e.kind !== 'call') outgoing.get(e.from).push(e);
        const instructions = [], nodes = new Map(), liftedByBlock = new Map(), label = id => 'L_' + (blocks.find(b => b.id === id)?.rva.toString(16) || 'unknown');
        for (const b of blocks) {
            const lifted = b.instructions.map(i => lift(i, report)); instructions.push(...lifted);
            liftedByBlock.set(b.id, lifted);
        }
        const callAnalysis = CALL.apply(report, blocks, edges, liftedByBlock, functionId, options.callAssumptions);
        const valueAnalysis = VA.analyze(report, blocks, edges, liftedByBlock, functionId);
        const registerSSA = SSA.analyze(report, blocks, edges, liftedByBlock, functionId);
        const registerExpressions = EXPR.analyze(registerSSA, liftedByBlock, options.expressionLimits);
        const rewrites = new Map(registerExpressions.rewrites.map(r => [r.source + ':' + r.operation, r]));
        for (const b of blocks) {
            const lifted = liftedByBlock.get(b.id);
            const body = lifted.flatMap(i => i.ops.map((op, index) => {
                const r = rewrites.get(i.source + ':' + index);
                return {kind: 'line', text: operation(op, i.source), operation: op, sources: [i.source],
                    ...(r ? {simplifiedOperation: r.replacement, simplifiedText: operation(r.replacement, i.source), simplifiedSources: r.sources} : {})};
            }));
            const last = lifted[lifted.length - 1], outs = outgoing.get(b.id);
            let term = {kind: 'exit', text: 'unknown_control_transfer();', sources: last ? [last.source] : []};
            const target = e => e?.to && owned.has(e.to) ? e.to : null;
            if (last?.control?.kind === 'return' && !outs.length)
                term = {kind: 'return', control: last.control, text: 'return_to_caller' + last.control.width + '(' + expr(last.control.adjustment) + ');', sources: [last.source]};
            else if (outs.length === 2 && outs.some(e => e.kind === 'taken') && outs.some(e => e.kind === 'not_taken')) {
                term = {kind: 'branch', condition: last?.control?.kind === 'branch' ? condition(last.control.condition) : 'unknown_condition()',
                    test: {code: last?.control?.condition || null, negate: false},
                    yes: target(outs.find(e => e.kind === 'taken')), no: target(outs.find(e => e.kind === 'not_taken')),
                    sources: last ? [last.source] : []};
            } else if (outs.length === 1 && ['jump', 'fallthrough', 'continuation'].includes(outs[0].kind))
                term = {kind: 'goto', to: target(outs[0]), sources: last ? [last.source] : []};
            nodes.set(b.id, {id: b.id, body, term, sources: b.instructions.map(i => i.id)});
        }
        const aliases = new Map();
        for (const a of valueAnalysis.accesses) if (a.alias) aliases.set(a.source + ':' + a.key, a);
        for (const n of nodes.values()) for (const line of n.body) {
            const sources = [...line.sources];
            line.displayText = operation(line.operation, line.sources[0], e => {
                const a = aliases.get(line.sources[0] + ':' + VA.addressKey(e));
                if (a) sources.push(...a.sources);
                return a?.alias;
            });
            line.displaySources = [...new Set(sources)];
        }
        const successors = n => n.term.kind === 'goto' ? [n.term.to] : n.term.kind === 'branch' ? [n.term.yes, n.term.no] : [];
        const stats = {supported: instructions.filter(i => i.status === 'supported').length,
            barriers: instructions.filter(i => i.status === 'barrier').length, assumedCalls: callAnalysis.applied, ifs: 0, loops: 0, gotos: 0};
        // Local single-entry graph reductions. Each rule preserves all effects
        // and successors. No address-order heuristics or speculative joins.
        const mayStructure = !report.module.truncated && blocks.every(b => new Set(b.owners).size === 1);
        if (mayStructure) for (let pass = 0; pass < LIMITS.blocks * 4; ++pass) {
            const preds = new Map([...nodes.keys()].map(id => [id, new Set()]));
            for (const n of nodes.values()) for (const to of successors(n)) if (preds.has(to)) preds.get(to).add(n.id);
            const only = (id, from) => id && id !== functionId && preds.get(id)?.size === 1 && preds.get(id).has(from);
            let changed = false;
            for (const n of nodes.values()) {
                const t = n.term;
                if (t.kind === 'branch' && t.yes && t.no && t.yes !== t.no) {
                    const self = t.yes === n.id || t.no === n.id;
                    if (self) {
                        const cond = t.yes === n.id ? t.condition : '!(' + t.condition + ')';
                        n.body = [{kind: 'do', body: n.body, condition: cond, test: {...t.test, negate: t.yes !== n.id}, sources: [...n.sources]}];
                        n.term = {kind: 'goto', to: t.yes === n.id ? t.no : t.yes, sources: t.sources};
                        ++stats.loops; changed = true; break;
                    }
                    for (const [inside, outside, inverted] of [[t.yes, t.no, false], [t.no, t.yes, true]]) {
                        const a = nodes.get(inside);
                        if (only(inside, n.id) && a?.term.kind === 'goto' && a.term.to === n.id) {
                            n.body = [{kind: 'while', head: n.body, body: a.body,
                                condition: inverted ? '!(' + t.condition + ')' : t.condition,
                                test: {...t.test, negate: inverted},
                                sources: [...n.sources, ...a.sources], testSources: t.sources}];
                            n.sources.push(...a.sources); n.term = {kind: 'goto', to: outside, sources: t.sources};
                            nodes.delete(inside); ++stats.loops; changed = true; break;
                        }
                    }
                    if (changed) break;
                    const a = nodes.get(t.yes), b = nodes.get(t.no);
                    let yes = [], no = [], join = null, remove = [];
                    if (only(t.yes, n.id) && only(t.no, n.id) && a?.term.kind === 'goto' && b?.term.kind === 'goto' && a.term.to && a.term.to === b.term.to && a.term.to !== n.id) {
                        yes = a.body; no = b.body; join = a.term.to; remove = [a, b];
                    } else if (only(t.yes, n.id) && a?.term.kind === 'goto' && a.term.to === t.no && t.no !== n.id) {
                        yes = a.body; join = t.no; remove = [a];
                    } else if (only(t.no, n.id) && b?.term.kind === 'goto' && b.term.to === t.yes && t.yes !== n.id) {
                        no = b.body; join = t.yes; remove = [b];
                    }
                    if (join) {
                        n.body.push({kind: 'if', condition: t.condition, test: t.test, yes, no, sources: [...t.sources, ...refs(remove)]});
                        for (const r of remove) {n.sources.push(...r.sources); nodes.delete(r.id);}
                        n.term = {kind: 'goto', to: join, sources: t.sources}; ++stats.ifs; changed = true; break;
                    }
                }
                if (t.kind === 'goto' && t.to !== n.id && only(t.to, n.id)) {
                    const next = nodes.get(t.to);
                    if (next) {
                        // Keep the removed transfer's provenance, even when it
                        // has no visible statement after sequence reduction.
                        n.body.push({kind: 'line', text: '/* fall through */', sources: t.sources}, ...next.body);
                        n.term = next.term; n.sources.push(...next.sources); nodes.delete(next.id); changed = true; break;
                    }
                }
            }
            if (!changed) break;
        }
        const lines = [], displayLines = [], simplifiedLines = [], simplifiedDisplayLines = [];
        for (const slot of valueAnalysis.slots.filter(s => s.aliasable)) {
            const offset = BigInt(slot.offset);
            displayLines.push({text: '/* ' + slot.id + ': read/write' + slot.width + '(entry_sp - 0x' + (-offset).toString(16) + ') */',
                depth: 0, sources: slot.sources});
        }
        simplifiedDisplayLines.push(...displayLines);
        const add = (text, depth, sources = [], displayText = text, displaySources = sources,
            simplifiedText = text, simplifiedSources = sources, simplifiedDisplayText = displayText,
            simplifiedDisplaySources = displaySources) => {
            lines.push({text, depth, sources: [...new Set(sources)]});
            displayLines.push({text: displayText, depth, sources: [...new Set(displaySources)]});
            simplifiedLines.push({text: simplifiedText, depth, sources: [...new Set(simplifiedSources)]});
            simplifiedDisplayLines.push({text: simplifiedDisplayText, depth, sources: [...new Set(simplifiedDisplaySources)]});
        };
        function render(body, depth) {
            for (const node of body) {
                if (node.kind === 'line') add(node.text, depth, node.sources, node.displayText, node.displaySources,
                    node.simplifiedText, node.simplifiedSources, node.simplifiedText ?? node.displayText, node.simplifiedSources ?? node.displaySources);
                else if (node.kind === 'if') {
                    add('if (' + node.condition + ') {', depth, node.sources); render(node.yes, depth + 1);
                    if (node.no.length) {add('} else {', depth, node.sources); render(node.no, depth + 1);}
                    add('}', depth, node.sources);
                } else if (node.kind === 'while') {
                    add('while (true) {', depth, node.sources); render(node.head, depth + 1);
                    add('if (!(' + node.condition + ')) break;', depth + 1, node.testSources);
                    render(node.body, depth + 1); add('}', depth, node.sources);
                } else if (node.kind === 'do') {
                    add('do {', depth, node.sources); render(node.body, depth + 1);
                    add('} while (' + node.condition + ');', depth, node.sources);
                }
            }
        }
        const transfer = to => {if (to) {++stats.gotos; return 'goto ' + label(to) + ';';} return 'unknown_control_transfer();';};
        const regions = [...nodes.values()].sort((a, b) => a.id === functionId ? -1 : b.id === functionId ? 1 : 0);
        for (const n of regions) {
            add(label(n.id) + ':', 0, n.sources); render(n.body, 1);
            const t = n.term;
            if (t.kind === 'branch') {
                add('if (' + t.condition + ') ' + transfer(t.yes), 1, t.sources);
                add('else ' + transfer(t.no), 1, t.sources);
            } else add(t.kind === 'goto' ? transfer(t.to) : t.text, 1, t.sources);
        }
        return {version: VERSION, status: stats.barriers ? 'partial' : stats.assumedCalls ? 'assumed_subset' : 'supported_subset', instructions, regions,
            lines, displayLines, simplifiedLines, simplifiedDisplayLines, valueAnalysis, registerSSA, registerExpressions, callAnalysis, stats,
            structured: mayStructure, complete: false, functionId,
            notice: 'C-like preview of normal-path machine effects. Inferred function boundaries; complete recovery is not proven. Registers retain machine names. read/write addresses are byte addresses; helpers use fixed-width bit vectors. Calls without an explicit summary and unsupported forms invalidate all state. Selected call summaries are analyst assumptions. for/while source spelling, variable names, types and I/O prototypes are not recovered.'};
    }
    const api = {VERSION, LIMITS, lift, recover, expr, condition};
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WEAPseudocodeModel = api;
})(typeof globalThis === 'object' ? globalThis : this);
