# Bounded register-expression simplification

Preview v5 adds a separate expression overlay to the original lifted operations.
Open **C-like → Simplify register expressions** (enabled initially) to see it;
turn the checkbox off to recover the original operations. The existing optimized
`scalar_ops` demo shows propagation through arithmetic; `transform_demo` exercises
branches, loops and memory boundaries. Source links include the consuming
instruction and every contributing definition.

```sh
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --simplified
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --raw --simplified
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --json
```

The CLI's existing default and `--raw` output remain unchanged. `--simplified`
selects the new text presentation; `--raw` additionally disables stack aliases.
JSON includes both presentations. `--ssa` continues to describe original machine
operations. Call bindings can be combined with simplified text, but no expression
propagates through a call, including a selected ABI summary.

## Supported transformations

[register-expressions.js](../web/register-expressions.js) consumes the existing
[register SSA](register-ssa.md) before structural graph reduction. Each block
starts with an empty expression cache. A pure definition can be substituted at a
later read only while every register leaf still has its recorded SSA version.
The version check matters for `a = b; b = b + 1; c = a`: substituting the new `b`
for `a` would be incorrect. A self-update cannot refer to its old register value
unless that value can be expressed using other still-current inputs or constants.

| Operation | Behavior |
| --- | --- |
| Constants and copies | Substitute within a block, tracking contributing source/definition IDs |
| Arithmetic/bitwise data results | Fold constants; simplify zero/one identities and same-version XOR/subtraction; substitute bounded pure expressions |
| Casts and slices | Preserve modular 8/16/32/64-bit widths, high-byte extraction, sign extension and x64 32-bit zero extension |
| Partial writes | Original insert/preservation semantics remain; a new 8/16-bit definition is not propagated as a full-register value |
| ALU flags | Keep the original ALU operation, operator and width; only its pure operands change |
| Loads, stores, stack operations, calls and unsupported effects | Keep original operations and stop expression propagation |
| Flag-dependent SETcc/CMOV and control transfers | Keep original operations and stop propagation; no flag-expression substitution |
| Joins and loops | Never substitute predecessor/PHI expressions; each original basic block is analyzed independently |

For example, `mov eax, 0xffffffff; add eax, 2; mov edx, eax` is displayed as:

```c
rax = u32(0xffffffff);
rax = u32(add32(0xffffffff, 0x2, &flags));
rdx = u32(0x1);
```

The arithmetic instruction still updates flags and the intermediate register
write remains. The final line links to all three instructions. This overlay
removes no instructions, register writes, memory accesses, calls, traps or flag
updates. It does not infer source variables or types. No memory value is cached.

`integer` expression nodes describe only a modular data result. Their operands
are pure expressions, with no load or flag read. The renderer uses explicit `uN`
truncation for arithmetic/bitwise expressions. `shlN_value`, `shrN_value` and
`sarN_value` use x86 count masking; SAR interprets the left operand as signed at
width N. These value helpers have no flag effects. Original ALU helpers still
receive `&flags`. BigInt arithmetic avoids JavaScript Number rounding.

## Export and fallback

The native report remains schema 2; SSA and value analysis remain version 1.
Preview JSON is version 5 with these additive fields:

| Field | Contract |
| --- | --- |
| `registerExpressions` | Version 1, status/reason, bounded rewrites, statistics and notice |
| `rewrites[]` | Consumer source, operation index, replacement typed operation, contributing source IDs and SSA definition IDs |
| `regions[].body` line nodes | Original `operation` remains; changed lines also have `simplifiedOperation`, text and sources |
| `simplifiedLines` | Simplified text with raw memory addresses and combined provenance |
| `simplifiedDisplayLines` | Simplified text with the existing optional stack aliases |
| `instructions`, `lines`, `displayLines` | Original lifted instructions and original presentations remain available |

Shared/truncated ownership and other SSA-unavailable cases disable simplification
with a visible explanation. Disconnected blocks without SSA records stay raw.
Per-expression limits are 64 nodes, depth 12 and 64 source IDs; reaching these
limits retains the original operand/operation and stops caching oversized values.
The pass caps total replacement operand nodes at 32,768 and counted work at
131,072. Exhausting either global budget discards every provisional rewrite;
original operations remain available. Existing recovery/SSA size budgets apply
first. Source lists are never silently truncated to support a rewrite.

## Validation

The tests are in [test_register_expressions.js](../tests/test_register_expressions.js),
[test_pseudocode.py](../tests/test_pseudocode.py),
[test_pseudocode_oracle.py](../tests/test_pseudocode_oracle.py) and
[test_pseudocode_browser.py](../tests/test_pseudocode_browser.py).

```sh
node tests/test_register_expressions.js
python3 tests/test_pseudocode.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
python3 tests/test_pseudocode_oracle.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
python3 tests/test_pseudocode_browser.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
```

The semantic harness evaluates original and simplified structured regions
separately, compares every register, defined flag and memory byte, and compares
with independent Unicorn execution of our authored/source-known machine code.
It also checks source-level results for x86/x64 O0/O1 compiler fixtures. New
multi-instruction cases specifically exercise substitutions and near misses;
independent emulation remains test-only. The analyzer and HTML viewer stay static.

Local validation on 2026-10-22 passed:

- Both Capstone and LLVM builds pass 22 CTest targets. The expression pass has
  225 focused checks; decoder/recovery integration passes 118 contracts with the
  source-known compiler fixtures. The fixture manifest retains Zig 0.13.0 /
  Clang 18.1.6 build identity; their C source and binaries are unchanged.
- All 987 independent instruction/CFG/source cases pass original/simplified
  parity, including 276 new expression-chain executions. The same run checks
  8,109 instruction states, 2,017 concrete stack-alias addresses, 9,739 SSA uses,
  720 selected joins and 5,136 exit values. One earlier parallel local run
  stopped at the emulator's existing return-budget assertion; the standalone
  rerun passed all cases without a semantic mismatch.
- Browser checks pass for Capstone (61) and LLVM fallback (13), including shared
  model output, original/simplified toggling, combined source links, history,
  unsafe-SSA fallback and the existing call controls. The optimized scalar
  preview was also inspected visually. All 15 publication checks pass.
- The existing 36 call executions still pass across 108 boundaries, including
  two invalid-ABI negative cases, 756 caller states, 2,352 SSA uses, 144 joins
  and 576 exit values.
- A full recovery run across 28 compiler-fixture candidates produced 49 changed
  operations. Under concurrent local validation it took 792.9 ms total /
  128.5 ms maximum per function (including lifting, value analysis, SSA and graph
  recovery). The largest expression overlay was 6,140 bytes, with at most 353
  counted expression-pass work units. This is a corpus measurement, not a
  worst-case guarantee.

## Next slice

This completes the constant/copy and pure-expression subset of M7.2 (P5).
M7.2 remains open for dead-value cleanup and wider propagation. Next, consider
bounded dead register-write cleanup with SSA liveness and explicit preservation
of flag, memory, call, trap and exit-state effects. Cross-block substitution,
precise memory SSA, source locals/types and argument/return recovery remain open.
