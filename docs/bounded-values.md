# Bounded values and stack memory aliases

Implemented in [`5c61ae7`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/5c61ae739ef57ef22075873fb5c3d74db5ec36db).

C-like preview v2 adds entry-relative register facts and readable stack memory
aliases to the existing typed operations. Open `transform_demo` in an O0 report,
select **C-like → Analysis details**, and expand **Stack locations**.
**Stack aliases** in the **Code** tab switches between named accesses and the original address expressions.
**Sources** shows the contributing instructions; expand **Value facts** for
before/after facts at the first instruction in that list. All original assembly links and rename IDs stay
stable.

For example, a proven 32-bit access at incoming SP minus 28 bytes can display as
`slot_m1c_u32 = 0x7;`. The comment above the code defines that name as
`read/write32(entry_sp - 0x1c)`. Every use still reads or writes that exact memory;
the name is neither an independent variable nor recovered C source. The raw
view still shows `write32(u64(rsp + 0x4), 0x7);` for a 32-byte allocation.
An unknown indexed access may alias a named slot. No load is cached and no
memory operation, flag update, call, trap or register assignment is removed.

```sh
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --raw
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --json
```

The current JSON export has `version: 8`, raw `lines`, alias-aware `displayLines`,
the unchanged typed instructions/regions, and `valueAnalysis.version: 1`.
Version 3 added [register SSA](register-ssa.md); version 4 adds
[explicit call assumptions](call-summaries.md) alongside the v2 value analysis.
Version 5 adds [register expressions](register-expressions.md) as a separate overlay. Analysis
results are computed on demand by the shared browser/Node model; native report
schema 2, `operandModelVersion: 1` and decoder capabilities are unchanged.
LLVM/legacy reports still report unavailable semantic features.

## Domain and transfer contract

[value-domain.js](../web/value-domain.js) holds 8/16/32/64-bit values. A finite
disjunction has at most four atoms, with these representations:

| Atom | Meaning and production rule |
| --- | --- |
| Constant | Exact modular unsigned bit pattern, serialized as a decimal string |
| Module address | Preferred VA plus module ID/base/RVA; classified only when an evaluated memory address starts within a reported mapped region |
| Entry-stack address | `entry_sp + signed offset`, with arithmetic modulo the native pointer width |
| Import reference | Reserved for independently supplied bindings; the pass never creates one from an IAT load |
| Unknown | Any bit pattern consistent with the retained known-bit mask/value |

Joins union alternatives, then widen to common known bits when the set exceeds
four. An unknown predecessor is never dropped. Known bits preserve partial
register writes, zero/sign extensions and supported logical/shift effects.
Module labels do not assert memory validity, a function pointer, a section type
or static load contents. Numeric address arithmetic may lose that label and be
classified again at a later memory access. Mixed symbolic alternatives remain
ambiguous; unsupported symbolic arithmetic becomes unknown.

[value-analysis.js](../web/value-analysis.js) consumes the same typed operations
as [pseudocode-model.js](../web/pseudocode-model.js). The abstract transfers and
test evaluator share integer data-result definitions in
[bitvectors.js](../web/bitvectors.js); flags remain explicit in the typed model.
The supported forms and normal-path assumptions are those in the
[recovery contract](c-like-recovery.md). Register copies, native stack/frame
address arithmetic, fixed-width integers, partial writes and extensions are
tracked. x64 32-bit writes zero-extend even for a false CMOV32 outcome. PUSH/POP
track native stack displacement, and after-RET facts include the popped return
address and encoded adjustment. Popped register values are unknown.

**All memory loads remain unknown**, including a load immediately after a store,
static data, saved-register slots and IAT-shaped addresses. No memory store
forwarding or alias-dependent value propagation is performed. Unselected calls
and every unsupported operation clear all register facts, including stack/frame
pointers. Preview v4's explicitly selected Windows x64 summaries retain
nonvolatile GPR/SP facts with the call assertion attached to their provenance.
All memory contents and flags remain unknown; call home/return storage is
excluded from independent-local interpretations. See the [call contract](call-summaries.md).
Flags are not abstractly propagated; both branch/CMOV/SETcc outcomes remain
possible, including infeasible paths.

## Fixed point, candidates and limits

The pass seeds only the candidate entry with symbolic SP. It runs a forward
worklist over owned discovered non-call edges, joins all reached predecessors,
and accumulates prior outputs so finite-set widening cannot oscillate. Loops
retain invariant stack facts when supported, but growing counters widen. No
facts are assigned to disconnected blocks. The pass does not discover code,
resolve indirect edges or prove function membership; `complete` is always false.

A named slot requires one proven entry-relative address at every recorded use
of that offset/width, entirely within the currently allocated negative-offset
stack region, with an uncapped address/SP derivation. The stack table retains
excluded locations and their reasons:

- Return-address regions and implicit return accesses are never local aliases.
- PUSH/POP storage is labeled as such; saved registers versus outgoing
  arguments are not guessed.
- Positive entry-stack offsets are kept explicit. On x64, offsets +8 through
  +39 may be the Windows home area, but the actual function/ABI role is unproven.
- Overlapping ranges or widths disable aliases for every affected candidate.
  Ambiguous joined addresses, accesses below current SP, dynamic stack changes,
  pointer-width truncation and incomplete provenance keep explicit accesses.
- The slot width describes a memory operation, not a recovered C type. Spills,
  outgoing parameters and locals are not distinguished by this value pass. The separate [v7 storage-role pass](stack-storage.md) labels supported patterns without relaxing these alias rules.

These conservative labels follow Microsoft's
[x64 stack usage](https://learn.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-170)
documentation: memory below current SP is volatile, and frame/home space can be
reused for several purposes. Instruction arithmetic follows the Intel references
in the recovery contract. No Windows x64 ABI profile is applied to x86 or custom
calling conventions.

| Budget | Limit / fallback |
| --- | --- |
| Function | 128 blocks, 2,048 instructions, 384 outgoing edges |
| Value alternatives | 4; widen to common known bits |
| Address offset | ±1 MiB; larger symbolic stack offsets become unknown |
| Provenance per value | 64 instruction IDs; mark truncation and disable dependent aliases |
| Fixed-point work | 4,096 block visits / 65,536 operation transfers |
| Recorded memory accesses | 8,192 |

Shared ownership, truncated discovery, unresolved non-call edges or outside
edges into the function interior disable the pass. Work-budget exhaustion
discards **all** provisional facts/slots, with an explicit reason; raw pseudocode
remains available. These bounds are separate from the existing CFG reductions.

## Validation

```sh
node tests/test_value_domain.js
python3 tests/test_value_analysis.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
python3 tests/test_pseudocode_oracle.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
python3 tests/test_pseudocode_browser.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
```

The domain suite checks 291 contracts, including exhaustive concretizations of
8-bit finite/known-bit arithmetic and shifts with independent integer formulas.
Decoder-to-analysis tests cover constants, conflicting/unknown joins, loop
widening, x86/x64 frame pointers, overlapping slots, dynamic stack adjustment,
call/unsupported clobbers, mutable/IAT-shaped loads, missing edges, provenance
caps and budget exhaustion. The existing nested-loop C demo is compiled at
O0/O1 for both architectures without source hints in the analyzer.

Local validation on 2026-10-19 uses Zig 0.13.0 / Clang 18.1.6: 121 analysis
contracts with the four generated reports and all 705 independent Unicorn
semantic cases pass. The oracle also checks static facts against every concrete
instruction state along those CFG/demo executions (6,370 states), and validates
2,017 concrete alias addresses. This verifies the displayed memory aliases as
well as the unchanged reduced-region effects. It is test-only emulation; the
product never executes the input EXE. Both backend CTest suites pass (19 local
targets each; linked compiler fixtures generated separately).
The browser checks pass for Capstone (24) and LLVM fallback (11), along with
15 publication tests. A local Node run over all 28 candidates in the four reports
took 53 ms total, with an 8.4 ms maximum per candidate; this is a corpus timing,
not a worst-case resource bound.

Hosted validation for `96a8c60` on 2026-10-19:

- [Analysis matrix passed](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/39217062898):
  21 CTest targets and 15 publication tests per backend, all existing browser
  suites, 24 Capstone C-like checks and 11 LLVM fallback checks. The Capstone
  job passed 705 independent cases with Clang 18/lld-link fixtures, checking
  6,654 executed instruction states and 2,017 alias addresses. LLVM explicitly
  skips semantic emulation.
- [Demo deployment passed](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/39217063042).
  The live manifest identifies the tested revision and eight reports. The
  [x64 O0 nested-loop demo](https://asr-tanyi.github.io/windows-exe-analyzer/recovery64-o0.html#m_38ea623bd3bb24a7_c_11a0)
  includes the updated preview. Live HTML/JSON returned HTTP 200 and the embedded
  analysis/view sources matched the committed files. The downloaded self-contained
  HTML passed browser checks for its eight aliases, raw toggle and value evidence.
  This site serves the latest deployment; workflow artifacts retain the tested snapshot.

## Next slice

[Register def-use/SSA joins](register-ssa.md) are now implemented in preview v3
for the bounded integer GPR subset (M7.1). Preview v4 also implements the explicit
Windows x64 normal-return subset of [M4.7 call summaries](call-summaries.md).
Preview v5 implements bounded pure-register expression substitution within blocks
([P5 contract](register-expressions.md)); preview v6 adds bounded
[dead register-write cleanup](register-cleanup.md), completing the block-local
M7.2 subset. Keep memory aliases
observable until alias assumptions and storage roles are supported. Broader ABI
profiles, I/O prototypes, indirect discovery, source local names/types,
argument/return inference, switches and exceptional paths remain pending;
Preview v7 adds [bounded storage roles](stack-storage.md) for the M7.3 subset without changing this value domain or forwarding loads. Preview v8 adds [function ABI register evidence](function-abi.md); M7.4 remains open.
