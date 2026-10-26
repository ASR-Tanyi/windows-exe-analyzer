# Conservative stack storage roles

Implemented in [`946b913`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/946b9137552358282c9cb732006dfd81e32bb7df).

Preview v7 adds `stackStorage.version: 1` beside the existing value analysis and
register SSA. Open **C-like → Analysis details → Stack locations** to inspect
roles, qualifications and exact instruction evidence. This is the bounded P7
subset of M7.3. It labels physical storage without changing any memory access,
alias, register effect, expression transformation or cleanup decision.

```sh
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --storage
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --json
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --storage --calls assumptions.json
```

Use a function RVA from the report. `--storage` and `--ssa` inspect original
evidence; `--simplified` and `--clean` apply only to code output. Native schema 2,
operand model 1 and stable annotation/navigation identities are unchanged.
LLVM and legacy reports retain their explicit unsupported-semantic result.

## What each label establishes

| Label | Evidence and limit |
| --- | --- |
| Saved entry register | A full native-width entry-register value was stored and reloaded into the same register/slice. Every discovered incoming path supplies a matching store and no possible intervening overwrite. This is a store/reload pair, not proof that the register is preserved at every function exit or is nonvolatile under an ABI. |
| Spill/reload candidate | A preceding store and reload of the same register slice are linked. The stored value is a later definition or a partial entry-register slice. Compiler intent and original variable identity are unknown. |
| Entry return-address region | Access overlaps the pointer-sized region at incoming SP. Its contents may be overwritten; the label does not prove the function returns to its caller. |
| Return target storage | An observed RET reads this region. A changed SP can make it different from the entry return-address region. |
| Call return-address region / Callee home space | Regions described by an explicitly selected Windows x64 call contract, with the call assumption retained in the evidence. No profile is inferred from PE bitness or an import name. |
| Outgoing stack-argument candidate | A preceding, still-live store lies at an eight-byte slot boundary beyond the selected call's home area. It may instead be other caller storage; no argument count or prototype is inferred. |
| Local / temporary candidate | The existing physical alias analysis proves allocated, nonoverlapping frame storage, without stronger role evidence. It is not an independent recovered C local. |
| Unclassified / Unknown | Incoming stack areas, unmatched PUSH/POP storage, ambiguous addresses or other insufficient evidence retain their uncertainty. |

Overlapping ranges and multiple roles are marked as mixed. Storage can be reused
at different points; a physical slot does not imply one variable or one lifetime.
Incoming positive offsets are not automatically classified as home space because
there is no explicit function-entry ABI contract yet. Call-area observations also
apply to overlapping smaller accesses, so a four-byte store in a callee-owned
eight-byte home region cannot be presented as an independent local.

The ABI regions follow Microsoft's [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170)
and [stack usage](https://learn.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-170)
contracts. The caller reserves home storage even when arguments are not stored
there, and the callee may reuse it. Additional stack arguments follow that area;
the existence of the area alone does not identify actual parameters.

## Proof and failure boundaries

[`stack-storage.js`](../web/stack-storage.js) consumes completed entry-relative
address facts, original typed operations and register SSA. A bounded forward
worklist tracks definitely preceding stores. At joins, it intersects matching
physical slices and register definitions across all reachable predecessors;
unknown/missing predecessors are not dropped. Matching stores on alternative
paths retain all source witnesses. Loop-invariant stores can survive; loop
overwrites remove the proof. Results are collected only after convergence.

The pass supports direct register MOV stores/reloads and native PUSH/POP. Full
entry-register identity must come directly from SSA; copy chains, extension
loads, reloads into a different register, vectors and general memory SSA are not
claimed. A partial slice may be a spill/reload candidate but cannot establish
full entry-register preservation.

Every known stack write invalidates overlapping stored slices. An unknown or
non-stack write may alias the stack and clears all remembered contents. Every
call, including an explicitly summarized call, also clears them. Unknown SP,
truncated address evidence and deallocation prevent a pair; restoring SP or
reallocating the same address does not resurrect old contents. This treats
released/below-SP storage conservatively, consistent with the stack contract.

These are normal-path proofs over discovered ownership, not exceptional-path or
whole-function correctness guarantees. Shared/truncated ownership or unresolved
flow disables the required value/SSA passes and therefore the role pass.
`complete` remains false. There is no load forwarding: loads remain unknown in
value analysis, register SSA still records memory reads, and every original
memory operation remains in all code presentations.

| Bound | Limit / fallback |
| --- | --- |
| Physical slices | 256, including implicit return/call regions |
| Fixed-point visits | 4,096 |
| Work units | 131,072 across transfers, joins and role collection |
| Evidence per stored value / role | 64 source instructions |
| Save/reload pairs | 2,048 |

The existing 128-block, 2,048-instruction and 384-edge recovery bounds also apply.
Options can lower these limits, not remove them. Any exhausted budget discards
all provisional roles/pairs. The report retains physical addresses and states
the fallback reason. Sources link stores, reloads, address derivations and any
explicit ABI assumptions; the base report and SSA retain the underlying CFG.

## Validation

Local validation on 2026-10-26 used Capstone 5.0.9, LLVM 20, Zig 0.13.0 / Clang
18.1.6, Playwright 1.57.0 and Unicorn 2.1.4:

- 180 focused storage checks cover both architectures, full and partial slices,
  matching/conflicting/missing incoming stores, loops, aliases, overlap,
  allocation lifetimes, unknown SP, explicit/default calls, evidence, immutable
  inputs and transactional budgets, including the actual 256-slot ceiling.
- 94 Capstone / 15 LLVM decoder/CLI contracts include all four source-known x86/x64 O0/O1 reports,
  unsafe ownership, explicit call-area provenance and backend fallback.
- 25 local CTest targets pass per backend; linked Clang/lld fixture generation
  is performed separately with Zig locally and by Clang/lld in hosted CI.
- 90 Capstone / 13 LLVM C-like browser checks pass, including stack-role sources,
  exact assembly/history navigation, candidate/ABI qualifications and the
  existing code, register-flow, keyboard, mobile and escaping checks.
- All four code presentations agree across 1,260 independent emulator cases,
  including 48 new storage executions. The emulator checks 148 claimed reloads
  against actual memory, including 56 full saved entry-register values. Existing
  36 independent call executions and 15 publication tests also pass.

On the 28 local C-demo candidates, 20 role-pass repetitions per function averaged
3.8 ms for one pass over the corpus, with a 0.76 ms maximum per function.
The Node 24.22.1 process peaked at about 78 MiB RSS, including the existing
analysis models, on a shared Linux x64 / Xeon Platinum 8573C host. This is a
fixture measurement, not a worst-case bound.

Hosted validation on 2026-10-26:

- The [Capstone/LLVM matrix](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/40283334985)
  passed all 27 CTest targets per backend, 15 publication tests and every browser
  suite, including 90 Capstone / 13 LLVM C-like checks.
- All 1,260 independent recovery cases and 36 call executions passed. With the
  hosted Clang 18 fixtures, the storage oracle checks 133 concrete reloads and
  41 saved entry-register values. The broader oracle checks 9,451 instruction
  states, 2,057 stack-alias addresses and 10,612 SSA uses. Counts differ from the
  local Zig fixtures because their emitted prologues and instructions differ.
- [Pages deployment](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/40283334967)
  passed. HTTPS downloads confirmed the tested commit and exact current model/view
  sources in all eight reports. The published reports passed all 90 C-like browser
  checks offline. The x86 scalar demo's v7 storage model exactly matches CLI JSON;
  proven-pair source links, assembly/Back navigation and phone layout were checked.

In the [published scalar demo](https://asr-tanyi.github.io/windows-exe-analyzer/recovery32-o0.html#m_6d2d785961232386_c_1000),
open **Analysis details → Stack locations** to see the saved EBP pair and a
spill/reload candidate. The site follows the latest deployment; workflow
artifacts retain the tested snapshot.

The next milestone is M7.4: explicit function ABI contracts and conservative
argument/return candidates. Original variable names/types, actual outgoing
argument counts, whole-function register preservation, other ABI profiles and
general memory/flag SSA remain outside this slice.
