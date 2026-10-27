# Explicit function ABI evidence

Preview v8 adds an opt-in, read-only `functionABI.version: 2` inspector. Open a
Capstone x64 function's **C-like → Analysis details → Function contract and
candidates**, then select **Assume Windows x64**. The existing `transform_demo`
in `recovery64-o0.html` and `recovery64-o1.html` exercises all four integer
register locations, loops, arrays, branches, and a direct caller.

This includes **P8 register evidence and P9 block-local stack evidence of M7.4**. It identifies possible machine
inputs and outputs, not a C prototype. Broader stack recovery, floating-point parameters, hidden
parameters, varargs, source types and prototype reconciliation remain open.
No original effects, stack aliases, call summaries, exits, or code presentations
change when the profile is selected. Code opens first; the new inspector stays
inside Analysis details. Source links open the owning function's exact assembly,
including links into a different caller. Back preserves the selected contract.

## What the evidence means

The reviewed profile is `windows-x64-gpr-v1`, based on Microsoft's
[x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170).
The first four integer register locations are RCX, RDX, R8 and R9, with integer
return candidates in RAX. ABI positions are not a recovered parameter count;
the corresponding floating-point locations, aggregate rules, hidden parameters
and unprototyped/variadic calls prevent inferring a signature from these GPRs.

| Evidence | Interpretation and limits |
| --- | --- |
| Possible register input | A supported operation may read unchanged entry bits from an ABI register location. The mask records those bits, not a source type. Copies, address calculations and spills can be witnesses. |
| RAX at a reachable RET | Reaching definitions are retained separately, including incoming values and unknown call/unsupported-operation clobbers. A write can be incidental in a void function. |
| Caller location | Each supported direct caller shows the reaching value at all four locations. An incoming value or preceding write does not prove an argument was passed. The caller's own entry ABI remains unknown. |
| Call-result read | A supported caller operation may read bits from the call's RAX clobber before those bits are overwritten. This is conditional on reaching the recorded continuation. No normal-return assertion is activated. |
| Contract conflict | Nonzero RET argument cleanup contradicts the selected Windows x64 caller-cleanup convention. The observation and warning remain visible; the selection is not certified. |

Evidence follows the original reachable register SSA, before expression
simplification and dead-write cleanup. A bounded fixed point tracks **may-reach
unchanged bits** through PHIs and the preserved portion of partial writes.
An x64 32-bit write clears all incoming bits of that register family. Unknown
effects end the identity chain. Ordinary computations end it too: their first
operand read is the input witness, not a claim that their result equals an
argument. Same-slice register XOR/SUB zeroing idioms are excluded.

PHIs union possible incoming bits; they do not say that every path reads an
entry value. Witnesses include contributing predecessor transfers and partial
writes. Return alternatives traverse PHIs without merging different writes or
dropping unknown alternatives. A partial RAX write records its slice and
preservation/zero-extension behavior, without choosing a return width.

## Callers and assumptions

Only discovered direct calls to the exact selected entry are examined. Each
caller must have unambiguous ownership, available SSA, a supported native CALL
target matching the callee's preferred address, and a unique owned continuation.
Unavailable or ambiguous caller records keep their reason. Indirect calls,
tail transfers, undiscovered callers and exception paths are outside this view.
No recursive interprocedural recovery is performed.

The caller's auxiliary SSA observes RCX/RDX/R8/R9 immediately before each raw
CALL, using `observeCallInputs: true`. These are diagnostic reads, not a
prototype. Every original all-register clobber remains. Normal register SSA
does not enable these observations. A prior unknown call therefore stays
unknown even if another function convention or report view was selected.

Function contracts and [call-site assumptions](call-summaries.md) are separate
documents and controls. Selecting a function convention does not preserve SP
or nonvolatile registers across its calls. If separately selected call summaries
affect the function's original SSA, their source IDs remain in
`functionABI.assumptionSources` and are linked in the inspector. Caller
observations always use the default all-state CALL barriers.

## Binding, JSON and CLI

Export/import is scoped to this exact module and function:

```json
{
  "version": 1,
  "moduleId": "<exact report module ID>",
  "functionId": "<exact function ID>",
  "profile": "windows-x64-gpr-v1"
}
```

Export from the UI for real IDs. `profile: null` clears the selection. Extra
fields, wrong identities, unsupported profiles, nonobjects and invalid versions
reject the entire document. Types/prototypes are not accepted by this schema;
they are never silently interpreted or discarded. Display annotations remain
separate. Files are capped at 64 KiB. Browser parse/size errors clear the previous
selection; schema errors display a rejection with no candidates. Reload clears
session selections. CLI parse/size errors return 1 and invalid bindings return 2.

```sh
node scripts/pseudocode.js report.json 0xFUNCTION_RVA --function-contract function-contract.json --abi
node scripts/pseudocode.js report.json 0xFUNCTION_RVA --function-contract function-contract.json --json
```

`--abi` is a text evidence export, mutually exclusive with `--raw`, `--ssa`,
`--storage` and `--json`. It requires available selected evidence and returns 2
otherwise. `--simplified` and `--clean` select code presentations and cannot be
combined with `--abi`. `--calls` remains a separate optional input.

The native report remains schema 2 and operand model version 1; preview JSON
advances to 8. `functionABI` exports the normalized contract, eligibility,
status (`default`, `available`, `invalid`, `unavailable`, `budget_exceeded`),
arguments, per-RET alternatives, per-caller observations, conflicts, assumption
sources and resource counts. `complete` remains false. The function's overall
support status still describes its original machine effects; the ABI selection
is an explicit assumption in this separate evidence object.

## Resource bounds and fallback

| Resource | Hard ceiling |
| --- | ---: |
| Function ABI data-flow work | 131,072 |
| Observations / leaf alternatives | 256 |
| Source IDs per evidence union | 64 |
| Direct call sites | 32 |
| Distinct caller functions analyzed | 8 |
| Module items scanned (functions, blocks, instructions, edges) | 131,072 |
| Contract file bytes | 65,536 |

The usual 128-block / 2,048-instruction / 384-edge function bounds apply, as do
the independent register-SSA ceilings for each of the at most eight callers.
`functionAbiLimits` can only lower these limits with safe integers; larger,
NaN or infinite options cannot disable them. Exceeding any ABI budget discards
all provisional candidates and caller results, with a reason. The selected
contract remains explicit and the original code/assembly remains available.
LLVM, x86, shared/truncated functions and unsupported SSA graphs never borrow
this profile's semantics.

## Validation

```sh
node tests/test_function_abi.js
python3 tests/test_function_abi.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
python3 tests/test_function_abi_browser.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
python3 tests/test_function_abi_oracle.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
```

Local validation on 2026-10-26:

- 27 CTest targets pass on both Capstone and LLVM. Linked fixture generation is
  separate locally; CI also registers two compiler-fixture generation targets.
- 100 focused graph checks and 77 Capstone / 2 LLVM decoder/CLI checks cover
  partial registers, zeroing, joins, loops, unreachable code, unknown effects,
  per-return alternatives, contract conflicts, caller ownership/continuations,
  exact export parity, rejected bindings and actual resource ceilings.
- 28 Capstone / 3 LLVM browser checks cover explicit selection, default absence,
  input/return/caller evidence, exact cross-function assembly navigation, Back,
  export/CLI parity, malformed and oversized files, reset, reload, rename,
  keyboard-native controls and phone layout. Existing C-like browser checks
  pass unchanged: 90 Capstone / 13 LLVM.
- Independent Unicorn execution of authored bytes and the existing O0/O1 C
  ladder checks 60 executions, 194 input reads, 60 concrete return values,
  100 caller values and 32 call-result reads. Candidate input bits have concrete
  witnesses across the authored branch paths. The oracle checks executed
  values against reported source definitions; it does not reuse the ABI pass
  to calculate instruction effects. Emulation remains test-only.
- Existing semantic checks pass: 1,260 recovery cases with original/simplified/clean/combined parity, 148 concrete stack reloads, and 36 call executions across 108 call/return boundaries. All 15 publication checks also pass.

A warmed Node 24.22.1 measurement over 20 repetitions of the 14 x64 O0/O1
function candidates averaged 1.75 ms in the ABI pass, including caller SSA,
with a 50.1 ms observed maximum on the shared Linux x64 host. The process
peaked at about 111 MiB RSS including all recovery models. This is a corpus
measurement, not a worst-case bound or an isolated peak-memory measurement.

### Hosted validation follow-up (2026-10-27)

The initial [matrix run](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/40348928866) passed LLVM but stopped Capstone at the existing CFG keyboard test. Arrow selection replaced the canvas and deferred focus until an animation frame, allowing a following Enter to be lost. The follow-up restores focus synchronously and adds a same-task regression that fails on the old implementation and passes with the fix (15 CFG checks). The downloaded published ABI demo passes all 28 function-contract browser checks, including export/CLI parity and cross-function links. [Report deployment](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/40348928401) succeeded. The initial Capstone run is not counted as complete. The [replacement matrix](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/40439251948) passes Capstone: 29 CTest targets, all browser suites (including 15 CFG and 28 function-ABI checks), 1,260 recovery cases, 36 call executions and 60 ABI executions. Hosted storage checks observe 133 reloads; the earlier local compiler corpus observed 148. LLVM subsequently passed all 29 CTest targets and its browser/fallback suites.

The [replacement deployment](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/40439251800) succeeds. All eight downloaded live reports match the implementation and embed the focus fix. The published CFG passes 15 checks; the function-ABI demo passes 28 including export/CLI parity. One local repeat briefly failed the signature-uncertainty text assertion; the unchanged rerun and hosted suite passed, so this is recorded as a remaining intermittent browser-test observation rather than a proven product defect at that revision. P9 subsequently reproduced a queued details-toggle race and fixes it by capturing live expanded state before rerendering.

## P9: bounded incoming stack arguments and caller stores

Implementation: [a77efe6](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/a77efe6f28879dc990f02dca0799656459123240).

The explicit function contract also enables read-only stack evidence. The
contract schema and profile ID remain unchanged for import compatibility;
`functionABI.version` advances to 2 with additive `stackArguments`, `stackStatus`,
`stackReason` and `stackScope` fields. Preview JSON stays at version 8. Existing
code, memory operations, call clobbers and value facts are unchanged.

The [Microsoft x64 convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
places the fifth argument at entry RSP + 40: eight bytes for the return address
and 32 bytes of home space. Immediately before CALL, that location is RSP + 32.
Later slots advance by eight bytes. Slot numbers do not establish parameter
counts, source types or a valid prototype.

This subset records aligned 1/2/4/8-byte explicit reads in the entry block, only
when converged address facts identify untouched incoming storage. A backedge
into entry excludes this proof. Known overlapping writes exclude later reads;
unknown writes, calls, unsupported effects, loss of precise SP or deallocation
above entry SP end incoming identity. Disjoint writes remain supported. Reads
in successor blocks and within the interior of an eight-byte slot stay outside
this subset. Earlier observations remain valid even if later writes occur.

For each discovered direct caller, a separate bounded scan tracks explicit
stores in the call's own block. The store must remain in allocated caller-frame
storage, cover the callee's observed read bytes, and match the exact
`caller_SP + entry_offset - 8` address. Partial overlapping writes invalidate
an earlier store; unknown writes, calls, lost SP and deallocation clear stored
contents. Stores in predecessor blocks are not followed. No store value is
forwarded, and a match does not assert a normal return, stack alignment,
prototype agreement or that the entire eight-byte argument was initialized.
Unmatched reads remain visible as unknown caller-store evidence.

Open **C-like → Analysis details → Function contract and candidates**, select
**Assume Windows x64**, then inspect **Possible incoming stack inputs** and
**Direct caller observations**. Every read/store has assembly links; `--abi`
and JSON expose the same evidence. The default unknown convention emits none.

Validation: 99 decoder/CLI contracts and 80 independent ABI executions include
16 concrete incoming stack reads and 12 matched caller stores. Cases cover
frame-pointer and adjusted-SP reads, home-space exclusion, partial writes,
unknown pointers, deallocation, entry backedges and cross-block fallback. The 35-check
browser test generates a source-known machine-code caller/callee demo, verifies
both tables and assembly navigation, and checks phone layout. A same-task
expand/change test covers the queued details-toggle race.

### P9 hosted validation (2026-10-27)

The [full matrix](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/40442270503)
passed all 29 CTest targets on both Capstone and LLVM, plus every browser suite.
Capstone passed 35 function-ABI and 90 C-like browser checks; LLVM passed its
three ABI and 13 C-like fallback checks. LLVM's semantic oracles are explicitly
skipped because that decoder does not provide structured operands.

Capstone's independent execution passed 1,260 recovery cases across all four
presentations, 36 call executions across 108 boundaries, and 80 ABI executions.
The ABI oracle checked 194 register-input reads, 80 returns, 180 caller values,
52 call-result reads, 16 incoming stack reads and 12 matched caller stores.
The hosted storage corpus checked 133 reloads, including 41 saved entry values.

[Pages deployment](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/40442270402)
also passed. The published manifest identifies implementation commit `a77efe6`;
all eight downloaded HTML reports contain the exact committed ABI model,
ABI view, pseudocode model and pseudocode view. This publication check verifies
source parity; interactive behavior is covered by the hosted browser suites.
The stack-specific browser fixture is generated from authored machine code;
the existing published C ladder does not add a new stack-parameter showcase.

## Next slice

M7.4 remains open. Broader cross-block stack proofs remain deferred. Next add a versioned
analyst-prototype representation that preserves conflicting declarations,
varargs and hidden-parameter uncertainty. Do not promote register locations or
access widths into automatic parameter counts, source names, types or a C
signature.
