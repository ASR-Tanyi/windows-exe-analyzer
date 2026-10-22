# Explicit Windows x64 call summaries

Implemented in [`a19bc95`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/a19bc95a777df174149f023de6f19fc1e6cf9b01).

C-like preview v4 can retain nonvolatile GPR and stack facts across a call when
the analyst explicitly selects the reviewed `windows-x64-normal-return-v1`
contract at that instruction. The default is still an all-state barrier. PE
bitness, import names, exports and nearby code never activate a profile.

Open **C-like → Call assumptions** and select a contract for each reviewed call.
The report index's **Call assumptions demo** opens the existing `pe_entry`
ladder, which calls all six functions in [recovery.c](../tests/fixtures/recovery.c).
Selecting all six allows SP facts to survive the whole chain. The nested-loop
`transform_demo` remains available separately. No new code is executed by the
product; both the native analyzer and the HTML viewer remain static.

Selections survive navigation and renaming in the current open document.
**Export call assumptions** saves them; **Import call assumptions** validates
them against the exact module and function. Reloading starts with no selections.
Display labels and their storage are separate. Use exported assumptions with
the shared Node model:

```sh
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --calls call-assumptions.json
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --calls call-assumptions.json --ssa
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --calls call-assumptions.json --json
```

## Conditional machine-state contract

Selecting the profile asserts that **every possible callee at that site** obeys
the standard Windows x64 ABI and returns normally to the recorded continuation.
The pre-call stack must be 16-byte aligned, with 32 bytes of writable home space
and valid return-address storage. These preconditions are displayed assumptions,
not inferred facts or a certification of the callee. No caller-entry alignment
or function prototype is silently inferred. A custom convention, nonreturning
callee, exception, longjmp, invalid stack or ABI violation is outside the summary.

| State at the normal-return continuation | Summary |
| --- | --- |
| RBX, RBP, RSI, RDI, RSP, R12–R15 | Preserve the entire incoming 64-bit value |
| RAX, RCX, RDX, R8–R11 | Fresh unknown 64-bit value, including unused return bits |
| Flags | Unknown; no pre-call comparison survives |
| Memory | May read or modify arbitrary memory; no memory value is retained |
| Vector, x87 and other unmodeled state | No preservation claim in this GPR-only model |
| Argument/return roles | Unknown; no type, count, varargs rule or I/O signature inferred |

The profile follows Microsoft's [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170),
[register usage](https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170#x64-register-usage)
and [stack usage](https://learn.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-170).
The implementation deliberately weakens flags and memory to unknown. x86
cdecl/stdcall/fastcall/thiscall, vectorcall, preserve-none, intrinsics and custom
conventions are not substituted for this profile.

## Raw CALL versus the summary

The [lifter](../web/pseudocode-model.js) retains `instruction.call` for supported
near CALL forms: the target expression, native width, next preferred VA, stack
entry delta and return-address size. Direct, register-indirect and supported
flat-memory-indirect targets are accepted. Prefixed operand-size, segmented and
far forms stay unsupported. Recording a target expression does not resolve it;
an IAT load is not a runtime DLL address.

Without a binding, `instruction.ops` contains the original barrier. With a valid
binding it contains one `call_summary` operation spanning **CALL through normal
return**. The raw CALL metadata is not an additional executed operation. The
callee-entry RSP is pre-call RSP minus eight, while the full summary has net RSP
delta zero. Caller allocation/cleanup instructions remain separate, so neither
the return-address push nor home-space allocation is double-counted. Target
registers and indirect target addresses are read before the transition.

[Value analysis](../web/value-analysis.js) attaches the call's source ID to every
retained fact. All loads, including saved-register and home-space loads, remain
unknown. Return-address storage and the four affected eight-byte home regions
are recorded as implicit call storage, not guessed C locals. These home-region
records describe potential effects, not four observed load/store instructions;
the general memory effect is still unknown everywhere.

[Register SSA](../web/register-ssa.js) creates fresh clobber definitions for the
seven volatile GPRs and retains existing nonvolatile versions. It records all
GPRs as possible call inputs without inventing parameter positions. The graph
and value analysis both export `assumptionSources`. No expressions, operations,
calls, memory effects or flags are removed.

## Binding and export contract

[call-summaries.js](../web/call-summaries.js) owns the fixed, versioned profile and
validates the analyst's binding file. Its only permitted fields are:

```json
{
  "version": 1,
  "moduleId": "<exact report module ID>",
  "functionId": "<exact function ID>",
  "sites": [
    {"source": "<exact call instruction ID>", "profile": "windows-x64-normal-return-v1"}
  ]
}
```

Export from the UI to obtain real IDs; the placeholders above are not valid
bindings. Empty `sites` means no assumptions. There is no wildcard, symbol-name
matching, editable clobber list or custom effect body. A module ID is the
existing content identity, not a cryptographic authenticity guarantee.

Files are capped at 64 KiB in the browser/CLI and bindings at 128 sites in the
model. The existing 128-block / 2,048-instruction / 384-edge recovery budgets
still apply. Every selected site must identify an eligible call in this function
with a unique owned continuation at its next instruction. Shared/truncated
ownership, outside entries, x86 forms, duplicate sites, wrong identities,
unknown profiles and extra fields reject the whole binding document. No valid
subset is silently applied. The browser shows the rejection with default
effects; CLI returns status 2. File-size/JSON parse failures are reported by the
CLI, and clear selections in the browser.

Preview JSON is `version: 4`; native report schema 2, operand model version 1,
value-analysis version 1 and register-SSA version 1 remain unchanged. The new
`callAnalysis` contains status (`default`, `applied`, `invalid`), call sites,
normalized assumptions, selected count, profile and notice. Selected instructions
have `status: "assumed"`; a function with no remaining barriers has
`status: "assumed_subset"`, never unconditional `supported_subset`.
`stats.assumedCalls` is separate from supported instructions and barriers.
`complete` remains false. LLVM and legacy reports remain unavailable for semantic
features. The [inspector](../web/call-summary-view.js), CLI, SSA and value analysis
all use this same model.

## Validation

```sh
python3 tests/test_call_summaries.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
python3 tests/test_call_oracle.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
python3 tests/test_pseudocode_browser.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
```

Local validation on 2026-10-21 uses Zig 0.13.0 / Clang 18.1.6:

- Both backends pass 21 CTest targets; linked compiler fixtures are generated
  separately. Capstone passes 54 call-summary contracts, including wrong-module,
  duplicate/extra/unsupported bindings, unsafe CFGs, limits, x86 fallback,
  indirect-target inputs, unchanged default clobbers and unsupported instructions
  following selected calls.
- The independent call oracle executes 36 authored/source-known cases across
  108 call/return boundaries and 756 caller instruction states. It checks actual
  return-address pushes, aligned call SP, nonvolatile register restoration,
  continuation SP, full-width volatile values, home-space writes and retained
  abstract facts. Direct, register/memory-indirect and looped calls are covered,
  together with the existing six-call C ladder at x64 O0/O1.
- Call-path SSA checks cover 2,352 uses, 144 selected join edges and 576 machine
  exit values. Deliberately broken register preservation and nonzero RET cleanup
  are rejected by the oracle, demonstrating the conditional nature of the ABI
  assumption. Emulation is test-only, bounded and limited to our authored corpus.
- Existing 711 instruction/CFG/source cases still pass. Browser checks pass for
  Capstone (53) and LLVM fallback (13), including explicit selections, export/
  import, invalid/oversize files, clear/reload, rename/history and assembly links.
  All 15 publication tests pass, including the new call-demo link.
- One Node run over 28 candidates, selecting every eligible demo call, took
  77.1 ms total / 11.0 ms maximum per candidate. The largest serialized
  `callAnalysis` was 2,722 bytes. This is a corpus measurement, not a worst-case
  resource guarantee.

Hosted validation for [`8ba2913`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/8ba29134fd72971beb8bb34e9bfe332c9405a482)
passed on 2026-10-21:

- The [regression matrix](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/39564735660)
  passed 23 CTest targets and 15 publication tests on each backend, all browser
  suites, and 53 Capstone / 13 LLVM C-like browser checks. LLVM continues to
  exercise the unavailable-semantics fallback; independent execution checks run
  with Capstone's structured operands.
- Hosted compiler output passed the same 711 independent semantic cases at
  7,283 instruction states, 2,017 stack-alias addresses, 8,574 SSA uses,
  699 selected join edges and 1,680 exit values. The 36 call executions covered
  108 call/return boundaries, 738 caller states, 2,328 SSA uses, 144 selected
  joins and 576 exit values. Both deliberately invalid ABI implementations were
  rejected. State/use counts differ from the local compiler output above.
- [HTML report generation and Pages deployment](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/39564735803)
  passed. On 2026-10-22, HTTPS downloads confirmed the deployed commit, eight
  manifest reports and the index's
  [call-assumptions demo](https://asr-tanyi.github.io/windows-exe-analyzer/recovery64-o0.html#m_38ea623bd3bb24a7_c_12a0)
  link. The downloaded HTML's six relevant embedded modules matched the source,
  and its embedded report matched the separate JSON. Offline Chromium checks of
  that exact artifact passed: zero selections by default, all six explicit
  profiles, export/CLI parity, exact assembly navigation and Back preserving the
  selections, with no JavaScript errors.

## Next slice

M4.7 is complete for this explicit Windows x64 normal-return GPR subset. Start
M7.2 with bounded, width-correct constant/copy and pure-register expression
substitution within a basic block, using SSA and preserving all contributing
source IDs. Keep flags, memory operations, traps, calls and unsupported effects
observable. Broader interprocedural summaries, x86 profiles, arguments/returns,
I/O prototypes, source locals/types and precise memory SSA remain pending.
