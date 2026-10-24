# Bounded dead register-write cleanup

Implemented in [`d8dc5b2`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/d8dc5b2615b11d74d54edb713addb4b06ce9fa14).

Preview v6 adds a separate cleanup overlay. **C-like → Code → Remove dead
writes** starts enabled alongside **Simplify expressions**. Cleanup can
also operate without expression substitution. Turn both off to inspect every
original operation; the original instruction list and register SSA never change.

The optimized `scalar_ops` demo loses one redundant LEA assignment after its
value is substituted into a later XOR. The nested-loop `transform_demo` also
exercises cleanup alongside branches and array reads/writes. The cleanup table under **Analysis details**
lists every omitted write, every flags-only operation and the later retained
overwrite, with exact assembly links and history navigation.

```sh
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --clean
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --simplified --clean
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --raw --simplified --clean
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --json
```

CLI text remains original by default. `--clean` and `--simplified` independently
select transformations; `--raw` disables stack aliases. JSON exports all forms.
`--ssa` describes the original machine effects. Existing per-site `--calls`
bindings work with any text view, but calls always stop cleanup.

## Supported transformations and retained effects

[register-cleanup.js](../web/register-cleanup.js) runs after register SSA and the
expression overlay, before structural graph reduction. It scans each reachable
original block backwards twice, using the actual operands in the raw and
simplified views. Raw SSA use counts alone would be wrong after substitution:
a copied register may no longer be read, while an earlier source register may
now be needed by a later expression.

All GPR families start live at every block end. A retained full-family write
kills the previous value; retained operand reads and partial-write preservation
make their families live again. An unused pure write is eligible only when a
later retained full-family overwrite exists in the same uninterrupted segment.
Every rewrite records both original SSA definitions and their instruction IDs.
Cascading dead copies disappear in one backward scan. Liveness is conservative
at whole-register-family granularity, including high-byte and 16-bit writes;
x64 32-bit writes also kill the old upper 32 bits.

| Operation or boundary | Cleanup behavior |
| --- | --- |
| Pure register assignment, including LEA | Omit if the result is dead before a retained overwrite |
| Register NOT | Omit when dead; it has no flag effects |
| Supported arithmetic, bitwise and shift operations | Drop only the dead destination; retain the same operator, width, pure operands and flag helper |
| CMP/TEST | Retain the helper and its input reads |
| Partial-register writes | Preserve untouched family bits when live; remove only if the entire old family is dead |
| Memory loads/stores and memory ALU | Retain every access and all incoming register state, including unused/faulting loads |
| PUSH/POP/RET, selected and unknown calls, SETcc/CMOV, unsupported operations | Retain effects and reset liveness to all GPRs; no cleanup crosses these boundaries |
| Branches, joins, loops and function exits | Preserve every GPR at each original block boundary; no cross-block or PHI cleanup |
| Disconnected blocks | Keep original operations because they have no usable SSA records |

For `add eax, 1; mov eax, 9`, cleaned output includes:

```c
add32(u32(rax), 0x1, &flags);
rax = u32(0x9);
```

The ADD still produces flags for a later branch or exit, including preserved or
undefined flag bits. Zero/masked-count shifts keep their original flag behavior.
No flag-liveness optimization, memory caching, load elimination, trap removal,
prototype inference or source-variable recovery is performed. The supported
normal-path domain and uncertainty rules remain those of the
[C-like recovery contract](c-like-recovery.md).

## Export, evidence and fallback

The native report remains schema 2. Preview JSON is version 6; SSA, value and
expression overlays remain version 1. Cleanup adds:

| Field | Contract |
| --- | --- |
| `registerCleanup` | Version 1, status/reason, `complete:false`, independent `raw`/`simplified` variants and work statistics |
| Each variant | `rewrites` plus `removed` and `flagsOnly` counts |
| Each rewrite | Original `source`, operation index, SSA `definition`, register family, `kind`, replacement, complete source list and `overwrittenBy` witness |
| `overwrittenBy` | Later retained full-write source, operation index and original SSA definition ID |
| `cleanOperation` / `simplifiedCleanOperation` on line nodes | Optional typed replacement; explicit `null` means omit this operation, absent means use the corresponding original/simplified operation |
| `cleanLines` / `cleanDisplayLines` | Raw-operand cleanup with original addresses / optional memory aliases |
| `simplifiedCleanLines` / `simplifiedCleanDisplayLines` | Combined expression and cleanup presentations |
| Original instructions, SSA and four previous line arrays | Remain available without mutation |

Removed operations remain in region nodes and the original instruction/SSA
inspectors. Cleaned output retains structural source lists, and the cleanup table
links each removed source, contributing expression source and retained overwrite.
The displayed instruction coverage counts still describe the original lifting.

Shared/truncated ownership or unavailable SSA disables cleanup with a visible
reason. Unavailable expression analysis still permits raw cleanup; both variants
then use raw operands. The pass caps total rewrites across both variants at
4,096, counted work at 131,072 and operand depth at 32. Existing recovery/SSA
limits apply first. Any global-budget, depth or missing-write failure discards
**both** provisional variants. There is no partial cleanup on failure and source
lists are not silently truncated.

## Validation

Local validation on 2026-10-23 used Capstone 5.0.9, LLVM 20, Unicorn 2.1.4,
Playwright 1.57.0, Chromium 143 and Zig 0.13.0's compiler/linker for source-known
x86/x64 O0/O1 fixtures. The fixture corpus records compiler commands and hashes.
No arbitrary analyzed executable was run.

- 23 CTest targets pass on each backend, including **752 cleanup checks** and
  225 expression checks. Linked clang/lld fixture targets are unavailable locally;
  equivalent recovery fixtures were built separately with Zig.
- **126 decoder/recovery contracts** pass with the compiled corpus, covering
  versioned JSON, flags-only rendering, raw/combined CLI parity, source retention
  and unsafe-graph fallback.
- **1,212 independent semantic cases** agree with Unicorn and known C results.
  Every case compares original, simplified, cleaned and combined evaluation,
  excluding only the interpreter step counter. This includes 276 expression-chain
  executions and **222 new dead-write executions**, plus three new branch cases
  whose condition depends on a flags-only arithmetic result. The chain corpus
  actually produces 41 omitted pure writes and 22 flags-only destinations.
- Those cases also check 8,872 concrete instruction states, 2,017 stack-alias
  addresses, 10,315 SSA uses, 723 selected joins and 7,920 exit values. All GPRs,
  defined flags and memory bytes are compared, not only the C return value.
- Existing call validation passes 36 executions, 108 call/return boundaries,
  756 caller states, 2,352 SSA uses, 144 joins and 576 exits. Two deliberately
  incorrect ABI implementations are rejected. Cleanup unit tests separately
  establish that selected and unknown calls retain all incoming register state.
- **72 Capstone / 13 LLVM browser checks** pass: independent toggles, shared-model
  text, complete cleanup evidence, overwrite navigation/Back, unavailable fallback,
  aliases, register-flow inspection, call assumptions and escaping. All 15
  report-publication tests pass.

On the local optimized x64 demo, combined cleanup removes one scalar assignment;
the nested-loop transform removes two assignments and retains three flags-only
operations. Its raw/combined text has 48/46 lines. Twenty repeated full recovery
runs averaged about 5.9 ms and the complete exported model was 310,885 bytes on
this machine; these are fixture measurements, not large-binary guarantees.

[Test sources](../tests/test_register_cleanup.js),
[decoder contracts](../tests/test_pseudocode.py),
[independent oracle](../tests/test_pseudocode_oracle.py), and
[browser checks](../tests/test_pseudocode_browser.py) are committed together with
the implementation.

Hosted validation on 2026-10-23:

- [Analysis model tests](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/39896686969)
  passed on both decoder backends: 25 CTest targets each (including clang/lld
  linked fixtures), every browser suite, 72 Capstone / 13 LLVM C-like checks and
  15 publication tests. LLVM explicitly skips unsupported semantic execution.
- Capstone passed all 1,212 independent cases and four-mode parity. Hosted
  compiler fixtures produce 9,156 concrete instruction states, 10,260 SSA uses,
  702 selected joins and 7,920 exit values. Call checks pass 36 executions,
  108 boundaries, 738 caller states, 2,328 SSA uses, 144 joins and 576 exits;
  both invalid ABI implementations are rejected.
- [HTML build and Pages deployment](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/39896686970)
  passed for the implementation revision. The live eight-report manifest and
  optimized report returned HTTP 200. Embedded JSON matched the separate JSON,
  and all four changed embedded modules matched committed source text exactly.
- The downloaded self-contained
  [scalar demo](https://asr-tanyi.github.io/windows-exe-analyzer/recovery64-o1.html#m_b2c773e4cf51a9a6_c_1000)
  and [nested-loop demo](https://asr-tanyi.github.io/windows-exe-analyzer/recovery64-o1.html#m_b2c773e4cf51a9a6_c_1080)
  passed offline browser/model/CLI parity for all four presentations. The scalar
  has one removed assignment; the transform has two removed assignments and
  three flags-only destinations. Every cleanup row is present; original-write
  and overwrite links open exact assembly, and Back preserves cleanup settings.
  No JavaScript errors occurred. These checks validate the deployed payload;
  workflow artifacts retain the tested snapshot when the public site advances.

## Next slice

P5 and P6 complete M7.2 for the documented block-local integer-register subset.
Cross-block/PHI substitution, bit-level dead-write precision, flag SSA and memory
SSA remain deferred. Next is M7.3: attach conservative storage-role evidence to
tracked stack locations, distinguishing saved registers and ABI regions from
candidate locals without turning physical memory aliases into invented C types.
