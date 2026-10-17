# M4.1–M4.3: structured operands and decoder capabilities

This slice implements queue item 8. The default Capstone 5 adapter now supplies
normalized operand facts for later value analysis and lifting. LLVM's public C
disassembler remains a limited assembly/CFG/reference path. The analyzer never
executes the input. Value propagation, ABI summaries, indirect-register target
recovery, and instruction semantics are still pending under M4.4 and later.

## Decision and supported scope

Use Capstone detail metadata for structured features; do not parse formatted
operands into a semantic model. Keep the existing LLVM constant-address grammar
for navigable static references, with its existing limited provenance. Capstone
static references now consume the normalized operand model. Display text is
used only to retain clickable spans; it does not supply operand facts.

The adapter requires Capstone 5 headers and a matching runtime API major/minor.
The repository default remains pinned to 5.0.9. `apiVersion` is the runtime
major/minor returned by `cs_version`; `headerVersion` records the compilation
headers, including their patch version. These are separate: the runtime API
does not expose a patch version. LLVM's version is `null` because this adapter
does not query it. Completing all analyzer/pass/version metadata remains M0.2.

Backend capability booleans describe what the adapter can supply. Per-instruction
booleans describe availability for that decoded instruction; `structuredOperands`,
`registerSlices`, `operandWidths`, and `operandAccess` require all represented
operands to have the corresponding metadata. A zero access byte is unknown,
including for immediates; it is never invented as a known read or known absence.
An operand with an unsupported kind stays in its original array position as
`unknown`. Consumers must inspect each operand and their required capabilities.

Neither adapter advertises complete implicit register access or instruction
semantics. Capstone's implicit lists are **reported observations with unknown
completeness**, not an exhaustive clobber set. For example, Capstone 5 reports no
implicit registers for `enter`, which clearly does not establish no stack or
register effects. LLVM and unavailable detail metadata use `null` lists and
`status: unavailable`. Capstone uses `status: reported_partial` and
`complete: false`, even when a reported list is empty. Diet builds cannot supply
register names/access lists; their capabilities and unknown fields reflect that.

## Additive serialization contract

The report still uses schema 2 and analysis model 1. The optional
`operandModelVersion: 1` extension adds `module.decoderInfo` and instruction
`operandDetails`. Existing `operands` text, `bytes`, `dataRefs`, module IDs,
instruction IDs, routes, and annotation schema 1 are unchanged. Old viewers can
ignore the new fields. New viewers skip the extension for absent/unknown versions.

| Field | Meaning and limits |
| --- | --- |
| `operandDetails.operands` | Ordered Capstone operands; `null` when unavailable, `[]` when no operands are reported. Decoder-synthesized string operands may be included; this is not an exhaustive set of instruction effects. |
| `widthBits` | Decoder operand width, not encoded immediate width or a full semantic access width. For example, a scalar SSE register operand may name a 128-bit register. `null` means unknown. |
| `register` | Name, storage family, bit offset/width, and family width. Unknown alias families/widths remain `null`, while the name is retained. |
| `immediate.value` | Lossless hexadecimal bit pattern, normalized to the reported operand width up to 64 bits. No signedness/extension rule is inferred. A single immediate control-flow operand is a preferred VA, explicitly tagged `preferred_va`, rather than its encoded relative displacement. |
| `memory` | Segment selector, base, index, scale, and signed decimal displacement string. A null register means absent in this expression, not a zero runtime register value. Address width belongs to the instruction. Segment selector width is not segment-base width. |
| `prefixes.leadingBytes` | Original ordered legacy/REX prefix bytes, including duplicates and mandatory SSE prefixes. Bytes 0x40–0x4f are recognized as REX only in 64-bit mode. |
| `prefixes.legacyGroups` / `decoderRex` | Capstone's four effective legacy groups and REX metadata. The decoder may omit mandatory SSE prefixes from these groups or synthesize REX-like bits for vector encodings; use raw bytes as the encoding authority. |
| `encoding` | Validated byte offset and bit width of the decoder's immediate/displacement field. Not a per-operand mapping: instructions with multiple immediates, such as ENTER, need instruction-specific interpretation. Null means no usable field was reported. |
| `implicitRegisters` | Partial decoder-reported names/slices, with explicit availability and unknown completeness. Memory effects, flags semantics, and full clobber sets are not supplied. |

All 64-bit immediates, preferred VAs, and signed displacements in the new model
are strings; no JavaScript number conversion is needed. Counts, widths, prefix
bytes, and offsets are small exact integers. Original bytes remain available
independently of these interpretations.

GPR families use native-mode storage (`rax` in x64, `eax` in x86). AH overlaps
bits 8–15; AL/AX/EAX overlap lower bits. Extended GPRs and REX low-byte registers
are x64-only. IP/EIP/RIP, segment selectors, and XMM/YMM/ZMM storage overlap are
represented. Flags, x87/MMX, control/debug registers, and unfamiliar names remain
opaque rather than receiving an invented alias model. A slice never implies
zero-extension, preservation, conditional writes, or vector lane write behavior.
VEX/EVEX/XOP semantic prefix interpretation is not supplied; full encoding bytes
are retained and `vectorSemantics` remains false.

The existing reference policy is preserved: register/index-dependent and
segmented memory expressions remain unresolved; the expression is still visible
in the inspector. Address-size overrides distinguish 16/32/64-bit addressing.
IP-relative references use the next instruction address and signed displacement.
LEA is address-only with zero accessed bytes in `dataRefs`; its operand width
remains visible separately. IAT storage is not an execution destination.

## Presentation, bounds, and compatibility

Selecting an instruction address updates the **Instruction operands** inspector
in block and whole-function views. It shows register slices, memory expressions,
prefix bytes, encoding widths, and implicit-effect limitations. LLVM reports
explain that structured operands are unavailable. Metadata is escaped as text;
it cannot inject HTML. The inspector renders one instruction at a time, so it
does not defeat function pagination or construct an additional whole-report DOM.

Decode is already bounded to 15 bytes per instruction. Capstone's fixed arrays
bound operands and reported implicit registers. Prefix collection is capped at
15 bytes. Encoding fields are rejected unless they fit in the actual instruction.
The existing instruction discovery limit bounds the total metadata; reports
will grow because the new facts are serialized for each decoded instruction.

## Validation

- `tests/test_operands.cpp`: architectural GPR aliases, AH/AL/AX/EAX widths,
  extended registers, selector/vector slices, opaque-register cases, mandatory
  prefixes, prefix order, and x86 INC versus x64 REX.
- `tests/test_decoder_operands.py`: byte-authored PE32/PE32+ fixtures exercise
  both backends. Structured checks include encoded-versus-operand widths,
  negative/full-width/zero immediates, base/index/scale/displacement, FS,
  16-bit and 32-bit overrides, LEA, REP/LOCK/mandatory SSE prefixes, incomplete
  implicit effects, unknown aliases, and truncated decode. JSON and embedded
  HTML facts are compared, and repeated reports must be deterministic.
- The same legacy-reference expectations run on both adapters; `--compare`
  additionally compares their supported VA/mode/access/width facts without
  demanding identical assembly spelling. LLVM structured-only cases explicitly
  skip; the unavailable-metadata tests must still pass.
- `tests/test_operand_browser.py`: block/function selection, history, bounded
  inspector rendering, legacy schema-2 reports, and HTML escaping.
- Existing native/parser/report/graph/string tests continue to run in both
  Linux CI matrix entries; browser and annotation compatibility checks run on
  both. Generated source-known demo HTML is retained with each matrix artifact.

Local validation for this slice: 16 CTest targets passed in each build, with
Capstone 5.0.9 headers/runtime API 5.0 and an LLVM 20 shared library. The operand
suite passed all 10 cases on Capstone; LLVM passed its three applicable cases
and explicitly skipped seven structured-only cases. The cross-backend comparison
passed. Chromium passed 12 Capstone and 7 LLVM operand-inspector checks.
Local clang/lld-link were unavailable, so source-compiled fixture checks were
explicitly skipped locally; the hosted matrix is responsible for that gate.

Hosted validation on 2026-10-17 completed that gate at `dbb4819`:
[both Linux matrix jobs passed](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/39024075997),
each with 17 CTest targets (including source-compiled EXE/DLL fixtures), 14
report-site tests, and all browser suites. The source-known
[report build and Pages deployment passed](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/39024075994).
The [live x64 demo](https://asr-tanyi.github.io/windows-exe-analyzer/demo64.html)
returned HTTP 200 with operand model 1, Capstone API 5.0 / headers 5.0.9, and 36
decoded instructions. The live URL follows future deployments; the linked run
artifacts retain this run's reports subject to artifact retention.

Reproduce with normal CMake builds for both adapters:

```sh
ctest --test-dir build-capstone --output-on-failure
ctest --test-dir build-llvm --output-on-failure
python3 tests/test_decoder_operands.py build-capstone/windows-exe-analyzer \
  --backend CAPSTONE --compare build-llvm/windows-exe-analyzer
python3 tests/test_operand_browser.py build-capstone/windows-exe-analyzer
python3 tests/test_operand_browser.py build-llvm/windows-exe-analyzer
```

The HTML-report workflow now builds Capstone so its generated demo includes
structured operands. The custom-input runtime retains its existing isolation
and LLVM runtime compatibility; the default Capstone decoder is linked into
the analyzer. This change does not claim that the separate custom-input container
acceptance gate M0.7 has been completed.

## Primary references

- [Capstone 5.0.9 x86 detail layout](https://github.com/capstone-engine/capstone/blob/5.0.9/include/capstone/x86.h): operands, access bytes, sizes, memory expressions, prefix groups, and encoding offsets.
- [Capstone 5.0.9 C API](https://github.com/capstone-engine/capstone/blob/5.0.9/include/capstone/capstone.h): runtime API version, diet capability, and reported implicit registers.
- [LLVM public C disassembler API](https://llvm.org/doxygen/group__LLVMCDisassembler.html): text output and symbol callbacks, not a full structured instruction/semantic interface.

Next: M4.4–M4.5, a bounded value domain and tested integer/address transfer
operations shared with the future IR. Add CFG propagation and call-clobber rules
after that core; do not infer targets by re-parsing operand display text.
