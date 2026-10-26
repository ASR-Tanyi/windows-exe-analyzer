# C-like recovery preview v8

Open a function in a Capstone-generated HTML report and select **C-like**.
Select an address to return to the exact instruction in whole-function assembly;
**source(s)** lists the contributing instructions for a combined region. Analyst
function renames change the heading without changing evidence IDs. Reports remain
self-contained and offline. LLVM and older reports show an unavailable message.

The shared [model](../web/pseudocode-model.js) also exports text or typed JSON:

```sh
./build/windows-exe-analyzer program.exe --json build/program.json
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --raw
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --simplified
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --simplified --clean
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --ssa
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --json
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --calls call-assumptions.json --json
```

Replace `0xFUNCTION_RVA` with an actual discovered function entry. This is a
separate preview, not a redefinition of the CLI's `--ir` observation notes.
The decoder's `instructionSemantics:false` capability is unchanged: decoding
itself supplies operands, not this model's effects. Preview version 8 appears in
the export; report schema 2 and existing identities remain compatible.

## What the output means

The first pass recovers low-level C-like operations, not original source. For
example, `write32(u64(base + index * 4), value)` describes an indexed memory
write. It does not prove that `base` is a C array or that `index` was a source
variable. Registers keep their machine names. Version 2 adds optional
[stack memory aliases and bounded value facts](bounded-values.md); every aliased
access still reads/writes memory, and the raw address view remains available.
Version 3 adds [register def-use chains and explicit joins](register-ssa.md).
Select the **Register flow** tab or click **Trace value** beside a code line.
Reads and writes link to each value's origin and later uses; branch/loop merges
show incoming alternatives. Stack locations, call assumptions and cleanup
evidence are grouped under **Analysis details**. See the [report guide](report-layout.md).
The graph preserves full-family and partial-write dependencies;
the original graph remains available when display expressions are simplified.
Version 4 adds [explicit call summaries](call-summaries.md) at analyst-selected
Windows x64 call sites. The default remains unknown; the UI displays all profile
assumptions and supports portable selection files. This does not recover a
function prototype or argument count.
Version 5 adds [bounded register-expression simplification](register-expressions.md).
The UI toggle and CLI `--simplified` expose constant/copy and pure arithmetic
substitution within each block, retaining every instruction and effect.
Version 6 adds a separate [dead register-write cleanup](register-cleanup.md)
overlay. The UI enables both overlays initially; disabling both restores all
original operations. CLI `--clean` selects cleanup independently of `--simplified`.
Unused assignments disappear; unused arithmetic destinations become flags-only
helpers. Memory, calls, unknown effects and every block exit retain their state.
Version 7 adds [stack storage roles](stack-storage.md) as separate evidence: saved-entry-register pairs, spill/reload candidates, explicit ABI call areas and mixed/unknown uses. It does not forward loads or change code effects.

Version 8 adds [explicit function ABI evidence](function-abi.md): register input candidates, separate RAX return alternatives and direct caller observations. It changes no original effects or code presentations; full M7.4 remains open.
There is no invented function prototype, return type, local name, or I/O API.

The normal-path domain is native x86/x64 Windows code with flat default segment
bases, mapped readable/writable memory, and no faults, concurrent writers,
exceptions, interrupts, or self-modification. Memory is little-endian and
byte-addressed. Reads and writes are observable operations and are never removed
as dead values. Explicit memory segments, LOCK/REP, 16-bit addressing and vector
effects are unsupported. This preview is not an executable C translation or
whole-program equivalence proof.

The typed operation contract is:

- `uN` truncates to an unsigned N-bit value. Arithmetic wraps; `sextA_to_B`
  sign-extends the A-bit interpretation before truncating to B bits.
- Register reads extract the requested slice. 8/16-bit writes preserve other
  bits, including high-byte aliases. x64 32-bit writes clear the upper half.
  Register CMOV32 also clears the upper half on the false path.
- Effective addresses wrap at the decoded 32/64-bit address width. x64
  address-size-32 expressions zero-extend the wrapped result. RIP/EIP-relative
  addresses use the next instruction and the preferred image base. LEA does
  not read memory.
- `addN`, `subN`, `cmpN`, `testN`, shifts and other ALU helpers consume **old**
  operands, calculate a fixed-width result, and update the defined flags before
  the destination write. Thus `cmp32(a,b,&flags)` snapshots the comparison;
  branches do not re-read `a` or memory. A later flag writer replaces that state.
- ADD/SUB/CMP/NEG define CF, OF, ZF, SF, PF and AF; INC/DEC preserve CF. Logic
  clears CF/OF, defines ZF/SF/PF and leaves AF unknown. NOT preserves flags.
  Two/three-operand IMUL returns the low half and defines only CF/OF.
- Shift counts are masked with 31, or 63 for 64-bit operands. A zero masked count
  preserves flags. OF is defined only for count 1; AF is unknown. SHL/SHR CF is
  unknown for counts at least the operand width. SAR retains the shifted-out
  sign behavior. Undefined flags are **unknown**, never selected constants.
- `pushN` reads its source before changing SP; `popN` reads then advances SP.
  `return_to_callerN(adjustment)` reads/pops the near return address, adds the
  encoded stack adjustment and exits the candidate. It does not infer a C return
  value. ABI inputs are used only by the fixture test harness.
- `unknown_effects(source)` invalidates **all registers, flags and memory**.
  No facts flow across an unselected call or unsupported operation. A displayed continuation
  after a call is still the existing CFG's assumption that it returns. Unknown
  control transfers remain explicit. The test evaluator stops on unknown state.
- An explicitly selected `call_summary` spans CALL through normal return under
  the documented Windows x64 assumptions. It preserves nonvolatile GPRs and
  pre-call SP, with fresh volatile values and unknown memory/flags. Raw CALL
  target/return-address metadata remains separate; the stack push is not applied
  a second time. Selected operations are marked `assumed`, not proven supported.

These rules follow Intel's [Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html),
Volume 1 §3.4.1 (general-purpose registers) and Volume 2 instruction entries
MOV/MOVSX/MOVSXD/MOVZX, LEA, ADD/SUB/ADC, AND/OR/XOR/TEST, CMP, INC/DEC,
NEG/NOT, IMUL, SAL/SAR/SHL/SHR, CMOVcc, SETcc, Jcc/JMP, PUSH/POP, RET and NOP.
ADC is cited as an unsupported contrast in the tests; its carry input is never
approximated by ADD. The exact supported forms are below.

## Support matrix

`r` means a validated general-purpose register slice; `m` means validated flat
memory, `i` a normalized bit-pattern immediate. Equal widths are required unless
an extension is explicit. Integer widths are 8/16/32/64 subject to the mode and
the actual decoded form. No assembly operand string is parsed.

| Family | Forms accepted by v1–v6 | Exclusions |
| --- | --- | --- |
| MOV / MOVABS | r←r/m/i, m←r/i | Segment/control/vector registers; memory-to-memory |
| MOVZX / MOVSX | 8/16-bit r/m to wider r | Unsupported width combinations |
| MOVSXD; CWDE/CDQE | 32→64 r/m; implicit accumulator extension | Other implicit extension forms |
| LEA | r16/32/64 from validated address | Segmented/16-bit addresses |
| ADD/SUB/AND/OR/XOR | r/m with r/i; r with m | Carry-input operations, LOCK, two memory operands |
| CMP/TEST | Equal-width r/m with r/i; r with m | Unsupported operand forms |
| INC/DEC/NEG/NOT | r/m | Flags outside the documented rules |
| IMUL | Two-operand r,r/m; three-operand r,r/m,i | Implicit full product, MUL/DIV/IDIV |
| SHL/SAL/SHR/SAR | r/m with immediate or CL | Rotate/double-shift forms |
| SETcc; CMOVcc | Byte r/m; equal-width r,r (16/32/64) | Memory-source CMOV, because it reads even when false |
| PUSH/POP | Native-width r; PUSH immediate | Memory stack operands, POP SP, non-native widths |
| Jcc/JMP; RET | Supported flag conditions with direct targets; unprefixed near RET, optional adjustment | Indirect/far transfers, LOOP/JCXZ family |
| NOP | Decoded NOP, including inert segment/size prefixes | LOCK/REP and PAUSE semantics |
| CALL (v4) | Near direct/register/flat-memory target metadata; optional explicit Windows x64 normal-return summary | Default barrier; no automatic profile, prototype, x86 summary or indirect-target resolution |
| Everything else | Visible all-state barrier | No guessed effect or call/I/O signature |

## Structure and limits

The model consumes the existing inferred block owners and edges. It reduces only
single-predecessor sequences, single-entry diamonds, a conditional loop header
with one returning body region, and conditional self-loops. Each reduction keeps
all operations and successors. Header effects remain **inside** `while (true)`;
post-tested loops use `do/while`. Source `for` and `while` spellings cannot in
general be distinguished, so both may use these forms. Other shapes, irreducible
cycles, early-return joins and unknown exits retain labels/gotos.

Shared ownership or truncated discovery disables restructuring. Limits are 128
owned blocks, 2,048 instructions and 384 outgoing edges, checked before lifting
or reductions. Over-budget functions retain assembly access and show an explicit
unavailable result. No extra code discovery is performed. `supported_subset`
means all encountered instructions fit the normal-path rules; `complete` is
always false because discovered function membership is not proven complete.

## Source-known demo and validation

[recovery.c](../tests/fixtures/recovery.c) contains six exported steps:
`scalar_ops`, `choose_value`, `array_read_write`, `sum_for`, `sum_while` and
`transform_demo`. The last combines bounded array writes, arithmetic, bit
operations, if/else, and a nested loop. A custom entry calls these functions;
its calls default to unknown-effect barriers and provide the v4 call-assumption
demo when the analyst selects the profile.

```sh
python3 tests/build_recovery_fixtures.py --output build/recovery-fixtures \
  --clang clang --linker lld-link --analyzer build/windows-exe-analyzer
python3 tests/test_pseudocode.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
python3 -m pip install unicorn==2.1.4
python3 tests/test_pseudocode_oracle.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
```

The generator compiles x86/x64 at O0 and O1 with vectorization, unrolling,
sanitizers and stack protection disabled for this bounded corpus. No source/map
hints are passed into analysis: exported names are PE evidence. The corpus JSON
records source/binary hashes, compiler version and command lines. `--zig` is an
optional local compiler/linker path; hosted CI uses Clang 18 and lld-link 18.
Only generated HTML/JSON and the authored C source are published, not EXEs.

The [test-only evaluator](../tests/pseudocode_eval.js) executes typed operations
and the **reduced region tree**, not rendered text. The [oracle harness](../tests/test_pseudocode_oracle.py)
compares every GPR, defined flag and stack/data byte against Unicorn 2.1.4 for
authored edge cases and the six functions. It separately checks source-level
return and array results over zero/small/max/over-limit counts. It accepts only
these generated fixtures, uses instruction/time budgets, and never runs a PE
natively. This is testing infrastructure, not a dynamic-analysis product mode.

Initial v1 local validation: 705 independent cases; 58 recovery contracts including the
four generated reports; 18 C-like browser checks; existing operand navigation
and publication checks pass. The unoptimized complex demo recovers two loops
and two conditional regions on both architectures. The local compiler was Zig
0.13.0's Clang 18.1.6.

Hosted validation for `7e93eb8` on 2026-10-18:

- [Analysis matrix passed](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/39094790674):
  19 CTest targets and 15 publication tests per backend, all existing browser
  suites, 18 Capstone C-like checks and 11 LLVM capability/fallback checks.
  The Capstone job also passed all 705 independent cases with hosted Clang 18 /
  lld-link fixtures. LLVM correctly skips semantic emulation.
- [Report deployment passed](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/39094790656).
  The live manifest reported the tested commit and eight reports; the x64 O0
  HTML/JSON returned HTTP 200 with the recovery model and view embedded.
  [Open the demo index](https://asr-tanyi.github.io/windows-exe-analyzer/), then
  **C-like demo** for direct access to the nested-loop function. The site serves
  the latest deployment; the run artifacts retain this tested snapshot.

## Next work

Version 2 implements bounded value propagation and conservative stack-slot
candidates; its [contract and validation](bounded-values.md) cover joins, loops,
overlap and all-state call clobbers. Version 3 implements bounded integer GPR
def-use/SSA with source-linked inspection and independent execution checks;
see its [contract and validation](register-ssa.md). Version 4 adds an explicit
Windows x64 call-summary subset with [independent boundary validation](call-summaries.md).
Preview v5 adds [bounded register expressions](register-expressions.md);
preview v6 adds [dead register-write cleanup](register-cleanup.md); preview v7 adds
[stack storage roles](stack-storage.md). Preview v8 adds the bounded [function ABI register subset](function-abi.md). Incoming stack arguments and prototype reconciliation are next. Broader ABI profiles,
full prototypes, I/O signatures, switches, exceptional paths, source types and
indirect-target discovery remain pending.
