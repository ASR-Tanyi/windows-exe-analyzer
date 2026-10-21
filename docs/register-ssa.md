# Register def-use chains and explicit joins

Implemented in [`a3c15bc`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/a3c15bcc95849ef6e79579e369283810ed5bd00b).

C-like preview v3 adds bounded register SSA for the supported x86/x64 integer
subset. Each write creates a register version, each read links to its reaching
definition, and a branch/loop join selects the version from the predecessor
that executed. These are machine register versions, not recovered C variables.
The existing code, memory aliases, flags and observable effects are retained.

Open a Capstone report, select a function, then **C-like → Register flow**.
Choose an instruction to inspect its reads, definitions and effects. Definition
buttons open their inputs and reverse uses; **Inspect use** returns to the
consuming instruction. **Branch / loop join** lists incoming definitions with
predecessor transfer links to exact assembly. Cyclic joins are explored one click
at a time. The existing optimized `transform_demo` is useful for inspecting
loop-carried versions; O0 also exposes joins in the machine exit state.

```sh
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --ssa
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --json
```

Use an actual discovered function RVA. `--ssa` exports definitions and incoming
uses; `--json` exports the full graph. Default text and `--raw` remain the existing
C-like views. HTML embeds the same model and works offline. LLVM and legacy
reports without structured operands retain their explicit unavailable result.

## Machine-state contract

[register-ssa.js](../web/register-ssa.js) consumes validated typed operations
from the [recovery model](../web/pseudocode-model.js), before graph reduction.
It does not parse assembly text or infer effects from decoder access lists.
The instruction forms and normal-path assumptions in the
[recovery contract](c-like-recovery.md) apply unchanged.

| Definition / effect | Meaning |
| --- | --- |
| Entry | Unknown incoming full-width GPR value, such as `rax_in` |
| Write | New full-family version, with the actual destination slice and source instruction |
| Partial write | Explicit old-family input for preserved bits; `preserveMask` identifies those bits, including AH/AX cases |
| x64 32-bit write | Zero upper 32 bits, including false-path register CMOV32; no upper-half preservation dependency |
| Join (`phi`) | One incoming use per distinct reachable predecessor block; the runtime predecessor chooses the value |
| Clobber | Fresh unknown version of every GPR at an unselected call or unsupported operation, including SP/FP and nonvolatile registers; v4 explicit call summaries clobber volatile GPRs only |
| Load | New register value marked `memoryRead`; address registers are inputs, memory contents remain unknown |
| Machine exit | Observe all GPRs after effects, including RET's updated SP; this does not select an ABI return register |

Every operation binds old operands before installing results. Register CMOV
records both candidate values and its flag read. PUSH's new SP depends on old
SP; its separately recorded source read occurs before that update. POP defines
SP and the loaded destination separately. Unsupported stack forms stay barriers.
Partial preservation is a masked dependency, not a read of an invented C local.

Memory and flags have explicit read/write/unknown effect markers per instruction,
but are outside this SSA graph. A flag-write marker means the operation may
write flags; the typed operation still determines masked-zero-count behavior,
preserved flags and undefined flags. No load/store forwarding, memory SSA, flag
SSA, expression substitution or dead-operation removal is introduced. Calls
without a selected profile continue to invalidate all state. Preview v4 adds
[explicit Windows x64 call assumptions](call-summaries.md) and exports their
source IDs as `assumptionSources`; no ABI is guessed from the PE architecture.

## Graph construction and bounds

The pass uses the existing owned CFG and only its entry-reachable blocks. A
virtual incoming predecessor (`null`) supplies initial values separately from
real backedges into the machine entry. Disconnected owned blocks are counted
but are not silently treated as alternate entries. Returns and known exits
observe every GPR, which seeds backwards family liveness. Liveness prunes dead
joins only; all original operations and write definitions remain.

Bounded dominator sets, immediate dominators, iterated dominance frontiers and
dominator-tree renaming build the graph. This also handles irreducible CFGs;
their C-like view can still retain labels/gotos. Joins appear at block entry,
with uses on predecessor edges. Instruction and edge source IDs remain attached.
Sorting by block RVA and stable IDs makes results deterministic.

The construction follows the dominance-frontier approach of
[Cytron et al. (1991)](https://cs.brown.edu/research/pubs/techreports/reports/CS-91-21.html).
The predecessor-edge interpretation is consistent with the
[LLVM phi contract](https://llvm.org/docs/LangRef.html#phi-instruction), without
adopting LLVM poison, overflow or memory assumptions for machine instructions.

| Budget | Limit |
| --- | ---: |
| Owned blocks | 128 |
| Instructions | 2,048 |
| Outgoing edges | 384 |
| Definitions, including entries/joins | 8,192 |
| Uses, including joins/exits | 32,768 |
| Counted analysis work | 131,072 |

Shared ownership, truncated discovery, unresolved non-call control flow and
outside edges into the function interior disable this pass. Work/definition/use
exhaustion discards the entire provisional graph, reports `budget_exceeded` and
leaves the other preview data available. Size/capability/unsupported-shape
failures report `unavailable`. No additional code discovery is performed and
`complete` remains false. The inspector displays at most 128 reverse uses per
definition with an explicit truncation message; JSON retains every bounded use.

## Additive export contract

Current preview JSON is `version: 4`, with `registerSSA.version: 1` alongside the
unchanged raw `lines`, alias-aware `displayLines`, typed instructions/regions and
`valueAnalysis.version: 1`. Native report schema 2, operand model version 1 and
existing annotation/navigation identities are unchanged.

| Register graph field | Contents |
| --- | --- |
| `definitions` | Stable ID, kind, family/width, block/source, readable label, input use IDs and reverse use IDs; write slice/mask/zero-extension metadata or join incoming uses |
| `uses` | Reaching definition ID, family/slice/mask, role and source; join uses also carry predecessor, consumer and transfer evidence |
| `instructions` | Ordered source/block records, read use IDs, write definition IDs, memory/flag effect markers |
| `blocks` | Reachable predecessors/successors, immediate dominator, join IDs, exit use IDs and family liveness |
| `stats` | Definition/join/use counts, reachable/disconnected blocks and counted work |

Entry and join definitions have no single source instruction. Their input/use
links carry the relevant evidence instead. Failure results contain no partial
definitions, uses, instruction records or block records.

## Validation

```sh
node tests/test_register_ssa.js
python3 tests/test_pseudocode.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
python3 tests/test_pseudocode_oracle.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
python3 tests/test_pseudocode_browser.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
```

The [673 graph contracts](../tests/test_register_ssa.js) cover diamonds, live and
dead joins, loop-carried state, entry backedges, irreducible graphs, unknown
predecessor values, partial writes, x64 zero-extension, clobbers, stack ordering,
disconnected blocks, malformed/unsupported inputs and budget fallback. An
independent graph-path check verifies dominance without reusing the constructor's
dominator algorithm. Reciprocal def-use links and exact predecessor coverage
are checked, and shuffled blocks/edges must produce identical output.

The [Unicorn oracle](../tests/test_pseudocode_oracle.py) chooses the actual path,
snapshots register values after native instructions and independently tracks
dynamic definition identities. It checks each register use and mask, parallel
join selection, partial-write preservation, zero-extension and machine exit
state. Existing typed-region, defined-flag, memory, source-result, abstract-value
and alias-address checks remain. Calls/barriers are tested structurally; the
oracle does not claim concrete execution through unknown effects.

Local validation on 2026-10-20, using Zig 0.13.0 / Clang 18.1.6 for x86/x64 O0/O1:

- Both Capstone and LLVM builds passed all 20 local CTest targets; linked
  compiler fixtures were generated separately. Capstone passed 86 recovery
  contracts across the four fixture reports.
- All 711 independent cases passed: 6,999 executed instruction states, 8,629 SSA
  use checks, 720 selected join edges, 1,680 exit-value checks and 2,017 concrete
  alias-address checks.
- Browser checks passed for Capstone (38) and LLVM capability/fallback (13),
  including source/history/rename compatibility, joins, reverse uses and escaping.
  All 15 publication tests passed.
- One Node measurement over 28 candidates in the four reports took 62.7 ms total
  and 8.5 ms maximum per candidate. The largest serialized `registerSSA` was
  87,147 bytes; the corpus contained 31 joins. These are corpus measurements,
  not worst-case resource guarantees.

Hosted validation for `deb52c0` on 2026-10-20:

- [Analysis matrix passed](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/39360855137):
  22 CTest targets and 15 publication tests per backend, all existing browser
  suites, 38 Capstone C-like checks and 13 LLVM capability/fallback checks.
  The Capstone job passed 711 independent cases with Clang 18/lld-link fixtures:
  7,283 instruction states, 8,574 SSA uses, 699 selected join edges, 1,680 exit
  values and 2,017 alias addresses. LLVM explicitly skips semantic emulation.
- [Demo deployment passed](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/39360855075).
  The live manifest identifies the tested revision and eight reports. The
  [optimized x64 nested-loop demo](https://asr-tanyi.github.io/windows-exe-analyzer/recovery64-o1.html#m_b2c773e4cf51a9a6_c_1080)
  exposes 54 register definitions and eight joins. Live HTML/JSON returned HTTP
  200, embedded JSON matched the separate report, and all four changed model/view
  scripts matched the committed sources. The downloaded self-contained HTML
  passed offline browser checks for join inputs, reverse-use inspection, exact
  assembly navigation and Back, without JavaScript errors. The site serves the
  latest deployment; workflow artifacts retain this tested snapshot.

## Next slice

M7.1 is complete for this bounded integer GPR subset. Preview v4 implements the
explicit Windows x64 normal-return subset of [M4.7](call-summaries.md), with
independent call-boundary checks. Use SSA next for M7.2 width-correct pure-register
expression substitution within basic blocks, retaining observable loads, stores,
flags, calls and traps. Other ABI profiles, source locals/types, argument/return
inference and I/O signatures remain pending.
