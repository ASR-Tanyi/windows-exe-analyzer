# Declared parameter locations and entry-read evidence

P16 associates the conditional parameter locations from [P15](declaration-abi.md) with existing callee-entry register and stack observations. It adds exact instruction links and bit/byte intersections to the inspector, CLI and model JSON. It does not infer signatures, select a winning declaration or establish type compatibility. Full M7.4 remains open.

## Scope and interpretation

The declaration must first pass all P15 prerequisites: explicit Windows x64 profile, supported fixed types, and explicit absence of variadic and hidden parameters. Unresolved declarations have no source associations. Each competing declaration is evaluated independently.

For a register parameter, each existing incoming-register read at the declared register is retained with its original incoming-bit mask. The overlap is the intersection of that mask with the declared bit range. A partially overwritten register can have a disjoint remaining entry mask even when a full register is later read. Original machine read widths are never narrowed or rewritten.

For a stack parameter, only existing untouched entry-stack reads at exactly the declared callee-entry offset are associated. Existing stack analysis supports aligned 1/2/4/8-byte reads. The association keeps the observed width and reports the number of overlapping declared bytes. It does not infer padding values, home copies or additional unobserved stack inputs. Broader unaligned/interior-offset recovery is outside this policy.

| Per-read relation | Meaning |
| --- | --- |
| `covers` | This read's incoming mask or bytes cover the declared bits |
| `partial` | This read overlaps some declared bits |
| `disjoint` | A read at the register observes only incoming bits outside the declaration |

These relations describe location overlap only. Copies, spills and address calculations count as existing observations; they do not establish source-level parameter use. Reads and paths remain separate: two partial reads are never combined into a claim of full coverage. The exact read instruction and all retained predecessor/address/overwrite witnesses are linked. Selected call assumptions remain explicit in the existing inspector and in the association model's `assumptionSources`.

## Unknowns and bounded fallback

A parameter row has one of these states:

| State | Meaning |
| --- | --- |
| `observed` | One or more existing reads at this location; individual relations remain separate |
| `no_observation` | The bounded analysis found no supported read at this location; parameter presence remains unknown |
| `unresolved` | The supplied declaration has no supported conditional placement |
| `unavailable` | Machine/stack observations or the association pass are unavailable |

Return rows explicitly say `not_reviewed`. P16 does not interpret RAX definitions as returned declared bits and does not associate direct-caller writes or post-call reads. Those existing observations remain inspectable in their original sections.

The association pass has independent hard limits: 32,768 work visits, 512 read links across all declarations, and 64 unique sources per link. Options can lower these limits but cannot raise them. The existing eight-declaration / 32-parameter limits bound output to 264 rows including returns. Exceeding an association limit discards **all** provisional associations, preserving conditional placements and machine observations. Failed machine analysis exposes no stale source links. Unavailable stack evidence does not erase available register associations.

## Data and UI contract

`functionABI.version` advances to 9. Additive `declarationEvidence` contains policy `declared-entry-read-associations-v1`, status, reason, work/link counts, assumption sources and per-declaration return/parameter rows. Register reads contain `observedMask`, `overlapMask`, register, relation, exact source and sources. Stack reads contain entry offset, observed width, overlap bytes, relation and sources. All masks are hexadecimal strings; stack offsets remain decimal strings.

Native schema 2, preview version 8 and analyst contract versions 1/2/3 remain unchanged. Derived links are recomputed and never exported as analyst annotations. Clearing a profile or required alias removes the associations. Existing machine effects, code rendering, call assumptions, candidate arrays and machine-analysis counters remain unchanged.

The **Declared ABI locations** table includes per-row observations, exact assembly navigation and expandable witness lists. Browser Back preserves the chosen contract and expanded location panels. Phone layouts scroll inside the table. CLI `--abi` prints the same per-read relations and source IDs; `--json` uses exactly the browser model.

## Validation

Local validation passed 32 CTest targets per backend, 64 focused association checks, 484 ABI graph checks and 169 decoder/CLI checks. Browser validation passed 128 Capstone / 3 LLVM ABI checks and 90 Capstone / 13 LLVM C-like checks. Tests cover partial overwrite, disjoint upper bits, conflicting widths, separate reads, exact stack offsets, unavailable evidence, all three real hard limits, transactional fallback, source navigation, export parity and phone layout.

The authored caller/callee Unicorn oracle checks 48 parameter values, five return values, one void-return case and 48 source-linked reads across six executions. Instruction offsets are independently authored and read values are checked during execution. Two deliberately wrong coordinates and one wrong source link are rejected. The existing ABI oracle still passes 112 executions, including incoming stack and caller-store proofs. LLVM explicitly reports its structured-operand limitation.

## Next slice

Next associate declared parameter locations with bounded direct-caller register and proven stack-store observations, keeping every call site and uncertain alternative separate. Return-bit association needs its own treatment of preserved bits, partial writes and per-RET alternatives. Neither extension should turn overlap into a prototype-compatibility verdict or enable call summaries.
