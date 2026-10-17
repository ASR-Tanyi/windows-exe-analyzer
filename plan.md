# windows-exe-analyzer: development plan

> Direction: a trustworthy, navigable reverse-engineering workspace for native Windows x86/x64 binaries, progressing from disassembly to evidence-backed low-level code recovery.
>
> Planning baseline: [`f789c59`](https://github.com/ASR-Tanyi/windows-exe-analyzer/tree/f789c59b590588426a64aa8c13c378865ab34996), reviewed on 2026-10-16. The baseline section is historical; the checklists below track subsequent implementation. Checked items link to their implementation and supported scope; unchecked items are pending or explicitly partial. Milestones express dependency order, not delivery-date commitments.

## Contents

- [1. Product goal and boundaries](#1-product-goal-and-boundaries)
- [2. Current baseline](#2-current-baseline)
- [3. Execution order](#3-execution-order)
- [4. Shared architecture and evidence contracts](#4-shared-architecture-and-evidence-contracts)
- [5. Detailed milestones](#5-detailed-milestones)
- [6. First implementation queue](#6-first-implementation-queue)
- [7. Validation and measurement](#7-validation-and-measurement)
- [8. Further targets](#8-further-targets)
- [9. Delivery and repository policy](#9-delivery-and-repository-policy)
- [10. Risks and decisions](#10-risks-and-decisions)
- [11. Definition of done and plan maintenance](#11-definition-of-done-and-plan-maintenance)
- [12. References](#12-references)

## 1. Product goal and boundaries

The intended analyst journey is:

```text
Open an EXE or DLL
  -> understand its entry points and discovered functions
  -> follow named code blocks, branches, calls, and data references
  -> inspect strings, constants, pointer candidates, and imported APIs
  -> connect selected DLL implementations
  -> inspect low-level operations and reconstructed expressions
  -> validate every interpretation against the original instructions
```

The primary deliverable remains a command-line analyzer with portable HTML/JSON output. Browsing a report must not require running the analyzed program. Each phase should improve the existing explorer rather than wait for a complete decompiler.

**Near-term scope:** ordinary native user-mode PE32/x86 and PE32+/x64 files, including stripped binaries and source-known optimized fixtures. Preserve both decoding modes; introduce semantic coverage in explicit architecture-specific stages.

**Not promised:** exact original source, complete discovery of arbitrary code, trustworthy names from bytes alone, recovery of optimized-away functions, or proof of whole-program equivalence. Unknown results are legitimate output.

**Deferred scope:** packed/self-modifying binaries, live debugging, kernel execution, managed IL, additional architectures, patching, and automatic unpacking. Some are exploration targets in section 8, not prerequisites for the initial roadmap.

## 2. Current baseline

The implementation at the pinned baseline provides the following starting point. These are repository capabilities, not newly executed test results for this document.

| Area | Present behavior | Important remaining gap |
| --- | --- | --- |
| PE parsing | Headers, sections, preferred addresses, ordinary imports and exports | Exception/TLS discovery, relocation-aware references, delay imports, richer metadata |
| Decoding | Capstone and LLVM adapters for x86/x64 | Common structured operands; backend capability and parity coverage |
| Discovery | PE entry, executable export candidates, analyst-supplied main, and direct-call targets | Metadata seeds, uncertain boundaries, indirect destinations |
| Control flow | Named blocks, direct edges, call continuations, inferred block owners | Whole-function presentation, graph analysis, better tail/shared-block treatment |
| Static data | Constant-address references, RIP/EIP-relative navigation, file-byte pages, numeric/string previews | Image-wide string discovery, range references, pointer candidates |
| HTML | Code/data links, incoming references, history, search, labels, annotation import/export | Function overview, scalable graphs, cross-module workspace, analysis provenance |
| Automation | Build/test/demo generation, custom public-input modes, artifacts, Pages deployment workflow | Broader compiler/backend testing, hardened publication, deployment verification |
| Recovery | Instruction observations and structural labels | Semantically accurate IR, value analysis, stack variables, useful pseudocode |

Baseline details are recorded in [README.md](README.md), [src/model.hpp](src/model.hpp), [src/pe.hpp](src/pe.hpp), [src/analyze.hpp](src/analyze.hpp), [src/decoder.cpp](src/decoder.cpp), and [the report workflow guide](docs/report-workflow.md). These relative links follow the checked-out revision; the baseline link above is immutable.

Important distinctions to preserve:

- `--main-rva` is an analyst assertion. `--ir` currently displays observations, not complete machine semantics.
- The report uses preferred image addresses, not an observed process layout. Original bytes, virtual zero-fill, omitted bytes, and unavailable addresses are distinct states.
- The report schema is currently 2; annotation schema is 1. The current module identity is a non-cryptographic content key.
- The workflow source exists, but an operational deployment claim needs a successful deployment and a checked URL. Do not infer Pages status from this plan or assume the custom-input container path has been exercised by a demo-only run.

## 3. Execution order

| Milestone | Priority | User-visible outcome | Main dependency |
| --- | --- | --- | --- |
| M0: Contracts and regression foundation | P0 | Trustworthy evidence, compatibility, repeatable tests | Existing baseline |
| M1: Function discovery and startup evidence | P0 | More functions, with explicit reasons for discovery | Minimal M0 contracts |
| M2: Whole-function explorer and CFG | P0 | Read a function without navigating one block at a time | M0; benefits from M1 |
| M3: Strings and richer data references | P0 | Search a string and jump to its referencing code | M0; integrates with M2 |
| M4: Structured operands and bounded value analysis | P1 | Resolve supported register-based references and indirect targets | M0, M1; M2/M3 presentation |
| M5: Cross-DLL workspace | P1 | Follow an import into a supplied DLL and back | M1, M2, M3; not all of M4 |
| M6: Precise low-level IR | P1 | Inspect supported machine operations and flag effects | M4 operand/transfer core |
| M7: Function recovery and stronger entry-role recognition | P1 | Linked low-level pseudocode and evidence-backed startup roles | M2, M6; selected M4 analyses |
| M8: Routine-use quality and distribution | P2 | Reliable larger reports, tested builds, usable releases | Incremental work throughout |

```text
M0 minimum contracts
  +-- M1 discovery --------+-- M2 whole-function view
  +-- M3 strings/xrefs ----+-- M5 supplied-DLL navigation
  +-- M4 operand/transfer core
        +-- M4 indirect-target analysis
        +-- M6 full semantics for selected instructions -- M7 recovery

M8 quality, safety, and performance work runs alongside all milestones.
```

This is not a requirement to finish every M0 improvement before shipping M1. Likewise, a lifter for one supported function does not need every DLL, jump table, or arbitrary indirect edge to be resolved. Analyze bounded regions, preserve uncertainty, and avoid waiting for an impossible complete-program picture.

## 4. Shared architecture and evidence contracts

### 4.1 Addresses, entities, and stable links

Use a module-qualified RVA as the canonical location of image-backed code/data. Keep file offsets, preferred VAs, supplied runtime VAs, and unmapped addresses explicitly tagged; never pass them around as interchangeable integers. PE RVAs and file positions are different coordinate systems [R1].

Proposed model, not an existing API:

```text
Location       = module_id + address_space + value
Instruction    = location + bytes + structured_operands + decoder_capabilities
CodeRange      = [begin_rva, end_rva) + origin + validation_state
Function       = id + entry_candidates + ranges + blocks + evidence
Reference      = source_location + target_location_or_expression
                 + kind + access_width + resolution_state + evidence
Annotation     = entity_id + name + note + provenance
```

Multiple functions may share a block; a function may have multiple ranges. A range supplied by metadata is not automatically a complete source function. Do not infer a function's end from the next discovered entry alone.

Names remain aliases. Renaming a function, block, or data item must not change links. Keep module identity stable for byte-identical inputs; introduce a SHA-256 identity and legacy alias/migration path before multi-module persistence rather than silently breaking saved annotations.

### 4.2 Evidence and uncertainty

Separate **where information came from** from **how certain the inference is**.

| Dimension | Proposed values |
| --- | --- |
| Provenance | Header, exception metadata, TLS metadata, decoded instruction, matched symbol, analysis rule, analyst annotation, runtime observation |
| Resolution | Exact encoded target, finite candidate set, symbolic expression, unresolved, conflicting |
| Inference status | Confirmed within stated assumptions, supported candidate, weak heuristic, unknown |

An analyst label is not a stronger machine fact than a decoded address. A symbol-backed name can still refer to a thunk or folded implementation. Avoid uncalibrated confidence percentages.

Every inferred result should retain its rule/version, source locations, assumptions, and conflicting evidence. Unsupported decoder metadata is different from a known absence of side effects. A memory reference and an execution destination must remain distinct entities.

### 4.3 Analysis passes and partial results

Separate parsing, discovery, CFG construction, data indexing, value analysis, and presentation. Each pass declares prerequisites, produced facts, budgets, and diagnostics. Refactor existing files incrementally when adding a pass; do not start with a wholesale rewrite.

Proposed diagnostic codes include `unmapped_target`, `overlapping_decode`, `unsupported_instruction`, `invalid_metadata`, `budget_exhausted`, and `ambiguous_owner`. Preserve counts even when displayed messages are capped.

A traversal frontier hitting a limit should produce a partial report with reasons. Empty work, failed decoding, and exhausted budgets must not all become the same error. Never turn an unresolved target into an invented destination.

### 4.4 Serialization and presentation

Add a documented schema and migration policy before broadening the model. Schema changes need compatibility fixtures and explicit version handling. Keep 64-bit addresses as lossless strings in JSON/JavaScript; arithmetic in the viewer must not silently lose precision.

Preserve source instruction IDs through analysis and simplification. HTML, IR, pseudocode, and graphs should navigate to the same underlying locations. A single self-contained HTML remains the small-report mode; an optional directory-based site can be introduced later for large workspaces.

## 5. Detailed milestones

### M0. Contracts and regression foundation

**Goal:** make subsequent discoveries measurable without destabilizing the existing explorer.

**Likely files:** `src/model.hpp`, `src/report.cpp`, `tests/`, `CMakeLists.txt`, and workflow configuration. New file paths mentioned throughout this plan are proposals, not claims they exist.

- [x] **M0.1** Define address/range types, structured evidence, and typed diagnostics; add serialization round-trip tests. Completed in [`9299868`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/9299868a6ccecc181ffd1dddf0a8f431faeb4fd7); [scope and tests](docs/m0-foundation.md). New analysis facts are typed; migrating every legacy integer API is not claimed.
- [ ] **M0.2** Record schema version, analyzer revision, decoder version/capabilities, effective limits, and enabled passes in report metadata. **Partial:** schema/model versions and selected limits exist; complete revision/capability/pass metadata remains pending.
- [x] **M0.3** Add a small corpus manifest with fixture source, compiler/linker identity, flags, architecture, input hash, and expected discoveries. Keep compiler-generated ground truth outside the analyzer's input in blind-discovery tests. Completed in [`9299868`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/9299868a6ccecc181ffd1dddf0a8f431faeb4fd7); see [fixture generator](tests/build_fixtures.py) and [blind-discovery tests](tests/test_analysis_model.py).
- [ ] **M0.4** Add independent build/regression CI for Linux and Windows, then macOS. Test both decoder adapters; distinguish backend-unavailable skips from passing tests. **Partial:** Linux/LLVM regression CI runs on main and PRs; the Windows/macOS and Capstone matrix remains pending.
- [x] **M0.5** Add schema/annotation compatibility fixtures and a regression proving labels survive a viewer update for the same binary. Completed in [`9299868`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/9299868a6ccecc181ffd1dddf0a8f431faeb4fd7); [browser compatibility tests](tests/test_model_browser.py) and [hosted regression evidence](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/38923497939).
- [ ] **M0.6** Add parser sanitizers and bounded malformed-input checks. Expand fuzzing incrementally as metadata parsers are added. **Partial:** bounded malformed-input tests and local sanitizer validation exist; persistent sanitizer/fuzz automation and broader coverage remain pending.
- [ ] **M0.7** Validate hosted demo deployment and the custom-input container separately, using only public-safe source-known inputs. Record run links instead of copying old test counts into new claims. **Partial:** [demo build/deployment succeeded](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/38929245698); the separate custom-input container validation is not yet recorded.

**Acceptance:** current navigation and fixture tests remain passing; repeated analysis has stable semantic output after documented volatile metadata is normalized; supported backend/OS combinations are explicit. CLI success alone is insufficient if discovery is partial.

**Boundary:** M0 establishes contracts and a minimal test matrix, not a full plugin framework or a guarantee that the parser is hardened against hostile files. The checked foundation items do not mean the entire M0 milestone is complete.

### M1. Function discovery and startup evidence

**Goal:** discover code that direct-call traversal misses and explain why an address is being treated as a function candidate.

**Likely files:** `src/pe.hpp`, `src/analyze.hpp`, `src/model.hpp`; proposed `src/discovery.*` and focused metadata fixtures.

#### M1A. x64 exception-directory discovery

The AMD64 exception mechanism supplies image-relative runtime-function ranges and unwind information; some leaf code lacks entries, and chained information can describe portions of a procedure [R2]. Use this as evidence, not a universal source-function list.

- [x] **M1.1** Locate the exception directory from the PE data directories, independent of the section's display name. Gate AMD64 record interpretation on the machine type. Completed in [`b47cf34`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/b47cf34f5ae23b3472d20d240c52686b48ea03e3); [parser contract and tests](docs/m1-exception-directory.md).
- [x] **M1.2** Parse bounded runtime-function records; validate record sizes, arithmetic, readable table extents, executable start locations, and half-open ranges. Preserve malformed-record diagnostics without silently accepting unsafe ranges. Completed in [`b47cf34`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/b47cf34f5ae23b3472d20d240c52686b48ea03e3) under the documented conservative file-backed policy; [hosted regression evidence](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/38929245712).
- [x] **M1.3** Preserve unwind RVAs, supported versions, chained associations, and handler candidates. Cap traversal and detect cycles; retain unknown versions without interpreting them as a known layout. Completed for the [documented structural version-1 subset](docs/m1-unwind-discovery.md) in [`7e85a68`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/7e85a68a872d0a2a8334a1f6f43aa3090fae91bb). Unknown versions stay opaque; runtime stack unwinding, actual prolog verification, and language-specific handler decoding are not claimed.
- [x] **M1.4** Seed valid range starts, merge duplicate evidence by location, and show metadata ranges separately from discovered instruction coverage. Do not linearly decode every byte inside a range as code. Completed for eligible supported records in [`7e85a68`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/7e85a68a872d0a2a8334a1f6f43aa3090fae91bb); [discovery/negative tests](tests/test_unwind_info.py), [budget/cache tests](tests/test_unwind_limits.cpp), and [navigation tests](tests/test_unwind_browser.py). Chained entries retain fragment/primary associations, not a proven source-function ownership merge.

#### M1B. TLS, x86 seeds, and startup roles

The TLS directory includes address-bearing fields and a callback array; use the documented field semantics instead of assuming every field is an RVA [R1].

- [x] **M1.5** Parse PE32 and PE32+ TLS callback arrays with checked VA-to-RVA conversion, element widths, null termination, count caps, and readable storage checks. Completed in [`d3f86a9`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/d3f86a9cfec5062c01dc4158cf447f0d42e91c01); [bounded TLS contract](docs/m1-tls-discovery.md), [mapping/budget checks](tests/test_tls_types.cpp), and [synthetic/source-compiled PE tests](tests/test_tls_directory.py). Partial arrays remain visible but do not add automatic roots; template/index allocation fields are recorded, not runtime-validated.
- [x] **M1.6** Add independent callback roots without creating a fake direct call from the PE entry point. Preserve possible initialization relationships separately from normal CFG edges. Completed in [`d3f86a9`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/d3f86a9cfec5062c01dc4158cf447f0d42e91c01); [HTML navigation tests](tests/test_tls_browser.py) and [successful hosted regression run](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/38996995301). Per-slot evidence, duplicate targets, existing names, and instruction boundaries are retained; encoded array order is not a runtime trace.
- [ ] **M1.7** Add an explicit arbitrary function-seed input distinct from `--main-rva`; retain existing exports and call targets. Keep prologue-pattern scanning optional and label it heuristic.
- [ ] **M1.8** Treat x86 discovery separately: do not apply the AMD64 unwind-table format to x86. Use decoded calls, exports, analyst seeds, and later matched symbols/validated pointers. **Partial:** architecture gating and existing direct/export discovery are in place; arbitrary seeds and later symbol/pointer-based discovery remain pending.
- [ ] **M1.9** Introduce entry-role records for PE entry, TLS callback, runtime startup candidate, application-entry candidate, and DLL initialization. Retain all alternatives and analyst overrides. **Partial:** PE entry, TLS callback, and analyst application-entry evidence exist; a general role model and tested startup profiles remain pending.

The Microsoft runtime entry varies with console, GUI, and DLL linkage [R3]. At this phase, recognize only tested startup profiles or explicit symbols. Do not rename the first call target to `main`, infer `main` from the subsystem alone, or require every program to have `main`. General argument-aware recognition is M7 work.

**Acceptance fixtures:** nonleaf functions reachable only indirectly but described by metadata; a leaf without metadata; renamed metadata sections; duplicate and malformed entries; chained/cyclic records; a DLL without a PE entry; x86/x64 TLS callbacks; a custom no-CRT entry; a real CRT-linked console fixture. Compiler maps are evaluation oracles, not hidden analyzer inputs.

**Exit gate:** every supported valid metadata seed appears with provenance; negative fixtures produce no extra high-confidence function claim; all ownership conflicts and missed/invalid seeds remain inspectable. Coverage is reported for the declared fixture subset, not as a percentage of unknown real-binary functions. M1.7-M1.9 and the broader compiler/startup corpus are still pending or partial; M1A and TLS completion are limited to their linked support contracts.

### M2. Whole-function explorer and control-flow graphs

**Goal:** read a complete function while retaining the current precise block/data navigation.

**Likely files:** `web/viewer.html`, `src/report.cpp`, function/edge models, browser tests. Presentation files may be split into authored CSS/JS and embedded at build time if the single template becomes difficult to maintain.

- [x] **M2.1** Add a function overview: entries, ranges, block/instruction counts, evidence, callers, callees, referenced data, and unresolved edges. Count unique bytes rather than double-counting shared ranges. Completed in [`ea32ba2`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/ea32ba20cfe80fe5c9d75c1c457ffa6423216ed0) using existing report ownership; [model checks](tests/test_function_model.js) and [scope](docs/m2-function-view.md). Missing membership and unresolved edges remain explicit; completeness is not inferred from their absence.
- [x] **M2.2** Render all owned blocks in one assembly view with sticky labels and source anchors. Preserve a dedicated block view and distinguish address order from execution order. Completed in [`ea32ba2`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/ea32ba20cfe80fe5c9d75c1c457ffa6423216ed0); all owned instructions are accessible through bounded pages, with repeated headings for blocks spanning pages rather than invented block splits.
- [x] **M2.3** Separate intraprocedural CFG edges from call-graph edges. Calls have an explicit continuation assumption; do not connect a callee return to every caller in the function CFG. Completed in the [presentation index](web/function-model.js) in [`ea32ba2`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/ea32ba20cfe80fe5c9d75c1c457ffa6423216ed0); this does not introduce a new native graph analysis or claim complete call-graph recovery.
- [x] **M2.4** Add a layout-backed graph view with selectable blocks, labeled branch edges, unknown exits, shared-block indicators, zoom, and keyboard navigation. Provide a list fallback when layout or size limits are reached. Implemented in [`247290e`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/247290e74fb1adf8957750adeb2b1595177ae8f2) with keyboard-focus follow-up [`5951b73`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/5951b731d6380b1f0eb392aae6dc9316230bc0e7); [bounded graph contract](docs/m2-cfg.md), [browser checks](tests/test_cfg_browser.py), and [successful hosted regression](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/39009132203). SVG layout is capped at 120 blocks / 300 intraprocedural edges and falls back to a list without dropping report facts.
- [x] **M2.5** Compute strongly connected regions and dominator-based natural-loop candidates on the discovered graph. Mark incompleteness; a backward address edge is only a clue. Irreducible regions must not be forced into a natural-loop model. Implemented in [`b8529ea`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/b8529eab42cbcf36087440cff38ded2318f93261) and covered by [graph-model fixtures](tests/test_cfg_model.js): reachability, dominators, SCCs, nested/self loops, multi-entry irreducible regions, unreachable blocks, incomplete graphs, and analysis budgets. Natural loops require dominance; unresolved/truncated graphs remain explicitly incomplete.
- [x] **M2.6** Retain function, block, exact instruction, selected data address, and scroll context in navigation history. Deep links must reopen the same entity after reload. Implemented in [`ea32ba2`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/ea32ba20cfe80fe5c9d75c1c457ffa6423216ed0); [browser tests](tests/test_function_browser.py) cover call/data/metadata navigation, function-qualified instruction routes, expanded details, and vertical/horizontal assembly scroll. The [hosted regression run](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/38999660185) additionally exercises actual document reload; managed content-only runs explicitly skip that check.
- [x] **M2.7** Add virtualized or paged rendering for large functions; do not put every decoded instruction into the DOM at once. Completed for the whole-function view in [`ea32ba2`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/ea32ba20cfe80fe5c9d75c1c457ffa6423216ed0): at most 250 instruction rows per page, including a single oversized block, with bounded detail lists and a four-function derived-index cache. This is not virtualization of the original block view or a global report-size bound.

**Acceptance:** fixtures for straight-line flow, a diamond, multiple returns, nested loops, irreducible flow, recursion, a tail transfer, shared blocks, and unresolved indirect exits. Browser tests cover assembly-to-graph selection, history, zoom, keyboard selection, list fallback, and return to whole-function assembly; earlier M2 tests continue covering data/code navigation, renaming, deep links, small screens, and escaping. Graph analysis is intentionally limited to already-discovered intraprocedural edges.

**Exit gate:** whole-function, block, and graph views agree on existing instruction/block identities and ownership evidence. Existing code/data navigation is not regressed. A graph may be incomplete, but cannot hide its missing targets. M2.1-M2.7 are complete within the linked presentation and bounded discovered-CFG contracts; this does not imply complete native function/edge recovery.

### M3. Strings, pointer candidates, and richer static-data references

**Goal:** start from recognizable data and find the code using it.

**Likely files:** `src/static_data.hpp`, `src/model.hpp`, `src/report.cpp`, `web/viewer.html`; proposed string/reference indexes and tests.

- [x] **M3.1** Scan readable file-backed image ranges for configurable ASCII and validated UTF-16LE candidates, including bounded unterminated prefixes. Do not restrict discovery to section names such as `.rdata` or fabricate strings from zero-fill. Completed in [`e316859`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/e316859c5cc92c263ee9fde250b8d3a3629b0e23); [scanner contract](docs/m3-static-strings.md), [native bounds tests](tests/test_string_scan.cpp), and [PE/CLI tests](tests/test_strings.py). Candidate detection uses a documented text heuristic and independent scan/retention budgets, not proof of object types or exhaustive text recovery.
- [x] **M3.2** Keep encoding, length in bytes/code units, termination, section, and candidate status. Do not deduplicate distinct addresses merely because their text is equal. Add non-Latin and surrogate-pair fixtures, not only zero-high-byte Latin text. Completed in [`e316859`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/e316859c5cc92c263ee9fde250b8d3a3629b0e23); [Unicode and identity tests](tests/test_string_scan.cpp) cover non-Latin text, supplementary characters, unaligned UTF-16LE, unpaired surrogates, termination, and distinct same-text addresses. Text previews are capped; scanned lengths and partial-prefix boundaries are explicit.
- [x] **M3.3** Add a searchable Strings view linked to bytes, exact references, interior references, and owning function candidates. Index discovery separately from the byte-embedding budget, with independent limits and completeness status. Completed in [`e316859`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/e316859c5cc92c263ee9fde250b8d3a3629b0e23), with legacy data-link compatibility corrected in [`67a00d6`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/67a00d6e79cf6bd5f633f46b5224e6ab174b5209); [reference-index tests](tests/test_string_model.js) and [browser tests](tests/test_string_browser.py). Search covers retained previews; exact/interior matches use the operand start address and preserve access kind and all reported owners. Byte embedding and reference-index budgets are separate and partial results are labeled.
- [ ] **M3.4** Extend xrefs from exact starting addresses to typed intervals when access width is known. Distinguish code-to-data, data-to-data, address-taking, reads, writes, and unknown access. Keep unknown object boundaries explicit. **Partial:** constant-address operand starts are matched against string candidate spans. General access-width overlaps, data-to-data references, relocation-informed pointers, and object-boundary analysis remain pending.
- [ ] **M3.5** Parse base-relocation blocks for supported x86/x64 forms with strict bounds. Use relocation locations as pointer evidence, not proof of a variable's source type [R1].
- [ ] **M3.6** Add bounded pointer-candidate following with selected pointer width, mapped-target checks, cycle/depth limits, and an evidence label. Never interpret an IAT's on-disk lookup value as the loaded function address.
- [ ] **M3.7** Keep an optional rebased image view distinct from original bytes. Do not apply relocations twice or silently change the file-byte display; unsupported relocation types stay unresolved.
- [ ] **M3.8** Add analyst data names and optional object extents/types as overlays with conflict handling. A manually defined string or structure must not erase underlying observations.

**Acceptance fixtures:** ASCII, UTF-16 non-Latin text, interior string pointers, false-positive printable bytes, pointer tables, relocations present/absent, cyclic pointers, rebasing, IAT storage, writable data, incomplete embedded pages, and accesses crossing a candidate object's boundary.

**Exit gate:** searching a known string reaches every discovered direct reference in the supported fixtures. Reference counts state their discovery scope; no-results never claims the data is unused. M3.1-M3.3 are complete within the linked bounded-string contract; M3.4-M3.8 and their broader pointer/relocation cases are not marked complete.

### M4. Structured operands and bounded value analysis

**Goal:** move beyond formatted assembly and resolve a useful subset of register-dependent references without pretending to execute the program.

**Likely files:** decoder/model code; proposed `src/operands.*`, `src/value_analysis.*`, and a reusable transfer-operation core.

#### M4A. Decoder capability contract

Capstone detail mode supplies structured operands and access metadata [R4]. The existing LLVM C adapter is text-oriented. Neither display strings nor access metadata alone are a complete semantic lifter.

- [ ] **M4.1** Normalize explicit registers, register slices, immediates, operand/address widths, segments, base/index/scale/displacement expressions, and relevant prefixes. Preserve raw bytes and display text separately.
- [ ] **M4.2** Advertise capabilities per backend and instruction. Choose a structured decoder for semantic features; keep the LLVM text adapter as a declared limited disassembly path unless an explicitly tested structured adapter is added.
- [ ] **M4.3** Test aliasing and width metadata, including partial general-purpose registers and address-size overrides. Unknown implicit accesses must remain unknown, not an empty known set.

#### M4B. A small reusable analysis core

- [ ] **M4.4** Define a bounded value domain: constants, module-relative addresses, import-symbol references, small finite target sets, and unknown. Preserve known-bit/width information where required; cap candidate growth.
- [ ] **M4.5** Implement tested transfer operations for a narrow integer/address subset and reuse their definitions in M6. Do not write a separate string-pattern value engine that later disagrees with the lifter.
- [ ] **M4.6** Propagate within blocks, then across the CFG to a fixed point. Joins with incompatible predecessors become a candidate set or unknown; work budgets must terminate loops.
- [ ] **M4.7** Apply explicit ABI summaries at calls. Unknown calls invalidate affected volatile registers and potentially modified memory; unsupported operations invalidate facts conservatively. Never propagate a pre-call value just because it was convenient.

The standard Windows x64 ABI specifies argument registers, volatile state, and stack conventions [R5]. Keep that profile separate from x86 cdecl/stdcall/fastcall/thiscall and from custom conventions.

#### M4C. Supported indirect-flow cases

- [ ] **M4.8** Resolve simple import thunks, a tracked `mov reg, [IAT]` followed by `call reg`, and locally constant function-pointer targets. Retain the full derivation path for each result.
- [ ] **M4.9** Recognize bounded switch tables only when index bounds, table base, entry interpretation, and executable destinations are supported. Handle absolute pointers and relative entries as different formats.
- [ ] **M4.10** Feed validated targets back into discovery with deduplication, iteration limits, and CFG rebuilding. Keep unresolved residual edges for paths the analysis has not covered.
- [ ] **M4.11** Treat mutable global pointers, overwritten tables, segments with unknown bases, and runtime-resolved APIs as unresolved unless independent evidence is supplied. Do not label every indirect call a virtual method.

**Acceptance:** positive patterns plus adversarial lookalikes: a register overwritten before use, a call clobbering the value, conflicting branch values, unchecked table indexes, signed relative entries, an IAT-like integer, and cycles. Decoder parity compares semantics of supported facts, not identical mnemonic spelling.

**Exit gate:** every resolved indirect target in the declared synthetic cases is correct, and negative cases remain unresolved. Publish resolution coverage with unsupported cases in the denominator; never claim universal indirect-call recovery.

### M5. Cross-DLL workspace

**Goal:** click an imported symbol, inspect the matching supplied implementation, and return to the precise EXE call site.

**Likely files:** PE import/export models, report generation, CLI, viewer routing; proposed `src/workspace.*`.

- [ ] **M5.1** Accept explicitly supplied DLL files or constrained search directories. Hash and index each module without loading it as executable code. Cap module count and total input/report sizes.
- [ ] **M5.2** Preserve import/export names, ordinals, aliases, forwarders, machine type, and original module names as structured fields rather than only combined display strings.
- [ ] **M5.3** Resolve names/ordinals into supplied exports with case-aware rules appropriate to each field. Detect architecture mismatch and duplicate candidate DLLs; filename agreement alone is not proof of the runtime-loaded module.
- [ ] **M5.4** Follow forwarded exports with depth/cycle limits. Record the entire chain. Treat API-set mapping as an explicitly supplied, versioned environment profile rather than a guessed universal mapping [R1].
- [ ] **M5.5** Parse supported delay-import metadata, retaining the distinction between on-disk identity, delay helper, and runtime-resolved target.
- [ ] **M5.6** Add module-qualified routes, a module selector, and cross-module incoming references. Distinguish the IAT slot, intended import identity, statically matched implementation, and observed runtime target.
- [ ] **M5.7** Keep missing modules navigable as unresolved import pages. Do not download arbitrary dependencies automatically or require all system DLLs before producing a useful report.

**Acceptance:** source-known EXE/DLL pairs for x86/x64; name and ordinal imports; a forwarded export; missing/mismatched DLL; same-name different binaries; duplicate export aliases; a forwarding cycle; and code/data/history navigation across modules.

**Exit gate:** the demo's import reaches the expected export implementation in an explicitly supplied DLL. Cross-module links remain stable when names change. Unavailable modules never produce broken or fabricated implementation links.

### M6. Precise low-level intermediate representation

**Goal:** represent supported instruction behavior accurately before simplifying it into readable code.

**Likely files:** reusable M4 transfers plus proposed `src/ir/` and instruction-semantics fixtures. A machine instruction may lift to several operations; preserve every operation's source instruction identity. Ghidra p-code is a useful reference for this separation, not a required runtime dependency [R6].

- [ ] **M6.1** Write a semantic contract for fixed-width bit-vectors, register slices, memory loads/stores, flags, control flow, and unknown/undefined values. Define what execution conditions are modeled and which are not.
- [ ] **M6.2** Start with the exact integer forms needed by the source-known checksum fixture: moves/extensions, address calculation, arithmetic, logic, shifts, comparisons, condition setting, jumps, calls, and returns. Publish a per-form support matrix; mnemonic coverage is not enough.
- [ ] **M6.3** Model partial-register writes, x64 32-bit destination behavior, effective-address width, carry/overflow/zero/sign flags, preserved flags, and masked shift counts using the instruction manuals. Keep undefined flags distinct from arbitrary chosen constants.
- [ ] **M6.4** Separate raw instruction effects from higher-level call summaries. Do not double-count return-address/stack effects, drop stack alignment assumptions, or invent external-call signatures.
- [ ] **M6.5** Represent unsupported instructions as effectful barriers with conservative invalidation; never as no-ops. Report semantic completeness per instruction, block, and function.
- [ ] **M6.6** Add a reference evaluator for the supported IR subset and compare against an independent instruction oracle in a bounded test harness. Test registers, defined flags, memory writes, and control flow, not just final return values.
- [ ] **M6.7** Add an HTML IR view linked both ways to assembly and data. Keep the existing observation notes separate so they cannot be mistaken for lifted semantics.

Do not use source-language undefined behavior to approximate machine wraparound. If LLVM IR is used later, audit overflow flags, poison/undef, memory assumptions, and shift rules rather than assuming they match the target machine [R7].

**Acceptance:** boundary values, arithmetic wraparound, signed/unsigned comparisons, partial writes, zero/masked shifts, preserved flags, memory widths, unknown calls, and unsupported forms. Define a fault-free domain for the first evaluator; trapping cases must be excluded explicitly or modeled, never silently validated as equivalent.

**Exit gate:** no unexplained mismatch in supported instruction-form tests, and every unsupported effect is visible. First-stage semantic support may be x64-only; x86 decoding remains usable and its semantic limitations are explicit.

### M7. Function recovery and stronger entry-role recognition

**Goal:** turn verified low-level effects into readable, inspectable function-level code.

**Likely files:** proposed data-flow/recovery passes, IR simplifier, renderers, browser tests, and additional CRT-linked fixtures.

- [ ] **M7.1** Build def-use chains and register SSA with explicit merge nodes. Begin with conservative memory effects; postpone precise memory SSA until alias assumptions are defined.
- [ ] **M7.2** Add constant/copy propagation, dead-value cleanup, and width-correct expression simplification. Do not remove potentially observable loads, stores, traps, or calls solely because a register result is unused.
- [ ] **M7.3** Recover stack-relative slots using tracked stack/frame state. Distinguish saved registers, return addresses, ABI home space, spills, outgoing arguments, and candidate locals. Unknown stack adjustment ends precise slot tracking.
- [ ] **M7.4** Infer arguments and return candidates from supported ABI profiles and callers. Preserve conflicting prototypes, varargs uncertainty, hidden parameters, and analyst-supplied types.
- [ ] **M7.5** Emit readable labeled low-level pseudocode first. Preserve `goto` for unsupported or irreducible structure; recover `if`, loops, and supported switches only when the graph/effects justify the transformation.
- [ ] **M7.6** Link each pseudocode expression to all contributing instructions, including transformations that combine multiple instructions. Renaming must update displays without rewriting the evidence.
- [ ] **M7.7** Revisit application-entry recognition using call arguments, return-value use, matched symbols, and versioned CRT profiles. Cover console/GUI and narrow/wide variants separately; retain custom entry and no-candidate outcomes.
- [ ] **M7.8** Add reviewed block/function summaries derived from supported operations. Suggested semantic names remain proposals until accepted; avoid declaring a specific algorithm from a short arithmetic pattern.

**First complete target:** recover the existing `checksum_bytes` computation with its early return, initialization, byte loop, and returned value. Validate against known source and assembly. Next cover a small caller and an imported call with an explicit prototype.

**Acceptance:** source-known arithmetic, branches, loops, stack locals, calls, and checksum functions compiled with optimization off/on. Compare observable behavior across valid inputs, not reconstructed text against the original source. Validate CFG/provenance links independently from semantic tests.

**Exit gate:** a selected supported function has correct low-level output within documented assumptions, navigable justification, and an honest support boundary. Do not market this milestone as a complete C++ decompiler or whole-program equivalence proof.

### M8. Routine-use quality and distribution

**Goal:** make the explorer dependable outside tiny demonstrations. Address security and regressions throughout development, not only at the end.

- [ ] **M8.1** Add large-report benchmarks for analysis time, peak memory, report size, browser startup, and navigation latency. Record machine/toolchain and input characteristics.
- [ ] **M8.2** Replace repeated full scans with indexes where measurements justify it: RVA/interval lookup, per-function references, string search, and graph adjacency. Preserve determinism during optimization.
- [ ] **M8.3** Add report integrity/schema validation, atomic output writing, corruption handling, and explicit truncation summaries. Avoid leaving a partial report under a filename that appears successful.
- [ ] **M8.4** Provide an optional directory-based report with lazy loading while preserving single-file export. Offline behavior, hosting assumptions, and browser restrictions must be documented separately.
- [ ] **M8.5** Add packaged Windows/Linux/macOS CLI builds with dependency/license notices, checksums, reproducible build instructions, and smoke tests on the corresponding platform. Do not bundle analyzed third-party programs into releases by default.
- [ ] **M8.6** Extend CI with browser tests, fuzz/sanitizer jobs, backend parity, and tested input modes. Keep deployment permissions separate from analysis, and untrusted pull-request runs separate from privileged publishing.
- [ ] **M8.7** Verify that only approved report files are publishable, reject symlinks/path escapes, escape all input-derived HTML, and review URLs/redirects and resource limits. A parser container does not make arbitrary generated HTML trustworthy.
- [ ] **M8.8** Add versioned report hosting or a run catalog with explicit retention, storage limits, publication/removal policy, and protection against demo runs silently replacing important custom reports.

**Exit gate:** a clean checkout builds and passes documented checks on supported platforms; a large partial report stays navigable; publishing has an auditable manifest and no undocumented input/runtime disclosure.

## 6. First implementation queue

Keep changes small enough to review independently. The first seven items now have implementation links; suggested commit titles for the remaining items describe future work.

| Order | Work item | Status / implementation or suggested commit | Completion evidence |
| --- | --- | --- | --- |
| 1 | Minimal M0 evidence/range model and baseline fixtures | Done: [`9299868`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/9299868a6ccecc181ffd1dddf0a8f431faeb4fd7) | [Contracts and compatibility tests](docs/m0-foundation.md); not all M0 |
| 2 | M1A exception records without aggressive discovery | Done: [`b47cf34`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/b47cf34f5ae23b3472d20d240c52686b48ea03e3) | [Bounded-parser contract and tests](docs/m1-exception-directory.md) |
| 3 | Integrate metadata seeds and ownership diagnostics | Done for supported v1: [`7e85a68`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/7e85a68a872d0a2a8334a1f6f43aa3090fae91bb) | [Unwind/discovery scope and tests](docs/m1-unwind-discovery.md); fragment associations remain explicit |
| 4 | TLS roots for x86 and x64 | Done: [`d3f86a9`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/d3f86a9cfec5062c01dc4158cf447f0d42e91c01) | [TLS contract and tests](docs/m1-tls-discovery.md); [hosted regression](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/38996995301) |
| 5 | M2 whole-function assembly, before graph polish | Done: [`ea32ba2`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/ea32ba20cfe80fe5c9d75c1c457ffa6423216ed0) | [Function-view contract](docs/m2-function-view.md), [model tests](tests/test_function_model.js), and [browser checks](tests/test_function_browser.py); graph work is tracked separately in item 7 |
| 6 | M3 searchable strings with direct references | Done: [`e316859`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/e316859c5cc92c263ee9fde250b8d3a3629b0e23) | [String contract](docs/m3-static-strings.md), [reference model](tests/test_string_model.js), and [browser checks](tests/test_string_browser.py); bounded previews and candidate status remain explicit |
| 7 | M2 graph view and bounded graph analysis | Done: [`247290e`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/247290e74fb1adf8957750adeb2b1595177ae8f2) + [`b8529ea`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/b8529eab42cbcf36087440cff38ded2318f93261) | [CFG contract](docs/m2-cfg.md), [graph-model tests](tests/test_cfg_model.js), [browser checks](tests/test_cfg_browser.py), [hosted regression](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/39009132203) |
| 8 | M4 common operand/capability model | Next: `refactor: expose structured decoder operands` | Backend and register-width tests |

Items 5 and 6 can proceed independently once the shared identities/reference contract is stable. Broader `main` recovery is deliberately not a prerequisite for discovering or browsing functions.

## 7. Validation and measurement

### 7.1 Corpus tiers

**Tier A: synthetic byte fixtures.** Small deterministic headers/instruction sequences for parser boundaries, branch splitting, relocation tables, invalid metadata, and exact instruction-form tests. These need not be runnable Windows applications.

**Tier B: source-known compiled fixtures.** Separate x86/x64 builds, no-CRT and ordinary CRT entry paths, EXEs/DLLs, function pointers, switches, shared tails, Unicode data, and supported exception cases. Include MSVC on a Windows runner, clang-cl, and a MinGW configuration when available. Record exact toolchain versions and use debug/unoptimized plus optimized configurations. Account for inlining, dead stripping, and identical-code folding in ground truth.

**Tier C: permissioned real binaries.** Choose small redistributable open-source programs with pinned source/build identity and checksums. Keep binaries out of `main`. Do not require unrelated proprietary inputs or the analyst's installed system DLLs for baseline CI.

**Tier D: robustness inputs.** Mutations, truncated tables, huge counts, repeated/cyclic relationships, ambiguous instruction streams, invalid encodings, unsafe strings, and excessive graph candidates. Run with strict time/memory/output budgets.

### 7.2 What to measure

| Metric | Definition and limitation |
| --- | --- |
| Function discovery precision | Correct predicted entries / predicted entries for fixtures with suitable ground truth; record aliases and fragments separately |
| Function discovery recall | Recovered expected machine-level entries / expected entries that survive the selected build; do not use source-function count blindly |
| CFG accuracy | Expected and spurious edges by supported fixture case, including unknown residual edges |
| Reference accuracy | Correct code/data links, width/kind, and false-positive candidates |
| Semantic coverage | Supported instruction forms and effects; separate from instruction-decoding coverage |
| Semantic agreement | Independent-oracle comparisons over the supported domain, with undefined/fault cases explicitly classified |
| Usability | Exact history return, deep-link stability, keyboard access, large-function navigation |
| Resource use | Time, peak RSS, bytes emitted, embedded-byte budget, graph/index size, browser timing |

Code-byte coverage on an unknown executable is not function-discovery recall. An unresolved target is not automatically an error; a fabricated resolved target is worse.

Establish performance baselines before setting fixed thresholds. Thereafter require review of material regressions against repeated measurements, not a single noisy CI timing. Hard correctness gates for deterministic supported fixtures are zero unexplained mismatches, no dangling links, and no silent unsupported semantics.

### 7.3 Per-feature test package

Every analysis feature should add a positive fixture, a near-miss negative fixture, a malformed/budget fixture where applicable, and an HTML regression if the feature is visible. Keep expected facts separate from screenshots. A screenshot can validate layout, not prove machine semantics.

Generated test expectations must not be produced solely by the same analyzer being tested. Use hand-derived cases, compiler maps/symbols withheld from discovery, independent decoding, and execution/evaluation of source-known snippets in an isolated harness as appropriate. Never execute arbitrary uploaded binaries in ordinary analysis CI.

## 8. Further targets

These are intentionally beyond the first implementation queue. Priority is relative to this project, not a promise to implement every item. Each target needs its own design and test gate before activation.

| ID | Target | Dependency / first bounded deliverable | Main risk or boundary |
| --- | --- | --- | --- |
| F01 | Exact-match symbols and demangling | M0/M1; ingest local matching PDB/map symbols with names, ranges, and provenance | Verify the format-specific identity; for RSDS use GUID plus age. Missing/legacy identities need explicit handling, not guessed matches |
| F02 | More complete startup profiles | M4/M7; tested MSVC and MinGW profiles for main/wmain/WinMain variants | Profile/version drift; custom startup and optimized paths may stay unknown |
| F03 | C++ object and class-layout recovery | M3/M5/M7; identify vtable candidates, field offsets, and constructor/destructor accesses | Multiple inheritance, adjustor thunks, stripped RTTI, and reused storage; preserve hypotheses |
| F04 | Structured-data overlays | M3; analyst-defined structs, arrays, enums, and pointer fields | Never overwrite raw facts or infer object lifetime from a byte layout alone |
| F05 | Exception-aware control flow | M1/M6; a selected unwind/handler format and separate exceptional edges | Unwind metadata does not by itself describe all language-level exception flow |
| F06 | Binary/version comparison | M2/M3/M7; compare functions, imports, strings, CFGs, and analyst labels between two builds | Address/layout changes, inlining, and code folding make matching uncertain; preserve match evidence |
| F07 | Normalized function fingerprints | M4/M6; index normalized operations and constants for reviewed matches | Similar code is not proof of identity; manage false matches and signature-dataset licensing |
| F08 | Dynamic trace and dump import | M0/M5; import an externally collected module map, trace, or minidump and overlay observed targets | Explicit capture identity, ASLR normalization, missing pages, timestamps, and sensitive runtime data |
| F09 | Bounded emulation and symbolic exploration | M6; explore a selected function with declared inputs and modeled APIs | Path explosion, incomplete environment, and unsupported instructions; no automatic native execution |
| F10 | Expanded ISA semantics | M6/M7; x86 calling conventions, then selected SSE/AVX and floating-point forms | Flag/rounding/NaN/exception behavior and vector lane widths require dedicated semantic tests |
| F11 | PE resources and richer binary metadata | M0/M3; navigable version strings, manifests, resource directories, and overlay locations | Resource trees are untrusted; certificate presence is not signature/trust verification |
| F12 | Incremental analysis and caches | M0/M8; content-addressed per-pass caching and invalidation after new labels/seeds | Cache keys must include analyzer/backend/rules/assumptions; stale facts must not survive invalidation |
| F13 | Analyst workspace interchange | M0/M2/M8; import/export names, notes, types, and evidence with reviewed conflict resolution | Different binary identities and schemas; no silent cross-build annotation remapping |
| F14 | Batch reports and run catalog | M5/M8; analyze a manifest of public-safe inputs and keep versioned report links | Storage/retention, privacy, licensing, per-file isolation, and deployment replacement behavior |
| F15 | Extensible analysis rules | M0/M4/M8; versioned trusted pass API and declarative recognition rules | Arbitrary plugins expand the trust boundary; do not execute code embedded in analyzed files or reports |
| F16 | Optional explanation/name suggestions | M6/M7; propose summaries from evidence-linked IR and analyst context | Suggestions can be wrong; explicit opt-in for external services, no secret upload, no automatic authoritative renames |
| F17 | Additional formats/architectures | Stable parser/IR contracts; a separately scoped ARM64 PE or managed-IL front end | A new front end is not obtained by changing the x86 decoder mode; preserve platform-specific semantics |
| F18 | Read-only patch planning and comparison | M6/F06; describe proposed byte changes and compare effects on controlled fixtures | Keep separate from automatic binary writing, code-signing changes, and arbitrary runtime injection |

F01 and F11 can be pulled forward as narrow enhancements if they unlock a real analysis task. F03, F06, and F08 are especially useful growth directions after the core explorer is reliable. None should block the first discovery/data-navigation milestones.

## 9. Delivery and repository policy

`main` contains authored source, tests, fixture generators, build/workflow configuration, and documentation. Generated EXEs/DLLs, downloaded inputs, reports, compiler intermediates, and dependencies remain ignored. `demo_exe` is only for deliberately curated showcase artifacts; routine Actions output remains in artifacts/Pages rather than commits.

Use focused, reviewable commits. For the current implementation work, commit directly to `main` as requested; a pull request is not required. A documentation request does not authorize implementing all roadmap items, creating every issue, changing repository settings, or rewriting history. Prefer additive commits; history rewriting needs a separate explicit request.

For each milestone, record the implementation commits, relevant CI runs, supported cases, known limitations, and a source-known HTML demonstration. Keep an old capability clearly marked partial until its acceptance criteria are met.

For public publishing, review exactly what the report embeds. Original bytes, strings, symbol names, file paths, and runtime observations can disclose sensitive material even when the EXE itself is not hosted. Default demos should be reproducible from repository source; custom inputs need explicit publication intent and retention/removal guidance.

## 10. Risks and decisions

| Risk | Planned response |
| --- | --- |
| False function discovery expands into data | Prefer validated metadata/direct evidence, bound traversal, retain competing candidates, use negative fixtures |
| Main recognition becomes a collection of fragile byte signatures | Versioned profiles plus arguments/call-chain evidence; permit no answer and keep analyst overrides |
| Decoder output changes break analysis | Structured operand contract and capabilities, pin tested versions, compare supported facts across adapters |
| Two analysis engines disagree | Reuse a common transfer/bit-vector core for value analysis and lifting |
| Incomplete CFG makes pseudocode misleading | Preserve unknown edges, show function-level completeness, avoid unjustified structuring |
| Cross-module resolution chooses the wrong DLL | Explicit supplied modules, hashes, architecture checks, collision handling, and runtime-vs-static distinction |
| Large HTML becomes unusable | Index facts, cap graph work, virtualize views, offer optional split reports |
| Schema/identity changes lose annotations | Versioned migration, legacy IDs, round-trip fixtures, explicit import conflict handling |
| Public Actions processes hostile inputs | Separate permissions, bounded isolated parsing, publication validation, no native execution of uploads |
| Feature count outruns tests | Require supported-domain evidence and a negative test before expanding coverage |

Before the relevant implementation, record short architecture decisions for: module identity migration; structured decoder strategy; function/range ownership; schema evolution; the semantic/unknown-value model; and single-file versus multi-file workspace hosting. Prefer decisions justified by fixtures and measured constraints over speculative abstractions.

## 11. Definition of done and plan maintenance

A task is complete only when its implementation, relevant tests, limitations, and report representation agree. A checked box should link to its implementing commit or pull request and acceptance evidence. The following reusable review checklist is applied per change; it is not an additional set of completed project features.

- [ ] Implementation is bounded, deterministic where expected, and handles malformed or unsupported cases explicitly.
- [ ] Tests cover positive behavior, an important negative case, and affected legacy behavior.
- [ ] UI claims preserve provenance and do not turn candidates into facts.
- [ ] Links, names, annotations, and schema compatibility have been checked.
- [ ] Supported architectures/backends and missing coverage are documented.
- [ ] Generated files follow the repository policy and publication has been reviewed.
- [ ] Resource use is measured for features that affect scaling.
- [ ] No new success claim relies only on a previous milestone's test count.

When priorities change, update this document and explain why. Keep completed evidence, split overly broad tasks, and move experiments to section 8 until there is a bounded implementation proposal. Owners, issue numbers, and dates should be added when actually assigned, not invented in advance.

**Recommended next work:** the common structured operand/capability model (queue item 8 / M4.1-M4.3), so later value analysis and IR do not depend on decoder display strings. M2 whole-function/CFG presentation and M3.1-M3.3 string discovery are implemented within their linked bounded contracts. M3.4-M3.8, M1.7-M1.9, and remaining foundation tasks stay pending or partial. Dynamic analysis remains deferred under F08.

## 12. References

Repository behavior at the planning baseline is grounded in the [pinned revision](https://github.com/ASR-Tanyi/windows-exe-analyzer/tree/f789c59b590588426a64aa8c13c378865ab34996). Later completion evidence is linked beside each checked item. Technical references below guide implementation; they are not evidence that unimplemented roadmap features are already complete.

- **R1:** Microsoft, [PE/COFF format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format): address spaces, directories, imports/exports, TLS, and relocations.
- **R2:** Microsoft, [x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64): runtime-function ranges and unwind metadata.
- **R3:** Microsoft, [linker entry-point symbols](https://learn.microsoft.com/en-us/cpp/build/reference/entry-entry-point-symbol): runtime/application entry distinctions.
- **R4:** Capstone, [C API and detail mode](https://www.capstone-engine.org/lang_c.html) and [operand access information](https://www.capstone-engine.org/op_access.html). Check the pinned version's headers/tests when older documentation differs.
- **R5:** Microsoft, [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention): ABI inputs, preserved state, and stack requirements.
- **R6:** Ghidra, [p-code reference](https://ghidra.re/ghidra_docs/languages/html/pcoderef.html): instruction-to-operation separation and source-address provenance.
- **R7:** LLVM, [language reference](https://llvm.org/docs/LangRef.html): IR semantics and undefined/poison behavior relevant to any future LLVM lowering.

For each newly supported instruction form or metadata version, add a precise primary-reference citation to its implementation notes/tests. This plan intentionally does not substitute a short mnemonic list for an instruction specification.
