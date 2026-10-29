# Bounded analyst type annotations and comparisons

Type parser (P12): [070bc88](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/070bc88b9c805a3db30a6a1bb91d342dced6f867).
Parsed-form comparisons (P13): [ff81e96](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/ff81e96d49739b6f6ae6ec48695ed7a826df4cbb).
Readable phone columns: [1e62340](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/1e62340ded29f256884da8236aa14cd7abf71e9e).

P12 adds a shared syntax parser for supplied return and parameter type labels.
Open **C-like → Analysis details → Function contract and candidates → Analyst
declarations**. Each original label remains visible beside its parsed form or
an explicit reason it remains unparsed. The same results are exported in JSON
and printed by `scripts/pseudocode.js --abi`.

P14 adds [explicit source-labeled alias definitions](declaration-aliases.md) in
version 3 function contracts. Undefined names still remain unresolved; no header
lookup or type discovery is performed.

These are annotations, not types recovered from instructions. Parsing does not
choose an authoritative declaration, establish prototype compatibility, infer
sizes/alignment, map ABI arguments, modify call summaries or change memory
effects. In particular, `const` and `volatile` never authorize deleting a load
or store, and a pointer annotation supplies no memory-alias or dereference assumptions.

## Reviewed grammar

Grammar ID: `c11-scalar-pointer-v1`. The reference is the public
[WG14 N1570 draft](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf),
sections 6.7.2 (specifier combinations), 6.7.3 (qualifiers), 6.7.6.1 (pointers)
and 6.7.7 (type names). This implementation deliberately accepts a subset.

Accepted bases are `void`, `_Bool`, the plain/signed/unsigned character forms,
the signed/unsigned integer families through `long long`, and `float`, `double`
and `long double`. Supported specifiers may appear in any order; omitted `int`
is normalized only in the explicitly supported signed/unsigned/short/long
forms. Plain `char` stays distinct from `signed char` and `unsigned char`.
`long double` stays distinct from `double`, regardless of a compiler's layout.

The base may have `const` and `volatile` qualifiers, followed by zero to four
plain pointer stars. Each star has its own optional `const`/`volatile` list.
Repeated identical qualifiers at one level are deduplicated; repeated or
incompatible scalar specifiers are rejected unless part of a supported form.
No default type is invented for a qualifier-only label.

| Supplied label | Parsed display |
| --- | --- |
| `unsigned` | `unsigned int` |
| `long int unsigned long` | `unsigned long long int` |
| `char const *` | `const char *` |
| `int * const` | `int * const` |
| `volatile long * const *` | `volatile long int * const *` |
| `size_t` or `HANDLE *` | Unparsed: names are unresolved |
| `int (*)(void)` or `int[4]` | Unparsed: complex declarators are outside this grammar |
| `null` | No type annotation supplied |

The tokenizer consumes the entire label. Only ASCII spaces are ignored; case
matters. Unsupported suffixes prevent a successful parse; no partial tree is emitted.
Named types and typedefs, including familiar header aliases such as `uint32_t`,
remain unresolved without their definitions. Arrays, function pointers,
references, aggregate/enum tags, declarator names, storage classes, comments,
macros, attributes, `restrict`, `_Atomic`, complex types, C++/compiler extensions
and newer dialect keywords remain unparsed. This includes `bool`: no header
or language-mode context is assumed. Unparsed does not mean invalid C.

## Data and compatibility

Function-contract versions 1 and 2 and preview version 8 are unchanged.
Version 2 imports/exports retain every original label, including whitespace,
unsupported syntax and unresolved names. Type syntax failure does not reject
an otherwise valid contract. Existing contract shape, text and file limits
still apply transactionally; invalid contracts expose no partial type results.

P12 introduced `functionABI.version: 5`; P13 advanced it to 6 and P14 to 7.
The base syntax fields remain unchanged:

- `declarationTypeGrammar`: `c11-scalar-pointer-v1`.
- `declarationTypes`: one record per declaration, with `declaration` (its ID),
  `returnType` (a parse result), and `parameters` (parse results in original order).

Every parse result has `status`, `canonical`, `type` and `reason`.
`parsed` results have a canonical string, a syntax tree and a null reason.
`unknown` (`null` labels) and `unsupported` results have null canonical/tree
fields and an explanatory reason; no partial tree is returned.

The syntax tree represents a base as
`{kind: "builtin", name: "int", qualifiers: ["const"]}`. Each pointer wraps
its pointee as `{kind: "pointer", qualifiers: [...], to: <type>}`. Qualifiers
are sorted and deduplicated at their own level. Thus the outer node in
`const int * volatile * const` is a const pointer to a volatile pointer to
const int. Trees contain no widths, preferred addresses or ABI locations.

Parsed annotations remain available when the function convention is unknown
and when machine-evidence budgets are exhausted. The existing recovery and
backend availability rules still apply. `--abi` prints annotations even with
an unknown convention, then returns 2 for unavailable machine ABI evidence.

Textual declaration disagreements remain unchanged: `unsigned` and `unsigned
int` can have equal parsed forms while their original spelling difference
remains recorded. Existing source-linked declaration reviews also retain their
original rules. P13 compares parsed forms separately, as described below.
No full signature or parameter-list validity is asserted, including for a
`void` annotation inside a supplied parameter record.

## P13: comparisons of parsed annotation forms

Open **Analyst declarations → Parsed declaration comparisons** to inspect every
unordered pair of declarations. Each pair retains both IDs and shows separate
rows for the return annotation, supplied parameter-record count, each parameter
position and the variadic/hidden-parameter flags. Source labels and parameter
names do not participate. The inspector, CLI and JSON share the same results.
Expanded comparison panels survive contract edits, import and convention changes
within the report session; reload clears session annotations as before.

The policy ID is `parsed-annotation-forms-v1`. This is a structural comparison of
supported annotations, not a C prototype-compatibility or machine-compatibility
decision. There is deliberately no overall pair verdict. Per-field results are:

| Inputs | Result |
| --- | --- |
| `unsigned` / `unsigned int` | Same parsed form; original spelling disagreement remains |
| `const int *` / `int *` | Different parsed form: pointee qualifiers at depth 1 |
| `int * const` / `int *` | Different parsed form: outer qualifiers at depth 0 |
| `char` / `signed char` | Different parsed base, regardless of machine representation |
| `int *` / `int **` | Different shape at depth 1 |
| `size_t` / `size_t` | Unknown: identical unresolved names do not establish agreement |
| A missing parameter record or null/unsupported type on either side | Unknown, with both original states retained |
| Explicit `yes` / `no` flag values | Different supplied flag |
| `unknown` on either side of a flag | Unknown, even when both flags say `unknown` |

Parsed type comparisons retain qualifiers at every written level; no parameter
adjustments or top-level qualifier erasure occur. Pointer nesting, built-in names
and qualifiers are compared independently. A shape difference stops further
descent at that position. If either whole annotation is unparsed, no matching
prefix or partial difference is reported. Supplied parameter counts compare
record lengths only; neither a count match nor a mismatch infers machine arity.
Even all matching rows do not validate a declaration or establish a full signature.

Version 6 adds `declarationComparisonPolicy` and `declarationComparisons`. Each
comparison contains `declarations: [leftId, rightId]`, field counts
`{same, different, unknown}`, and ordered `fields`. A field contains `field`,
`kind` (`type`, `count` or `flag`), `status`, `left`, `right` and `reason`.
Type sides retain `{label, status, canonical, reason}`; a missing parameter
record has side status `missing`, distinct from an unspecified (`unknown`) label.
Type fields additionally contain `differences`, whose entries have `kind`
(`base`, `shape` or `qualifiers`), `depth`, `left` and `right`. Depth zero is
the outer type; each successive pointer increases it by one. Side parse status
`unsupported` produces comparison status `unknown`.

At most eight declarations produce 28 pairs. At most 32 parameters produce
36 fields per pair, for a hard bound of 1,008 comparison rows. Type comparison
is iterative and stops within the parser's four-pointer bound. These separate
annotation bounds do not consume or relax machine-evidence budgets. Comparisons
remain available with an unknown convention or exhausted machine-evidence budget;
invalid contracts expose no partial comparisons. The original contract stays
unchanged, and comparisons are recomputed from its labels on import. No comparison
changes textual conflicts, source-linked reviews, ABI candidates, register/stack
facts, calls, memory effects or rendered code.

Local validation on 2026-10-29 passes 165 focused comparison checks, 204 syntax
checks, 384 ABI graph checks and 136 Capstone decoder/CLI checks. All 29 local
CTest targets pass on each backend. Browser checks pass: 73 Capstone / 3 LLVM
ABI checks and 90 Capstone / 13 LLVM C-like checks. They cover mixed results,
escaping, native keyboard expansion, retained panel state, exact original-label
export, browser/CLI JSON parity, clearing and expanded phone layout. Comparison
columns retain a readable minimum width and scroll within a keyboard-focusable
region on narrow screens; a visual check covers both sides of that region.

The independent ABI oracle still passes 112 executions with 226 input reads,
112 returns, 308 caller values, 84 call-result reads, 60 incoming stack reads
and 32 matching stores. Local C fixtures are the existing Zig 0.13.0 corpus,
reanalyzed with this report bundle. Hosted CI additionally generates its Clang
fixtures and runs the complete browser and recovery matrix.

## Limits and validation

Each label has hard ceilings of 128 characters, 32 tokens and four pointer
levels. All limits are fixed; there is no option to raise them. The existing
contract cap of eight declarations with at most 32 parameters each bounds
parsing to 264 labels. No recursion, identifier resolution, file/network lookup
or evaluation of supplied text occurs. A per-label limit leaves that label
unparsed while preserving the other validated annotations.

Run the focused checks with:

```sh
node tests/test_declaration_types.js
node tests/test_declaration_comparisons.js
node tests/test_function_abi.js
python3 tests/test_function_abi.py build/windows-exe-analyzer
python3 tests/test_function_abi_browser.py build/windows-exe-analyzer --fixtures build/recovery-fixtures
```

The syntax checks cover supported spellings, qualifier levels, canonical
round trips, unresolved names, incompatible combinations, complete-token
consumption, hostile text, all bounds and fresh independent result trees.
Model/decoder checks verify unchanged contracts, machine effects, code
presentations, value/SSA/storage facts and ABI observations. Browser checks
cover parsed/unparsed/unknown displays, escaping, export/CLI parity, persistence
with an unknown convention and phone layout.

Local validation on 2026-10-28 passes 204 focused syntax checks, 357 ABI graph
checks, 132 Capstone decoder/CLI checks and all 28 CTest targets per backend.
The 58 Capstone / 3 LLVM ABI browser checks and 112 independent ABI executions also
pass, including 60 incoming stack reads and 32 matching caller stores. Machine
evidence counts remain identical to P11. The local recovery binaries are the
existing Zig 0.13.0 corpus, reanalyzed with the new report bundle; hosted CI
also generates its Clang fixtures and runs the full browser/semantic matrix.
Existing C-like browser checks pass on both backends: 90 Capstone and 13 LLVM.

## Hosted validation (2026-10-28)

The [hosted matrix](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/40652011489)
passed all 30 CTest targets per backend and every browser suite. Capstone
passed 58 function-ABI and 90 C-like browser checks; LLVM passed its 3 ABI and
13 C-like fallback checks. The unsupported LLVM semantic suites remain
explicitly skipped. The new syntax test is registered for both backends.

Capstone also passed 1,260 recovery cases across all four presentations,
36 call executions across 108 boundaries and 112 ABI executions. The ABI
counts remain 226 input reads, 112 returns, 308 caller values, 84 call-result
reads, 60 incoming stack reads and 32 matching stores. Its storage corpus
checked 133 reloads, including 41 saved entry-register values.

The [Pages build and deployment](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/40652011557)
passed. The live manifest identifies `070bc88`; all eight downloaded reports
embed the exact committed type parser and ABI/pseudocode models/views. The
58-check ABI suite also passed with the downloaded published x64 O1 report
(its authored stack/declaration case is generated separately).

Ten additional interactions applied annotations directly in that published
report and verified normalized qualifier levels, explicit unresolved/unknown
results, unchanged code, exact original-label export, versioned syntax trees,
CLI JSON parity, retention with an unknown convention, phone layout and no
JavaScript errors. Original declarations remain the exported source of truth;
derived syntax is recomputed on import.

## P13 hosted validation (2026-10-29)

The final [hosted matrix](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/40809989414)
passed all 31 CTest targets per backend and every browser suite. Capstone
passed 73 function-ABI and 90 C-like browser checks; LLVM passed its 3 ABI and
13 C-like fallback checks. Both backends run the focused syntax and comparison
tests. LLVM's unsupported semantic suites remain explicitly skipped.

Capstone passed 1,260 recovery cases across all four presentations, 36 call
executions across 108 boundaries and 112 ABI executions. ABI evidence counts
remain 226 input reads, 112 returns, 308 caller values, 84 call-result reads,
60 incoming stack reads and 32 matched stores. The storage corpus checked
133 reloads, including 41 saved entry-register values.

The [Pages build and deployment](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/40809988854)
passed. The live manifest identifies `1e62340`; all eight downloaded reports
embed the exact committed parser/comparison, ABI and pseudocode models/views.
Twelve direct interactions in the published x64 O1 report verified matching
forms alongside retained textual conflicts, precise qualifier differences,
unknown typedefs/flags, unchanged code, preserved expanded panels, original-label
export, versioned comparison records, exact CLI JSON parity, convention independence,
readable phone columns, clearing and no JavaScript errors.

Visual inspection caught cramped columns that the original overflow-only check
missed. The follow-up fixes their minimum width inside a keyboard-focusable scroll
region, and the browser regression now checks a readable field-column width.
Both sides of the narrow-screen table were inspected after the fix.
