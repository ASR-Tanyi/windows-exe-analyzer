# Bounded analyst type annotations

P12 adds a shared syntax parser for supplied return and parameter type labels.
Open **C-like → Analysis details → Function contract and candidates → Analyst
declarations**. Each original label remains visible beside its parsed form or
an explicit reason it remains unparsed. The same results are exported in JSON
and printed by `scripts/pseudocode.js --abi`.

These are annotations, not types recovered from instructions. Parsing does not
choose an authoritative declaration, establish prototype compatibility, infer
sizes/alignment, map ABI arguments, modify call summaries or change memory
effects. In particular, `const` and `volatile` never authorize deleting a load
or store, and a pointer annotation supplies no alias or dereference assumptions.

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

`functionABI.version` advances to 5 with additive fields:

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
original rules. Semantic declaration reconciliation is a separate next slice.
No full signature or parameter-list validity is asserted, including for a
`void` annotation inside a supplied parameter record.

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
