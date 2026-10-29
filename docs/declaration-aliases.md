# Explicit analyst type aliases

P14 adds source-labeled alias definitions to the bounded scalar/pointer annotation
grammar. Open **C-like → Analysis details → Function contract and candidates →
Analyst declarations → Type alias definitions**. The editor applies one explicit
alias context to every declaration in that function contract. Nothing is imported
from headers, symbols, other functions or familiar names such as `size_t`.

Definitions, original declaration labels and textual disagreements remain retained.
Resolved forms and comparisons show the names of the supplied aliases they use.
An alias is an analyst assumption, not a recovered or independently verified type.
No type resolution changes register/stack candidates, machine effects, code,
call summaries, source-linked declaration reviews or memory alias analysis.

## Contract and scope

Function-contract version 3 requires exactly `version`, `moduleId`, `functionId`,
`profile`, `declarations` and `typeAliases`. Identity and profile validation is
unchanged. Version 1 and 2 documents remain accepted and exported in their original
schema until an alias edit selects version 3. For example, the `typeAliases` field
can contain:

```json
[
  {"name": "Count", "source": "header.h", "type": "unsigned"},
  {"name": "P", "source": "header.h", "type": "int *"},
  {"name": "ConstP", "source": "analyst notes", "type": "const P"}
]
```

Each definition requires exactly `name`, `source` and `type`. Names are unique,
case-sensitive ASCII C identifiers of 1–64 characters; C11 keywords cannot be
redefined. Sources allow 1–256 characters and definition labels 1–128 characters.
Empty/control-character labels, duplicate names, unknown fields and malformed
records reject the complete imported contract. A bad editor draft leaves the
applied definitions intact. Source labels are preserved text, not trusted paths
or instructions to fetch a file.

All definitions share one explicitly supplied namespace. Forward references are
allowed; list order does not select an authoritative definition. Conflicting
definitions for the same name must be resolved by the analyst before importing
them. There is no per-header scope, automatic merging or inferred typedef context.

Clearing aliases preserves declarations and the function convention, and turns
now-undefined labels back into unparsed results. Clearing declarations preserves
aliases. Selecting a convention preserves both; clearing the whole contract or
reloading the report clears both. Version 3 export retains original spellings,
definition order and source labels; derived results are recomputed on import.

## Resolution rules

Policy ID: `explicit-scalar-pointer-aliases-v1`. The underlying tree grammar
remains `c11-scalar-pointer-v1`; see [the base grammar](declaration-types.md).
A supported type name can use one explicit alias in place of its scalar base,
with `const`/`volatile` qualifiers and zero to four pointer stars. An alias cannot
be combined with scalar specifiers or a second alias: `unsigned Count` and `P Count`
remain unparsed. Arrays, function pointers, aggregate tags and extensions remain
outside the reviewed grammar even when they appear inside an alias definition.

Resolution operates on type nodes, not textual substitution. Qualifiers on an
alias qualify the aliased type at its outer level, before any additional pointer
stars are applied. This follows the pointer-typedef example in
[WG14 N1570 §6.7.6.1 paragraph 4](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf),
with the selected qualifier and type-definition rules in §§6.7.3 and 6.7.8.

| Annotation using the definitions above | Resolved form |
| --- | --- |
| `Count` | `unsigned int` |
| `const Count *` | `const unsigned int *` |
| `P` | `int *` |
| `const P` | `int * const` |
| `volatile ConstP *` | `int * const volatile *` |
| `size_t` without a supplied definition | Unparsed; no definition is guessed |

Missing definitions, direct/indirect cycles, unsupported definition syntax and
expansion limits produce `unsupported` results with null tree/canonical fields
and an explanatory reason. The encountered alias names remain visible, but no
partial type is emitted. Such definitions are retained as annotations and do not
invalidate unrelated supported labels. A null declaration label remains `unknown`.
Unparsed types compare as unknown, including identical cyclic or undefined names.
Expanded types use P13's structural comparison policy; matching forms still do
not establish full prototype compatibility or machine argument locations.

## Bounds and data

There are at most 32 definitions and 8 KiB of normalized alias JSON. Every input
label retains the existing 128-character and 32-token ceilings. Each resolution
visits at most eight alias definitions, consumes at most 128 total tokens including
the original label, and produces at most four pointer levels including levels
inside aliases. Traversal is iterative. There is no recursion, evaluation or
filesystem/network lookup. Limits are fixed and cannot be raised by a contract.

At most 264 declaration labels and 32 definition results are independently
resolved. Pairwise comparisons retain their 28-pair / 1,008-field bound. Each
dependency path has at most eight names. Normalized version 3 contracts, including
the export newline, are also checked against the existing 64 KiB file limit.
These annotation limits do not consume or loosen machine-evidence budgets.

`functionABI.version` advances to 7. `declarationAliasPolicy` identifies the
resolution policy; `declarationAliases` contains `{name, result}` records in
definition order. Version 3 parse results add an `aliases` array of encountered
names, in dependency order. Definition records themselves remain in
`contract.typeAliases`. Comparison sides copy their dependency paths and retain
the original declaration labels. Trees and paths are independent values.

Aliases and their results remain available with an unknown function convention or
exhausted machine-evidence budget. Existing backend/recovery availability rules
still apply. CLI `--abi` prints supplied definitions, resolution results and
comparison dependencies before reporting unavailable machine evidence; JSON uses
the exact browser model. Native report schema 2 and preview version 8 are unchanged.

## Validation

Local validation on 2026-10-29 passes 100 focused alias checks, 204 syntax checks,
165 comparison checks, 431 ABI graph checks and 150 Capstone decoder/CLI checks.
All 30 local CTest targets pass per backend. Browser suites pass 93 Capstone / 3
LLVM ABI checks and 90 Capstone / 13 LLVM C-like checks. The alias UI is also
visually inspected at a 390-pixel viewport.

Checks cover authored pointer-qualifier examples, forward references, missing
names, cycles, the actual depth/token/pointer/definition/byte bounds, keyword
collisions, hostile labels, independent contexts/results, retained disagreements,
transactional rejection, all three contract versions, editor/clear/import behavior,
unknown convention, budget exhaustion, original-label export and CLI JSON parity.
The independent ABI oracle passes 112 executions with unchanged evidence counts:
226 input reads, 112 returns, 308 caller values, 84 call-result reads, 60 incoming
stack reads and 32 matching stores. Local C fixtures are the existing Zig 0.13.0
corpus; hosted CI additionally rebuilds the Clang fixtures and full test matrix.
