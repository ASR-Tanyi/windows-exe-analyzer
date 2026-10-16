# M1: supported unwind validation and metadata-derived discovery

This continues the bounds-only [exception-directory parser](m1-exception-directory.md)
and implements M1.3/M1.4 of [plan.md](../plan.md) for the explicit version-1 policy
below. It does not implement TLS discovery, runtime stack unwinding, language-level
exception flow, automatic main recognition, or dynamic analysis.

## Structural support contract

`src/unwind_info.hpp` reads each distinct unwind header once and keeps a separate
assessment for every runtime-function record. A cached header is not a cached
function-range assertion: prolog extent and chain context are checked separately
for each reference.

Supported primary records use UNWIND_INFO version 1 and the documented handler or
chain flags. The parser retains prolog length, slot count, frame-register fields,
operation slots and operands, aligned trailer addresses, handler candidates, and
chained runtime-function tuples. Multi-slot operands are not interpreted as new
opcodes. The odd-slot alignment padding must be readable, but its value is not
assumed to be zero.

The supported operation forms are PUSH_NONVOL, ALLOC_LARGE (both forms),
ALLOC_SMALL, SET_FPREG, SAVE_NONVOL/FAR, SAVE_XMM128/FAR, and PUSH_MACHFRAME.
Checks cover slot counts, reserved/operation-info values, code-offset ordering,
frame fields, supported saved registers, scaled offsets, and file-backed extents.
Noncanonical but structurally decodable allocation sizes are not automatically
rejected solely for failing the shortest-encoding recommendation.

Versions 0, 2, 3, and other unknown versions remain opaque: header values are
retained with `unsupported` status, without reading their arrays or trailers as
version 1. Unknown flags/opcodes and saved-register forms outside the selected
nonvolatile register set also block eligibility. `supported_v1` is a structural
result, **not proof that the prolog's actual instructions implement those effects**.

### Chains and handlers

The first chained subset supports zero-code fragments and MOV-based integer
register-save records. Other secondary operation forms are retained but labeled
unsupported, not unconditionally declared invalid under the Windows loader.
Chains require readable, aligned headers and executable file-backed range contexts;
frame register/offset must match along the chain. Cycles and excessive depth are
reported. The final primary range address is retained as an association.

An encoded handler is a candidate. Its pointer storage must be readable and its
nonzero destination must be executable/file-backed under the existing PE mapping.
The language-specific data start may be displayed, but no object size or handler
format is inferred. Handler addresses are **not automatically seeded as ordinary
functions** and no artificial call edges are added.

Independent ceilings are 65,536 unique unwind nodes, 1,048,576 code slots, and
32 nodes per chain. A shared header is charged once. Tests can lower these limits;
callers cannot raise the ceilings. Node/slot/depth exhaustion remains distinct
from invalid metadata and from the instruction budget. Diagnostic detail limits
do not discard occurrence counts.

## Discovery policy

Default analysis now uses eligible top-level runtime-function range starts as
additional candidates, after the existing PE-entry/export/direct-call traversal.
This ordering preserves already-decoded instruction boundaries when metadata
points into an existing instruction. A candidate rejected by decoding or the
instruction budget stays visible as `not_decoded`, not as a successful function.

A record is eligible only when the directory is complete, aligned, and ordered;
its range/address checks pass; its entire supported unwind chain validates; and
it has no disqualifying conflicts. Exact duplicate tuples may share one candidate
while retaining each table location as evidence. Overlap conflicts also block
copies of the conflicting canonical record. Invalid records do not silently
become seeds; unknown unwind versions never get guessed into version-1 layouts.

Linear decoding started in a metadata range stops at its end and rejects an
instruction crossing that end. Reachable branches/calls are still followed; the
analyzer does not linearly decode every byte covered by metadata. Existing direct
traversal remains independent, so decoded coverage may differ from metadata spans.
No bytes are filled into gaps just to make the ranges match.

Chained top-level entries are labeled **procedure-fragment candidates** with a
primary association. They are not asserted to be distinct source functions, and
this step does not merge source-level ownership across fragments. An embedded
primary range is not an extra root unless it is independently listed or discovered.
Grouping all such fragments into source-language procedures remains later work.

Display names and `--main-rva` assertions preserve their original evidence.
Additional facts use origin `exception_directory`, rule `pe.unwind_v1_seed`, and
the table record's source RVA. Header facts, direct calls, and analyst assertions
are not replaced by the new evidence.

For inspection or comparison without these new roots:

```sh
windows-exe-analyzer program.exe --no-unwind-seeds --html report.html
```

This option disables only metadata-derived discovery. It still reads the unwind
metadata and shows the structural results. It does not disable original entry,
export, direct-call, or analyst-supplied discovery.

## Report and HTML

Report schema 2 and analysis-model version 1 remain. The additive `unwindInfo`
version-1 extension contains budgets, cached nodes, per-record assessments,
primary associations, eligibility, and actual discovery outcomes. Functions gain
`metadataRecords`, a list of original table indices, separate from `decodedRanges`.

The existing bounds-only `exceptionDirectory.status` remains independent of the
unwind assessment. Its `unwindSemantics` field is now `structural_v1_only`, and
`discoverySeedsAdded` reflects the selected candidate roots instead of a constant
false value. Consumers must not equate structural validity with decoded semantics.

The Exception metadata view links to individual unwind nodes. **Unwind validation**
opens the new node view, including raw-byte links, operation slots, chained parents,
handler pointer/target bytes, and reasons for blocked eligibility. Function
inspectors have a **Metadata ranges** section alongside **Decoded coverage**.

Links retain module/RVA identities. Back/Forward returns to the exact originating
instruction, node, or metadata page. Renaming is an annotation overlay and does
not erase relationships. Views cap incoming/associated record rendering at 100;
all records remain in JSON. Older reports without the new extension still render.
All JavaScript is embedded; no server, network request, or analyzed-code execution
is required by the viewer.

## Validation

New tests are split by responsibility:

- `tests/test_unwind_info.py`: 36 test methods covering supported forms, unknown
  versions, malformed/truncated data, chain context/cycles/depth, conflicts,
  discovery priority, range boundaries, budgets, deterministic mutation cases,
  and a compiler-produced demo. The compiled-demo check skips explicitly without
  `--fixtures`; no symbols or main RVA are supplied to the analyzer in that test.
- `tests/test_unwind_limits.cpp`: 25 native checks for independent node/slot/depth
  limits, shared-header caching, unsupported versions, and capped diagnostics.
- `tests/test_unwind_browser.py`: 32 checks for metadata/code/data history,
  primary/handler links, annotations, unsupported/cyclic cases, legacy reports,
  escaping, mobile access, and absence of JavaScript/network errors.

The previous 34 raw-table tests and 31 metadata-browser checks now use
`--no-unwind-seeds` to isolate their original bounds-only scope. Default discovery
has its own positive and negative assertions; previous checks are not removed.
The model-tests workflow runs the new suites on direct `main` pushes as well as PRs.
Generated input files and reports remain outside `main`.

```sh
ctest --test-dir build --output-on-failure
python3 tests/test_unwind_info.py build/windows-exe-analyzer --fixtures build/test-fixtures
python3 tests/test_unwind_browser.py build/windows-exe-analyzer
```

Linux/LLVM is the validation path for this slice. Do not infer Windows/macOS or
Capstone validation from those results. Hosted run status must be checked on the
corresponding source commit rather than copied from an earlier milestone.

## References and next work

The format and structural rules follow Microsoft's
[x64 exception-handling documentation](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)
and [PE/COFF format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
Version-2/3 layouts require separately scoped implementations; their existence
must not be interpreted as version-1 compatibility.

Next in the implementation queue: bounded PE32/PE32+ TLS callback discovery,
with independent callback roots and no fabricated normal-call edges.
