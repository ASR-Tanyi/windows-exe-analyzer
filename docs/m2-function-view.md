# M2 first slice: whole-function HTML overview and assembly

The report now provides a function-level view alongside its original block view.
This is a presentation/indexing change over existing schema-2 report facts, not
new native function discovery, decompilation, or a claim of complete boundaries.

## Using the view

Select **Whole function** from a block, or select an entry under the **Functions**
sidebar tab. A shared block requires choosing an owner instead of silently picking
one. **Block view** links return to the existing single-block interface. Default
report startup remains the existing PE-entry/block view.

The overview shows the entry address, reported member blocks, unique decoded byte
count, instructions, call sites, disjoint decoded spans, shared blocks, and data
references. The inspector separates incoming calls, outgoing call targets,
non-call exits/transfers, unresolved references, discovery evidence, and encoded
metadata ranges. No missing reference is treated as proof that code is unused.

Assembly is shown in RVA order, not execution order, with explicit successors.
Internal branches stay in the selected function context. A call to another known
entry opens that function; an imported call opens its existing import page. An
interior target with ambiguous ownership can still be inspected in Block view.
Incoming caller links choose a function view only for an unambiguous reported
owner. No callee-return-to-every-caller edges are synthesized.

Click memory operands to inspect original bytes. Back returns to the originating
function, exact instruction, instruction page, expanded details, and scroll
position. The raw source instruction is retained separately for RIP calculations.
Function, TLS, unwind, exception, import, and data routes share navigation history.
Names and notes use existing entry-block annotation identities, so a rename or
annotation export/import does not change a link's underlying identity.

## Bounds and routes

Each assembly page has at most **250 instruction rows**, including when a single
basic block exceeds that limit. A spanning block repeats its heading on the next
page; it is not split into invented analyzer blocks. Use Previous/Next instructions
or **Go to instruction RVA** to reach another page. The latter accepts decimal or
`0x`-prefixed RVAs only at known member-instruction starts, not file offsets or VAs.

Detail lists show at most 100 entries with an explicit truncation notice; all
owned instructions remain accessible through assembly pages and the complete
facts remain in the embedded report. This is not a global cap on report size or
initial JSON parsing. Derived function row indexes are cached for at most four
functions. The full report and membership indexes still consume memory.

Function-view routes are separate from stable entity/annotation IDs:

```text
<module>_fn_<entry-RVA>                   overview / first page
<module>_fn_<entry-RVA>_p<page>            later page (zero-based)
<module>_fn_<entry-RVA>_at_<instruction>   exact instruction, page inferred
```

RVAs in routes are hexadecimal. A selected instruction must belong to that
function's reported blocks. Function names are never used as routing keys.
Existing `_b_`, `_i_`, and `_d_` links retain their meaning. A new renderer can
consume old schema-2 facts without the optional metadata extensions; an already
exported old HTML file must be regenerated to gain the new interface.

## Analysis contract

`web/function-model.js` is a pure index over `functions`, `blocks[].owners`, edges,
and memory references. It does not modify those facts or infer ownership for
orphan blocks. A missing entry owner is explicitly reported. Shared blocks count
once per owning function; instruction-byte intervals are unioned for byte counts
without filling address gaps. Module-level counts remain the original report's
counts, not the sum of potentially overlapping function memberships.

Call edges are distinct from intraprocedural successors. A continuation retains
the existing assumption that its callee returns. An unknown call/jump remains
unknown; tail transfers are not relabeled as calls. Metadata ranges stay separate
from decoded coverage. The overview always says completeness is not proven,
even when no unresolved edge was discovered. Ownership, decoder, and traversal
limitations still apply.

`web/function-view.js` is embedded by CMake after the existing viewer extensions.
It reuses the existing code/data rendering helpers and label store. No remote
scripts, CDN graph library, input execution, or server is required by the report.
The schema and native analysis behavior are unchanged.

## Validation

Run the pure model checks with Node.js 18 or newer:

```sh
node tests/test_function_model.js
```

CMake registers this suite when Node is available and explicitly reports a skip
otherwise. Node is a test dependency, not a report or analyzer runtime dependency.
The cases cover ownership, shared tails, disjoint coverage, calls/continuations,
recursion, tail transfers, unresolved targets, imports, data references, high
RVAs, duplicate facts, cache eviction, and no mutation of report facts.

After fixture generation, run the browser suite with Playwright and Chromium:

```sh
python3 tests/test_function_browser.py --fixtures build/test-fixtures
```

Hosted regression CI additionally uses `--document-navigation`. That mode serves
a document through Playwright's request interception, allowing real reload and
new-page deep-link tests without an external site. Managed test browsers that
block document navigation can use the default content-only mode; the real reload
check is explicitly skipped, not counted as passing.

Browser cases cover callers/callees, internal branches, imports, RIP provenance,
back/forward history, annotations, metadata routes, shared-owner selection, mobile
layout, large single-block paging, exact goto, scroll restoration, unknown calls,
legacy/empty reports, escaping, x86, and a DLL without a PE entry. Synthetic report
cases exercise presentation only; they are not evidence of machine-code recovery.

## Roadmap scope

M2.1 and M2.2 are implemented using existing reported ownership. M2.3 is implemented
in the presentation index, without a new native CFG/call-graph serialization.
M2.6 covers function/block/instruction/data context and scroll; M2.7 covers paged
whole-function assembly, not virtualization of the original block view or all
report indexes. Graph layout, graph selection, dominators, natural-loop recovery,
and irreducible-region analysis (M2.4/M2.5) remain pending. No part of this slice
implements IR semantics, automatic main recognition, or dynamic analysis.
