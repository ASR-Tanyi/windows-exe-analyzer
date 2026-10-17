# M2 graph slice: interactive CFG and bounded graph analysis

The offline report now includes a **CFG** view for each function candidate. The
view is derived only from the report's already-discovered intraprocedural edges
and block ownership. It does not add code, resolve indirect targets, or claim
complete function recovery.

This completes M2.4 and M2.5 within the bounded presentation/analysis contract
below.

## Graph model

`web/cfg-model.js` consumes the existing whole-function presentation index.
Calls remain outside the intraprocedural CFG. Continuations, conditional edges,
jumps, and fallthrough edges already classified as owned-function flow are
retained. Transfers outside owned blocks and unresolved destinations stay
separate and visible.

The graph starts at the reported function-entry block when it is owned by the
function. Reachability is therefore *reachability in the discovered graph*, not
runtime reachability. Blocks that are owned but unreachable from that entry are
retained and visually muted instead of discarded.

## Bounded analysis

For the discovered intraprocedural graph the viewer computes:

- deterministic predecessor/successor indexes;
- entry reachability;
- dominator sets and immediate-dominator candidates;
- strongly connected components using Tarjan's algorithm;
- cyclic SCCs and multi-entry cyclic regions;
- dominator-backed natural-loop candidates from back edges.

A backward RVA edge alone is never classified as a loop. A natural-loop
candidate requires the target to dominate the back-edge source. Multi-entry
cyclic SCCs are labeled **irreducible** rather than forced into a natural-loop
shape.

Default presentation/analysis limits are:

| Limit | Default |
| --- | ---: |
| SVG-layout blocks | 120 |
| SVG-layout intraprocedural edges | 300 |
| Dominator fixed-point iterations | 10,000 |

When the layout limits are exceeded, the report switches to a bounded list
fallback instead of trying to render an unbounded SVG. The underlying report
facts are not removed. If the dominator iteration limit is exhausted, the
viewer reports the condition and does not emit natural-loop candidates based on
an unfinished dominator solution.

The report's existing truncation, unresolved-edge, ownership, and
`completeness: not_proven` facts propagate to a visible incomplete-graph
warning. An apparently closed graph is not silently promoted to a proof of
complete control flow.

## Interaction

Use **CFG** from a function/block context. The graph provides:

- selectable blocks;
- branch-kind labels on intraprocedural edges;
- shared-block styling;
- outside/unknown exits in the side panel;
- links back to block view and exact whole-function assembly;
- 50%-200% zoom controls;
- arrow-key block selection and Enter to open assembly;
- stable hash routes containing function and selected-block RVAs.

Selection is address/identity based, so analyst renames do not change links.
Existing assembly, strings, bytes, imports, annotations, and history remain
separate views over the same report identities.

## Tests and limits of the claim

`tests/test_cfg_model.js` covers diamonds, nested loops, self loops,
irreducible multi-entry SCCs, unreachable owned blocks, unresolved/truncated
graphs, shared ownership, layout limits, and dominator-budget exhaustion.

`tests/test_cfg_browser.py` checks SVG rendering, edge display, selection,
zoom, keyboard navigation, assembly/history return, unknown-exit presentation,
and the large-graph list fallback against source-known generated reports.

This slice does **not** implement graph recovery from indirect targets, switch
tables, exception semantics, runtime traces, or structured source-level loop
reconstruction. Those depend on later M4/M6/M7 work.
