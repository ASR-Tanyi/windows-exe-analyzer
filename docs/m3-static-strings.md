# M3 first slice: static strings and code references

The CLI now produces an optional `strings.version=1` catalog. It scans original
file bytes, independently of data-page embedding and function discovery. The HTML
provides a searchable **Strings** view and links between candidates, their bytes,
and already-discovered constant-address instruction operands.

This implements M3.1/M3.2/M3.3 for the bounded candidate contract below. It does
not recover data objects, resolve register-derived pointers, or establish runtime
usage. M3.4's general access-interval and data-to-data reference analysis remains
pending, beyond the start-address-to-string-span matching provided here.

## Candidate contract

`src/string_scan.hpp` scans file-backed headers and sections with the PE readable
flag. Section names are not used to decide whether to scan. Read extents are
clipped to stored file data, the virtual/file-backed section extent, SizeOfImage,
and the RVA domain. Header/section overlaps are skipped with a partial-result
reason rather than counted twice. Strings do not bridge sections, virtual
zero-fill, raw padding, or unmapped gaps.

Three bounded passes examine each selected region: printable ASCII, UTF-16LE
starting at byte parity zero, and UTF-16LE starting at byte parity one. Thus an
unaligned wide string can be discovered. Each pass reports maximal runs, not all
possible suffixes. Distinct addresses and different encoding interpretations are
retained even when their text matches or their spans overlap.

The ASCII predicate is U+0020 through U+007E. The wide predicate accepts Unicode
scalars outside C0/C1 controls, noncharacters, BOM and selected bidirectional
control marks. This is a broad text heuristic, **not** a complete Unicode-category
or language detector. Noncharacters are valid Unicode but excluded by this
candidate policy. Correct surrogate pairs produce one scalar and two code units;
unpaired surrogates end a run explicitly. UTF-8, UTF-16BE, ANSI code pages,
encrypted/compressed strings and text containing excluded controls are not
recovered by this slice. Printable binary data can create false positives,
particularly under a different UTF-16 alignment.

Each candidate retains start RVA, file offset, section, encoding, scanned text
byte length (excluding a terminator), code-unit count, Unicode-scalar count,
termination/end reason, and a bounded text preview. End reasons distinguish NUL,
non-text data, malformed/incomplete UTF-16, range end, and scan-budget cutoff.
A cutoff describes only the scanned prefix: its full object length is unknown.
The preview can be truncated while the scanned run's bounds and counts remain
complete. Neither case is silently described as a NUL-terminated string.

## Bounds and CLI

```sh
windows-exe-analyzer program.exe --html report.html
windows-exe-analyzer program.exe --strings-min 6 --html report.html
windows-exe-analyzer program.exe --strings-limit 20000 --strings-scan-limit 67108864 --html report.html
windows-exe-analyzer program.exe --no-strings --html report.html
```

Defaults and ceilings:

| Limit | Default | Maximum / behavior |
| --- | --- | --- |
| Minimum scalars per candidate | 4 | Configurable 1..1024 |
| Selected file bytes | 32 MiB | Configurable 0..256 MiB |
| Retained candidates | 10,000 | Configurable 0..100,000 |
| Preview per candidate | 256 scalars | Fixed; counts and scanned extents are separate |
| Total retained preview | 1,048,576 scalars | Fixed memory/output guard |
| HTML reference associations | 200,000 | Fixed presentation-index guard |
| Visible list/ref page | 100 entries | All retained entries accessible by pages |

The scanner processes regions in RVA order, then ASCII/even/odd passes. A budget
can therefore affect which candidates are retained. Final display ordering is
RVA then encoding. Limits are deterministic and explicit, not a significance
ranking. `selectedBytes` measures bytes selected for the detector passes, **not**
a claim that every pass finished when candidate/preview retention exhausted.
`completedDetectorPasses`, `partial`, and `reasons` report that distinction.

`--data-limit 0` does not disable discovery: candidates and references still
appear, while the byte browser explicitly shows omitted file bytes. `--no-strings`
produces a disabled empty catalog, not a claim that no strings exist. Scanner
budgets do not modify the disassembly-truncation flag. Large catalogs still cost
JSON parsing/index memory; paging is not global report virtualization.

## References and HTML

`web/string-model.js` indexes already-reported `instructions[].dataRefs` by start
address against candidate intervals. Exact and interior matches are distinct;
interior offsets are bytes, including for UTF-16, and do not assert a character
boundary. The terminator is outside the text interval. Known access kind/width
and original source instruction are retained; LEA remains address-taking, and
writes remain writes. Accesses that start outside but overlap the span are not
included by this start-address index. General interval/reference analysis is
still M3.4 work.

The reference index preserves all reported owning function candidates. It neither
chooses one owner for shared code nor adds functions or control-flow edges. A
missing reference means only that none was discovered in the indexed scope.
On index-budget exhaustion, counts/lists carry a partial warning.

Use **Strings**, search text/section/RVA, and optionally filter the encoding.
Search covers retained previews, not omitted suffix text. Open a candidate to see
its metadata, exact/interior references, and owning-function links. Inline text
candidate links also appear beside relevant code operands. The byte inspector
links back to containing candidates, including addresses inside a candidate.

Search/filter/page state and candidate IDs are encoded in hash routes. These
routes join the existing function-aware history: following a text link from
whole-function assembly and pressing Back restores its precise instruction.
Candidate identity uses module + encoding + RVA, not preview text or list index.
Existing annotation identities and report schema 2 are unchanged. Renaming data
continues through the existing byte view; this slice adds no inferred type/name
as an authoritative annotation.

`web/string-view.js` is embedded before the function-view extensions so their
history handling wraps string routes as well. No CDN, remote service or binary
execution is involved. Input-derived text is JSON/HTML escaped, including closing
script tags; supplementary characters survive serialization correctly. Existing
exported HTML needs regeneration to acquire the feature; optional catalog absence
keeps legacy behavior.

## Validation

```sh
ctest --test-dir build --output-on-failure
node tests/test_string_model.js
python3 tests/test_strings.py build/windows-exe-analyzer
python3 tests/test_string_browser.py build/windows-exe-analyzer --document-navigation
```

The native scanner suite uses an independent image adapter for bounds, UTF-16,
overlap, exact-limit, large-preview, and JSON cases. The CLI suite generates real
x86/x64 PE byte fixtures with known string addresses and never executes them.
The pure reference model checks exact/interior matches, shared ownership, high
RVAs, cap behavior, and non-mutation. Browser tests cover inline and function
navigation, bytes, history, Unicode search, escaping, paging, legacy reports,
partial/disabled states, and small screens. Real document reload is exercised
with `--document-navigation` in CI; content-only local mode explicitly skips it.

Native Windows/macOS and Capstone remain outside this change's initial Linux/LLVM
validation matrix. Hosted run results, not this feature list, establish whether
the full integration passed. CI retains its CTest log and roadmap snapshot as a
short-lived test-evidence artifact; generated binaries/reports are not committed.

Primary references: Microsoft's [PE/COFF section layout and flags](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
and Unicode's [UTF encoding FAQ](https://unicode.org/faq/utf_bom.html), including
surrogate-pair validity and the distinction between noncharacters and invalid
encoding. The text-candidate predicate is our documented heuristic, not a rule
imposed by either specification.
