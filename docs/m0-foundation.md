# M0 first slice: discovery evidence and decoded ranges

This implements the first row of [the implementation queue](../plan.md#6-first-implementation-queue):
**minimal M0.1 evidence/range contracts and the initial M0.3 fixture manifest**.
It does not complete all of M0. Metadata-based function discovery (M1), dynamic
capture/import, new instruction semantics, and automatic main recognition remain
pending. The detailed roadmap is still the scope authority.

## New model, unchanged identities

`src/analysis_types.hpp` introduces explicit `Rva`, `FileOffset`, `PreferredVa`,
`Address`, and module-qualified `Location` types. New evidence and diagnostics
use these types; existing decoder/PE integer APIs have not all been migrated.
An RVA is checked against the 32-bit coordinate space. A `CodeRange` is nonempty
and half-open, `[begin, end)`, with a 64-bit exclusive endpoint so the last byte
at RVA `0xffffffff` can be represented by end `0x100000000`.

These checks establish coordinate/range validity, **not** that an arbitrary
address is mapped, executable, canonical, or a real source-language function.
PE mappings continue to supply file-backed/executable validation. The distinction
between RVA, VA, and file position follows [Microsoft's PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

The old module content key, block/instruction IDs, CLI names, and annotation
storage key remain unchanged. SHA-256 module-identity migration is future work.
The fixture manifest uses SHA-256 to identify its input files independently.

## Evidence instead of one overwritten explanation

Function and block records gain a deterministic, deduplicated `evidenceRecords`
collection. Distinct source call sites are retained. A supplied name changes the
display, not earlier discovery facts.

Each record separates:

| Field | Meaning |
| --- | --- |
| `origin` | PE header, export table, decoded instruction, analyst, or analysis rule |
| `claim` | The specific assertion: image entry, function entry, application entry, display name, or block role |
| `resolution` | Encoded in the input, supplied by the analyst, or inferred |
| `status` | Confirmed encoded claim, candidate, analyst assertion, or heuristic |
| `rule`, `ruleVersion` | The rule responsible for producing this fact |
| `source` | An optional module-qualified address with an explicit coordinate system |
| `detail`, `assumptions` | Supporting explanation and limitations |

An encoded direct-call destination is exact as a destination but only a
**candidate function entry**. `--main-rva` remains an analyst assertion. A PE
header fact confirms the image-entry field, not that the destination is `main`.
Header source locations use file offsets; call-site sources use RVAs. Export
sources refer to the export-address-table entry, not an invented call instruction.

The legacy `evidence` string is retained for existing readers. It remains a
short display summary, not the authoritative collection of provenance facts.
Browser-only labels remain annotation overlays; importing them does not mutate
the static evidence embedded in the report.

## Decoded ranges, not guessed function boundaries

Blocks gain `decodedRange`; functions gain `decodedRanges`. They describe only
file-backed instructions decoded by the existing traversal and assigned by its
existing ownership rules. Contiguous ranges can be coalesced; skipped bytes are
never filled in. Shared blocks contribute to each inferred owner and generate an
`ambiguous_owner` diagnostic. Neither the next function's address nor executable
section padding is used as a substitute for a discovered function end.

For example, a jump from `0x1000` to a return at `0x1010` produces:

```json
"decodedRanges": [
  {"beginRva":"0x1000","endRva":"0x1002","origin":"decoded_instructions","validation":"file_backed_decoding"},
  {"beginRva":"0x1010","endRva":"0x1011","origin":"decoded_instructions","validation":"file_backed_decoding"}
]
```

These are decoded-coverage observations under inferred ownership. They do not
prove complete coverage, runtime execution, or semantically valid instructions.
Future exception-directory ranges must have their own origin and validation;
this slice deliberately does not implement a metadata-range parser.

## JSON compatibility

The report retains `schema: 2` and adds `analysisModelVersion: 1`. This is an
optional, additive extension: old fields are not removed or renamed. New location
values and range bounds are hexadecimal strings, including 64-bit VAs.

```json
{
  "schema": 2,
  "analysisModelVersion": 1,
  "functions": [{
    "location": {"moduleId":"m_example","space":"rva","value":"0x1010"},
    "evidenceRecords": [],
    "decodedRanges": []
  }],
  "diagnostics": {"limit":100,"total":0,"omitted":0,"counts":{},"items":[]}
}
```

This abbreviated example shows only extension fields. Consumers must continue
to accept schema-2 reports without the extension and ignore unknown optional
fields. The viewer renders model details only for extension version 1; ordinary
navigation remains usable without it. Annotation schema remains 1.

The serializer is output-only. Round-trip tests parse/re-encode its output with
Python's independent JSON consumer; this does not introduce a C++ report importer.
The optional differential test compares every legacy report field against a
previous executable, excluding this explicitly versioned extension.

## Typed diagnostics and budgets

PE optional-metadata warnings and discovery warnings now carry a code, phase,
message, and optional tagged location. Implemented codes are `invalid_metadata`,
`unsupported_feature`, `unmapped_target`, `overlapping_decode`, `decode_failed`,
`budget_exhausted`, `unresolved_seed`, `ignored_annotation`, and `ambiguous_owner`.
This slice does not convert fatal CLI/header parse exceptions into report records.

The first 100 detailed diagnostics are retained. Per-code and total occurrence
counts continue after that limit, and `omitted` makes missing details explicit.
Legacy `warnings` remain available. JSON and HTML are not allowed to silently
represent a capped warning list as a complete absence of further problems.

An instruction budget is now reported exhausted only when traversal still has
unvisited file-backed code. A terminal return at exactly the limit is not marked
truncated. This is a bounded correctness fix, not a new discovery heuristic.
Unknown indirect targets remain unknown.

## Initial source-known corpus manifest

`tests/build_fixtures.py` additionally emits `corpus.json` under its output
(build) directory. The manifest records generator/source SHA-256 hashes,
compiler/linker versions, target architecture, actual compile/link command
arguments, hashes of the x86/x64 EXEs and DLLs, and linker-map/source-based expected
entry points and import/export identities. Absolute local source/tool paths are
not recorded in the command list. Compiler intermediates and generated reports
remain untracked.

The new blind-discovery test reads the manifest as its evaluation oracle but
invokes the analyzer without `--main-rva`, `--name`, symbols, or linker-map input.
This is a small baseline corpus, not the future multi-compiler/optimization matrix.

## HTML additions

The block inspector has optional **Discovery evidence** and **Decoded coverage**
sections. Decoded source-instruction evidence links to the exact call site; file
offsets are not turned into code links. Coverage text explicitly states that it
does not give complete function boundaries. Existing RIP-data navigation and
annotation export/import remain unchanged.

The small authored extension lives in `web/analysis-model.js`, separate from the
base viewer. CMake embeds it after the base script into the same standalone HTML;
it is not a fetched asset. It decorates the existing block renderer and refreshes
the initial route. The base viewer source and existing navigation remain intact.

## Validation scope

The read-only `Analysis model tests` workflow adds Linux/LLVM pull-request
regressions without Pages deployment or write permissions. It runs CTest, report
site tests, and the three browser suites against newly generated demo reports.
This is only the first CI slice; the full M0.4 Windows/macOS and dual-backend
matrix remains pending. The previous-executable comparison is an optional local
check, not a claim that CI ran it.

## Validation commands

```sh
cmake -S . -B build -DWEA_DECODER=LLVM -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
python3 tests/test_analysis_model.py build/windows-exe-analyzer \
  --fixtures build/test-fixtures --baseline /path/to/previous/windows-exe-analyzer
python3 tests/test_browser.py --fixtures build/test-fixtures
python3 tests/test_data_browser.py build/windows-exe-analyzer --fixtures build/test-fixtures
python3 tests/test_model_browser.py --fixtures build/test-fixtures
```

The previous-executable comparison is explicitly skipped without `--baseline`.
Linked-corpus checks explicitly skip when clang/lld-link fixtures are unavailable.
Browser tests need Playwright and Chromium. Native type tests use runtime checks
even in Release builds, not disabled C `assert` macros.

Acceptance cases cover coordinate bounds, range gaps, shared ownership, duplicate
and distinct call-site evidence, analyst renames, HTML escaping, JSON precision,
metadata failures, overlapping decoding, capped diagnostics, exact limits,
old-format annotation import, and navigation with/without the extension.

The implementation keeps dynamic analysis deferred. The next code-discovery
step remains the bounded x64 exception-directory parser in M1A.
