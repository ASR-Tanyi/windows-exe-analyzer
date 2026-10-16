# M1 first slice: bounded AMD64 exception-directory parsing

This implements the second row of [the implementation queue](../plan.md#6-first-implementation-queue): parse
runtime-function metadata before using it to expand code discovery.

| Plan item | State in this slice |
| --- | --- |
| M1.1: directory-based, machine-gated lookup | Implemented |
| M1.2: bounded records, checked extents and ranges | Implemented with the conservative file-backed policy below |
| M1.3: unwind versions, chains, and handlers | Deferred; unwind RVAs are retained, but their contents are opaque |
| M1.4: additional discovery roots | Deferred; no metadata-derived disassembly seeds are added |

The previous M0 foundation is already on `main` in
[`9299868`](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/9299868a6ccecc181ffd1dddf0a8f431faeb4fd7).
This is not completion of M1A, all of M1, or the entire M0 roadmap.

## Parser contract

`src/exception_directory.hpp` reads PE data directory index 3. Section names are
not used to find the table. Interpretation is enabled only when the existing PE
parser has validated AMD64 machine type plus a PE32+ optional header. x86 images
still disassemble normally, but a nonempty exception directory is explicitly
reported as an unsupported architecture rather than decoded as AMD64 records.

Each 12-byte record retains its table index, source RVA, BeginAddress,
EndAddress, and UnwindInfoAddress. Range endpoints are half-open. Every complete
readable record is retained in original table order, including invalid records.
An all-zero record is invalid data, not an array terminator.

Checks cover:

- A coherent RVA/size pair, 32-bit RVA arithmetic, SizeOfImage bounds, DWORD
  alignment, complete record sizes, and file-backed table extents.
- Nonzero starts and nonempty ranges wholly covered by file-backed executable
  spans. Adjacent RVA spans can have disjoint physical file positions.
- A nonzero, DWORD-aligned unwind RVA with at least four file-backed bytes.
- Ascending start addresses, duplicate records, and overlapping ranges.

The file-backed range check is deliberately stricter than merely locating a
virtual executable mapping. Virtual zero-fill, missing bytes, and non-executable
ranges fail this gate; this is not a claim that the Windows loader would reject
all such images. `PE::parse` still has its own documented restrictions, including
rejection of overlapping image sections.

`bounds_checked` means only that the implemented address/table checks passed.
It does **not** validate unwind opcodes, supported unwind versions, frame state,
chains, handler data, runtime execution, or source-language function identity.
Even an unknown version in a readable unwind header remains opaque in this
slice. Low-bit/unaligned unwind encodings are flagged, never masked into an
invented direct RVA.

## Bounds and malformed input

There is an independent fixed limit of **65,536 records**. This limit does not
reuse the instruction budget. A budget hit produces a partial metadata result,
omitted-record counts, and a `budget_exhausted` diagnostic. It does not make the
instruction traversal's `module.truncated` flag true.

If table bytes become unavailable, the readable prefix is retained. No bytes
are fabricated for the rest. Trailing bytes are reported separately, including
when they are not file-backed. A directory extending beyond the image/RVA space
is rejected before any table record is read.

Duplicate/overlap checks use sorted indexes, not an all-pairs comparison. Each
conflicting record retains at most one overlap witness rather than an unbounded
list of every overlapping pair. Exact duplicates retain the index of their
first occurrence. Records participating in a duplicate or overlap have issues
attached; the raw evidence is not silently deduplicated or discarded.

Diagnostics use the M0 typed log with `phase=exception_directory` and a tagged
RVA source location. `invalid_metadata`, `unsupported_feature`, and
`budget_exhausted` remain distinct. Detailed messages are capped while total
occurrence counts remain available. Optional-directory problems do not prevent
ordinary code traversal; fatal base-PE parsing errors still reject the input.

## JSON and compatibility

Report schema 2, analysis-model extension 1, annotation schema 1, and all existing
module/block/instruction IDs are unchanged. A new optional top-level object is
added:

```json
{
  "exceptionDirectory": {
    "version": 1,
    "origin": "exception_directory",
    "status": "parsed",
    "directoryRva": "0x2000",
    "directorySize": 12,
    "supported": true,
    "malformed": false,
    "partial": false,
    "recordLimit": 65536,
    "declaredRecords": 1,
    "omittedRecords": 0,
    "trailingBytes": 0,
    "unwindSemantics": "not_decoded",
    "discoverySeedsAdded": false,
    "issues": [],
    "records": [{
      "index": 0,
      "tableRva": "0x2000",
      "beginRva": "0x1010",
      "endRva": "0x1011",
      "unwindRva": "0x3000",
      "rangeFileBacked": true,
      "unwindAddressFileBacked": true,
      "validation": "bounds_checked",
      "duplicateOf": null,
      "overlapWith": null,
      "issues": []
    }]
  }
}
```

Addresses are lossless hexadecimal strings. Status is `absent`,
`unsupported_architecture`, `parsed`, `malformed`, or `partial`. Inspect the
separate `malformed` and `partial` booleans because both conditions can coexist.
`declaredRecords` is computed only for the supported AMD64 format. Unsupported
architectures are not assigned a guessed AMD64 record count.

`records` are metadata, not additions to `functions`, `decodedRanges`, or CFG
edges. Known decoded instructions may be linked by the viewer, but no source
function boundaries or names are inferred from these records yet.

## HTML

The standalone report gains an **Exception metadata** toolbar button. The view
shows raw ranges, table and unwind RVAs, validation issues, duplicate/overlap
witnesses, and parser limits. It renders at most 100 records per page.

Click a table or unwind RVA to inspect its original file bytes when mapped.
A range start links to assembly only if that exact instruction was already
decoded. Otherwise it is marked `not decoded`, without inventing a code target.
Back/Forward preserves the originating instruction or metadata page. Paged
metadata has stable hash routes. Old reports without the extension still work.

`web/exception-directory.js` is embedded after the existing viewer extensions
by CMake. It requires no network, server, or external script. An omitted static
byte page remains omitted when opened from a metadata link; parsing metadata
does not override the byte-embedding budget.

## Tests

```sh
cmake -S . -B build -DWEA_DECODER=LLVM -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
python3 tests/test_exception_directory.py build/windows-exe-analyzer \
  --fixtures build/test-fixtures
python3 tests/test_exception_browser.py build/windows-exe-analyzer
```

The parser suite currently has 34 test methods, with additional subcases. It
includes a compiled source-known x64 demo checked against its linker-map main
RVA. That check is explicitly skipped when `--fixtures` is absent. The map is
not passed to the analyzer. Synthetic fixtures exercise invalid metadata,
record limits, readable prefixes, split file mappings, and independent code
coverage. None of the input PE files is executed.

The browser suite has 31 checks covering metadata/bytes/code links, exact history,
paging, malformed/absent/x86 records, old-report compatibility, escaping, mobile
layout, and no JavaScript errors or network requests. The existing model-tests
workflow now runs on relevant `main` pushes as well as pull requests, so direct
commits receive the same regression checks. Generated reports and fixtures remain
outside the source branch.

## References and next step

- Microsoft [PE/COFF format, .pdata](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section): exception-directory lookup and target-specific record formats.
- Microsoft [x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64): image-relative runtime-function entries, alignment, and unwind metadata.

Next: add explicitly supported unwind-header/chain/handler validation, then feed
eligible, evidence-backed range starts into discovery with duplicate merging,
conflict handling, and independent metadata/decoded-coverage displays. Do not
turn this bounds-only gate into a claim of a fully validated unwind program.
