# M1.5 / M1.6: TLS callbacks as independent entry candidates

This slice adds bounded PE32/x86 and PE32+/x64 TLS callback parsing and static
entry-point discovery. It does not execute the input, collect runtime events,
implement TLS storage allocation, or automatically identify `main`.

## Parser contract

`src/tls_directory.hpp` locates the TLS header through PE data directory **9**,
not a section name. The header is 24 bytes for PE32 and 40 bytes for PE32+.
Its first four address fields and its callback-array values are **preferred
VAs**, not RVAs. Conversion checks subtraction, the 32-bit RVA space,
`SizeOfImage`, target pointer width, and mapped file-backed bytes. The metadata
stores original address values as hexadecimal strings, preserving 64-bit
precision in JSON and JavaScript. See Microsoft's
[TLS directory specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-directory).

Header extents and every pointer read are bounded. Adjacent RVA mappings can be
read across disjoint raw-file locations. Virtual zero-fill is not fabricated
into a stored null pointer. Template start/end, index VA, zero-fill size, and
characteristics are retained as raw fields; this feature does **not** establish
that those fields describe a fully loader-valid TLS allocation.

A zero callback-array VA is `no_callback_array`: no array is dereferenced. It is
distinct from a mapped array whose first pointer is null (`terminated=true`,
zero callbacks). A null element ends the array; data after it is not scanned.

Every non-null readable slot retains its array ordinal, slot RVA, original target
VA, checked target RVA when available, eligibility, issues, and duplicate-target
index. Duplicates remain in their encoded order; they are not silently erased.
A target must begin in executable file-backed bytes to become a candidate.

The parser stores at most **4,096 callbacks** and reads at most **4,097 slots**.
The final look-ahead allows exactly 4,096 callbacks followed by a null terminator.
An unavailable slot or exceeded budget preserves the prefix with an explicit
partial result. A partial/unterminated array contributes **no automatic roots**.
Within a complete, otherwise readable array, a bad target blocks that entry but
does not erase unrelated valid siblings. These are conservative analysis rules,
not a claim that Windows would accept or reject the whole image identically.

Diagnostics use the existing typed log (`phase=tls`) with tagged RVA sources.
Detailed messages remain capped while occurrence counts are retained. Callback
budget exhaustion does not by itself set the instruction-traversal truncation
flag; those are independent budgets.

## Discovery and evidence

TLS discovery is a third phase, after existing entry/export/direct-call traversal
and unwind-derived roots. Earlier instruction boundaries are retained. A pointer
into the middle of an existing instruction stays `not_decoded`, with a conflict
diagnostic; it does not create an overlapping stream.

Each eligible slot supplies a `pe.tls_callback_seed` evidence record, with origin
`tls_directory`, claim `tls_callback_entry`, encoded resolution, and candidate
status. Its source is the **pointer slot**, not an invented call instruction.
Several slots for the same address contribute distinct evidence but only one
queued root. Existing names, direct-call evidence, analyst assertions, and
unwind evidence are preserved. New unnamed roots use `tls_callback_<RVA>`.

Callback array order is an encoded loader relationship, not a runtime trace.
No call, fall-through, or execution-order edge is fabricated from `pe_entry` or
from one callback to the next. Real calls discovered *inside* callback bodies
are analyzed normally. A DLL with no PE entry can still have callback roots.

`--main-rva` remains an analyst assertion. Callback discovery never assigns
`main` merely because the callback is an initialization entry point.

```sh
# Normal callback discovery is enabled by default.
windows-exe-analyzer program.exe --html report.html

# Inspect TLS metadata without adding TLS callback roots.
windows-exe-analyzer program.exe --no-tls-seeds --html report.html

# Disable both independent metadata discovery mechanisms, retaining inspection.
windows-exe-analyzer program.exe --no-tls-seeds --no-unwind-seeds --html report.html
```

The report adds optional `tlsDirectory.version=1` metadata while retaining report
schema 2, analysis model version 1, annotation schema 1, and existing entity IDs.
Discovery status distinguishes `disabled`, `blocked`, `decoded_candidate`, and
`not_decoded`. Eligibility is not evidence that the callback ran or that its
complete body was recovered. Counts of submitted roots include candidates that
could not be decoded because of the instruction budget or boundary conflicts.

## HTML

The **TLS callbacks** button opens a paged metadata table (100 slots per page).
Header fields, array/slot/terminator RVAs link to original bytes when mapped;
callback targets link only to already decoded instructions. The existing byte
embedding budget still applies, so a mapped page can show omitted bytes.

The function inspector links callback entries back to their metadata page and
pointer slots. Exact code/data/back/forward navigation, analyst renaming, and
metadata page deep links are retained. Raw values and input-derived diagnostic
text are escaped. Older reports without this extension retain their old UI.
The extension is embedded during CMake configuration; no external script or
network request is needed to view the report.

## Tests and scope

`tests/test_tls_types.cpp` checks parser mapping and budget boundaries through an
independent image adapter, including split mappings, high addresses, diagnostics
caps, and exact-limit termination. `tests/test_tls_directory.py` checks real
synthetic PE headers plus source-compiled x86/x64 EXEs and no-entry DLLs. Compiler
maps are evaluation oracles only, never inputs to discovery. The compiled case
is explicitly skipped when clang/lld-link are unavailable.

`tests/fixtures/tls_callbacks.c` supplies the linker-recognized TLS directory and
one callback without an ordinary call site. Tests compile and link the fixtures
but never run them. `tests/test_tls_browser.py` exercises the standalone viewer,
including partial and invalid input, disabled discovery, paging, history,
escaping, small screens, and older report compatibility.

```sh
ctest --test-dir build --output-on-failure
python3 tests/test_tls_directory.py build/windows-exe-analyzer
python3 tests/test_tls_browser.py build/windows-exe-analyzer
```

This completes the bounded scope of M1.5/M1.6, not all of M1. Arbitrary analyst
function seeds (M1.7), broader x86 discovery work, and a general startup-role
model/recognizer remain separate items. Native Windows/macOS and Capstone
validation must be recorded independently from Linux/LLVM results.
