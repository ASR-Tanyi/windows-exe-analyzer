# windows-exe-analyzer

A cross-platform C++20 static analyzer for native Windows x86/x64 EXEs and DLLs.
Decode instructions, navigate named basic blocks, inspect imports/exports, and
follow RIP-relative references into a self-contained HTML data viewer. The
analyzer and report **never execute the input PE file**.

## GitHub Actions: open reports in your browser

Use [Actions > HTML reports > Run workflow](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/workflows/html-report.yml)
on `main`. The default run builds x86/x64 demo EXEs and DLLs from test source,
generates four baseline reports plus four C-recovery reports (x86/x64, O0/O1),
and publishes a clickable report index to GitHub Pages.
The run summary contains the live links after deployment succeeds.

**One-time setup:** [Settings > Pages](https://github.com/ASR-Tanyi/windows-exe-analyzer/settings/pages)
> Build and deployment > Source > **GitHub Actions**. Until this is enabled,
report artifacts are available but the Pages deployment cannot succeed.

Manual runs can also select a published release asset, a direct public HTTPS
EXE/DLL URL, or a file on another repository branch. Set `publish=false` for
artifact-only output. Generated files are never committed to either branch.
**Reports contain original bytes and strings; submit only public-safe inputs.**
The Pages URL serves the latest successful deployment; run artifacts retain
older reports for 30 days, subject to repository retention limits.

See [the report workflow guide](docs/report-workflow.md) for input examples,
Pages setup, download options, runtime restrictions, and troubleshooting.

## Repository layout and branches

| Branch | Contents |
| --- | --- |
| `main` | Analyzer source, HTML template, test code, fixture generators, build configuration, and documentation. |
| `demo_exe` | The source snapshot plus generated EXE/DLL fixtures and showcase reports under `demo/`. |

Do not merge generated artifacts into `main`. Build outputs, downloaded
third-party dependencies, external input samples, reports, archives, images,
caches, and local secrets are ignored. `web/viewer.html` is source code and is
intentionally tracked. All test fixtures are generated from C/Python source;
no precompiled PE file is required by the source-only tests.

## Build

Requires CMake 3.20+ and a C++20 compiler. The default decoder is pinned to
Capstone 5.0.9; the first FetchContent download requires Git and network access.

```sh
git clone https://github.com/ASR-Tanyi/windows-exe-analyzer.git
cd windows-exe-analyzer
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j
ctest --test-dir build -C Release --output-on-failure
```

Use installed Capstone 5 headers/runtime with `-DWEA_USE_SYSTEM_CAPSTONE=ON`, or use a locally
installed LLVM shared library without downloading dependencies:

```sh
cmake -S . -B build-llvm -DWEA_DECODER=LLVM -DCMAKE_BUILD_TYPE=Release
cmake --build build-llvm --config Release -j
ctest --test-dir build-llvm -C Release --output-on-failure
```

Set `-DWEA_LLVM_LIBRARY=/absolute/path/to/libLLVM.so` (or your platform's library)
if discovery fails. LLVM development headers are not required. Both adapters
have native/report regression coverage; CI runs both on Linux. Capstone provides
structured operands. LLVM remains a limited text/disassembly path and explicitly
reports structured metadata as unavailable.

The executable is `windows-exe-analyzer`. On macOS/Linux it
is normally `build/windows-exe-analyzer`; Visual Studio multi-config builds
normally place it at `build/Release/windows-exe-analyzer.exe`.

## Analyze and navigate

```sh
./build/windows-exe-analyzer program.exe --html build/program.html
./build/windows-exe-analyzer plugin.dll --html build/plugin.html
./build/windows-exe-analyzer program.exe --asm
./build/windows-exe-analyzer program.exe --json build/program.json --limit 20000
```

Open the HTML locally: no server, CDN, or external assets are required. Click
call/jump targets to follow code, or constant-address memory operands to inspect
original file bytes. Back/Forward returns to the exact originating instruction.
Search, rename, and annotate blocks/data. Export annotations as JSON for portable
storage; browser localStorage is best-effort. The legacy annotation storage
prefix is retained so previous labels remain compatible.

Select **C-like** for an initial assembly-to-pseudocode preview: assignments,
integer arithmetic, memory reads/writes, indexed addresses, supported if/else
and loops, with exact assembly links. It keeps machine register names and
explicit unknown effects; it does not reconstruct original C names/types or
call signatures. Source `for` loops may normalize to `while`/`do-while`.
Proven stack locations now get optional readable memory aliases, with bounded
register-value facts and source evidence. The stack table explains ambiguous or
overlapping locations; the toggle restores raw addresses. These are memory
aliases, not inferred C locals. See the [value-analysis contract](docs/bounded-values.md).
Expand **Register flow** to follow each register read to its defining write,
inspect branch/loop joins and browse reverse uses with assembly evidence.
Partial writes and unknown call clobbers stay explicit; see the
[register SSA contract](docs/register-ssa.md).
For reviewed x64 call sites, **Call assumptions** can explicitly select a
Windows x64 normal-return summary. It preserves nonvolatile GPR/SP facts while
keeping volatile registers, flags and memory unknown. Export/import selections
for reuse; unselected calls retain all-state barriers. See the
[call-summary contract](docs/call-summaries.md) and **Call assumptions demo** in
the report index.
See the [support contract and testing demo](docs/c-like-recovery.md).
The [C demo source](tests/fixtures/recovery.c) includes a larger array transform
with branches and nested loops. In its report, select `transform_demo`, then
**C-like**. A text export is also available:

```sh
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --raw
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --ssa
node scripts/pseudocode.js build/program.json 0xFUNCTION_RVA --calls call-assumptions.json --json
```

All CLI addresses are **RVAs**, not file offsets or live VAs. `--main-rva 0xRVA`
is an analyst assertion, not automatic main discovery. `--name 0xRVA=label`
labels code and `--data-name 0xRVA=label` labels data. Names/addresses must come
from the binary being analyzed, not copied from another build.

The PE entry point is not automatically `main()`. The test programs deliberately
use a custom no-CRT entry. Structural labels are clues, not recovered source
meaning; a backward jump alone is not proof of a loop.

## Static data

The viewer includes hex/ASCII pages, bounded ASCII/UTF-16LE candidates,
little-endian numeric interpretations, preferred VA/RVA/file offsets, section
permissions, and exact starting-address references. RIP-relative addressing uses
**next instruction + signed displacement**. LEA is address-only; recognized
memory accesses show read/write intent and width. Unknown accesses stay unknown.

An IAT operand opens the original slot bytes, separately from its imported
symbol. It is not presented as a resolved runtime DLL address. `--` means virtual
zero-fill with no stored bytes; `??` means bytes omitted by the report budget.
Relocations and loader fixups are not applied. Types, object boundaries, and
mutable runtime values are not inferred.

`--data-limit BYTES` accepts 0 through 67108864 (default 4 MiB of original bytes).
Referenced pages have priority; the encoded report can exceed this byte budget.
Report schema is 2; annotation schema is 1. Stable identities use a
non-cryptographic content key plus RVA, not display names.

## Structured instruction operands

Select an instruction address in block or whole-function assembly and open
**Instruction operands** in the inspector. Capstone reports GPR slices (including
AH and extended registers), immediate bit patterns, operand/address widths,
segment selectors, base/index/scale/displacement expressions, and prefix/encoding
metadata. The default hosted demo now uses Capstone.

The additive `operandModelVersion: 1` JSON extension preserves assembly text,
raw bytes, existing schema-2 links, and schema-1 annotations. Backend capabilities
appear in `module.decoderInfo`; each instruction carries `operandDetails`.
LLVM metadata is explicitly unavailable. Reported register accesses may be
incomplete; empty lists do not prove absence of implicit effects. Register
overlap metadata does not yet implement zero-extension or other machine
semantics. The separate C-like preview implements a bounded typed integer/value
subset; ABI summaries and indirect-register target recovery remain pending.

See the [operand/capability contract and tests](docs/m4-structured-operands.md).

## Tests and reproducible examples

Python 3 runs synthetic parser, traversal, naming, safety, and data-reference
regressions. When CMake also finds `clang` and `lld-link`, CTest builds real
x86/x64 EXE/DLL fixtures under `build/test-fixtures/` and tests imports/exports.
Without those tools, linked-fixture checks are explicitly skipped; synthetic
checks remain available. Without Python, CMake reports that tests are disabled.
No analyzed Windows code is executed.

```sh
python3 tests/build_fixtures.py --output build/test-fixtures \
  --analyzer build/windows-exe-analyzer
```

The generator reads function/data labels from the current linker map and sets PE
timestamps to zero. Layout still depends on the compiler/linker version. Browser
regressions require Playwright and Chromium:

```sh
python3 -m pip install playwright
python3 -m playwright install chromium
python3 tests/test_browser.py --fixtures build/test-fixtures
python3 tests/test_data_browser.py build/windows-exe-analyzer \
  --fixtures build/test-fixtures
```

Pass `--chromium /path/to/chromium` for a system browser. Reports come from the
current build, not the demo branch. Screenshots go to a temporary directory.

Use a separate checkout for publishing generated examples:

```sh
git fetch origin
git worktree add ../windows-exe-analyzer-demo demo_exe
python3 tests/build_fixtures.py --output ../windows-exe-analyzer-demo/demo \
  --analyzer build/windows-exe-analyzer
```

The demo branch documents its artifact package and uses narrow ignore-rule
exceptions. Review its diff before publishing; never force-add outputs on main.

## Implementation and limits

`src/pe.hpp` parses PE headers and RVA mappings; `src/decoder.cpp` provides
Capstone/LLVM decoding; `src/analyze.hpp` discovers and splits blocks;
`src/static_data.hpp` collects bounded original-byte pages; `src/report.cpp`
serializes JSON and embeds `web/viewer.html` through a build-generated header.

This is a disassembly explorer, not a complete decompiler. `--ir`/`--both` expose
conservative observations, not complete instruction semantics or recovered C.
Indirect register calls, switch tables, delay imports, PDB discovery,
cross-DLL implementation navigation, relocation-aware pointer chains, and live
values remain unimplemented. LLVM memory extraction uses a deliberately narrow
Intel-text grammar; Capstone uses structured operands.

Inputs are capped at 256 MiB; instruction discovery defaults to 100,000 (maximum
1,000,000). Only discovered file-backed code is decoded. Packed, encrypted, or
self-modifying programs need a separate acquisition stage. This educational
parser is not hardened for hostile inputs; analyze untrusted files in isolation.

## License

MIT; see [LICENSE](LICENSE). Third-party decoders retain their own licenses and
are not vendored in this repository.
