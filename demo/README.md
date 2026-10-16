# windows-exe-analyzer: generated showcase

This directory belongs only to the `demo_exe` branch. It is deliberately absent
from `main`, which contains source, tests, configuration, and documentation.
Do not merge generated artifacts back into `main`.

Source snapshot: `d8aeb6eda7a7e1295a40c277cb8ea65c0c5eda12`.
All examples were generated from `tests/fixtures/application.c` and `library.c`
using `tests/build_fixtures.py`; no external executable or DLL is included.

## Open the offline reports

The package contains ready-made reports and small native x86/x64 PE fixtures.
Reports are packaged together to avoid duplicating the same embedded viewer in
the Git history. Extract them before opening a report:

```sh
git clone --branch demo_exe https://github.com/ASR-Tanyi/windows-exe-analyzer.git
cd windows-exe-analyzer/demo
tar -xf windows-exe-analyzer-demo.tar.xz
```

Open `demo64.html` in a browser. Select **Main (analyst)**, then click the
underlined RIP-relative operand to inspect `demo_payload`. Back returns to the
exact source instruction. Data references, imported DLL identities, renaming,
and hexadecimal/ASCII/numeric views are included. No server is required.

On macOS, `open demo64.html` opens the report. On other platforms, open the file
with a browser through the file manager. The HTML never runs the PE binaries.

## Package contents

| Files | Purpose |
| --- | --- |
| `demo32.exe`, `demo64.exe` | Source-known x86/x64 example executables for static analysis. |
| `demo_math32.dll`, `demo_math64.dll` | Matching DLLs exporting `transform_score`. |
| `demo32.html`, `demo64.html` | Offline EXE disassembly and data viewers. |
| `dll32.html`, `dll64.html` | Offline DLL disassembly viewers. |
| `demo32.json`, `demo64.json`, `dll32.json`, `dll64.json` | Machine-readable report data. |
| `demo32.map`, `demo64.map` | Linker maps for checking function addresses. |
| `demo32.symbols.json`, `demo64.symbols.json` | Ground-truth RVAs parsed from those maps. |

These no-CRT test programs are analysis fixtures, not end-user applications.
They have a deliberately custom entry point; they are not examples of ordinary
MSVC CRT startup. No Windows executable was run to generate or validate them.
Main and semantic labels are source/linker-map assertions, not automatic recovery.
File bytes are not live memory, and an IAT slot is not a resolved DLL function.

## Integrity and regeneration

`SHA256SUMS` covers the archive. Verify it before extraction:

```sh
# Linux
sha256sum -c SHA256SUMS
# macOS
shasum -a 256 -c SHA256SUMS
```

Regenerate fixtures/reports from a built source checkout:

```sh
python3 tests/build_fixtures.py --output build/test-fixtures \
  --analyzer build/windows-exe-analyzer
```

Use the executable path for your build configuration. Clang and lld-link are
required; compiler/linker versions can change layout. The generator obtains
labels from the new map rather than reusing addresses from this package.

Only `.exe`, `.dll`, `.html`, `.json`, and `.map` fixture outputs are included in
the archive. Compiler intermediates, imported libraries, dependencies, caches,
and unrelated input samples are excluded. The tar metadata is normalized, and
all 16 archived files were compared byte-for-byte with their generated originals.
The uploaded archive's Git blob SHA was also checked against the local package.

Validation of the source snapshot used the LLVM backend: 3/3 CTest tests,
424 analyzer assertions, 54 static-data browser assertions, and the existing
browser navigation regression. Browser checks had no JavaScript errors or HTTP
requests. The Capstone backend is available but was not built in this environment.

The branch-specific ignore rules allow only this README, the checksum manifest,
and the curated archive. Extracted files and compiler intermediates remain
ignored, so a casual `git add .` does not publish them accidentally.
