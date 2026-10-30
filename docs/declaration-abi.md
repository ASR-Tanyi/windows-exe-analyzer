# Conditional declared ABI locations

P15 adds read-only Windows x64 locations for analyst-supplied integer and pointer declarations. These are conditional placements, not recovered signatures, observed uses or compatibility verdicts. Machine effects and call assumptions remain unchanged.

## Gate and bounds

A declaration maps only when the function profile explicitly selects `windows-x64-gpr-v1`, both `variadic` and `hiddenParameters` explicitly say `no`, and every parameter and return annotation resolves to a supported type. The supplied parameter list is assumed complete and fixed. One unsupported field withholds **all** locations and widths for that declaration; field-specific blockers explain why. Parameters are never dropped or renumbered. Competing declarations map independently and retain their source labels, alias dependencies and textual disagreements.

The existing eight-declaration and 32-parameter caps bound output to 264 rows, including returns. Invalid contracts commit no partial locations. Machine-analysis budget exhaustion does not erase valid declared placements. Clearing the profile or introducing unresolved aliases withholds locations again.

## Reviewed mapping

| Type or position | Conditional placement |
| --- | --- |
| char / signed char / unsigned char | 8-bit value |
| short / unsigned short | 16-bit value |
| int / unsigned int / long / unsigned long | 32-bit value (Windows LLP64) |
| long long / unsigned long long | 64-bit value |
| Supported parsed pointer | 64-bit value |
| Parameters 1–4 | Low declared-width bits of RCX, RDX, R8, R9 respectively |
| Parameter n, n ≥ 5 | Callee entry RSP + n × 8 bytes; 8-byte slot |
| Integer or pointer return | Low declared-width bits of RAX |
| void return | No declared return value |

Unused register bits and slot padding remain unspecified. No extension or register home-space copy is inferred. A literal void parameter record is unsupported, not an empty parameter list. Boolean, floating-point, aggregate, vector, array and function-pointer ABI handling remains unreviewed; unsupported syntax and unresolved names stay unknown. A supported pointer can point to a floating-point type without becoming a floating-point argument.

The mapping follows Microsoft's [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention), [x64 software conventions](https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions), [basic type storage](https://learn.microsoft.com/en-us/cpp/c-language/storage-of-basic-types) and [stack usage](https://learn.microsoft.com/en-us/cpp/build/stack-usage) documentation.

## Model and presentation

`functionABI.version` is 8. Additive `declarationLocationPolicy` is `windows-x64-declared-integer-pointer-v1`; `declarationLocations` contains each declaration's status, blockers, return and positional parameter rows. Row status is `declared`, `none` or `unknown`; widths and coordinates are null when unresolved. Register locations carry bit offset, width and container width. Stack locations carry `entry_rsp`, a decimal byte offset, value width and slot size.

Native report schema 2, preview version 8 and contract versions 1/2/3 remain unchanged. Derived locations do not enter exported analyst contracts. The inspector's **Declared ABI locations** table, CLI `--abi` output and model JSON share the same mapping. Original annotations and sources are escaped and retained. Details support keyboard navigation and phone-width horizontal table scrolling.

## Validation

Local validation passed 31 CTest targets per backend, 178 declared-location checks, 454 ABI graph checks, 109 Capstone / 3 LLVM ABI browser checks and 90 Capstone / 13 LLVM C-like browser checks.

The independent Unicorn oracle executes authored caller/callee bytes in six cases, checking 48 parameter values, five return values and one void-return case. Dirty unused register bits and stack padding expose incorrect widths. Two deliberately incorrect coordinates are rejected. LLVM explicitly skips the typed execution oracle because it does not provide structured operands.

## Remaining work

Next associate declared placements with source-linked observed register and stack evidence while retaining uncertainty. This must not select a winning declaration, infer a signature, or claim prototype compatibility. Full M7.4 remains open.

## Hosted validation — 2026-10-30

Implementation: [b354205](https://github.com/ASR-Tanyi/windows-exe-analyzer/commit/b354205afe0156dcb1b3f57c070a0bd840c93933).

The [hosted matrix](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/40998578854) passed both Capstone and LLVM jobs, including 33 CTest targets per backend and all browser suites. Local decoder/CLI validation passed 161 checks. The independent execution suites retained their existing machine-semantics coverage and the new six-case declared-location oracle passed.

The [Pages deployment](https://github.com/ASR-Tanyi/windows-exe-analyzer/actions/runs/40998578835) passed. Its manifest identifies the implementation commit. All eight downloaded HTML reports contain the exact committed declaration parser, location mapper, ABI model/view and pseudocode model/view. The published x64 O1 report passed the full 109-check ABI browser suite, including conditional locations, unknown prerequisites, alias clearing, unchanged code, export/CLI parity and phone layout. Authored synthetic caller cases within that suite remain separate from the published source demonstration.
