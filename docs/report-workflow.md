# Generate and open HTML reports with GitHub Actions

The **HTML reports** workflow builds the analyzer, runs regression tests, creates
a report index, saves downloadable artifacts, and deploys the site to GitHub
Pages. Nothing generated is committed to `main` or `demo_exe`.

## One-time setup

Open **Settings > Pages > Build and deployment > Source**, then select **GitHub
Actions**. Do not select a branch or create another starter workflow. Keep the
`github-pages` deployment environment restricted to `main`.

The workflow cannot enable Pages using the default `GITHUB_TOKEN`. When Pages
is disabled, its build still saves reports; the deploy job explains the missing
setup and fails. After enabling Pages, re-run failed jobs while the Pages artifact
is retained (7 days), or start a fresh run.

## Run a demo

Open **Actions > HTML reports > Run workflow**. Select branch **main**, leave
`source=demo` and `publish=true`, and run it. Relevant source changes on `main`
also automatically rebuild the demo site. Runs selected on another branch are
skipped; `file_ref` selects an input file's branch, not the workflow's code.

After the deploy job succeeds, click **Open all reports** in the run summary or
**View deployment** in the `github-pages` environment. With the default domain:

- Index: https://asr-tanyi.github.io/windows-exe-analyzer/
- x64 demo: https://asr-tanyi.github.io/windows-exe-analyzer/demo64.html
- x86 demo: https://asr-tanyi.github.io/windows-exe-analyzer/demo32.html
- C recovery x64, O0: https://asr-tanyi.github.io/windows-exe-analyzer/recovery64-o0.html
- C recovery x64, O1: https://asr-tanyi.github.io/windows-exe-analyzer/recovery64-o1.html
- C recovery source: https://asr-tanyi.github.io/windows-exe-analyzer/recovery.c
- Custom input, when present: https://asr-tanyi.github.io/windows-exe-analyzer/sample.html

These are expected addresses, not a claim that Pages has already been enabled.
The actual deployment URL returned by GitHub is used in the run summary, so
custom domains also work.

## Analyze another EXE or DLL

All modes retain the four baseline and four C-recovery reports; custom modes add
one input report. The C-recovery reports cover x86/x64 at O0/O1. Select a function
such as `transform_demo`, then **C-like**. See the [recovery contract](c-like-recovery.md)
for supported forms and limitations.

| source | target | Other inputs |
| --- | --- | --- |
| `demo` | Leave blank | No external input; EXE/DLL fixtures are built from test source. |
| `release` | Exact asset name, e.g. `program.exe` | `release_tag=v1.0` or `latest`; release is in this repository. |
| `url` | A direct, publicly downloadable HTTPS `.exe` or `.dll` URL | Optional `sha256`. |
| `repository` | Repository-relative path, e.g. `samples/program.exe` | `file_ref=demo_exe`, another branch, tag, or commit SHA. |

For release mode, first upload the EXE/DLL as an asset of a **published release**,
then run this workflow. Publishing a release does not automatically start it.
A blank asset name is accepted only when the release has exactly one EXE/DLL
asset. This avoids silently selecting the wrong architecture. Private/draft
release assets and authenticated URLs are not supported. `latest` uses GitHub's
latest-release endpoint; use an explicit tag for a prerelease.

The repository's existing demo archive is not a direct EXE: use `source=demo`
instead. Arbitrary ZIP/TAR extraction is deliberately unsupported. Keep externally
supplied binaries on `demo_exe` or in release assets, never on `main`.

`sha256` is an optional 64-hex-character expected checksum. A mismatch stops the
run. A manifest records each input hash, the analyzer source commit and run ID.

Set `publish=false` to generate only an Actions artifact without changing Pages.
Download `html-reports-<run-id>-<attempt>`, extract it, and open `index.html`.
GitHub's artifact download is not an in-browser HTML preview. Downloadable reports
are retained for 30 days, subject to repository/organization retention limits.

## Publishing behavior and privacy

The Pages site represents the **latest successful publishing run**. Each deployment
replaces the site; old run-specific URLs are not retained. An automatic demo run
can replace a previously published custom report. Download artifacts to keep older
reports. A failed build leaves the previous deployment in place.

**Reports embed original bytes and strings. Treat all submitted inputs as public.**
No EXE/DLL file is copied into the published directory, but that does not make its
contents confidential. Do not submit proprietary binaries, secrets, credentials,
or signed/private download links. Artifact-only mode is not a privacy guarantee.

Custom inputs are limited to 64 MiB and must have x86 PE32 or x64 PE32+ headers.
The analyzer gets a 100,000-instruction limit, 4 MiB static-byte budget and a
120-second process timeout. Large or indirect-control-flow-heavy programs can
produce partial reports; this is not a full decompiler or runtime trace.

The hosted workflow analyzes custom inputs in a Docker container with no network,
a read-only root, a non-root UID, no extra capabilities, limited memory/CPU/PIDs,
and only dedicated input/output mounts. No CI token is passed to the analyzer.
Download URLs and redirects must be public HTTPS endpoints. These controls reduce
risk but do not turn the educational PE parser into a hardened malware sandbox.
Use GitHub-hosted runners; do not move untrusted-input analysis to a sensitive
self-hosted machine. The separate deployment job alone gets Pages/OIDC write
permissions. Actions are pinned to commit SHAs and credentials are not persisted
by checkout.

## Local generation and tests

The site generator requires Python 3.11+. After building the analyzer:

```sh
ctest --test-dir build --output-on-failure
python3 -m unittest discover -s tests -p 'test_report_site.py' -v
python3 scripts/report_site.py \
  --analyzer build/windows-exe-analyzer --fixtures build/test-fixtures \
  --output build/site
```

The output directory must be new or empty. The local CLI can run custom analysis
without Docker only for trusted samples; use `--sandbox-image` for a prepared
Linux runtime image. The workflow always supplies that image for custom inputs.

Implementation: `.github/workflows/html-report.yml`, `scripts/report_site.py`,
`scripts/Dockerfile.report`, and `tests/test_report_site.py`.

GitHub documentation:
- https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site
- https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages
