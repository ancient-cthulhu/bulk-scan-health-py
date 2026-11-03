# Veracode Scan Health

Checks the health of Veracode SAST scans: across a whole tenant, for one application, or for one scan. Python port of [veracode/scan_health](https://github.com/veracode/scan_health) (Go v2.47) with all 31 checks.

Not an official Veracode product.

## Install

Python 3.11+.

```bash
pip install veracode-api-signing requests openpyxl
pip install defusedxml        # optional, hardened XML parsing
```

## Authenticate

Standard Veracode HMAC credentials, in `~/.veracode/credentials`:

```ini
[default]
veracode_api_key_id = YOUR_API_KEY_ID
veracode_api_key_secret = YOUR_API_KEY_SECRET
```

or as `VERACODE_API_KEY_ID` / `VERACODE_API_KEY_SECRET`. Role: Reviewer or Security Lead (Results API for API users).

## Run

**Tenant (bulk)**

```bash
python scan_health.py --dry-run                          # list profiles, estimate runtime
python scan_health.py                                    # all profiles
python scan_health.py --include-sandboxes --region eu
python scan_health.py --app-name-filter "^Pay" --max-apps 10
```

Writes `scan_health.xlsx`, `tenant_report.html`, module/file CSVs and a checkpoint to a run folder. An interrupted run resumes when you rerun the same command (within 72 hours; `--restart` starts fresh). Run weekly for trends.

**One application**

```bash
python scan_health.py --app "Payments API"               # latest 10 policy scans
python scan_health.py --app "<platform link to the app or a sandbox>"
python scan_health.py --app-id <app_id> --history 25
python scan_health.py --app "Payments API" --sandbox "feature-x"
```

**One scan**

```bash
python scan_health.py --scan "<platform link to the scan>"   # --sast is an alias
python scan_health.py --scan <build_id>                       # build ID
python scan_health.py --scan <build_id> --history 0           # no trend
```

**Links.** Copy the link from the Veracode Platform address bar. Either form works:

```
https://analysiscenter.veracode.com/auth/index.jsp#<Page>:<account_id>:<app_id>:...
https://analysiscenter.veracode.com/?loc=<Page>:<account_id>:<app_id>:...
```

- `--app`: the application page (`HomeAppProfile`), a sandbox (`SandboxView`), or any scan page.
- `--scan`: a scan page (Triage Flaws, Review Modules, Static Overview, source files, result summary, detailed report, SCA) or a sandbox (its latest scan).
- `.com` is the commercial region and `.eu` is EU. FedRAMP is not supported.
- Quote links in the shell. The trend uses earlier scans in the same policy or sandbox.

App and scan runs write `report.html` and `report.json`. `report.json` field names and values stay stable across versions (schema 1.0); `owner_role` on actions is kept but always empty. The HTML report is one self-contained file (offline, light and dark) with verdicts, a ranked action plan, changes since the previous scan, all checks, duration and findings trends. It has a **Save as PDF** button (A4, via the browser's print dialog, also Ctrl+P). The PDF is a summary: every section, with narrow tables sized for the page; longer parts (changes and checks, scan time, findings, modules) start on a new page. Every full table on screen has a **Copy table** button that pastes as a table into Excel, Sheets, Word or an email. Every trend is compared within one scope, shown in the header: the app's policy scans, one sandbox, or nothing for a single scan.

**Large applications:** each analysed build costs one `detailedreport.do`, which Veracode can take minutes to produce for very large apps. If a detailed report fails (including Veracode answering "No report available." for a published build, seen after about 5 minutes on very large apps), the build falls back to `summaryreport.do` (timing, size, policy, flaw counts; checks marked not run). If one is slow (over 2 minutes) or fails, older builds use the summary report automatically. Failures print their reason on the console. `--history-mode light` does the same from the start.

Bad links are rejected before any API call, with the reason. While the app or scan is being resolved, a 401/403 or an unreachable API stops in seconds instead of retrying. These exit with code `2` and write nothing.

## Output folders

```
scan_health_output/                (--out-dir)
  tenant/<region>/<date_time>/     bulk runs
  apps/<app>_<id>/<date_time>/     --app  (scan_<build>_<date_time>/ for --scan)
  history/                         keep: snapshots and per-app history (trends)
  cache/                           safe to delete: raw API responses
```

`history/` and `cache/` contain file names and flaw data; on Linux and macOS they are restricted to your user. `--no-cache` disables the cache. Explicit `--output`, `--report-dir`, `--cache-dir` and `--snapshot-dir` are used as given.

**Exit codes:** `0` ok, `1` auth or fatal API error, `2` usage error or unresolved app/scan, `3` report write failed, `130` interrupted. A partial report is written on `1` and `130`.

## Rate limiting

Veracode limits per IP: 80/min for `detailedreport.do` and other results XML APIs, 250/min for other XML APIs, 500/min for REST. Each class is paced separately at `--rate-budget` percent (default 70). A policy profile costs about 4 calls, so the default runs about 56 profiles/min. `--parallel` only hides slow responses; it does not raise the rate. Every retry (timeout, 5xx, 401) is sent with a fresh HMAC signature.

## Options (bulk)

| Option | Default | Description |
|---|---|---|
| `--out-dir` | `./scan_health_output` | Root output folder |
| `--output` | run folder | Main output file, used as given |
| `--output-format` | `xlsx` | `xlsx`, `csv` or `json` |
| `--region` | `commercial` | `commercial` or `eu` |
| `--rate-budget` | `70` | Percent of each rate limit to use |
| `--parallel` | `8` | Worker threads |
| `--max-retries` | `8` | Retries for 5xx |
| `--retry-backoff` | `2.0` | Backoff factor for 5xx |
| `--timeout` | `120` | HTTP timeout, seconds |
| `--report-timeout` | `600` | Read timeout for `detailedreport` and other report APIs, seconds |
| `--auth-retry-window` | `3600` | Seconds to retry a request through 401/403 |
| `--max-apps` | `0` (all) | Limit app count |
| `--app-name-filter` | | Regex on app names |
| `--include-sandboxes` | off | Also check sandbox scans |
| `--skip-no-scan` | off | Skip apps without a policy scan |
| `--skip-checks` | | Check numbers to skip, e.g. `1,17,30` |
| `--detail` | `csv` | Module/file rows: `csv`, `xlsx` or `none` |
| `--no-dashboard` | off | Skip the dashboard sheets |
| `--dashboard-output` | | Dashboard workbook for csv/json output |
| `--previous-report` | | Prior xlsx for per-app trends |
| `--snapshot-dir` | `<out-dir>/history/tenant` | Snapshot folder |
| `--no-snapshot` | off | Do not save a snapshot |
| `--keep-snapshots` | `0` (all) | Keep the newest N snapshots |
| `--trend-window` | `12` | Snapshots used for tenant trends |
| `--no-html` | off | Skip `tenant_report.html` |
| `--checkpoint` | `<output>.ckpt.jsonl` | Checkpoint path |
| `--restart` | off | Start a new run |
| `--dry-run` | off | List and estimate, then exit |
| `--log-level` | `INFO` | `DEBUG`, `INFO` or `WARNING` |

App and scan options: `--app`, `--app-id`, `--app-guid`, `--sandbox`, `--scan`, `--history`, `--history-since`, `--history-mode`, `--formats`, `--report-dir`, `--hide-teams`. See `--help`.

Teams come from the application profile. Access teams named `Service Delivery - *` are not shown; `--hide-teams "Pattern*,Other"` hides more.

## Outputs (bulk)

- **Workbook:** Executive Dashboard, App Heatmap, Issue Heatmap, Scan Health Summary, Recommendations, Tenant Aggregation, Tenant Overview, and Trends with `--previous-report`. CSV writes one file per sheet; JSON writes one document.
- **tenant_report.html:** scan health and findings side by side; a fix list filterable by team, business unit, check and priority, with CSV export; a heatmap and a group table with per-run trends; where to focus, changes and trends. A **Group by** switch (business unit or team) changes every grouped view; it starts on whichever most profiles use. A profile in several teams counts in each. Analysis time is compared per profile against its own earlier scans and by size band, never as one tenant-wide average. A "How results are classified" section states every rule the report uses. One page, no external resources; values are escaped and the only script is allowed by hash.
- **Snapshots:** a small gzip record per run, used for tenant trends. Only runs with the same scope are compared.

**Priority** (same rule in every report) comes from what the problem does to the results, as Veracode's scan_health describes each check. P1: code not scanned (high severity), sensitive files or a Git repository uploaded, or Very High flaws open. P2: other code not scanned, code you do not ship analysed, a likely misconfiguration, old results, policy not met. P3: slower scans only. **Effort**: Small (packaging), Medium (build change), Large (code or toolchain).

Scan health and findings are separate: a healthy scan does not mean no vulnerabilities. Apps without a published scan are Unknown, not healthy. Only `accepted` mitigations close a flaw. A failed API retrieval marks the profile `Error`, never clean.

## Health checks

| # | Check | Severity | Flags |
|---|---|---|---|
| 1 | ignoreJunkFiles | Medium | Unnecessary files uploaded |
| 2 | thirdParty | Medium | Third-party libraries as entry points |
| 3 | flawCount | Medium | Zero or over 2,500 flaws |
| 4 | fatalErrors | High | Missing PDB, no Java binaries, nested JARs |
| 5 | unscannableJava | High | Java modules with fatal errors |
| 6 | detectUnwantedFiles | Medium | 7z, scripts, installers, pyc, ClickOnce and similar |
| 7 | nestedArchives | High | Archives inside archives |
| 8 | missingPrecompiled | High | ASP.NET views not precompiled |
| 9 | missingSCA | Medium | No SCA results |
| 10 | unselectedJS | Medium | JavaScript modules not selected |
| 11 | unexpectedSource | High | Source code instead of binaries |
| 12 | missingSupporting | Medium | Missing supporting files |
| 13 | missingDebug | Medium | .NET modules without PDB |
| 14 | unsupportedPlatform | High | Unsupported compiler or platform |
| 15 | gradleWrapper | High | gradle-wrapper.jar selected |
| 16 | sensitiveFiles | High | Keys, certificates, secrets, Office docs, notebooks |
| 17 | repositories | Medium | Git repository uploaded |
| 18 | nodeModules | Medium | node_modules uploaded |
| 19 | testingArtefacts | High/Medium | Test frameworks or mocks |
| 20 | tooManyFiles | Medium | Over 10,000 files |
| 21 | excessMicrosoft | Medium | .NET Roslyn components |
| 22 | looseClassFiles | Medium | Loose Java .class files |
| 23 | goWorkspace | Medium | Go workspace files |
| 24 | unselectedFirstParty | Medium | First-party modules not selected |
| 25 | overScanning | Medium | Overlapping selected modules |
| 26 | dependenciesSelected | Medium | Dependencies as entry points |
| 27 | duplicateFiles | High/Medium | Duplicate file names |
| 28 | minifiedJS | Medium | Minified JavaScript |
| 29 | moduleCount | Medium | Over 500 modules or 100 selected |
| 30 | regularScans | Medium | No scan in 30 days |
| 31 | analysisSize | Medium | Over 500 MB analysed or 1 GB of modules |

## API calls

REST `/appsec/v1/applications`; XML `getbuildinfo`, `detailedreport`, `getfilelist`, `getprescanresults`, plus `getbuildlist` (fallback) and `getsandboxlist` (sandboxes). About 4 calls per profile.

## Differences from the Go tool

Adds bulk mode, Excel/CSV/JSON, dashboard, trends, checkpoint and resume, per-endpoint pacing, and skippable checks. It picks the latest published build. Not ported: scan compare, self-update and region auto-detection (use `--region`).

## Repository

```
scan_health.py   entry point
helpers/         report, analytics, rendering and layout modules
tests/           pytest, offline fixtures
```

## License

MIT, as the original. No support or warranty.
