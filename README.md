# Veracode Tenant-Wide Scan Health

A Python tool that evaluates the health of every SAST scan across all application profiles in a Veracode tenant and exports the results to Excel, CSV, or JSON.

This is a port of [veracode/scan_health](https://github.com/veracode/scan_health) (Go, v2.47), re-engineered to operate in bulk across an entire tenant. All health checks, pattern lists, thresholds, severity classifications, and recommendation strings from the original Go tool are preserved and individually callable. The output includes scan health summary, module details, uploaded files, per-app recommendations, tenant-level issue aggregation, an executive dashboard, and optional trend analysis against a prior run.

Runs at tenant scale are measured in hours. Three things make that survivable: an incremental checkpoint written after every profile, rate limiting paced separately against each of Veracode's published per-endpoint ceilings, and a report write that happens on every exit path including failure.

---

## Requirements

- Python 3.11 or later
- A Veracode API credentials file or environment variables
- The Reviewer or Security Lead role on the Veracode account

```
pip install veracode-api-signing requests openpyxl
```

---

## Authentication

Configure credentials using the standard Veracode HMAC approach.

### Credentials file

Create `~/.veracode/credentials`:

```ini
[default]
veracode_api_key_id = YOUR_API_KEY_ID
veracode_api_key_secret = YOUR_API_KEY_SECRET
```

### Environment variables

```bash
export VERACODE_API_KEY_ID=YOUR_API_KEY_ID
export VERACODE_API_KEY_SECRET=YOUR_API_KEY_SECRET
```

Credentials are signed per request. If they are rotated or revoked mid-run, the tool retries rather than aborting. See [Failure handling](#failure-handling).

---

## Quick Start

```bash
# All apps, default Excel output, dashboard included
python scan_health.py

# Estimate runtime and list what would be processed
python scan_health.py --dry-run

# Conservative pacing
python scan_health.py --rate-budget 20

# Faster turnaround, heavier API use
python scan_health.py --rate-budget 50 --parallel 8

# Limit to the first 10 apps
python scan_health.py --max-apps 10

# Filter to specific apps
python scan_health.py --app-name-filter "^MyApp.*"

# Include sandboxes, EU region
python scan_health.py --include-sandboxes --region eu

# JSON output
python scan_health.py --output-format json --output results.json

# Trend analysis against last week's report
python scan_health.py --previous-report last_week.xlsx

# Skip specific checks
python scan_health.py --skip-checks 1,17,30

# Discard the checkpoint and start clean
python scan_health.py --restart
```

There is no resume command. Rerunning the same command resumes automatically.

---

## Rate limiting

There are three separate ceilings, **all per IP address**:

| Endpoint class | Limit |
|---|---|
| Flaw Report and Results XML APIs (`detailedreport.do`, `summaryreport.do`, and similar) | 80 calls/minute |
| All other XML APIs | 250 calls/minute |
| All REST APIs | 500 calls/minute |

Each class is paced against its own ceiling. `--rate-budget` sets the share of every ceiling to consume, defaulting to 70%. Requests within a class are spaced evenly rather than burst, so traffic never spikes at the start of a minute window.

Each policy profile costs **4 requests**: one in the 80/min bucket and three in the 250/min bucket. The two ceilings therefore bind at almost the same point (80 vs 250/3 = 83 profiles/min), so no budget is stranded in either bucket.

### Choosing a budget

| `--rate-budget` | Profiles/min | Total req/min |
|---|---|---|
| 15 | 12 | 48 |
| 20 | 16 | 64 |
| 30 | 24 | 96 |
| 50 | 40 | 160 |
| 70 (default) | 56 | 224 |
| 85 | 68 | 272 |

`--dry-run` prints the estimate for your own tenant size and flags.

---

## Command-Line Options

| Option | Default | Description |
|---|---|---|
| `--output` | `scan_health_YYYYMMDD_HHMMSS.xlsx` | Output file path |
| `--output-format` | `xlsx` | `xlsx`, `csv`, or `json` |
| `--region` | `commercial` | `commercial` or `eu` |
| `--rate-budget` | `70` | Percent of each published per-IP rate limit to consume |
| `--parallel` | `8` | Concurrent workers. Does **not** raise the request rate |
| `--max-retries` | `8` | Retry attempts for 5xx responses |
| `--retry-backoff` | `2.0` | Exponential backoff factor for 5xx retries |
| `--timeout` | `120` | Per-request HTTP timeout in seconds |
| `--auth-retry-window` | `3600` | Seconds to retry a single request through 401/403 before abandoning it |
| `--max-apps` | `0` (all) | Limit number of apps to process |
| `--app-name-filter` | None | Regex to filter application names |
| `--include-sandboxes` | `false` | Also evaluate sandbox scans. Roughly doubles runtime |
| `--skip-no-scan` | `false` | Skip apps with no policy scan builds |
| `--skip-checks` | None | Comma-separated check numbers to skip (e.g. `1,17,30`) |
| `--detail` | `csv` | Where module and file rows go: `csv`, `xlsx`, or `none` |
| `--no-dashboard` | `false` | Skip the executive dashboard sheets |
| `--dashboard-output` | None | Dashboard workbook path, used only with `--output-format csv` or `json` |
| `--previous-report` | None | Path to a prior run's xlsx for trend analysis |
| `--checkpoint` | `<output>.ckpt.jsonl` | Checkpoint path |
| `--restart` | `false` | Move any existing checkpoint aside and start from scratch |
| `--dry-run` | `false` | List apps that would be processed with a runtime estimate, then exit |
| `--log-level` | `INFO` | `DEBUG`, `INFO`, or `WARNING` |

### `--parallel` does not make it faster

The request rate is fixed by `--rate-budget`. 

Workers exist so that slow responses do not leave the budget unused: `detailedreport.do` on a large application can take tens of seconds, and a single worker would idle through it. Eight is a sensible default. Raising it will not increase throughput.

---

## Executive Dashboard

On by default; it consumes no API calls. Three sheets are prepended to the workbook, leaving the others unchanged.

| Sheet | Contents |
|---|---|
| **Executive Dashboard** | KPI cards, health distribution, attention bands, priority matrix, top organisational issues, tenant trend, applications requiring attention |
| **App Heatmap** | One row per profile: health, scan age, Veracode score/rating, policy status, flaw severity breakdown, density, and the basis behind each rating. Autofilter and frozen panes |
| **Issue Heatmap** | All 31 checks with prevalence, severity, and trend |

Each application gets an **Attention Score** (0-100) for prioritisation.

Findings risk is an absolute severity floor plus a size-aware volume signal. The floor means an open Very High is never green regardless of application size. For volume, the tool uses Veracode's own scan score and rating when the scan reports them, since those are already severity-weighted and size-adjusted; otherwise it falls back to severity-weighted open flaws (VH 10, H 5, M 1, L 0.1) divided by `analysis_size_bytes`, so a large app is not penalised for being large. Every application records the signal that classified it in `Findings Basis`. Policy compliance status is reported alongside, with unknown outcomes excluded from the pass rate rather than counted as failures. All thresholds and the density basis are configurable in `DASHBOARD_CONFIG`.

Scan health and security findings are shown as separate dimensions. A healthy scan does not mean an application has no vulnerabilities, and poor scan health with a low flaw count is not evidence of safety. Applications with no published scan are reported as Unknown in grey, never as healthy.

With `--output-format csv` or `json`, the dashboard is written as a separate workbook via `--dashboard-output`.

---

## Health Checks

The tool runs 31 individual checks, each identified by number. All checks can be toggled via `--skip-checks`.

| # | Check | Severity | Description |
|---|---|---|---|
| 1 | ignoreJunkFiles | Medium | Unnecessary files uploaded (build artifacts, docs, images) |
| 2 | thirdParty | Medium | Third-party libraries selected as entry points |
| 3 | flawCount | Medium | Zero flaws or excessive flaws (>2,500) |
| 4 | fatalErrors | High | Missing PDB, no Java binaries, nested JARs |
| 5 | unscannableJava | High | Java modules with fatal errors |
| 6 | detectUnwantedFiles | Medium | 7z, CoffeeScript, scripts, installers, pyc/pyd, ClickOnce, CodeMeter |
| 7 | nestedArchives | High | Archives inside other archives |
| 8 | missingPrecompiled | High | ASP.NET views not precompiled |
| 9 | missingSCA | Medium | No SCA results when expected |
| 10 | unselectedJS | Medium | JavaScript modules not selected |
| 11 | unexpectedSource | High | Source code uploaded instead of compiled binaries |
| 12 | missingSupporting | Medium | Modules missing supporting files |
| 13 | missingDebug | Medium | .NET modules without PDB files |
| 14 | unsupportedPlatform | High | Unsupported compiler or platform |
| 15 | gradleWrapper | High | gradle-wrapper.jar selected for analysis |
| 16 | sensitiveFiles | High | Certificates, keys, secrets, Office docs, Jupyter notebooks |
| 17 | repositories | Medium | Git repository uploaded |
| 18 | nodeModules | Medium | node_modules folders uploaded |
| 19 | testingArtefacts | High/Medium | Test frameworks, mocks selected or uploaded |
| 20 | tooManyFiles | Medium | More than 10,000 files uploaded |
| 21 | excessMicrosoft | Medium | .NET Roslyn runtime components uploaded |
| 22 | looseClassFiles | Medium | Java .class files not in JAR/WAR/EAR |
| 23 | goWorkspace | Medium | Go multi-module workspace files |
| 24 | unselectedFirstParty | Medium | First-party modules not selected |
| 25 | overScanning | Medium | Dependencies selected that overlap with other selected modules |
| 26 | dependenciesSelected | Medium | Dependencies incorrectly selected as entry points |
| 27 | duplicateFiles | High/Medium | Duplicate filenames with same or different hashes |
| 28 | minifiedJS | Medium | Minified JavaScript files uploaded |
| 29 | moduleCount | Medium | Excessive module count (>500 total, >100 selected) |
| 30 | regularScans | Medium | Application not scanned within 30 days |
| 31 | analysisSize | Medium | Analysis size >500MB or total module size >1GB |

**Check 30** measures from the published date of the policy scan itself, taken from `detailedreport`. Earlier versions used the profile's `modified_date` from `getappinfo.do`, which moves whenever anyone edits the profile. The scan date is both the more honest signal and one fewer API call per application. 

---

## Output Format

### Excel (default)

| Sheet | Contents |
|---|---|
| **Executive Dashboard** | See above |
| **App Heatmap** | See above |
| **Issue Heatmap** | See above |
| **Scan Health Summary** | One row per app/sandbox: health status, flaw breakdown, selected module names, SCA component count, scan age bucket, total upload size, health trend, issues, recommendations, platform URLs, and an open-flaw severity breakdown (Very High / High / Medium / Low) with a `Flaw Severity Data` availability flag. Health and Scan Age Bucket columns are conditionally formatted |
| **Recommendations** | One row per recommendation per app, with severity and any documentation URL extracted from the text |
| **Trends** | Per-app previous-vs-current health, flaw counts, and open-policy flaw deltas. Present only with `--previous-report` |
| **Tenant Aggregation** | Each check that fired, with affected app count, share of tenant, business units, a normalised issue pattern, and the top recommendation |
| **Tenant Overview** | Aggregate statistics including health distribution, total flaws, and average scan age |

### Module and file detail

Module and file rows are streamed to `<output>_modules.csv` and `<output>_files.csv` during the run and are **not** placed in the workbook by default.

`--detail xlsx` restores the previous behaviour of embedding both as workbook sheets, which is fine for small tenants. `--detail none` discards them.

### CSV

One file per sheet, named `{stem}_{sheet}.csv`.

### JSON

Single structured file:

```json
{
  "generated": "2026-08-12T12:00:00+00:00",
  "summary": {"total": 100, "good": 60, "fair": 25, "poor": 15},
  "apps": [...],
  "modules": [...],
  "files": [...],
  "trends": [...] | null
}
```

---

## API Calls

| Endpoint | Bucket | Purpose |
|---|---|---|
| `GET /appsec/v1/applications` (REST) | rest | List all app profiles |
| `GET /api/5.0/getbuildinfo.do` | xml | Latest scan and its published date |
| `GET /api/5.0/detailedreport.do` | report | Scan results, flaws, modules, SCA, score, policy status |
| `GET /api/5.0/getfilelist.do` | xml | Uploaded files with MD5 |
| `GET /api/5.0/getprescanresults.do` | xml | Prescan modules with issues |
| `GET /api/5.0/getbuildlist.do` | xml | Fallback only, when the newest scan is unpublished |
| `GET /api/5.0/getsandboxlist.do` | xml | Sandbox list, with `--include-sandboxes` |

**Approximately 4N calls for N apps.**


---

## Differences from the Go Tool

- **Bulk operation**: iterates all apps in a tenant, not a single scan URL
- **Excel/CSV/JSON output**: replaces console + JSON output
- **Executive dashboard**: attention scoring, heatmaps, and tenant KPIs
- **Trend analysis**: compares against a prior run
- **Checkpointing and resume**: durable after every profile
- **Per-endpoint rate limiting**: paced against each published ceiling independently
- **Parallel execution**: configurable worker threads
- **Check toggling**: individual checks can be skipped by number
- **Build selection**: automatically finds the latest *published* build, not just the last build in the list
- **Scan compare** (`-action compare`) is not ported; this tool focuses on health assessment
- **Self-update** (GitHub releases check) is not ported
- **Region auto-detection** (`getmaintenancescheduleinfo.do`) is replaced by the `--region` flag
- **API response caching** (`-cache` flag) is not implemented

---

## License

This tool is not an official Veracode product. It comes with no support or warranty. The original scan_health tool is licensed under the MIT License. This port follows the same terms.
