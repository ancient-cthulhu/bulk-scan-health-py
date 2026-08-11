# Veracode Tenant-Wide Scan Health

A Python tool that evaluates the health of every SAST scan across all application profiles in a Veracode tenant and exports the results to Excel, CSV, or JSON.

This is a port of [veracode/scan_health](https://github.com/veracode/scan_health) (Go, v2.47), re-engineered to operate in bulk across an entire tenant. All health checks, pattern lists, thresholds, severity classifications, and recommendation strings from the original Go tool are preserved and individually callable. The output includes scan health summary, module details, uploaded files, per-app recommendations, tenant-level issue aggregation, and optional trend analysis against a prior run.

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

---

## Quick Start

```bash
# All apps, default Excel output
python script.py

# Limit to the first 10 apps
python script.py --max-apps 10

# Filter to specific apps
python script.py --app-name-filter "^MyApp.*"

# Include sandboxes, EU region
python script.py --include-sandboxes --region eu

# Parallel execution with 4 workers
python script.py --parallel 4 --delay 0.2

# JSON output
python script.py --output-format json --output results.json

# Trend analysis against last week's report
python script.py --previous-report last_week.xlsx

# Resume a partial run
python script.py --resume partial_output.xlsx

# Dry run (list apps only)
python script.py --dry-run

# Skip specific checks
python script.py --skip-checks 1,17,30

# Executive dashboard (adds 3 sheets to the front of the workbook)
python script.py --dashboard
```

---

## Command-Line Options

| Option | Default | Description |
|---|---|---|
| `--output` | `scan_health_YYYYMMDD_HHMMSS.xlsx` | Output file path |
| `--output-format` | `xlsx` | Output format: `xlsx`, `csv`, or `json`. CSV writes one file per sheet. |
| `--max-apps` | `0` (all) | Limit number of apps to process |
| `--delay` | `0.5` | Delay in seconds between apps for rate limiting |
| `--skip-no-scan` | `false` | Skip apps with no policy scan builds |
| `--include-sandboxes` | `false` | Also evaluate sandbox scans |
| `--region` | `commercial` | Veracode region: `commercial` or `eu` |
| `--app-name-filter` | None | Regex to filter application names |
| `--parallel` | `1` | Number of concurrent worker threads |
| `--resume` | None | Path to a prior partial xlsx; skips already-processed apps |
| `--previous-report` | None | Path to a prior run's xlsx for trend analysis |
| `--dry-run` | `false` | List apps that would be processed, then exit |
| `--log-level` | `INFO` | Logging level: `DEBUG`, `INFO`, or `WARNING` |
| `--timeout` | `120` | Per-request HTTP timeout in seconds |
| `--skip-checks` | None | Comma-separated check numbers to skip (e.g. `1,17,30`) |
| `--dashboard` | `false` | Add the executive dashboard sheets. See [DASHBOARD.md](DASHBOARD.md) |
| `--dashboard-output` | None | Dashboard workbook path. Only used with `--output-format csv` or `json` |

---

## Executive Dashboard

`--dashboard` prepends three sheets to the workbook for leadership reporting. The seven sheets below are unchanged.

| Sheet | Contents |
|---|---|
| **Executive Dashboard** | KPI cards, health distribution, attention bands, priority matrix, top organisational issues, tenant trend, applications requiring attention |
| **App Heatmap** | One row per profile: health, scan age, Veracode score/rating, policy status, flaw severity breakdown, density, and the basis behind each rating. Autofilter and frozen panes |
| **Issue Heatmap** | All 31 checks with prevalence, severity, and trend |

Each application gets an **Attention Score** (0-100) for prioritisation. It does not replace the Good/Fair/Poor classification, and it is explainable: every score lists its drivers (e.g. `Scan health is POOR (+27); 7 open very-high flaws (+23); scan is 260 days old (+18)`). Thresholds and weights are configurable in `DASHBOARD_CONFIG`.

Findings risk is an absolute severity floor plus a size-aware volume signal. The floor means an open Very High is never green regardless of application size. For volume, the tool uses Veracode's own scan score and rating when the scan reports them, since those are already severity-weighted and size-adjusted; otherwise it falls back to severity-weighted open flaws (VH 10, H 5, M 1, L 0.1) divided by `analysis_size_bytes`, so a large app is not penalised for being large. Every application records the signal that classified it in `Findings Basis`. Policy compliance status is reported alongside, with unknown outcomes excluded from the pass rate rather than counted as failures. All thresholds and the density basis are configurable.

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

---

## Output Format

### Excel (default)

Seven sheets. `--dashboard` prepends three more, leaving these unchanged: **Executive
Dashboard**, **App Heatmap** and **Issue Heatmap**. See [DASHBOARD.md](DASHBOARD.md).

1. **Scan Health Summary**: One row per app/sandbox. Includes health status, flaw breakdown, selected module names, SCA component count, scan age bucket, total upload size, health trend, issues, recommendations, platform URLs, and an open-flaw severity breakdown (Very High / High / Medium / Low) with a `Flaw Severity Data` availability flag. Health and Scan Age Bucket columns are conditionally formatted.

2. **Module Details**: One row per module per build with selection status, dependency flag, fatal errors, third-party classification, platform, compiler, size, and prescan issues.

3. **Uploaded Files**: One row per file per build with status, MD5, ignored/third-party flags.

4. **Recommendations**: One row per recommendation per app. Includes severity, recommendation text, and any documentation URL extracted from the text.

5. **Trends** (when `--previous-report` provided): Per-app comparison showing previous and current health, flaw counts, and open-policy flaw deltas.

6. **Tenant Aggregation**: Most common issues across all apps with occurrence count, severity, affected app names, and the top recommendation.

7. **Tenant Overview**: Aggregate statistics including health distribution, total flaws, and average scan age.

### CSV

One file per sheet, named `{stem}_{sheet}.csv`.

### JSON

Single structured file:

```json
{
  "generated": "2026-05-01T12:00:00+00:00",
  "summary": {"total": 100, "good": 60, "fair": 25, "poor": 15},
  "apps": [...],
  "modules": [...],
  "files": [...],
  "trends": [...] | null
}
```

---

## API Calls

| Endpoint | Purpose |
|---|---|
| `GET /appsec/v1/applications` (REST) | List all app profiles |
| `GET /api/5.0/detailedreport.do` | Scan results, flaws, modules, SCA |
| `GET /api/5.0/getappinfo.do` | Last-modified date for recency check |
| `GET /api/5.0/getbuildlist.do` | Build list for policy and sandboxes |
| `GET /api/5.0/getbuildinfo.do` | Build status to find latest published build |
| `GET /api/5.0/getfilelist.do` | Uploaded files with MD5 |
| `GET /api/5.0/getprescanresults.do` | Prescan modules with issues |
| `GET /api/5.0/getsandboxlist.do` | Sandbox list (when `--include-sandboxes`) |

For N apps: approximately 6N API calls (7N with sandboxes, plus per-sandbox calls).

---

## Differences from the Go Tool

- **Bulk operation**: iterates all apps in a tenant, not a single scan URL
- **Excel/CSV/JSON output**: replaces console + JSON output
- **Trend analysis**: compares against a prior run
- **Resume**: can continue from a partial run
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
