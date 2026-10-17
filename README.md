# Veracode Tenant-Wide Scan Health

Analyze SAST scan health across a Veracode tenant or for a specific application, sandbox, or scan.

The tool identifies packaging and configuration issues, prioritizes fixes, tracks trends, and exports self-contained HTML reports plus Excel, CSV, JSON, or Markdown data.

> This is an unofficial Python port of [Veracode Scan Health](https://github.com/veracode/scan_health). It is not an official Veracode product.

## Install

Requires Python 3.11 or later.

```bash
pip install veracode-api-signing requests openpyxl
pip install defusedxml  # optional, recommended
```

## Authenticate

Use a Veracode account with the **Reviewer**, **Security Lead**, or **Results API** role.

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

## Run

### Entire tenant

```bash
# Preview scope and estimated runtime
python scan_health.py --dry-run

# Analyze all policy profiles
python scan_health.py

# Include sandboxes in the EU region
python scan_health.py --include-sandboxes --region eu

# Compare against a previous report
python scan_health.py --previous-report last_week.xlsx
```

Bulk runs resume automatically when the same command is rerun within 72 hours. Use `--restart` to start over.

### One application

```bash
python scan_health.py --app "Payments API" --dry-run
python scan_health.py --app "Payments API"
python scan_health.py --app-id 4242 --history 25
python scan_health.py --app "Payments API" --sandbox "feature-x"
python scan_health.py --app "Payments API" --history-since 2026-01-01
```

`--app` also accepts a quoted Veracode application, sandbox, or scan URL.

### One scan

```bash
# Analyze a published build
python scan_health.py --scan 12345678

# Analyze only that build, without trend history
python scan_health.py --scan 12345678 --history 0

# Use a quoted Veracode scan URL
python scan_health.py --scan "<veracode-scan-url>"

# --sast is an alias for --scan
python scan_health.py --sast "<veracode-scan-url>" --dry-run
```

A numeric build ID works after the scan has published results. The tool supports commercial and EU links. US/FedRAMP is not supported.

## Output

Everything is written under `./scan_health_output` by default:

```text
scan_health_output/
  tenant/<region>/<timestamp>/          tenant reports and exports
  apps/<app>_<app_id>/<timestamp>/      application reports
  apps/<app>_<app_id>/scan_<build>_<timestamp>/
  history/                              trend snapshots
  cache/                                reusable API responses
```

Use `--out-dir` to change the root folder.

### Tenant run

The primary output is `tenant_report.html`. Additional outputs include:

- `scan_health.xlsx`
- Module and file detail CSVs
- Tenant trend snapshot
- Resume checkpoint

### Application or scan run

The primary outputs are `report.html` and `report.json`.

`report.html` is self-contained, works offline, prints cleanly, and includes:

- Scan-health and security verdicts
- Ranked actions with owner, effort, evidence, fix, and verification
- Changes since the previous scan
- All 31 health checks
- Duration, throughput, size, cadence, and findings trends
- Module composition and data-quality notes

Default formats are `html,xlsx,json,md`. Select formats with `--formats`.

## Common options

```bash
# Process only matching applications
python scan_health.py --app-name-filter "^Payments.*"

# Limit a test run
python scan_health.py --max-apps 10

# Reduce API usage
python scan_health.py --rate-budget 20

# Increase workers without increasing the configured request rate
python scan_health.py --parallel 8

# Skip selected health checks
python scan_health.py --skip-checks 1,17,30

# Disable response caching
python scan_health.py --no-cache

# Start a new run instead of resuming
python scan_health.py --restart
```

| Option | Default | Purpose |
|---|---:|---|
| `--region` | `commercial` | `commercial` or `eu` |
| `--rate-budget` | `70` | Percentage of each API limit to consume |
| `--parallel` | `8` | Concurrent workers |
| `--max-apps` | `0` | Maximum applications; `0` means all |
| `--include-sandboxes` | Off | Include sandbox scans |
| `--skip-no-scan` | Off | Skip profiles without policy scans |
| `--skip-checks` | None | Check numbers to exclude |
| `--detail` | `csv` | Module/file detail: `csv`, `xlsx`, or `none` |
| `--previous-report` | None | Previous XLSX report for tenant trends |
| `--trend-window` | `12` | Comparable tenant snapshots |
| `--no-dashboard` | Off | Skip Excel dashboard sheets |
| `--no-html` | Off | Skip the tenant HTML report |
| `--no-cache` | Off | Disable response caching |
| `--restart` | Off | Ignore the resumable run |
| `--dry-run` | Off | Show scope and estimate without scanning |
| `--log-level` | `INFO` | `DEBUG`, `INFO`, or `WARNING` |

Run the following for the complete option list:

```bash
python scan_health.py --help
```

## Rate limits

Limits are applied separately and are **per IP address**:

| API class | Published limit |
|---|---:|
| Flaw Report and Results XML APIs | 80 calls/minute |
| Other XML APIs | 250 calls/minute |
| REST APIs | 500 calls/minute |

`--rate-budget` controls how much of each limit the tool uses. Requests are evenly paced rather than sent in bursts.

A policy profile normally requires four requests: one report request and three standard XML requests.

| Rate budget | Approx. profiles/minute |
|---:|---:|
| `20` | 16 |
| `30` | 24 |
| `50` | 40 |
| `70` | 56 |
| `85` | 68 |

Use `--dry-run` for an estimate based on the tenant and selected options.

`--parallel` does not raise the request rate. Workers prevent slow responses from leaving the configured budget unused.

## Health checks

The tool evaluates 31 scan-health conditions covering:

- Junk, sensitive, duplicate, and unwanted files
- Nested archives and repository contents
- Missing debug or supporting files
- Unscannable or unsupported modules
- Incorrect entry-point selection
- First-party, third-party, and dependency selection
- JavaScript, Java, .NET, Go, and ASP.NET packaging
- Excessive files, modules, or analysis size
- Missing SCA results
- Flaw-count anomalies
- Scan recency

Skip checks by number when needed:

```bash
python scan_health.py --skip-checks 1,17,30
```

Only flaws with an **accepted** mitigation are excluded from open-flaw counts. Proposed, rejected, and unmitigated flaws remain open.

Failed API retrieval is reported as **Error**, never as a healthy scan.

## Dashboard and reports

The tenant HTML report and Excel dashboard keep scan health separate from security risk:

- **Scan health** shows whether the scan is accurate, efficient, and current.
- **Security risk** shows findings severity, Veracode score or rating, and policy status.

A healthy scan does not mean the application has no vulnerabilities. Likewise, a low flaw count from an unhealthy scan is not evidence of safety.

The Excel workbook includes:

- **Executive Dashboard**
- **App Heatmap**
- **Issue Heatmap**
- **Scan Health Summary**
- **Recommendations**
- **Tenant Aggregation**
- **Tenant Overview**
- **Trends**, when a previous report is provided

Applications without a published scan are reported as **Unknown**, not healthy.

## Trends

Tenant runs save compact snapshots under:

```text
scan_health_output/history/tenant/<region>/<account_id>/
```

Run the tool regularly with the same scope to track:

- Degraded or improved applications
- New or stale scans
- Policy changes
- New Very High findings
- Renamed or removed profiles
- Recurring tenant-wide packaging issues

Snapshots are compared only when the region, filters, sandbox scope, application limit, and skipped checks match.

## Reliability

Tenant-scale runs may be long-running. The tool protects progress through:

- A checkpoint after every processed profile
- Automatic resume for matching runs
- Per-endpoint rate limiting
- Retries with exponential backoff
- Partial reports on fatal errors or interruption
- Cached API responses for application and scan runs

There is no separate resume command. Rerun the same command or use `--restart` to discard the current checkpoint.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Success |
| `1` | Authentication or fatal API error |
| `2` | Invalid usage or non-unique application match |
| `3` | Report write failed |
| `130` | Interrupted |

Once collection begins, the tool attempts to write a partial report on exit codes `1` and `130`.

## Repository layout

```text
scan_health.py       main entry point
helpers/             collection, analytics, output, and report modules
tests/               pytest suite with offline fixtures
```

## License

This tool is not an official Veracode product. It comes with no support or warranty. The original scan_health tool is licensed under the MIT License. This port follows the same terms.
