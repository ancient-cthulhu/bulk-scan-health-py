"""Tenant snapshots: write, read, select comparable series."""

from __future__ import annotations

import contextlib
import gzip
import json
import logging
import os
import re
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import scan_health as sh

from . import app_report as ar

log = logging.getLogger("scan_health.tenant_report")

SNAPSHOT_SCHEMA = "1.2"      # 1.1 adds "checks", 1.2 per-app "teams"; readers accept any 1.x
TOOL_VERSION = "4.1"
UNKNOWN_TENANT = "account-unknown"
_NAME_RE = re.compile(r"^\d{8}T\d{6}Z(-\d+)?\.json\.gz$")
_ACCOUNT_RE = re.compile(r"#[A-Za-z]+:(\d{1,12}):")


class SnapshotError(Exception):
    """A snapshot file that cannot be used (unreadable, corrupt, newer schema)."""


def run_scope(args: Any, skip_checks: set[int]) -> dict[str, Any]:
    """What a run covered."""
    return {
        "region": getattr(args, "region", "commercial"),
        "app_name_filter": getattr(args, "app_name_filter", None) or None,
        "max_apps": int(getattr(args, "max_apps", 0) or 0),
        "include_sandboxes": bool(getattr(args, "include_sandboxes", False)),
        "skip_no_scan": bool(getattr(args, "skip_no_scan", False)),
        "skip_checks": sorted(skip_checks),
        "check_count": len(sh.CHECK_REGISTRY),
    }


def comparable(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """True when two scopes describe the same population and check set."""
    keys = ("region", "app_name_filter", "max_apps", "include_sandboxes", "skip_no_scan",
            "skip_checks", "check_count")
    return all(a.get(k) == b.get(k) for k in keys)


def tenant_key(rows: list[dict[str, Any]]) -> str:
    """Account id read from the platform links in the rows (every Review Modules link carries it)."""
    for r in rows:
        m = _ACCOUNT_RE.search(str(r.get("Review Modules URL") or ""))
        if m:
            return m.group(1)
    return UNKNOWN_TENANT


def _app_key(guid: str, app_id: str, name: str, sandbox: str) -> str:
    """Stable identity across runs: GUID, then legacy id, then name."""
    if guid:
        return f"guid:{guid}|{sandbox}"
    if app_id and app_id != "0":
        return f"id:{app_id}|{sandbox}"
    return f"name:{name}|{sandbox}"


def _opt_int(v: Any) -> int | None:
    return sh._si_or_none(v)


def app_record(row: dict[str, Any], ah: sh.ApplicationHealth | None, guid: str,
               teams: list[str] | None = None) -> dict[str, Any]:
    """One compact record per profile (and sandbox) from the bulk row and its dashboard scoring."""
    app_id = str(row.get("App ID") or "")
    sandbox = str(row.get("Sandbox") or "")
    name = str(row.get("App Name") or "")
    sev = str(row.get("Flaw Severity Data") or "") == "Available"
    pub = sh._parse_dt(str(row.get("Published") or ""))
    rec: dict[str, Any] = {
        "key": _app_key(guid, app_id, name, sandbox),
        "guid": guid or None, "app_id": _opt_int(app_id), "name": name,
        "bu": str(row.get("Business Unit") or ""), "teams": list(teams or []),
        "policy_name": str(row.get("Policy") or ""),
        "sandbox": sandbox, "build_id": str(row.get("Build ID") or "") or None,
        "status": str(row.get("Scan Status") or ""),
        "published": pub.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if pub else None,
        "health": str(row.get("Health") or ""),
        "high_issues": _opt_int(row.get("High Issues")),
        "medium_issues": _opt_int(row.get("Medium Issues")),
        "sev_available": sev,
        "open_vh": _opt_int(row.get("Open Very High Flaws")) if sev else None,
        "open_h": _opt_int(row.get("Open High Flaws")) if sev else None,
        "open_m": _opt_int(row.get("Open Medium Flaws")) if sev else None,
        "open_l": _opt_int(row.get("Open Low Flaws")) if sev else None,
        "total_flaws": _opt_int(row.get("Total Flaws")),
        "open_policy_flaws": _opt_int(row.get("Open Affecting Policy")),
        "policy_status": str(row.get("Policy Status") or "") or None,
        "score": _opt_int(row.get("Veracode Score")),
        "rating": str(row.get("Veracode Rating") or "") or None,
        "duration_seconds": _opt_int(row.get("Duration (s)")),
        "analysis_size_mib": row.get("Analysis Size (MB)") if row.get("Analysis Size (MB)") else None,
        "files_uploaded": _opt_int(row.get("Files Uploaded")),
        "total_modules": _opt_int(row.get("Total Modules")),
        "selected_modules": _opt_int(row.get("Selected Modules")),
        "fatal_errors": _opt_int(row.get("Fatal Errors")),
        "sca_components": _opt_int(row.get("SCA Components")),
    }
    if ah is not None:
        rec.update({
            "attention": ah.attention_score, "attention_band": ah.attention_band,
            "attention_level": ah.attention_level, "failed_checks": list(ah.failed_checks),
            "sca_status": ah.sca_status, "scan_health_risk": ah.scan_health_risk,
            "findings_risk": ah.security_findings_risk, "quadrant": ah.quadrant,
            "top_issue": ah.top_issue or None, "ever_scanned": ah.ever_scanned,
        })
    return rec


def build_snapshot(rows: list[dict[str, Any]], bundle: dict[str, Any],
                   guid_by_id: dict[str, str], scope: dict[str, Any], *,
                   complete: bool, generated: str | None = None,
                   teams_by_id: dict[str, list[str]] | None = None) -> dict[str, Any]:
    """The snapshot document for one bulk run."""
    by_key = {(a.app_id, a.sandbox): a for a in bundle["apps"]}
    apps = []
    for r in rows:
        aid = str(r.get("App ID") or "")
        sbx = str(r.get("Sandbox") or "")
        apps.append(app_record(r, by_key.get((aid, sbx)), guid_by_id.get(aid, ""),
                               (teams_by_id or {}).get(aid)))
    m: sh.TenantMetrics = bundle["metrics"]
    metrics = asdict(m)
    metrics.update({"scan_compliance_pct": m.scan_compliance_pct,
                    "policy_pass_pct": m.policy_pass_pct, "healthy_pct": m.healthy_pct,
                    "errors": sum(1 for r in rows if r.get("Scan Status") == "Error")})
    issue_rows = bundle.get("issue_rows", [])
    issue_counts = {str(row["Check #"]): row["Apps Affected"] for row in issue_rows}
    # Capped: the text can quote file names.
    checks = {str(row["Check #"]): {"severity": str(row.get("Severity") or ""),
                                    "rec": str(row.get("Top Recommendation") or "")[:600]}
              for row in issue_rows}
    return {
        "schema_version": SNAPSHOT_SCHEMA,
        "tool_version": TOOL_VERSION,
        "generated": generated or datetime.now(timezone.utc).replace(microsecond=0)
        .isoformat().replace("+00:00", "Z"),
        "complete": complete,
        "tenant_key": tenant_key(rows),
        "scope": scope,
        "metrics": metrics,
        "check_apps_affected": issue_counts,
        "checks": checks,
        "apps": apps,
    }


def snapshot_dir(root: Path, region: str, key: str) -> Path:
    """<root>/<region>/<tenant-key>."""
    if region not in sh.REGIONS:
        raise ValueError(f"bad region {region!r}")
    if key != UNKNOWN_TENANT and not key.isdigit():
        raise ValueError(f"bad tenant key {key!r}")
    return root / region / key


def _stamp(generated: str) -> str:
    d = datetime.fromisoformat(generated.replace("Z", "+00:00")).astimezone(timezone.utc)
    return d.strftime("%Y%m%dT%H%M%SZ")


def write_snapshot(root: Path, snap: dict[str, Any]) -> Path:
    """Atomic, private write."""
    d = snapshot_dir(root, snap["scope"]["region"], snap["tenant_key"])
    created = not root.exists()
    ar.ResponseCache._ensure_dir(d)
    if created:
        with contextlib.suppress(OSError):
            (root / ".gitignore").write_text("# Created by scan_health.py\n*\n", encoding="utf-8")
    base = _stamp(snap["generated"])
    path = d / f"{base}.json.gz"
    n = 1
    while path.exists():
        path = d / f"{base}-{n}.json.gz"
        n += 1
    body = json.dumps(snap, separators=(",", ":"), sort_keys=True, default=str).encode("utf-8")
    fd, tmp = tempfile.mkstemp(dir=str(d), prefix=".tmp_", suffix=".json.gz")
    try:
        with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            gz.write(body)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return path


def list_snapshots(root: Path, region: str, key: str) -> list[Path]:
    """Snapshot files for one tenant, newest first (names sort by time)."""
    try:
        d = snapshot_dir(root, region, key)
    except ValueError:
        return []
    if not d.is_dir():
        return []
    return sorted((p for p in d.iterdir() if _NAME_RE.match(p.name)), key=lambda p: p.name, reverse=True)


def load_snapshot(path: Path) -> dict[str, Any]:
    """Read one snapshot."""
    try:
        with gzip.open(path, "rb") as fh:
            doc = json.loads(fh.read().decode("utf-8"))
    except (OSError, EOFError, ValueError) as e:
        raise SnapshotError(f"{path.name}: unreadable ({type(e).__name__})") from e
    if not isinstance(doc, dict) or not isinstance(doc.get("apps"), list):
        raise SnapshotError(f"{path.name}: not a snapshot")
    major = str(doc.get("schema_version", "")).split(".")[0]
    if major != SNAPSHOT_SCHEMA.split(".")[0]:
        raise SnapshotError(f"{path.name}: schema {doc.get('schema_version')} is not supported "
                            f"by this version ({SNAPSHOT_SCHEMA})")
    return doc


def select_series(root: Path, region: str, key: str, scope: dict[str, Any], window: int,
                  exclude: Path | None = None) -> tuple[list[dict[str, Any]], list[str]]:
    """Up to `window` comparable snapshots, newest first, plus a note for each one skipped and why."""
    series: list[dict[str, Any]] = []
    notes: list[str] = []
    for p in list_snapshots(root, region, key):
        if len(series) >= window:
            break
        if exclude is not None and p.resolve() == exclude.resolve():
            continue
        try:
            doc = load_snapshot(p)
        except SnapshotError as e:
            notes.append(f"Skipped snapshot {e}")
            continue
        if not comparable(doc.get("scope") or {}, scope):
            notes.append(f"Skipped snapshot {p.name}: different scope")
            continue
        doc["_path"] = str(p)
        series.append(doc)
    return series, notes


def prune(root: Path, region: str, key: str, keep: int) -> list[Path]:
    """Delete all but the newest `keep` snapshots for this tenant."""
    if keep <= 0:
        return []
    removed = []
    for p in list_snapshots(root, region, key)[keep:]:
        try:
            p.unlink()
            removed.append(p)
        except OSError as e:
            log.warning("Could not prune snapshot %s: %s", p, e)
    return removed


def finish_run(rows: list[dict[str, Any]], bundle: dict[str, Any] | None,
               guid_by_id: dict[str, str], args: Any, skip_checks: set[int], *,
               complete: bool, issue_records: list[dict[str, Any]] | None = None,
               teams_by_id: dict[str, list[str]] | None = None) -> tuple[Any, Path | None]:
    """End of a bulk run: save the snapshot (unless --no-snapshot), then read the comparable earlier
    snapshots and build the TenantReport."""
    from . import tenant_analytics as ta
    if bundle is None:
        bundle = sh.generate_dashboard(health_rows=rows, issue_records=issue_records or [],
                                       check_categories=sh.CHECK_CATEGORIES)
    scope = run_scope(args, skip_checks)
    hide = getattr(args, "hide_teams", None)
    teams = {k: ar.visible_teams(v, hide) for k, v in (teams_by_id or {}).items()}
    team_note = _team_note(teams_by_id or {}, teams)
    snap = build_snapshot(rows, bundle, guid_by_id, scope, complete=complete, teams_by_id=teams)
    root = Path(args.snapshot_dir).expanduser()
    path: Path | None = None
    if not getattr(args, "no_snapshot", False):
        try:
            path = _write_and_prune(root, snap, args)
        except Exception as e:
            log.warning("Snapshot not written (reports are unaffected): %s", e)
    window = max(1, int(getattr(args, "trend_window", 12) or 12))
    series, notes = select_series(root, scope["region"], snap["tenant_key"], scope,
                                  window - 1, exclude=path)
    rep = ta.analyse(snap, series, notes, extras=run_extras(rows, bundle, guid_by_id))
    log.info("[*] Teams: %s", team_note)
    rep.note("Teams", team_note, "info" if rep.has_teams else "warning")
    return rep, path


def _team_note(raw: dict[str, list[str]], shown: dict[str, list[str]]) -> str:
    """What the run found about teams, so an empty Team view is never a mystery."""
    n = len(raw)
    with_raw = sum(1 for v in raw.values() if v)
    with_shown = sum(1 for v in shown.values() if v)
    if not n:
        return "No team data was collected for this run."
    if not with_raw:
        return f"None of the {n:,} profiles has a team assigned in Veracode."
    if not with_shown:
        return (f"{with_raw:,} of {n:,} profiles have teams, but all are hidden access teams "
                "(Service Delivery - * or --hide-teams), so grouping is by business unit only.")
    return f"{with_shown:,} of {n:,} profiles have a team."


def run_extras(rows: list[dict[str, Any]], bundle: dict[str, Any],
               guid_by_id: dict[str, str]) -> dict[str, Any]:
    """Per-profile detail that only the current run has (not stored in snapshots): what each failing
    check found, its recommendation, and the Review Modules link of the analysed build."""
    def key(app_id: str, name: str, sandbox: str) -> str:
        return _app_key(guid_by_id.get(app_id, ""), app_id, name, sandbox)

    names = {(str(r.get("App ID") or ""), str(r.get("Sandbox") or "")): str(r.get("App Name") or "")
             for r in rows}
    links = {}
    for r in rows:
        aid, sbx = str(r.get("App ID") or ""), str(r.get("Sandbox") or "")
        url = str(r.get("Review Modules URL") or "")
        if url:
            links[key(aid, names[(aid, sbx)], sbx)] = url
    details: dict[tuple[str, int], tuple[str, str, str]] = {}
    for i in bundle.get("issues") or []:
        aid, sbx = str(getattr(i, "app_id", "") or ""), str(getattr(i, "sandbox", "") or "")
        k = key(aid, names.get((aid, sbx), str(getattr(i, "app_name", "") or "")), sbx)
        c = int(getattr(i, "check_number", 0) or 0)
        found = str(getattr(i, "description", "") or "")[:200]
        sev = str(getattr(i, "severity", "") or "")
        old = details.get((k, c))
        if old is not None:
            sev = old[0] if old[0] == "high" else sev
            sep = " " if old[1].endswith(".") else "; "
            found = (old[1] + sep + found)[:200] if found and found not in old[1] else old[1]
        details[(k, c)] = (sev, found, str(getattr(i, "recommendation", "") or "")[:600])
    return {"details": details, "links": links}


def _write_and_prune(root: Path, snap: dict[str, Any], args: Any) -> Path:
    path = write_snapshot(root, snap)
    removed = prune(root, snap["scope"]["region"], snap["tenant_key"],
                    int(getattr(args, "keep_snapshots", 0) or 0))
    if removed:
        log.info("[*] Pruned %d old snapshot(s)", len(removed))
    if snap["tenant_key"] == UNKNOWN_TENANT:
        log.warning("[!] Account id not found in the results; snapshot stored under '%s'.",
                    UNKNOWN_TENANT)
    return path


def html_path(args: Any) -> Path:
    """tenant_report.html in the run folder; with an explicit --output, <output without
    extension>_tenant_report.html next to it."""
    out = Path(str(getattr(args, "output", "") or "scan_health.xlsx")).expanduser()
    if getattr(args, "layout_run", False):
        return out.with_name("tenant_report.html")
    return out.with_name(f"{out.stem}_tenant_report.html")


def write_html(rep: Any, args: Any, client: Any = None) -> Path:
    """Render and atomically write the tenant HTML report."""
    from . import tenant_report_html
    collection: dict[str, Any] = {}
    if client is not None:
        collection["API requests this run"] = f"{int(getattr(client, 'request_count', 0)):,}"
        lim = getattr(client, "limiter", None)
        if lim is not None and getattr(lim, "started", None) is not None:
            import time
            collection["Elapsed"] = sh._hms(time.monotonic() - lim.started)
    path = html_path(args)
    ar.write_atomic(path, tenant_report_html.render_html(rep, collection or None))
    return path
