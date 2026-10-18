"""Tenant analytics over bulk-run snapshots. Pure functions, no I/O."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import scan_health as sh

from . import app_report_analytics as ana

TENANT_CONFIG: dict[str, Any] = {
    # Same threshold as the bulk dashboard ("fresh" vs "stale").
    "stale_days": sh.DASHBOARD_CONFIG["scan_age"]["healthy_days"],
    # Scan age buckets in days (upper bounds, inclusive); None is open-ended.
    "age_buckets": [(30, "0-30 days"), (60, "31-60 days"), (90, "61-90 days"),
                    (180, "91-180 days"), (365, "181-365 days"), (None, "Over 1 year")],
    # Analysis time buckets in seconds (upper bounds, exclusive).
    "duration_buckets": [(600, "Under 10 min"), (1800, "10-30 min"), (3600, "30-60 min"),
                         (7200, "1-2 h"), (14400, "2-4 h"), (None, "Over 4 h")],
    "score_buckets": [(59, "0-59"), (79, "60-79"), (100, "80-100")],
    "top_movement": 25,
    "top_list": 20,
    "top_checks": 5,
    "check_app_list": 50,
    "check_severity_weight": {"HIGH": 3, "MEDIUM": 1, "LOW": 0},
    # Tenant verdict thresholds. These are this tool's defaults, not Veracode
    # guidance; change them here.
    "verdict": {
        "poor_share_green": 10.0, "poor_share_yellow": 25.0,
        "vh_share_yellow": 5.0, "vh_share_orange": 15.0,
        "policy_pass_green": 80.0, "policy_pass_yellow": 60.0,
        "stale_share_green": 10.0, "stale_share_yellow": 25.0, "stale_share_orange": 50.0,
    },
}

HEALTH_ORDER = ("Good", "Fair", "Poor", "Unknown")
_HEALTH_RANK = {"Good": 0, "Fair": 1, "Poor": 2}
_BAND_ORDER = [b[2] for b in sh.DASHBOARD_CONFIG["attention_bands"]]
NO_BU = "No business unit"


@dataclass
class TenantVerdict:
    name: str
    level: str          # GREEN | YELLOW | ORANGE | RED | GRAY
    label: str
    reason: str


@dataclass
class TenantReport:
    """Everything the tenant renderers need. Plain data, JSON-serialisable."""
    generated: str
    tenant_key: str
    region: str
    scope: dict[str, Any]
    complete: bool
    kpis: dict[str, Any]
    verdicts: list[TenantVerdict]
    actions: dict[str, Any]
    distributions: dict[str, Any]
    checks: list[dict[str, Any]]
    business_units: list[dict[str, Any]]
    performance: dict[str, Any]
    findings: dict[str, Any]
    coverage: dict[str, Any]
    series: list[dict[str, Any]]
    movement: dict[str, Any] | None
    baseline: str | None            # generated time of the snapshot compared against
    apps: list[dict[str, Any]]      # current records, highest attention first
    notes: list[dict[str, str]] = field(default_factory=list)
    # Every failing check on every profile (the fix list). Details (what was
    # found, the recommendation, platform links) come from the current run
    # when available; snapshots alone give the check and its generic advice.
    fixes: list[dict[str, Any]] = field(default_factory=list)
    links: dict[str, str] = field(default_factory=dict)     # app key -> Review Modules URL

    def note(self, topic: str, message: str, level: str = "info") -> None:
        self.notes.append({"topic": topic, "message": message, "level": level})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ==========================================================================
# Small helpers
# ==========================================================================

def _dt(s: Any) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def scan_age_days(rec: dict[str, Any], at: str) -> int | None:
    """Days from the record's published date to the snapshot time `at`."""
    pub, now = _dt(rec.get("published")), _dt(at)
    if pub is None or now is None:
        return None
    return max(0, (now - pub).days)


def _bucket(v: float, buckets: list[tuple[float | None, str]], inclusive: bool) -> str:
    for hi, label in buckets:
        if hi is None or (v <= hi if inclusive else v < hi):
            return label
    return buckets[-1][1]


def _share(n: int, d: int) -> float | None:
    return round(100.0 * n / d, 1) if d else None


def _bu(rec: dict[str, Any]) -> str:
    return str(rec.get("bu") or "") or NO_BU


def _display(rec: dict[str, Any]) -> str:
    name = str(rec.get("name") or "")
    return f"{name} [{rec['sandbox']}]" if rec.get("sandbox") else name


def _app_ref(rec: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """Compact reference to one app for lists."""
    out = {"key": rec.get("key"), "name": _display(rec), "bu": _bu(rec),
           "app_id": rec.get("app_id"), "health": rec.get("health") or "Unknown",
           "attention": rec.get("attention")}
    out.update(extra)
    return out


def _sum_opt(recs: list[dict[str, Any]], k: str) -> int | None:
    vals = [r[k] for r in recs if r.get(k) is not None]
    return sum(vals) if vals else None


def _policy_level(rec: dict[str, Any]) -> str:
    return sh._policy_level(str(rec.get("policy_status") or ""))


def _metric(snap: dict[str, Any], k: str) -> Any:
    return (snap.get("metrics") or {}).get(k)


def _policy_pass_pct(snap: dict[str, Any]) -> float | None:
    m = snap.get("metrics") or {}
    known = sum(int(m.get(k) or 0) for k in ("policy_pass", "policy_conditional", "policy_fail"))
    return _share(int(m.get("policy_pass") or 0), known)


def _checks_affected(snap: dict[str, Any]) -> dict[int, int]:
    raw = snap.get("check_apps_affected") or {}
    out: dict[int, int] = {}
    for k, v in raw.items():
        if str(k).isdigit() and isinstance(v, int):
            out[int(k)] = v
    return out


# ==========================================================================
# Current run
# ==========================================================================

def kpis(snap: dict[str, Any]) -> dict[str, Any]:
    """Headline numbers. Counts from TenantMetrics match the workbook."""
    m = snap.get("metrics") or {}
    apps = snap.get("apps") or []
    sev = [a for a in apps if a.get("sev_available")]
    scanned = int(m.get("scanned_apps") or 0)
    return {
        "profiles": int(m.get("total_apps") or len(apps)),
        "scanned": scanned,
        "never_scanned": int(m.get("never_scanned") or 0),
        "good": int(m.get("good") or 0), "fair": int(m.get("fair") or 0),
        "poor": int(m.get("poor") or 0), "unknown": int(m.get("unknown") or 0),
        "stale": int(m.get("stale") or 0), "fresh": int(m.get("fresh") or 0),
        "policy_pass": int(m.get("policy_pass") or 0),
        "policy_conditional": int(m.get("policy_conditional") or 0),
        "policy_fail": int(m.get("policy_fail") or 0),
        "policy_unknown": int(m.get("policy_unknown") or 0),
        "policy_pass_pct": _policy_pass_pct(snap),
        "open_vh": _sum_opt(sev, "open_vh"), "open_h": _sum_opt(sev, "open_h"),
        "open_m": _sum_opt(sev, "open_m"), "open_l": _sum_opt(sev, "open_l"),
        "apps_with_open_vh": sum(1 for a in sev if (a.get("open_vh") or 0) > 0),
        "apps_with_open_h": sum(1 for a in sev if (a.get("open_h") or 0) > 0),
        "severity_unavailable": int(m.get("flaw_severity_unavailable") or 0),
        "missing_sca": int(m.get("missing_sca") or 0),
        "errors": int(m.get("errors") or 0),
        "sandboxes": sum(1 for a in apps if a.get("sandbox")),
        "median_scan_age": m.get("median_scan_age"),
    }


def distributions(snap: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    apps = snap.get("apps") or []
    at = str(snap.get("generated") or "")
    bands = Counter(str(a.get("attention_band") or "") for a in apps if a.get("attention_band"))
    ages: Counter[str] = Counter()
    for a in apps:
        d = scan_age_days(a, at)
        ages["Never scanned" if d is None else _bucket(d, cfg["age_buckets"], True)] += 1
    age_order = [b[1] for b in cfg["age_buckets"]] + ["Never scanned"]
    quad = Counter(str(a.get("quadrant") or "") for a in apps if a.get("quadrant"))
    return {
        "attention_bands": [{"band": b, "apps": bands.get(b, 0)} for b in _BAND_ORDER],
        "scan_age": [{"bucket": b, "apps": ages.get(b, 0)} for b in age_order],
        "quadrants": [{"quadrant": q, "apps": n} for q, n in sorted(quad.items(), key=lambda t: -t[1])],
    }


def business_units(snap: dict[str, Any], prev: dict[str, Any] | None,
                   cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Per-BU health mix, policy, open Very High/High and stale count, with the
    change since the baseline snapshot. Worst Poor share first."""
    def per_bu(s: dict[str, Any]) -> dict[str, dict[str, Any]]:
        at = str(s.get("generated") or "")
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for a in s.get("apps") or []:
            groups[_bu(a)].append(a)
        out = {}
        for bu, recs in groups.items():
            h = Counter(str(r.get("health") or "Unknown") for r in recs)
            pl = Counter(_policy_level(r) for r in recs)
            sev = [r for r in recs if r.get("sev_available")]
            stale = sum(1 for r in recs
                        if (d := scan_age_days(r, at)) is not None and d > cfg["stale_days"])
            known = pl["GREEN"] + pl["YELLOW"] + pl["RED"]
            out[bu] = {"bu": bu, "apps": len(recs),
                       **{k.lower(): h.get(k, 0) for k in HEALTH_ORDER},
                       "poor_share": _share(h.get("Poor", 0), len(recs)),
                       "policy_pass": pl["GREEN"], "policy_conditional": pl["YELLOW"],
                       "policy_fail": pl["RED"], "policy_unknown": pl["GRAY"],
                       "policy_pass_pct": _share(pl["GREEN"], known),
                       "open_vh": _sum_opt(sev, "open_vh"), "open_h": _sum_opt(sev, "open_h"),
                       "stale": stale}
        return out

    cur = per_bu(snap)
    old = per_bu(prev) if prev is not None else {}
    rows = []
    for bu, r in cur.items():
        p = old.get(bu)
        r["poor_share_delta"] = (round(r["poor_share"] - p["poor_share"], 1)
                                 if p and r["poor_share"] is not None and p["poor_share"] is not None
                                 else None)
        r["open_vh_delta"] = (r["open_vh"] - p["open_vh"]
                              if p and r["open_vh"] is not None and p["open_vh"] is not None else None)
        r["new"] = prev is not None and p is None
        rows.append(r)
    rows.sort(key=lambda r: (-(r["poor_share"] or 0), -r["apps"], r["bu"].lower()))
    return rows


def check_table(snap: dict[str, Any], prev: dict[str, Any] | None,
                cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """All 31 checks: apps affected, share, severity, change, top BUs and the
    affected apps (highest attention first, capped)."""
    apps = snap.get("apps") or []
    total = len(apps)
    info = snap.get("checks") or {}
    cur = _checks_affected(snap)
    old = _checks_affected(prev) if prev is not None else {}
    by_check: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for a in apps:
        for c in a.get("failed_checks") or []:
            if isinstance(c, int):
                by_check[c].append(a)
    rows = []
    for num in sorted(sh.CHECK_CATALOG):
        label, max_sev = sh.CHECK_CATALOG[num]
        hit = sorted(by_check.get(num, []), key=lambda r: (-(r.get("attention") or 0), _display(r).lower()))
        n = cur.get(num, len(hit))
        ci = info.get(str(num)) or {}
        owner, effort, category = ana._CHECK_META.get(num, ("AppSec", "M", "Results accuracy"))
        bus = Counter(_bu(r) for r in hit)
        p = old.get(num) if prev is not None else None
        rows.append({
            "check": num, "label": label,
            "category": sh.CHECK_CATEGORIES.get(num, "Other"),
            "severity": str(ci.get("severity") or max_sev.upper()),
            "apps": n, "share": _share(n, total),
            "previous": p, "delta": (n - p) if p is not None else None,
            "top_bus": [{"bu": b, "apps": k} for b, k in bus.most_common(3)],
            "owner": owner, "effort": effort, "impact": category,
            "recommendation": str(ci.get("rec") or ""),
            "affected": [_app_ref(r) for r in hit[:cfg["check_app_list"]]],
            "affected_more": max(0, len(hit) - cfg["check_app_list"]),
        })
    return rows


def performance(snap: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    apps = snap.get("apps") or []
    durs = [a for a in apps if isinstance(a.get("duration_seconds"), int)]
    secs = sorted(float(a["duration_seconds"]) for a in durs)
    sizes = [a for a in apps if isinstance(a.get("analysis_size_mib"), (int, float))]
    hist = Counter(_bucket(s, cfg["duration_buckets"], False) for s in secs)
    over = [a for a in apps if 31 in (a.get("failed_checks") or [])]
    n = cfg["top_list"]
    return {
        "measured": len(secs),
        "p50_seconds": round(ana.percentile(secs, 50)) if secs else None,
        "p90_seconds": round(ana.percentile(secs, 90)) if secs else None,
        "max_seconds": round(secs[-1]) if secs else None,
        "histogram": [{"bucket": b[1], "apps": hist.get(b[1], 0)} for b in cfg["duration_buckets"]],
        "slowest": [_app_ref(a, duration_seconds=a["duration_seconds"],
                             analysis_size_mib=a.get("analysis_size_mib"), build_id=a.get("build_id"))
                    for a in sorted(durs, key=lambda r: -r["duration_seconds"])[:n]],
        "largest": [_app_ref(a, analysis_size_mib=a["analysis_size_mib"],
                             duration_seconds=a.get("duration_seconds"))
                    for a in sorted(sizes, key=lambda r: -float(r["analysis_size_mib"]))[:n]],
        "over_size_threshold": len(over),
        "over_size_threshold_apps": [_app_ref(a) for a in over[:n]],
    }


def findings(snap: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    apps = snap.get("apps") or []
    sev = [a for a in apps if a.get("sev_available")]
    vh = sorted((a for a in sev if (a.get("open_vh") or 0) > 0),
                key=lambda r: (-(r.get("open_vh") or 0), -(r.get("open_h") or 0), _display(r).lower()))
    pol = Counter(str(a.get("policy_status") or "Unknown") for a in apps)
    scores = [a["score"] for a in apps if isinstance(a.get("score"), int)]
    sb = Counter(_bucket(s, cfg["score_buckets"], True) for s in scores)
    return {
        "severity_available": len(sev),
        "totals": {k: _sum_opt(sev, f"open_{k}") for k in ("vh", "h", "m", "l")},
        "apps_with_open_vh": len(vh),
        "top_open_vh": [_app_ref(a, open_vh=a.get("open_vh"), open_h=a.get("open_h"),
                                 policy_status=a.get("policy_status"))
                        for a in vh[:cfg["top_movement"]]],
        "policy_mix": [{"status": s, "apps": n} for s, n in pol.most_common()],
        "score_measured": len(scores),
        "score_buckets": [{"bucket": b[1], "apps": sb.get(b[1], 0)} for b in cfg["score_buckets"]],
    }


def coverage(snap: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    apps = snap.get("apps") or []
    n = cfg["top_movement"]

    def lst(pred: Any) -> dict[str, Any]:
        hit = [a for a in apps if pred(a)]
        return {"count": len(hit), "apps": [_app_ref(a, status=a.get("status")) for a in hit[:n]]}

    return {
        # Same definition as the workbook's "never scanned" count, which also
        # covers profiles whose retrieval failed (listed again under errors).
        "never_scanned": lst(lambda a: not a.get("ever_scanned", bool(a.get("published")))),
        "errors": lst(lambda a: a.get("status") == "Error"),
        "severity_unavailable": lst(lambda a: a.get("published") and not a.get("sev_available")),
        "sandboxes": sum(1 for a in apps if a.get("sandbox")),
    }


# ==========================================================================
# Trend and movement
# ==========================================================================

def series_point(snap: dict[str, Any]) -> dict[str, Any]:
    """One point of the tenant time series."""
    apps = snap.get("apps") or []
    secs = [float(a["duration_seconds"]) for a in apps if isinstance(a.get("duration_seconds"), int)]
    return {
        "generated": snap.get("generated"), "complete": bool(snap.get("complete")),
        "profiles": _metric(snap, "total_apps"),
        "good": _metric(snap, "good"), "fair": _metric(snap, "fair"),
        "poor": _metric(snap, "poor"), "unknown": _metric(snap, "unknown"),
        "stale": _metric(snap, "stale"),
        "policy_pass_pct": _policy_pass_pct(snap),
        "open_vh": _metric(snap, "critical_flaws"), "open_h": _metric(snap, "high_flaws"),
        "median_analysis_seconds": round(ana.median(secs)) if secs else None,
        "checks": {str(k): v for k, v in sorted(_checks_affected(snap).items())},
    }


def _degrade_reasons(old: dict[str, Any], new: dict[str, Any]) -> tuple[list[str], list[str]]:
    """(worse, better) reasons between two records of the same app."""
    worse: list[str] = []
    better: list[str] = []
    ho, hn = _HEALTH_RANK.get(str(old.get("health"))), _HEALTH_RANK.get(str(new.get("health")))
    if ho is not None and hn is not None and ho != hn:
        (worse if hn > ho else better).append(f"Health {old['health']} to {new['health']}")
    pi, pn = old.get("high_issues"), new.get("high_issues")
    if isinstance(pi, int) and isinstance(pn, int) and pi != pn:
        (worse if pn > pi else better).append(f"High-severity check failures {pi} to {pn}")
    lo, ln = _policy_level(old), _policy_level(new)
    if lo in ("GREEN", "YELLOW") and ln == "RED":
        worse.append(f"Policy {old.get('policy_status')} to {new.get('policy_status')}")
    elif lo == "RED" and ln in ("GREEN", "YELLOW"):
        better.append(f"Policy {old.get('policy_status')} to {new.get('policy_status')}")
    vo, vn = old.get("open_vh"), new.get("open_vh")
    if isinstance(vo, int) and isinstance(vn, int) and vo != vn:
        if vn > vo:
            worse.append("New open Very High" if vo == 0 else f"Open Very High {vo} to {vn}")
        else:
            better.append("No open Very High" if vn == 0 else f"Open Very High {vo} to {vn}")
    return worse, better


def movement(cur: dict[str, Any], prev: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    """Per-app, per-check and per-BU change between the baseline snapshot and
    this run. An app absent now is "no longer listed", never "fixed"."""
    n = cfg["top_movement"]
    old = {a["key"]: a for a in prev.get("apps") or [] if a.get("key")}
    new = {a["key"]: a for a in cur.get("apps") or [] if a.get("key")}
    t_old, t_new = str(prev.get("generated") or ""), str(cur.get("generated") or "")
    lists: dict[str, list[dict[str, Any]]] = {k: [] for k in (
        "degraded", "improved", "newly_stale", "newly_scanned", "new_apps", "no_longer_listed",
        "renamed")}
    rescanned = 0
    # Every app's movement (not capped), for the application table.
    status: dict[str, dict[str, Any]] = {}
    for k, a in new.items():
        p = old.get(k)
        if p is None:
            lists["new_apps"].append(_app_ref(a))
            status[k] = {"tag": "New", "worse": [], "better": []}
            continue
        if a.get("build_id") and a.get("build_id") != p.get("build_id"):
            rescanned += 1
        if str(a.get("name") or "") != str(p.get("name") or ""):
            lists["renamed"].append(_app_ref(a, previous_name=p.get("name")))
        worse, better = _degrade_reasons(p, a)
        att = ((a.get("attention") or 0) - (p.get("attention") or 0)
               if a.get("attention") is not None and p.get("attention") is not None else None)
        tag = ""
        if worse:
            lists["degraded"].append(_app_ref(a, reasons=worse, also_better=better,
                                              attention_delta=att))
            tag = "Degraded"
        elif better:
            lists["improved"].append(_app_ref(a, reasons=better, attention_delta=att))
            tag = "Improved"
        if not p.get("published") and a.get("published"):
            lists["newly_scanned"].append(_app_ref(a))
            tag = tag or "Newly scanned"
        do, dn = scan_age_days(p, t_old), scan_age_days(a, t_new)
        if do is not None and dn is not None and do <= cfg["stale_days"] < dn:
            lists["newly_stale"].append(_app_ref(a, scan_age_days=dn))
            tag = tag or "Newly stale"
        if tag:
            status[k] = {"tag": tag, "worse": worse, "better": better}
    for k, p in old.items():
        if k not in new:
            lists["no_longer_listed"].append(_app_ref(p))

    lists["degraded"].sort(key=lambda r: (-(r["attention_delta"] or 0), -len(r["reasons"]),
                                          r["name"].lower()))
    lists["improved"].sort(key=lambda r: ((r["attention_delta"] or 0), -len(r["reasons"]),
                                          r["name"].lower()))
    for k in ("newly_stale", "newly_scanned", "new_apps", "no_longer_listed", "renamed"):
        lists[k].sort(key=lambda r: (-(r["attention"] or 0), r["name"].lower()))

    co, cn = _checks_affected(prev), _checks_affected(cur)
    checks: list[dict[str, Any]] = [{"check": c, "label": sh.CHECK_CATALOG[c][0], "previous": co.get(c, 0),
               "current": cn.get(c, 0), "delta": cn.get(c, 0) - co.get(c, 0)}
              for c in sorted(sh.CHECK_CATALOG) if cn.get(c, 0) != co.get(c, 0)]
    checks.sort(key=lambda r: (-abs(r["delta"]), r["check"]))

    out: dict[str, Any] = {"baseline": t_old, "rescanned": rescanned, "checks": checks,
                           "counts": {k: len(v) for k, v in lists.items()},
                           "app_status": status}
    for k, v in lists.items():
        out[k] = v[:n]
    pk, ck = kpis(prev), kpis(cur)
    out["kpi_deltas"] = {k: (ck[k] - pk[k] if isinstance(ck.get(k), (int, float))
                             and isinstance(pk.get(k), (int, float)) else None)
                         for k in ("profiles", "scanned", "never_scanned", "good", "fair", "poor",
                                   "unknown", "stale", "policy_pass_pct", "open_vh", "open_h",
                                   "apps_with_open_vh", "errors", "missing_sca")}
    if isinstance(out["kpi_deltas"].get("policy_pass_pct"), float):
        out["kpi_deltas"]["policy_pass_pct"] = round(out["kpi_deltas"]["policy_pass_pct"], 1)
    return out


# ==========================================================================
# Verdicts and actions
# ==========================================================================

def verdicts(k: dict[str, Any], mv: dict[str, Any] | None, cfg: dict[str, Any]) -> list[TenantVerdict]:
    v = cfg["verdict"]
    out: list[TenantVerdict] = []
    scanned = k["scanned"]
    poor = _share(k["poor"], scanned)
    if poor is None:
        out.append(TenantVerdict("Scan health", "GRAY", "Unknown", "No scanned profiles"))
    else:
        lv = ("GREEN" if poor <= v["poor_share_green"] else
              "YELLOW" if poor <= v["poor_share_yellow"] else "RED")
        out.append(TenantVerdict("Scan health", lv, f"{poor:g}% Poor",
                                 f"{k['poor']} of {scanned} scanned profiles are Poor, "
                                 f"{k['good']} Good"))
    sev_known = scanned - k["severity_unavailable"]
    vh = _share(k["apps_with_open_vh"], sev_known)
    if vh is None:
        out.append(TenantVerdict("Findings risk", "GRAY", "Unknown", "Flaw severity unavailable"))
    else:
        lv = ("GREEN" if k["apps_with_open_vh"] == 0 else "YELLOW" if vh <= v["vh_share_yellow"]
              else "ORANGE" if vh <= v["vh_share_orange"] else "RED")
        out.append(TenantVerdict("Findings risk", lv, f"{k['apps_with_open_vh']} apps",
                                 f"{k['apps_with_open_vh']} profiles have open Very High flaws "
                                 f"({k['open_vh'] or 0} in total)"))
    pp = k["policy_pass_pct"]
    if pp is None:
        out.append(TenantVerdict("Policy compliance", "GRAY", "Unknown", "No known policy outcomes"))
    else:
        lv = ("GREEN" if pp >= v["policy_pass_green"] else
              "YELLOW" if pp >= v["policy_pass_yellow"] else "RED")
        out.append(TenantVerdict("Policy compliance", lv, f"{pp:g}% pass",
                                 f"{k['policy_pass']} pass, {k['policy_conditional']} conditional, "
                                 f"{k['policy_fail']} did not pass; {k['policy_unknown']} unknown "
                                 "excluded"))
    st = _share(k["stale"], scanned)
    if st is None:
        out.append(TenantVerdict("Freshness", "GRAY", "Unknown", "No scanned profiles"))
    else:
        lv = ("GREEN" if st <= v["stale_share_green"] else "YELLOW" if st <= v["stale_share_yellow"]
              else "ORANGE" if st <= v["stale_share_orange"] else "RED")
        out.append(TenantVerdict("Freshness", lv, f"{st:g}% stale",
                                 f"{k['stale']} scanned profiles older than {cfg['stale_days']} days"
                                 + (f"; {k['never_scanned']} never scanned" if k["never_scanned"] else "")))
    if mv is None:
        out.append(TenantVerdict("Trend", "GRAY", "No baseline",
                                 "Trends start once a second comparable run exists"))
    else:
        c = mv["counts"]
        d = mv["kpi_deltas"]
        net = c["degraded"] - c["improved"]
        if net > 0 or ((d.get("open_vh") or 0) > 0 and net >= 0):
            lv, lab = "ORANGE", "Declining"
        elif net < 0 or (d.get("open_vh") or 0) < 0:
            lv, lab = "GREEN", "Improving"
        else:
            lv, lab = "GREEN", "Stable"
        out.append(TenantVerdict("Trend", lv, lab,
                                 f"{c['degraded']} degraded, {c['improved']} improved since "
                                 f"the last run; Poor {_fmt_delta(d.get('poor'))}, open Very High "
                                 f"{_fmt_delta(d.get('open_vh'))}"))
    return out


def _fmt_delta(v: Any) -> str:
    if v is None:
        return "n/a"
    return f"+{v}" if v > 0 else str(v)


def issue_priority(check: int, share: float | None, cfg: dict[str, Any]) -> str:
    """The app report's P1/P2/P3 rubric for the check, raised one level when
    the check affects at least the "widespread" share of profiles."""
    if check in ana._P1_ACCURACY:
        base = "P1"
    elif check in ana._P2_ACCURACY or check in ana._P2_PERF:
        base = "P2"
    else:
        base = "P3"
    wide = sh.DASHBOARD_CONFIG["issue_prevalence"]["widespread_pct"]
    if share is not None and share >= wide and base != "P1":
        base = "P1" if base == "P2" else "P2"
    return base


def actions(checks: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
    """Organisational issues ranked by priority, then by profiles affected
    weighted by severity."""
    w = cfg["check_severity_weight"]
    issues = []
    for c in checks:
        if not c["apps"]:
            continue
        pr = issue_priority(c["check"], c["share"], cfg)
        trend = ("" if c["delta"] is None else
                 f"; {c['delta']:+d} since the last run" if c["delta"] else "; unchanged since the last run")
        issues.append({
            **{k: c[k] for k in ("check", "label", "severity", "apps", "share", "delta", "owner",
                                 "effort", "impact", "recommendation", "top_bus")},
            "priority": pr,
            "quick_win": c["effort"] == "S",
            "why": ana._WHY.get(c["impact"], "Affects scan quality."),
            "evidence": f"{c['apps']} profiles ({c['share']}% of the tenant){trend}",
            "examples": c["affected"][:5],
            "verify": f"Apps affected by check #{c['check']} falls on the next bulk run.",
            "_weight": c["apps"] * w.get(c["severity"], 1),
        })
    issues.sort(key=lambda i: (i["priority"], -i["_weight"], i["check"]))
    for i in issues:
        i.pop("_weight")
    return {
        "issues": issues[:cfg["top_checks"]],
        "issues_more": max(0, len(issues) - cfg["top_checks"]),
    }


# ==========================================================================
# Entry point
# ==========================================================================

def analyse(current: dict[str, Any], history: list[dict[str, Any]],
            history_notes: list[str] | None = None,
            cfg: dict[str, Any] | None = None,
            extras: dict[str, Any] | None = None) -> TenantReport:
    """Build the TenantReport for `current` (this run's snapshot) and its
    comparable earlier snapshots `history` (newest first)."""
    cfg = cfg or TENANT_CONFIG
    prev = next((s for s in history if s.get("complete")), None)
    apps = sorted(current.get("apps") or [],
                  key=lambda a: (-(a.get("attention") or -1), _display(a).lower()))
    k = kpis(current)
    checks = check_table(current, prev, cfg)
    bus = business_units(current, prev, cfg)
    mv = movement(current, prev, cfg) if prev is not None else None
    series = [series_point(s) for s in reversed(history)] + [series_point(current)]
    rep = TenantReport(
        generated=str(current.get("generated") or ""),
        tenant_key=str(current.get("tenant_key") or ""),
        region=str((current.get("scope") or {}).get("region") or ""),
        scope=dict(current.get("scope") or {}), complete=bool(current.get("complete")),
        kpis=k, verdicts=verdicts(k, mv, cfg), actions=actions(checks, cfg),
        distributions=distributions(current, cfg), checks=checks, business_units=bus,
        performance=performance(current, cfg), findings=findings(current, cfg),
        coverage=coverage(current, cfg), series=series, movement=mv,
        baseline=str(prev.get("generated")) if prev is not None else None, apps=apps)
    ex = extras or {}
    rep.fixes = fix_list(current, prev, checks, ex.get("details"), cfg)
    rep.links = dict(ex.get("links") or {})
    if not ex.get("details"):
        rep.note("Fix list", "What was found on each profile comes from the bulk run; this "
                 "report was built from snapshots only, so the fix list shows each check's "
                 "general advice.")
    for n in history_notes or []:
        rep.note("Snapshots", n, "warning")
    partial = sum(1 for s in history if not s.get("complete"))
    if partial:
        rep.note("Snapshots", f"{partial} partial snapshot(s) are shown in the trend but never "
                 "used as the baseline for per-app changes.")
    if not current.get("complete"):
        rep.note("Collection", "This run did not finish; counts cover the profiles processed.",
                 "warning")
    if prev is None:
        rep.note("Trend", "No earlier complete snapshot with the same scope; trends and changes "
                 "start from the next run.")
    elif mv and mv["counts"]["no_longer_listed"]:
        rep.note("Movement", f"{mv['counts']['no_longer_listed']} profile(s) from the baseline "
                 "are no longer listed (deleted, renamed out of the name filter, or access "
                 "removed). They are not counted as fixed.")
    rep.note("Priorities", "Organisational issue priority uses the app report's P1/P2/P3 rubric "
             "for the check, raised one level when it affects at least "
             f"{sh.DASHBOARD_CONFIG['issue_prevalence']['widespread_pct']:g}% of profiles.")
    rep.note("Thresholds", "Tenant verdict thresholds are this tool's defaults (TENANT_CONFIG), "
             "not Veracode guidance.")
    rep.note("Units", "Analysis Size is in MiB (2^20 bytes), as in the bulk workbook.")
    return rep


def summary_lines(rep: TenantReport) -> list[str]:
    """A few console lines for the end of a bulk run."""
    k = rep.kpis
    lines = [f"Tenant {rep.tenant_key}: {k['profiles']} profiles, Good {k['good']}, "
             f"Fair {k['fair']}, Poor {k['poor']}, stale {k['stale']}, "
             f"policy pass {k['policy_pass_pct'] if k['policy_pass_pct'] is not None else 'n/a'}%"]
    if rep.movement is None:
        lines.append(f"Trend: {len(rep.series)} snapshot(s); per-app changes start from the next "
                     "comparable run")
    else:
        c, d = rep.movement["counts"], rep.movement["kpi_deltas"]
        lines.append(f"Since {rep.baseline}: {c['degraded']} degraded, {c['improved']} improved, "
                     f"{c['new_apps']} new, {c['no_longer_listed']} no longer listed, "
                     f"{c['newly_stale']} newly stale; Poor {_fmt_delta(d.get('poor'))}, "
                     f"open Very High {_fmt_delta(d.get('open_vh'))}")
        lines.append(f"Trend: {len(rep.series)} comparable snapshot(s)")
    return lines


_SEV_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
_PRI_RANK = {"P1": 0, "P2": 1, "P3": 2}


def fix_list(current: dict[str, Any], prev: dict[str, Any] | None, checks: list[dict[str, Any]],
             details: dict[tuple[str, int], tuple[str, str, str]] | None = None,
             cfg: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """One row per failing check per profile, highest priority first.

    details maps (app key, check) to (severity, what was found,
    recommendation) from the current run. Change is "New" when the check
    was not failing on that profile in the baseline (or the profile is new),
    "Recurring" when it was, and "" without a baseline."""
    cfg = cfg or TENANT_CONFIG
    det = details or {}
    share = {c["check"]: c["share"] for c in checks}
    rec = {c["check"]: c.get("recommendation") or "" for c in checks}
    sev_seen = {c["check"]: c["severity"] for c in checks}
    base = ({a["key"]: set(a.get("failed_checks") or []) for a in prev.get("apps") or [] if a.get("key")}
            if prev is not None else None)
    out = []
    for a in current.get("apps") or []:
        key = a.get("key")
        for c in a.get("failed_checks") or []:
            if not isinstance(c, int) or c not in sh.CHECK_CATALOG:
                continue
            sev, found, advice = det.get((key, c), ("", "", ""))
            owner, effort, impact = ana._CHECK_META.get(c, ("AppSec", "M", "Results accuracy"))
            change = "" if base is None else ("Recurring" if c in base.get(key, set()) else "New")
            out.append({
                "key": key, "app_id": a.get("app_id"), "name": _display(a), "bu": _bu(a),
                "attention": a.get("attention"), "check": c, "label": sh.CHECK_CATALOG[c][0],
                "severity": (sev or "").upper() or sev_seen.get(c) or sh.CHECK_CATALOG[c][1].upper(),
                "priority": issue_priority(c, share.get(c), cfg), "owner": owner, "effort": effort,
                "impact": impact, "found": found, "recommendation": advice or rec.get(c, ""),
                "change": change, "quick_win": effort == "S",
            })
    out.sort(key=lambda f: (_PRI_RANK[f["priority"]], _SEV_RANK.get(f["severity"], 3),
                            -(f["attention"] or 0), f["check"], f["name"].lower()))
    return out


def check_bu_matrix(apps: list[dict[str, Any]], top_bus: int = 8,
                    top_checks: int = 12) -> dict[str, Any]:
    """Share of each business unit's profiles failing each check, for the
    most common failing checks and the largest business units (the rest
    folded into "Other")."""
    sizes = Counter(_bu(a) for a in apps)
    bus = [b for b, _ in sizes.most_common(top_bus)]
    other = len(sizes) > top_bus
    cols = bus + (["Other"] if other else [])
    totals = {b: sizes[b] for b in bus}
    if other:
        totals["Other"] = sum(n for b, n in sizes.items() if b not in bus)
    hits: dict[int, Counter[str]] = defaultdict(Counter)
    for a in apps:
        col = _bu(a) if _bu(a) in totals else "Other"
        for c in a.get("failed_checks") or []:
            if isinstance(c, int):
                hits[c][col] += 1
    ranked = sorted(hits, key=lambda c: (-sum(hits[c].values()), c))[:top_checks]
    rows = []
    for c in ranked:
        cells = []
        for col in cols:
            n, t = hits[c][col], totals[col]
            cells.append((round(100.0 * n / t, 1) if t else None, n, t))
        rows.append({"check": c, "label": sh.CHECK_CATALOG.get(c, (str(c), ""))[0],
                     "apps": sum(hits[c].values()), "cells": cells})
    return {"cols": cols, "totals": [totals[c] for c in cols], "rows": rows}
