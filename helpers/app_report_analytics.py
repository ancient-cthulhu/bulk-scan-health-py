"""Analytics for the app report. Pure functions, no I/O."""

from __future__ import annotations

import math
import statistics
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

import scan_health as sh

if TYPE_CHECKING:
    from .app_report import AppReport, BuildRef, BuildSnapshot

ANALYTICS_CONFIG: dict[str, Any] = {
    # Duration regression: latest above median + k * 1.4826 * MAD AND above
    # ratio * median of the baseline window.
    "regression_mad_k": 3.0,
    "regression_ratio": 1.5,
    "min_baseline_points": 4,
    # Probable drivers below this relative change are not listed.
    "driver_min_change": 0.10,
    # Engine effect: total flaws moved by more than this share with the same
    # selected modules and a new engine version.
    "engine_effect_change": 0.15,
    # Scan staleness, days since the latest published policy scan.
    "stale_days": 30,
    # Failure rate above which the action plan raises a P1.
    "failure_rate_p1": 0.20,
    "evidence_limit": 25,
}


# ==========================================================================
# Small statistics (stdlib)
# ==========================================================================

def median(xs: Sequence[float]) -> float:
    """Median of a non-empty list."""
    return float(statistics.median(xs))


def mad(xs: Sequence[float]) -> float:
    """Median absolute deviation (unscaled)."""
    m = median(xs)
    return median([abs(x - m) for x in xs])


def percentile(xs: Sequence[float], p: float) -> float:
    """Linear-interpolated percentile, p in [0, 100]."""
    s = sorted(xs)
    if len(s) == 1:
        return float(s[0])
    k = (len(s) - 1) * p / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    return float(s[lo] + (s[hi] - s[lo]) * (k - lo))


def theil_sen(ys: list[float]) -> tuple[float, float] | None:
    """(slope, intercept) of the Theil-Sen line through (i, ys[i]). Robust to
    outliers: the slope is the median of all pairwise slopes. None for < 2
    points."""
    n = len(ys)
    if n < 2:
        return None
    slopes = [(ys[j] - ys[i]) / (j - i) for i in range(n) for j in range(i + 1, n)]
    slope = median(slopes)
    intercept = median([ys[i] - slope * i for i in range(n)])
    return slope, intercept


def _rel(new: float | None, base: float | None) -> float | None:
    if new is None or base is None or base == 0:
        return None
    return (new - base) / base


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# ==========================================================================
# Model
# ==========================================================================

@dataclass
class DurationPoint:
    build_id: str
    published: str | None
    seconds: int
    size_mb: float | None
    loc: int | None
    sec_per_mb: float | None
    sec_per_kloc: float | None
    engine: str | None


@dataclass
class DurationStats:
    """Analysis time (submit to publish) across published builds, oldest first."""
    points: list[DurationPoint] = field(default_factory=list)
    latest: int | None = None
    p50: float | None = None
    p90: float | None = None
    min: int | None = None
    max: int | None = None
    fastest_build: str | None = None
    slowest_build: str | None = None
    baseline_n: int = 0
    baseline_median: float | None = None
    baseline_mad: float | None = None
    threshold: float | None = None           # seconds; regression above this
    status: str = "Insufficient history"     # Regression | Normal | Insufficient history | Unavailable
    reason: str = ""
    slope_min_per_scan: float | None = None
    window_change_pct: float | None = None
    drivers: list[str] = field(default_factory=list)
    has_size_or_module_driver: bool = False


@dataclass
class CadenceStats:
    published_count: int = 0
    days_since_last: int | None = None
    last_published: str | None = None
    median_interval_days: float | None = None
    max_interval_days: float | None = None
    longest_gap: tuple[str, str] | None = None
    scans_last_30d: int = 0
    scans_last_90d: int = 0
    attempts: list[dict[str, Any]] = field(default_factory=list)   # timeline points
    failure_rate: float | None = None
    failure_rate_note: str = ""


@dataclass
class FindingsRow:
    build_id: str
    published: str | None
    very_high: int | None
    high: int | None
    medium: int | None
    low: int | None
    open_policy: int | None
    mitigated: int | None
    total: int | None
    new: int | None
    reopen: int | None
    fixed: int | None
    fixed_source: str | None
    net_change: int | None
    score: int | None
    rating: str | None
    policy: str | None


@dataclass
class FindingsTrend:
    rows: list[FindingsRow] = field(default_factory=list)        # oldest first
    events: list[dict[str, str]] = field(default_factory=list)
    engine_effect: str = ""


@dataclass
class Diffs:
    available: bool = False
    reason: str = ""
    previous_build: str | None = None
    modules_added: list[str] = field(default_factory=list)
    modules_removed: list[str] = field(default_factory=list)
    modules_unchanged: int = 0
    new_unselected_first_party: list[str] = field(default_factory=list)
    files_added: list[str] = field(default_factory=list)
    files_removed: list[str] = field(default_factory=list)
    files_changed: list[str] = field(default_factory=list)
    ext_added: dict[str, int] = field(default_factory=dict)
    ext_removed: dict[str, int] = field(default_factory=dict)
    analysis_size_delta: int | None = None
    prescan_size_delta: int | None = None
    checks_new: list[int] = field(default_factory=list)
    checks_resolved: list[int] = field(default_factory=list)
    engine: tuple[str | None, str | None] = (None, None)
    policy: tuple[str | None, str | None] = (None, None)
    flaws_total: tuple[int | None, int | None] = (None, None)


@dataclass
class CheckHistory:
    check_num: int
    check_name: str
    label: str
    statuses: list[tuple[str, str]] = field(default_factory=list)   # (build_id, status), oldest first
    lifecycle: str = "Unknown"
    consecutive_failing: int = 0


@dataclass
class Verdict:
    name: str
    level: str      # GREEN | YELLOW | ORANGE | RED | GRAY
    value: str
    reason: str


@dataclass
class ActionItem:
    priority: str            # P1 | P2 | P3
    title: str
    owner_role: str
    effort: str              # S | M | L (estimate)
    category: str
    why: str
    evidence: list[str] = field(default_factory=list)
    evidence_total: int | None = None
    how_to_fix: list[str] = field(default_factory=list)
    verify: str = ""
    expected_effect: str = "Not quantifiable from available data"
    links: list[tuple[str, str]] = field(default_factory=list)
    check_num: int | None = None
    consecutive_failing: int = 0


@dataclass
class Analysis:
    verdicts: list[Verdict]
    actions: list[ActionItem]
    duration: DurationStats
    cadence: CadenceStats
    findings: FindingsTrend
    diffs: Diffs
    check_history: list[CheckHistory]
    modules: list[dict[str, Any]]


# ==========================================================================
# Duration
# ==========================================================================

def duration_stats(builds: list[BuildSnapshot], baseline_window: int,
                   cfg: dict[str, Any] | None = None) -> DurationStats:
    """Duration trend, baseline and regression flag.

    builds: newest first, as collected. The baseline is the previous
    `baseline_window` published builds excluding the latest, median and MAD,
    and needs min_baseline_points of them.
    """
    cfg = cfg or ANALYTICS_CONFIG
    st = DurationStats()
    timed = [b for b in reversed(builds) if b.analysis_seconds is not None]
    for b in timed:
        size_mb = b.analysis_size_bytes / 1e6 if b.analysis_size_bytes else None
        secs = int(b.analysis_seconds or 0)
        st.points.append(DurationPoint(
            build_id=b.build_id, published=b.published, seconds=secs,
            size_mb=round(size_mb, 2) if size_mb else None, loc=b.loc_total,
            sec_per_mb=round(secs / size_mb, 2) if size_mb else None,
            sec_per_kloc=round(secs / (b.loc_total / 1000), 2) if b.loc_total else None,
            engine=b.engine_version))
    if not st.points:
        st.status, st.reason = "Unavailable", "No build has both submitted and published dates"
        return st
    vals = [p.seconds for p in st.points]
    st.latest = vals[-1] if builds and builds[0].analysis_seconds is not None else None
    st.p50, st.p90 = round(percentile(vals, 50), 1), round(percentile(vals, 90), 1)
    st.min, st.max = min(vals), max(vals)
    st.fastest_build = st.points[vals.index(st.min)].build_id
    st.slowest_build = st.points[vals.index(st.max)].build_id
    ts = theil_sen([float(v) for v in vals])
    if ts is not None:
        slope, intercept = ts
        st.slope_min_per_scan = round(slope / 60.0, 2)
        if intercept > 0:
            st.window_change_pct = round(100.0 * slope * (len(vals) - 1) / intercept, 1)

    if st.latest is None:
        st.status, st.reason = "Unavailable", "The latest build has no analysis time"
        return st
    base_pts = st.points[:-1][-baseline_window:]
    base = [float(p.seconds) for p in base_pts]
    st.baseline_n = len(base)
    if len(base) < cfg["min_baseline_points"]:
        st.status = "Insufficient history"
        st.reason = (f"{len(base)} earlier build(s) with timing; "
                     f"{cfg['min_baseline_points']} needed for a baseline")
        return st
    st.baseline_median = round(median(base), 1)
    st.baseline_mad = round(mad(base), 1)
    st.threshold = round(max(st.baseline_median + cfg["regression_mad_k"] * 1.4826 * st.baseline_mad,
                             cfg["regression_ratio"] * st.baseline_median), 1)
    if st.latest > st.threshold:
        st.status = "Regression"
        st.reason = (f"Latest {sh._fmt_seconds(st.latest)} vs baseline median "
                     f"{sh._fmt_seconds(int(st.baseline_median))} "
                     f"({_pct_str(_rel(st.latest, st.baseline_median))})")
    else:
        st.status = "Normal"
        st.reason = (f"Latest {sh._fmt_seconds(st.latest)}, baseline median "
                     f"{sh._fmt_seconds(int(st.baseline_median))}")
    st.drivers, st.has_size_or_module_driver = _drivers(builds, base_pts, cfg)
    return st


def _pct_str(r: float | None) -> str:
    return "n/a" if r is None else f"{r * 100:+.0f}%"


def _drivers(builds: list[BuildSnapshot], base_pts: list[DurationPoint],
             cfg: dict[str, Any]) -> tuple[list[str], bool]:
    """Probable drivers of the latest build's duration, ranked by relative
    change against the baseline builds. Correlation, not causation."""
    latest = builds[0]
    base_ids = {p.build_id for p in base_pts}
    base = [b for b in builds if b.build_id in base_ids]
    metrics: list[tuple[str, float | None, list[float]]] = [
        ("Analysis size", latest.analysis_size_bytes,
         [float(b.analysis_size_bytes) for b in base if b.analysis_size_bytes]),
        ("Lines of code", latest.loc_total, [float(b.loc_total) for b in base if b.loc_total]),
        ("Selected modules", latest.selected_module_count,
         [float(b.selected_module_count) for b in base if b.selected_module_count]),
        ("Uploaded module size (prescan)", latest.prescan_total_bytes,
         [float(b.prescan_total_bytes) for b in base if b.prescan_total_bytes]),
    ]
    ranked: list[tuple[float, str, str]] = []
    for name, cur, hist in metrics:
        if cur is None or not hist:
            continue
        r = _rel(float(cur), median(hist))
        if r is not None and abs(r) >= cfg["driver_min_change"]:
            ranked.append((abs(r), name, f"{name} {_pct_str(r)} vs baseline median"))
    ranked.sort(reverse=True)
    out = [t for _, _, t in ranked]
    sized = any(n in ("Analysis size", "Selected modules", "Uploaded module size (prescan)")
                for _, n, _ in ranked)
    prev_engine = builds[1].engine_version if len(builds) > 1 else None
    if latest.engine_version and prev_engine and latest.engine_version != prev_engine:
        out.append(f"Engine version changed ({prev_engine} to {latest.engine_version})")
    return out, sized


# ==========================================================================
# Cadence
# ==========================================================================

def cadence_stats(builds: list[BuildSnapshot], others: list[BuildRef],
                  now: datetime | None = None) -> CadenceStats:
    """How regularly published scans happen, and how often attempts fail."""
    now = now or datetime.now(timezone.utc)
    cs = CadenceStats()
    dated = sorted((d, b.build_id) for b in builds if (d := _dt(b.published)) is not None)
    cs.published_count = len(dated)
    for d, bid in dated:
        cs.attempts.append({"build_id": bid, "date": d.isoformat(), "state": "published"})
    for o in others:
        d = _dt(o.published) or _dt(o.policy_updated_date)
        cs.attempts.append({"build_id": o.build_id, "date": d.isoformat() if d else None,
                            "state": o.status_class, "status": o.status})
    if dated:
        last = dated[-1][0]
        cs.last_published = last.isoformat()
        cs.days_since_last = (now - last).days
        cs.scans_last_30d = sum(1 for d, _ in dated if (now - d).days <= 30)
        cs.scans_last_90d = sum(1 for d, _ in dated if (now - d).days <= 90)
    if len(dated) >= 2:
        gaps = [((dated[i + 1][0] - dated[i][0]).total_seconds() / 86400.0, i)
                for i in range(len(dated) - 1)]
        cs.median_interval_days = round(median([g for g, _ in gaps]), 1)
        g, i = max(gaps)
        cs.max_interval_days = round(g, 1)
        cs.longest_gap = (dated[i][0].date().isoformat(), dated[i + 1][0].date().isoformat())
    failed = sum(1 for o in others if o.status_class in ("failed", "cancelled"))
    attempted = len(dated) + failed
    if failed and attempted:
        cs.failure_rate = round(failed / attempted, 3)
        cs.failure_rate_note = f"{failed} failed or cancelled of {attempted} attempts in the window"
    else:
        cs.failure_rate_note = ("Unavailable: failed builds are normally deleted before the next "
                                "upload, so the build list cannot show them")
    return cs


# ==========================================================================
# Findings
# ==========================================================================

def findings_trend(builds: list[BuildSnapshot], cfg: dict[str, Any] | None = None) -> FindingsTrend:
    """Per-build findings, timeline events and the engine-effect flag."""
    cfg = cfg or ANALYTICS_CONFIG
    ft = FindingsTrend()
    prev: BuildSnapshot | None = None
    for b in reversed(builds):
        sev = b.open_by_severity or {}
        fs = b.flaw_status
        total = fs.total if fs and fs.total is not None else b.total_flaws
        prev_total = None
        if prev is not None:
            pfs = prev.flaw_status
            prev_total = pfs.total if pfs and pfs.total is not None else prev.total_flaws
        ft.rows.append(FindingsRow(
            build_id=b.build_id, published=b.published,
            very_high=sev.get("very_high") if b.open_by_severity else None,
            high=sev.get("high") if b.open_by_severity else None,
            medium=sev.get("medium") if b.open_by_severity else None,
            low=sev.get("low") if b.open_by_severity else None,
            open_policy=b.open_policy_flaws, mitigated=b.mitigated_flaws, total=total,
            new=fs.new if fs else None, reopen=fs.reopen if fs else None,
            fixed=fs.fixed if fs else None, fixed_source=b.flaw_status_source,
            net_change=(total - prev_total) if total is not None and prev_total is not None else None,
            score=b.score, rating=b.rating, policy=b.policy_compliance_status))
        if prev is not None:
            if b.policy_version and prev.policy_version and b.policy_version != prev.policy_version:
                ft.events.append({"build_id": b.build_id, "event":
                                  f"Policy version {prev.policy_version} to {b.policy_version}"})
            if b.engine_version and prev.engine_version and b.engine_version != prev.engine_version:
                ft.events.append({"build_id": b.build_id, "event":
                                  f"Engine {prev.engine_version} to {b.engine_version}"})
                same_mods = {m.name for m in b.modules} == {m.name for m in prev.modules}
                r = _rel(float(total) if total is not None else None,
                         float(prev_total) if prev_total else None)
                if same_mods and r is not None and abs(r) > cfg["engine_effect_change"] \
                        and b is builds[0]:
                    ft.engine_effect = ("Result shift likely engine-related; review before "
                                        "attributing to code changes (engine changed, total "
                                        f"flaws {_pct_str(r)}, same selected modules)")
        if b.grace_period_expired:
            ft.events.append({"build_id": b.build_id, "event": "Grace period expired"})
        if b.scan_overdue:
            ft.events.append({"build_id": b.build_id, "event": "Scan overdue"})
        prev = b
    return ft


# ==========================================================================
# Diffs, latest vs previous
# ==========================================================================

def _ext(name: str) -> str:
    suf = PurePosixPath(name.replace("\\", "/")).suffix.lower()
    return suf or "(none)"


def diffs(builds: list[BuildSnapshot]) -> Diffs:
    """Composition and outcome changes between the two newest builds."""
    d = Diffs()
    if len(builds) < 2:
        d.reason = "Only one published build in this context"
        return d
    cur, prev = builds[0], builds[1]
    d.previous_build = prev.build_id
    d.engine = (prev.engine_version, cur.engine_version)
    d.policy = (prev.policy_compliance_status, cur.policy_compliance_status)
    d.flaws_total = (prev.total_flaws, cur.total_flaws)
    if cur.analysis_size_bytes is not None and prev.analysis_size_bytes is not None:
        d.analysis_size_delta = cur.analysis_size_bytes - prev.analysis_size_bytes
    if cur.prescan_total_bytes is not None and prev.prescan_total_bytes is not None:
        d.prescan_size_delta = cur.prescan_total_bytes - prev.prescan_total_bytes
    if cur.checks_ran and prev.checks_ran:
        ps = {c.check_num: c.status for c in prev.checks}
        for c in cur.checks:
            if c.status == "Fail" and ps.get(c.check_num) == "Pass":
                d.checks_new.append(c.check_num)
            if c.status == "Pass" and ps.get(c.check_num) == "Fail":
                d.checks_resolved.append(c.check_num)
    if cur.detail is None or prev.detail is None:
        d.reason = "Module and file lists are not available for both builds"
        return d
    d.available = True
    sel_c = {m["name"] for m in cur.detail.merged_modules if m.get("is_selected")}
    sel_p = {m["name"] for m in prev.detail.merged_modules if m.get("is_selected")}
    d.modules_added = sorted(sel_c - sel_p)
    d.modules_removed = sorted(sel_p - sel_c)
    d.modules_unchanged = len(sel_c & sel_p)
    prev_names = {m["name"] for m in prev.detail.merged_modules}
    d.new_unselected_first_party = sorted(
        m["name"] for m in cur.detail.merged_modules
        if not m.get("is_selected") and not m.get("is_dep") and not m.get("is_third_party")
        and not m.get("is_ignored") and m["name"] not in prev_names)
    fc: dict[str, set[str]] = {}
    fp: dict[str, set[str]] = {}
    for f in cur.detail.files:
        fc.setdefault(f["name"], set()).add(f.get("md5", ""))
    for f in prev.detail.files:
        fp.setdefault(f["name"], set()).add(f.get("md5", ""))
    d.files_added = sorted(set(fc) - set(fp))
    d.files_removed = sorted(set(fp) - set(fc))
    d.files_changed = sorted(n for n in set(fc) & set(fp) if fc[n] != fp[n])
    d.ext_added = dict(Counter(_ext(n) for n in d.files_added).most_common())
    d.ext_removed = dict(Counter(_ext(n) for n in d.files_removed).most_common())
    return d


# ==========================================================================
# Check history
# ==========================================================================

def check_history(builds: list[BuildSnapshot]) -> list[CheckHistory]:
    """Status of every check across builds where checks ran, with a lifecycle
    label for the latest build: New, Recurring, Regressed, Resolved, Never seen."""
    ran = [b for b in reversed(builds) if b.checks_ran]
    out: list[CheckHistory] = []
    for num, name, _ in sh.CHECK_REGISTRY:
        h = CheckHistory(check_num=num, check_name=name,
                         label=sh.CHECK_CATALOG.get(num, (name, ""))[0])
        for b in ran:
            st = next((c.status for c in b.checks if c.check_num == num), "Unknown")
            h.statuses.append((b.build_id, st))
        judged = [s for _, s in h.statuses if s in ("Pass", "Fail")]
        if not judged or not builds or not builds[0].checks_ran:
            h.lifecycle = "Unknown"
        else:
            latest = judged[-1]
            earlier = judged[:-1]
            for s in reversed(judged):
                if s != "Fail":
                    break
                h.consecutive_failing += 1
            if latest == "Fail":
                if earlier and earlier[-1] == "Fail":
                    h.lifecycle = "Recurring"
                elif "Fail" in earlier:
                    h.lifecycle = "Regressed"
                else:
                    h.lifecycle = "New"
            else:
                h.lifecycle = "Resolved" if "Fail" in earlier else "Never seen"
        out.append(h)
    return out


# ==========================================================================
# Evidence (single-app only; the bulk path never calls this)
# ==========================================================================

def _files(files: list[dict[str, Any]], pats: list[str]) -> list[str]:
    return sh._fancy_match_files(files, pats)


def _mods(mods: list[dict[str, Any]], pred: Any) -> list[str]:
    return list(dict.fromkeys(m["name"] for m in mods if pred(m)))


def evidence_for(num: int, files: list[dict[str, Any]], modules: list[dict[str, Any]]) -> list[str]:
    """The concrete files or modules check `num` judges, computed on the same
    state the check sees (called from the observer's before hook) with the
    same pattern lists and predicates. Empty when the check has no item list."""
    dn, java = sh._is_dotnet, sh._is_java
    st = sh._has_status
    def plain(m: dict[str, Any]) -> bool:
        return not m["is_ignored"] and not m["is_third_party"]

    if num == 1:
        return [f["name"] for f in files
                if not (f["name"].lower().endswith(".pdb") or f["name"].lower() in (".gitignore", "head"))
                and sh._fancy_match(f["name"], sh.JUNK_FILE_PATTERNS)]
    if num == 2:
        return _mods(modules, lambda m: m.get("is_selected") and sh._fancy_match(m["name"], sh.THIRD_PARTY_PATTERNS))
    if num == 4:
        return _mods(modules, lambda m: m["has_fatal"] and (
            (dn(m["name"]) and plain(m) and st(m, "Primary Files Compiled without Debug Symbols"))
            or (java(m["name"]) and (st(m, "No Scannable Binaries")
                                     or st(m, "does not support jar files nested inside")))))
    if num == 5:
        return _mods(modules, lambda m: java(m["name"]) and m["has_fatal"]
                     and not st(m, "No Scannable Binaries")
                     and not st(m, "does not support jar files nested inside"))
    if num == 6:
        pats = (sh.UNWANTED_7Z + sh.UNWANTED_COFFEE + sh.UNWANTED_SCRIPTS + sh.UNWANTED_INSTALLERS
                + sh.UNWANTED_PYD + sh.UNWANTED_PYC + sh.UNWANTED_DEPLOY + sh.UNWANTED_WIBU)
        return _files(files, pats)
    if num == 7:
        return list(dict.fromkeys(f["name"] for f in files
                                  if f["status"] == "Archive File Within Another Archive"
                                  and not f.get("is_ignored")))
    if num == 8:
        return _files(files, sh.DOTNET_PRECOMPILE_PATTERNS) + _mods(modules, lambda m: (
            m.get("is_selected") and dn(m["name"]) and plain(m)
            and any("No precompiled files were found" in i for i in m.get("issues", []))))
    if num == 10:
        return _mods(modules, lambda m: sh._is_js_module(m["name"]) and not sh._is_node_module(m["name"])
                     and "extracted from .map file" not in m["name"].lower() and not m["has_fatal"]
                     and plain(m) and not m.get("is_selected"))
    if num == 11:
        return _files(files, sh.SRC_JAVA + sh.SRC_CS + sh.SRC_SLN + sh.SRC_CSPROJ + sh.SRC_C
                      + sh.SRC_CPP + sh.SRC_SWIFT)
    if num == 12:
        return _mods(modules, lambda m: m.get("is_selected") and not m["is_ignored"]
                     and any(i.startswith("Missing Supporting Files") for i in m.get("issues", [])))
    if num == 13:
        return _mods(modules, lambda m: dn(m["name"]) and plain(m)
                     and any("No supporting files or PDB files" in i for i in m.get("issues", [])))
    if num == 14:
        return _mods(modules, lambda m: m["has_fatal"] and plain(m) and (
            st(m, "(Fatal)Unsupported Platform") or st(m, "(Fatal)Unsupported Compiler")))
    if num == 15:
        return sh._fancy_match_modules(modules, sh.GRADLE_WRAPPER, selected_only=True)
    if num == 16:
        return _files(files, sh.SENSITIVE_SECRET_PATTERNS + sh.SENSITIVE_BACKUP_PATTERNS
                      + sh.SENSITIVE_WORD_PATTERNS + sh.SENSITIVE_SPREADSHEET_PATTERNS
                      + sh.SENSITIVE_JUPYTER_PATTERNS)
    if num == 17:
        return [f["name"] for f in files if f["name"].lower() in ("fsmonitor-watchman.sample", "fetch_head")]
    if num == 18:
        return _mods(modules, lambda m: sh._is_node_module(m["name"]))
    if num == 19:
        sel = sh._fancy_match_modules(modules, sh.TEST_FILE_PATTERNS, selected_only=True)
        up = _files(files, sh.TEST_FILE_PATTERNS)
        inner = _mods(modules, lambda m: any("test/" in i.lower() for i in m.get("issues", [])))
        out = {n: f"{n} (selected)" for n in sel}
        for n in [*up, *inner]:
            out.setdefault(n, n)
        return list(out.values())
    if num == 21:
        return _files(files, sh.EXCESS_MSFT_PATTERNS)
    if num == 22:
        return _files(files, sh.LOOSE_CLASS_FILE) + sh._fancy_match_modules(modules, sh.LOOSE_CLASS_MODULE)
    if num == 23:
        return _files(files, sh.GO_WORKSPACE_PATTERNS)
    if num == 24:
        return _mods(modules, lambda m: not m["is_dep"] and plain(m) and not m.get("is_selected")
                     and not sh._is_js_module(m["name"]) and not m["has_fatal"])
    if num == 25:
        chosen = {m["name"] for m in modules if m.get("is_selected") and not m["is_ignored"]}
        return sorted(chosen & {m["name"] for m in modules if m["is_dep"]})
    if num == 26:
        return _mods(modules, lambda m: m.get("is_selected") and not m["is_ignored"] and m["is_dep"])
    if num == 27:
        seen: Counter[str] = Counter(f["name"] for f in files
                                     if not f.get("is_ignored") and not f.get("is_third_party"))
        return [n for n, c in seen.items() if c > 1]
    if num == 28:
        return list(dict.fromkeys(f["name"] for f in files if f["name"].lower().endswith(".min.js")))
    return []


# ==========================================================================
# Verdicts
# ==========================================================================

def findings_risk(b: BuildSnapshot) -> tuple[str, str]:
    """(level, reason) from the dashboard's own findings scoring, so the
    single-app verdict and the tenant dashboard agree."""
    if b.open_by_severity is None:
        return "GRAY", "Flaw severity breakdown unavailable for this build"
    cfg = sh.DASHBOARD_CONFIG
    app = sh.ApplicationHealth(ever_scanned=True, flaw_severity_available=True,
                               critical_flaws=b.open_by_severity["very_high"],
                               high_flaws=b.open_by_severity["high"],
                               medium_flaws=b.open_by_severity["medium"],
                               low_flaws=b.open_by_severity["low"],
                               veracode_score=b.score,
                               analysis_size_mb=(b.analysis_size_bytes or 0) / (1024 * 1024))
    app.weighted_flaw_load = round(sh.flaw_weighted_load(app, cfg), 2)
    basis, label = sh.flaw_density_basis(app, cfg)
    app.density_basis_value, app.density_basis_label = basis, label
    if basis > 0:
        app.flaw_density = round(app.weighted_flaw_load / max(basis, cfg["flaws"]["min_basis"]), 2)
    level = sh._flaw_risk(app, cfg)
    return level, app.findings_basis or "No open very-high or high flaws"


def verdicts(report: AppReport, dur: DurationStats, cad: CadenceStats,
             cfg: dict[str, Any] | None = None) -> list[Verdict]:
    """Five headline verdicts, each with a one-line reason."""
    cfg = cfg or ANALYTICS_CONFIG
    b = report.latest
    out: list[Verdict] = []
    if b is None:
        return [Verdict("Scan health", "GRAY", "No published scan", "Nothing to evaluate")]
    hl = {"Good": "GREEN", "Fair": "YELLOW", "Poor": "RED"}.get(b.health, "GRAY")
    if b.checks_ran:
        why = f"{b.high_issues or 0} high and {b.medium_issues or 0} medium severity issues"
    else:
        why = "Checks could not run on this build (inputs unavailable)"
    out.append(Verdict("Scan health", hl, b.health, why))
    lvl, why = findings_risk(b)
    out.append(Verdict("Findings risk", lvl, {"GREEN": "Low", "YELLOW": "Moderate", "ORANGE": "High",
                                              "RED": "Very high", "GRAY": "Unknown"}[lvl], why))
    pol = b.policy_compliance_status or "Unknown"
    out.append(Verdict("Policy", sh._policy_level(pol), pol,
                       f"{b.policy_name or 'Policy'}"
                       + (f", rules {b.policy_rules_status}" if b.policy_rules_status else "")))
    if report.context.get("type") == "sandbox":
        out.append(Verdict("Freshness", "GRAY", "Sandbox",
                           "Scan recency applies to policy scans only"))
    elif b.is_latest_build is False:
        # A linked older scan (--scan): check #30 is not evaluated either.
        out.append(Verdict("Freshness", "GRAY", "Not latest",
                           "A newer scan exists in this context; recency is not evaluated"))
    elif cad.days_since_last is None:
        out.append(Verdict("Freshness", "GRAY", "Unknown", "No dated published scan"))
    else:
        d = cad.days_since_last
        lv = "GREEN" if d <= cfg["stale_days"] else ("ORANGE" if d <= 90 else "RED")
        out.append(Verdict("Freshness", lv, f"{d} days",
                           f"Last policy scan {d} days ago" + (
                               f"; median interval {cad.median_interval_days} days"
                               if cad.median_interval_days is not None else "")))
    dl = {"Regression": "RED", "Normal": "GREEN"}.get(dur.status, "GRAY")
    out.append(Verdict("Duration trend", dl, dur.status, dur.reason))
    return out


# ==========================================================================
# Action plan
# ==========================================================================

# check -> (owner, effort estimate, category)
_CHECK_META: dict[int, tuple[str, str, str]] = {
    1: ("Build/Release Engineer", "S", "Scan performance"),
    2: ("AppSec", "S", "Results accuracy"),
    3: ("AppSec", "M", "Results accuracy"),
    4: ("Developer", "M", "Results accuracy"),
    5: ("Build/Release Engineer", "M", "Results accuracy"),
    6: ("Build/Release Engineer", "S", "Scan performance"),
    7: ("Build/Release Engineer", "S", "Scan performance"),
    8: ("Developer", "M", "Results accuracy"),
    9: ("AppSec", "M", "Results accuracy"),
    10: ("AppSec", "S", "Results accuracy"),
    11: ("Build/Release Engineer", "M", "Results accuracy"),
    12: ("Build/Release Engineer", "M", "Results accuracy"),
    13: ("Build/Release Engineer", "S", "Results accuracy"),
    14: ("Developer", "L", "Results accuracy"),
    15: ("AppSec", "S", "Results accuracy"),
    16: ("Build/Release Engineer", "S", "Security exposure"),
    17: ("Build/Release Engineer", "S", "Security exposure"),
    18: ("Build/Release Engineer", "S", "Scan performance"),
    19: ("Build/Release Engineer", "S", "Results accuracy"),
    20: ("Build/Release Engineer", "M", "Scan performance"),
    21: ("Build/Release Engineer", "S", "Scan performance"),
    22: ("Build/Release Engineer", "M", "Results accuracy"),
    23: ("Build/Release Engineer", "M", "Results accuracy"),
    24: ("AppSec", "S", "Results accuracy"),
    25: ("AppSec", "S", "Results accuracy"),
    26: ("AppSec", "S", "Results accuracy"),
    27: ("Build/Release Engineer", "S", "Results accuracy"),
    28: ("Build/Release Engineer", "S", "Scan performance"),
    29: ("App Owner", "L", "Scan performance"),
    30: ("App Owner", "S", "Process/cadence"),
    31: ("Build/Release Engineer", "M", "Scan performance"),
}
_WHY: dict[str, str] = {
    "Results accuracy": "Affects which code is analysed, so findings can be missing or misleading.",
    "Scan performance": "Adds upload and analysis time without improving results.",
    "Security exposure": "Sensitive material was uploaded to the scanning service.",
    "Process/cadence": "Stale results hide issues introduced since the last scan.",
}
_P1_ACCURACY = {4, 5, 8, 11, 14, 16, 19}
_P2_ACCURACY = {2, 10, 12, 13, 24, 25, 26}
_P2_PERF = {1, 6, 7, 18, 20, 21, 28, 31}


def _prescan_bytes(names: list[str], b: BuildSnapshot) -> int | None:
    """Total prescan size of the named modules, when every one has a size."""
    if b.detail is None or not names:
        return None
    sizes = {m["name"]: sh._parse_module_size(m.get("size", "")) for m in b.detail.prescan_modules}
    uniq = list(dict.fromkeys(n.removesuffix(" (selected)") for n in names))
    vals = [sizes.get(n) for n in uniq]
    if any(v is None or v == 0 for v in vals):
        return None
    return sum(v for v in vals if v)


def action_plan(report: AppReport, dur: DurationStats, cad: CadenceStats,
                hist: list[CheckHistory], cfg: dict[str, Any] | None = None) -> list[ActionItem]:
    """Ranked actions from failing checks, regressions and findings signals."""
    cfg = cfg or ANALYTICS_CONFIG
    b = report.latest
    if b is None:
        return []
    by_num = {h.check_num: h for h in hist}
    items: list[ActionItem] = []
    links = [(lbl, u) for lbl, u in (("Review Modules", b.review_url), ("Triage Flaws", b.triage_url))
             if u]
    for c in b.checks:
        if c.status != "Fail":
            continue
        owner, effort, category = _CHECK_META.get(c.check_num, ("AppSec", "M", "Results accuracy"))
        if (c.check_num in _P1_ACCURACY and c.severity == "high") or c.check_num == 30:
            prio = "P1"
        elif c.check_num in _P2_ACCURACY | _P2_PERF or c.severity == "high":
            prio = "P2"
        else:
            prio = "P3"
        h = by_num.get(c.check_num)
        verify = f"Check #{c.check_num} passes on the next scan."
        effect = "Not quantifiable from available data"
        size = _prescan_bytes(c.evidence, b) if c.check_num in (2, 15, 18, 19, 24, 25, 26) else None
        if size:
            effect = (f"Prescan module size of the listed items: {size / 1e6:.1f} MB "
                      "(upper bound on what deselecting or removing them takes out of the scan)")
            verify += f" Uploaded module size drops by up to {size / 1e6:.1f} MB."
        items.append(ActionItem(
            priority=prio, title=c.label, owner_role=owner, effort=effort, category=category,
            why=_WHY[category], evidence=list(c.issues) + ([f"{c.evidence_total} item(s) matched"]
                                                          if c.evidence_total else []),
            evidence_total=c.evidence_total, how_to_fix=list(c.recommendations),
            verify=verify, expected_effect=effect, links=links, check_num=c.check_num,
            consecutive_failing=h.consecutive_failing if h else 0))
    if b.open_by_severity and b.open_by_severity.get("very_high"):
        n = b.open_by_severity["very_high"]
        items.append(ActionItem(
            priority="P1", title=f"Remediate {n} open Very High flaw(s)", owner_role="Developer",
            effort="M", category="Security exposure",
            why="Very High flaws are the most exploitable findings and usually block policy.",
            evidence=[f"{n} open Very High, {b.open_by_severity.get('high', 0)} open High"],
            how_to_fix=["Fix or, where justified, propose a mitigation for each Very High flaw.",
                        "Use Triage Flaws to filter by severity 5."],
            verify="Open Very High count is 0 on the next policy scan.", links=links))
    if dur.status == "Regression":
        items.append(ActionItem(
            priority="P1" if dur.has_size_or_module_driver else "P2",
            title="Investigate the scan duration regression", owner_role="Build/Release Engineer",
            effort="M", category="Scan performance", why=dur.reason,
            evidence=dur.drivers or ["No size, LOC or module driver identified"],
            how_to_fix=["Compare the uploaded package with the previous build (see What changed).",
                        "Remove test, third-party and duplicate artefacts from the upload."],
            verify="Analysis time returns below the baseline threshold "
                   f"({sh._fmt_seconds(int(dur.threshold or 0))}).", links=links))
    if cad.failure_rate is not None and cad.failure_rate > cfg["failure_rate_p1"]:
        items.append(ActionItem(
            priority="P1", title="Reduce failed scan attempts", owner_role="Build/Release Engineer",
            effort="M", category="Process/cadence", why=cad.failure_rate_note,
            evidence=[f"Failure rate {cad.failure_rate:.0%}"],
            how_to_fix=["Review the prescan errors of the failed builds.",
                        "Use the Veracode CLI auto-packager to produce consistent uploads."],
            verify="The next attempts publish results."))
    if sh._policy_level(b.policy_compliance_status or "") == "RED":
        items.append(ActionItem(
            priority="P2", title="Bring the application back into policy compliance",
            owner_role="App Owner", effort="M", category="Security exposure",
            why=f"Policy {b.policy_name or ''} status is {b.policy_compliance_status}.",
            evidence=[f"Rules status: {b.policy_rules_status or 'Unknown'}"],
            how_to_fix=["Address the policy-affecting flaws first (Triage Flaws, filter by policy)."],
            verify="Policy status is Pass on the next policy scan.", links=links))
    rank = {"P1": 0, "P2": 1, "P3": 2}
    items.sort(key=lambda a: (rank[a.priority], -a.consecutive_failing, a.check_num or 0))
    return items


# ==========================================================================
# Module table and entry point
# ==========================================================================

def _sev_counts(s: Any) -> list[int | None]:
    """[Very High, High, Medium, Low] from numflawssev5..0 (Low = 0-2)."""
    n = s.numflawssev
    low = [x for x in n[:3] if x is not None]
    return [n[5], n[4], n[3], sum(low) if low else None]


def module_table(b: BuildSnapshot | None) -> list[dict[str, Any]]:
    """Per-module rows for the latest build, selected modules first."""
    if b is None or b.detail is None:
        return []
    stats = {m.name: m for m in b.modules}
    rows = []
    for m in b.detail.merged_modules:
        s = stats.get(m["name"])
        rows.append({
            "name": m["name"], "selected": bool(m.get("is_selected")), "dependency": bool(m.get("is_dep")),
            "fatal": bool(m.get("has_fatal")), "third_party": bool(m.get("is_third_party")),
            "compiler": m.get("compiler", ""), "platform": m.get("platform", ""),
            "size": m.get("size", ""), "loc": s.loc if s else None,
            "flaws_by_sev": _sev_counts(s) if s else None,
            "issues": list(m.get("issues", [])),
        })
    rows.sort(key=lambda r: (not r["selected"], r["name"].lower()))
    return rows


def analyse(report: AppReport, baseline_window: int, now: datetime | None = None) -> Analysis:
    """Build the full Analysis for a collected report."""
    dur = duration_stats(report.builds, baseline_window)
    cad = cadence_stats(report.builds, report.other_builds, now)
    hist = check_history(report.builds)
    return Analysis(
        verdicts=verdicts(report, dur, cad), actions=action_plan(report, dur, cad, hist),
        duration=dur, cadence=cad, findings=findings_trend(report.builds),
        diffs=diffs(report.builds), check_history=hist, modules=module_table(report.latest))
