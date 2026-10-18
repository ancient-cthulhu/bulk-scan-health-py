"""Single app, sandbox or scan report: resolve, collect, cache, run()."""

from __future__ import annotations

import argparse
import contextlib
import difflib
import fnmatch
import gzip
import html
import json
import logging
import os
import re
import tempfile
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, parse_qs, unquote, urlsplit

import requests

import scan_health as sh

from . import app_report_analytics as ana

log = logging.getLogger("scan_health.app_report")

SCHEMA_VERSION = "1.0"
TOOL_NAME = "scan_health.py single-application report"

EXIT_OK = 0
EXIT_FATAL = 1
EXIT_RESOLVE = 2
EXIT_WRITE = 3
EXIT_INTERRUPT = 130

APP_REPORT_CONFIG: dict[str, Any] = {
    "history_hard_cap": 50,
    "max_unpublished_walk": 10,
    # Reports carry mitigation state, which changes after publication.
    "report_cache_ttl_hours": 24,
    # Access-scoping teams, not owners; --hide-teams adds more patterns.
    "hidden_teams": ("Service Delivery - *",),
}

CACHEABLE_ENDPOINTS: frozenset[str] = frozenset({
    "getbuildinfo.do", "detailedreport.do", "summaryreport.do",
    "getfilelist.do", "getprescanresults.do",
})
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DIGITS_RE = re.compile(r"^\d{1,12}$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class ResolutionError(Exception):
    """The requested application or sandbox matched zero or several profiles."""

    def __init__(self, message: str, candidates: list[str] | None = None) -> None:
        super().__init__(message)
        self.candidates = candidates or []


class AccessDenied(ResolutionError):
    """The API refused the credentials (401/403) while the link or name was being checked."""


def access_denied_message(status: int, what: str, region: str) -> str:
    return (f"The Veracode API refused access (HTTP {status}) while checking {what}. Nothing was "
            "collected. Usual causes: the link is for a different region than the API credentials "
            f"(this run uses {region}); the application belongs to another Veracode account; or the "
            "API user lacks the Results API / Reviewer role. Fix the link or credentials and run again.")


class ApiUnreachable(ResolutionError):
    """The Veracode API could not be reached while the link or name was being checked."""


def unreachable_message(url: str, exc: Exception, region: str) -> str:
    host = urlsplit(url).hostname or url
    return (f"Could not reach the Veracode API at {host} ({type(exc).__name__}). Nothing was "
            "collected. Check network, proxy or firewall access to that host, and that the region "
            f"is right (this run uses {region}; set --region eu for analysiscenter.veracode.eu).")


class FatalAPIError(Exception):
    """An API failure that leaves nothing meaningful to report (for example the application lookup
    itself failing)."""


def term_safe(s: object) -> str:
    """Strip control characters before printing attacker-controllable names (profile, sandbox, module
    and file names) to a terminal, so an embedded escape sequence cannot rewrite the operator's
    screen."""
    return _CTRL_RE.sub("?", str(s))


def slugify(name: str, max_len: int = 40) -> str:
    """Filesystem-safe slug for the default report folder name."""
    s = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").lower()
    return (s[:max_len].rstrip("_")) or "app"


def iso_utc(raw: str | None) -> str | None:
    """Veracode date string to ISO 8601 UTC, or None when absent or unparseable."""
    if not raw:
        return None
    dt = sh._parse_dt(raw)
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def utc_now_iso() -> str:
    """Current time, ISO 8601 UTC with a Z suffix."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(s: str | None) -> datetime | None:
    """Inverse of iso_utc."""
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _txt(el: ET.Element, name: str) -> str | None:
    """Text attribute, unescaped."""
    v = el.get(name)
    return None if v is None else html.unescape(v)


def _bool_attr(v: str | None) -> bool | None:
    """'true'/'false' to bool."""
    if v is None:
        return None
    lv = v.strip().lower()
    if lv == "true":
        return True
    if lv == "false":
        return False
    return None


_SEEN_UNKNOWN: set[tuple[str, str]] = set()


def _log_unknown_attrs(element: str, el: ET.Element, known: frozenset[str]) -> None:
    """DEBUG-log attributes not in the documented or observed set, once each, so new platform fields
    are noticed without being parsed on guesswork."""
    for k in el.attrib:
        if k.startswith("{") or k in known:
            continue
        key = (element, k)
        if key not in _SEEN_UNKNOWN:
            _SEEN_UNKNOWN.add(key)
            log.debug("Unmapped attribute %s/@%s (value not parsed)", element, k)


@dataclass
class DataNote:
    """One entry in the report's Data Notes: a source, a gap, or a caveat."""
    topic: str
    message: str
    level: str = "info"


@dataclass
class AppInfo:
    """The resolved application profile."""
    guid: str
    legacy_id: int
    name: str
    business_unit: str = ""
    policy: str = ""
    business_criticality: str | None = None
    teams: list[str] = field(default_factory=list)
    region: str = "commercial"


@dataclass
class BuildRef:
    """One build from getbuildlist, enriched with getbuildinfo."""
    build_id: str
    version: str = ""
    policy_updated_date: str | None = None
    analysis_type: str | None = None
    status: str = ""
    status_class: str = "unknown"
    published: str | None = None
    engine_version: str | None = None
    submitter: str | None = None
    platform: str | None = None
    lifecycle_stage: str | None = None
    policy_name: str | None = None
    policy_version: str | None = None
    policy_compliance_status: str | None = None
    rules_status: str | None = None
    grace_period_expired: bool | None = None
    scan_overdue: bool | None = None
    legacy_scan_engine: bool | None = None
    results_ready: bool | None = None
    sca_results_ready: bool | None = None
    info_error: str = ""


@dataclass
class FlawStatus:
    """The flaw-status element."""
    new: int | None = None
    reopen: int | None = None
    open: int | None = None
    cannot_reproduce: int | None = None
    fixed: int | None = None
    total: int | None = None
    not_mitigated: int | None = None
    sev_change: dict[str, int | None] = field(default_factory=dict)


@dataclass
class ModuleStat:
    """static-analysis/modules/module."""
    name: str
    compiler: str = ""
    os: str = ""
    architecture: str = ""
    loc: int | None = None
    score: int | None = None
    numflawssev: list[int | None] = field(default_factory=lambda: [None] * 6)


@dataclass
class CheckOutcome:
    """Result of one health check on one build."""
    check_num: int
    check_name: str
    label: str
    category: str
    max_severity: str
    status: str
    severity: str = ""
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    reason: str = ""
    evidence: list[str] = field(default_factory=list)
    evidence_total: int | None = None


@dataclass
class BuildDetail:
    """Per-build lists that are too heavy for JSON but needed for diffs and evidence."""
    files: list[dict[str, Any]] = field(default_factory=list)
    prescan_modules: list[dict[str, Any]] = field(default_factory=list)
    merged_modules: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class BuildSnapshot:
    """Everything known about one published build."""
    build_id: str
    version: str = ""
    sandbox: str = ""
    is_latest: bool = False
    mode: str = "full"
    status: str = ""
    submitted: str | None = None
    published: str | None = None
    analysis_seconds: int | None = None
    analysis_duration: str = "Unavailable"
    analysis_size_bytes: int | None = None
    engine_version: str | None = None
    score: int | None = None
    rating: str | None = None
    mitigated_score: int | None = None
    mitigated_rating: str | None = None
    policy_name: str | None = None
    policy_version: str | None = None
    policy_compliance_status: str | None = None
    policy_rules_status: str | None = None
    grace_period_expired: bool | None = None
    scan_overdue: bool | None = None
    is_latest_build: bool | None = None
    legacy_scan_engine: bool | None = None
    submitter: str | None = None
    platform: str | None = None
    lifecycle_stage: str | None = None
    business_criticality: str | None = None
    first_build_submitted_date: str | None = None
    last_update_time: str | None = None
    total_flaws: int | None = None
    flaws_not_mitigated: int | None = None
    flaw_status: FlawStatus | None = None
    flaw_status_source: str | None = None
    open_by_severity: dict[str, int] | None = None
    open_policy_flaws: int | None = None
    mitigated_flaws: int | None = None
    modules: list[ModuleStat] = field(default_factory=list)
    loc_total: int | None = None
    selected_module_count: int | None = None
    prescan_module_count: int | None = None
    files_uploaded: int | None = None
    prescan_total_bytes: int | None = None
    sca_enabled: bool | None = None
    sca_vulnerable_components: int | None = None
    sca_components: list[str] = field(default_factory=list)
    checks: list[CheckOutcome] = field(default_factory=list)
    checks_ran: bool = False
    health: str = "Unavailable"
    high_issues: int | None = None
    medium_issues: int | None = None
    review_url: str = ""
    triage_url: str = ""
    overview_url: str = ""
    sources: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    cache_hits: list[str] = field(default_factory=list)
    detail: BuildDetail | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready dict."""
        d = asdict(self)
        d.pop("detail", None)
        return d


@dataclass
class AppReport:
    """Single source of truth consumed by every renderer."""
    app: AppInfo
    context: dict[str, Any]
    parameters: dict[str, Any]
    generated: str = field(default_factory=lambda: utc_now_iso())
    builds: list[BuildSnapshot] = field(default_factory=list)
    other_builds: list[BuildRef] = field(default_factory=list)
    history_status: str = "Unknown"
    data_notes: list[DataNote] = field(default_factory=list)
    collection: dict[str, Any] = field(default_factory=dict)
    complete: bool = True
    analysis: Any = None

    @property
    def latest(self) -> BuildSnapshot | None:
        return self.builds[0] if self.builds else None

    def note(self, topic: str, message: str, level: str = "info") -> None:
        """Add a Data Notes entry, ignoring exact duplicates."""
        n = DataNote(topic, message, level)
        if n not in self.data_notes:
            self.data_notes.append(n)


class ResponseCache:
    """Gzip-compressed raw API responses under <root>/<region>/<app_id>/<build_id>/."""

    def __init__(self, root: Path | None, mode: str = "use",
                 ttl_hours: float = 24.0, history_root: Path | None = None) -> None:
        if mode not in ("use", "refresh", "off"):
            raise ValueError(f"bad cache mode {mode!r}")
        self.root = root
        self.history_root = history_root
        self.mode = mode if root is not None else "off"
        self.ttl_seconds = ttl_hours * 3600.0
        self.hits = 0
        self.misses = 0
        self.writes = 0
        self.write_errors = 0
        if self.mode != "off" and self.root is not None:
            try:
                created = not self.root.exists()
                self._ensure_dir(self.root)
                if created:
                    (self.root / ".gitignore").write_text("# Created by scan_health.py\n*\n",
                                                          encoding="utf-8")
            except OSError as e:
                log.warning("[!] Cache disabled: cannot use %s (%s). The run continues "
                            "without caching.", self.root, e)
                self.mode = "off"

    @staticmethod
    def _ensure_dir(path: Path) -> None:
        """Create each missing level with mode 0700."""
        missing: list[Path] = []
        p = path
        while not p.exists():
            missing.append(p)
            if p.parent == p:
                break
            p = p.parent
        for d in reversed(missing):
            # Windows: plain mkdir. Python 3.13 (and CVE-2024-4030 backports) turn mode=0o700 into a
            # protected owner-only ACL, which other tools and sync clients may not be able to read.
            if os.name == "nt":
                with contextlib.suppress(FileExistsError):
                    d.mkdir()
                continue
            with contextlib.suppress(FileExistsError):
                d.mkdir(mode=0o700)
            # mkdir's mode is filtered by the umask; set it explicitly.
            with contextlib.suppress(OSError):
                os.chmod(d, 0o700)

    def path(self, region: str, app_id: str, build_id: str, endpoint: str) -> Path:
        """Cache path for one response."""
        if self.root is None:
            raise RuntimeError("cache disabled")
        if region not in sh.REGIONS:
            raise ValueError(f"bad region {region!r}")
        if not _DIGITS_RE.match(app_id) or not _DIGITS_RE.match(build_id):
            raise ValueError("app_id and build_id must be numeric for caching")
        if endpoint not in CACHEABLE_ENDPOINTS:
            raise ValueError(f"endpoint {endpoint!r} is not cacheable")
        return self.root / region / app_id / build_id / f"{endpoint}.xml.gz"

    def read(self, p: Path, ttl: bool) -> bytes | None:
        """Cached bytes, or None on miss, expiry, corruption, or refresh mode."""
        if self.mode != "use":
            return None
        try:
            st = p.stat()
        except OSError:
            self.misses += 1
            return None
        if ttl and (time.time() - st.st_mtime) > self.ttl_seconds:
            self.misses += 1
            return None
        try:
            with gzip.open(p, "rb") as fh:
                data = fh.read()
        except (OSError, EOFError) as e:
            log.debug("Discarding unreadable cache entry %s: %s", p, e)
            self.misses += 1
            return None
        self.hits += 1
        return data

    def write(self, p: Path, data: bytes) -> None:
        """Atomic, private write."""
        if self.mode == "off":
            return
        try:
            self._ensure_dir(p.parent)
            # mkstemp is 0600 on POSIX; os.fchmod is missing on Windows before 3.13.
            fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".tmp_", suffix=".gz")
            try:
                with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
                    gz.write(data)
                os.replace(tmp, p)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
            self.writes += 1
        except OSError as e:
            self.write_errors += 1
            log.warning("Cache write failed for %s: %s", p, e)

    def history_path(self, app_guid: str) -> Path | None:
        """<history_root>/<app_guid>.jsonl, or <root>/<app_guid>/history.jsonl without a history_root
        (then None when caching is off)."""
        if not _GUID_RE.match(app_guid):
            return None
        if self.history_root is not None:
            return self.history_root / f"{app_guid.lower()}.jsonl"
        if self.mode == "off" or self.root is None:
            return None
        return self.root / app_guid.lower() / "history.jsonl"

    def append_history(self, app_guid: str, record: dict[str, Any]) -> Path | None:
        """Append one point-in-time snapshot so trends survive builds being deleted on the platform."""
        hp = self.history_path(app_guid)
        if hp is None:
            return None
        try:
            created = not hp.parent.exists()
            self._ensure_dir(hp.parent)
            if created and self.history_root is not None:
                with contextlib.suppress(OSError):
                    (hp.parent / ".gitignore").write_text("# Created by scan_health.py\n*\n",
                                                          encoding="utf-8")
            fd = os.open(hp, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True, default=str) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            with contextlib.suppress(OSError):
                os.chmod(hp, 0o600)
            return hp
        except OSError as e:
            log.warning("history.jsonl append failed for %s: %s", hp, e)
            return None


@dataclass
class FetchResult:
    """Outcome of one XML request."""
    endpoint: str
    root: ET.Element | None = None
    error: str = ""
    from_cache: bool = False
    raw: bytes = b""

    @property
    def ok(self) -> bool:
        return self.root is not None and not self.error


class Fetcher:
    """Every XML request in single-application mode goes through here, and from here through
    VeracodeClient._get."""

    def __init__(self, client: sh.VeracodeClient, cache: ResponseCache, region: str) -> None:
        self.client = client
        self.cache = cache
        self.region = region
        self.calls: dict[str, int] = {"report": 0, "xml": 0, "rest": 0}
        self.errors: list[str] = []
        # While resolving, 401/403 stops at once; afterwards the auth window covers credential
        # rotation.
        self.fail_fast = False

    def xml(self, endpoint: str, params: dict[str, Any], *, app_id: str,
            build_id: str | None = None, cache_policy: str = "none") -> FetchResult:
        """Fetch one XML endpoint."""
        if cache_policy not in ("none", "immutable", "ttl", "refresh", "read_only"):
            raise ValueError(f"bad cache policy {cache_policy!r}")
        cpath: Path | None = None
        if cache_policy != "none" and build_id is not None and self.cache.mode != "off":
            try:
                cpath = self.cache.path(self.region, app_id, build_id, endpoint)
            except ValueError as e:
                log.debug("Not caching %s: %s", endpoint, e)
        if cpath is not None and cache_policy in ("immutable", "ttl", "read_only"):
            data = self.cache.read(cpath, ttl=(cache_policy == "ttl"))
            if data is not None:
                try:
                    root = sh.parse_xml_bytes(data)
                    if root.tag != "error":
                        return FetchResult(endpoint, root=root, from_cache=True, raw=data)
                except ET.ParseError:
                    log.debug("Corrupt cache entry %s ignored", cpath)

        bucket = sh.RateLimiter.classify(endpoint)
        url = f"{self.client._cfg['xml']}/{endpoint}"
        self.calls[bucket] += 1
        try:
            r = self.client._get(url, params, bucket, auth_retry=not self.fail_fast,
                                 quick=self.fail_fast)
        except sh.TransientAuthError as e:
            return self._fail(endpoint, f"authentication failure persisted: {e}")
        except requests.RequestException as e:
            if self.fail_fast:
                raise ApiUnreachable(unreachable_message(url, e, self.region)) from e
            return self._fail(endpoint, f"{type(e).__name__}: {e}")
        if self.fail_fast and r.status_code in (401, 403):
            raise AccessDenied(access_denied_message(r.status_code, f"app {app_id} ({endpoint})",
                                                     self.region))
        if not r.ok:
            return self._fail(endpoint, f"HTTP {r.status_code}")
        try:
            root = sh.parse_xml_bytes(r.content)
        except ET.ParseError as e:
            return self._fail(endpoint, f"unparseable XML: {e}")
        # XML APIs report errors as HTTP 200 with an <error> body; never read as empty.
        if root.tag == "error":
            return self._fail(endpoint, f"API error: {(root.text or '').strip()[:200]}")
        if cpath is not None and cache_policy in ("immutable", "ttl", "refresh"):
            self.cache.write(cpath, r.content)
        return FetchResult(endpoint, root=root, raw=r.content)

    def store(self, result: FetchResult, app_id: str, build_id: str) -> None:
        """Cache a fresh response the caller has decided is immutable."""
        if result.from_cache or not result.raw or self.cache.mode == "off":
            return
        try:
            p = self.cache.path(self.region, app_id, build_id, result.endpoint)
        except (ValueError, RuntimeError):
            return
        self.cache.write(p, result.raw)

    def rest(self, path: str, params: dict[str, Any] | None = None,
             auth_retry: bool | None = None) -> dict[str, Any]:
        """REST GET through the client."""
        self.calls["rest"] += 1
        retry = (not self.fail_fast) if auth_retry is None else auth_retry
        url = f"{self.client._cfg['rest']}{path}"
        try:
            r = self.client._get(url, params, "rest", auth_retry=retry, quick=self.fail_fast)
        except requests.RequestException as e:
            if self.fail_fast:
                raise ApiUnreachable(unreachable_message(url, e, self.region)) from e
            raise
        if auth_retry is None and self.fail_fast and r.status_code in (401, 403):
            raise AccessDenied(access_denied_message(r.status_code, "the application", self.region))
        if r.status_code == 404:
            return {}
        r.raise_for_status()
        body = r.json()
        return body if isinstance(body, dict) else {}

    def _fail(self, endpoint: str, msg: str) -> FetchResult:
        log.debug("%s failed: %s", endpoint, msg)
        self.errors.append(f"{endpoint}: {msg}")
        return FetchResult(endpoint, error=msg)


def visible_teams(teams: list[str], extra: str | None = None) -> list[str]:
    """Teams minus hidden name patterns (case-insensitive, * wildcard)."""
    pats = [*APP_REPORT_CONFIG["hidden_teams"], *(x.strip() for x in (extra or "").split(",") if x.strip())]
    return [t for t in teams if not any(fnmatch.fnmatchcase(t.casefold(), x.casefold()) for x in pats)]


def normalise_application(a: dict[str, Any]) -> AppInfo:
    """REST application JSON to AppInfo."""
    p = a.get("profile") or {}
    pols = p.get("policies") or []
    teams_raw = p.get("teams")
    teams: list[str] = []
    if isinstance(teams_raw, list):
        for t in teams_raw:
            if isinstance(t, dict) and t.get("team_name"):
                teams.append(str(t["team_name"]))
    elif teams_raw is not None:
        log.debug("profile.teams has unexpected type %s", type(teams_raw).__name__)
    bc = p.get("business_criticality")
    if bc is None:
        log.debug("profile.business_criticality absent for %s", a.get("guid"))
    legacy = a.get("id")
    return AppInfo(
        guid=str(a.get("guid") or ""),
        legacy_id=_as_int(legacy),
        name=str(p.get("name") or ""),
        business_unit=str((p.get("business_unit") or {}).get("name") or ""),
        policy=str(pols[0].get("name") or "") if pols and isinstance(pols[0], dict) else "",
        business_criticality=str(bc) if bc is not None else None,
        teams=teams,
    )


def _as_int(v: object) -> int:
    """REST legacy id to int; 0 when absent or non-numeric."""
    if isinstance(v, bool):
        return 0
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.isdigit():
        return int(v)
    return 0


def _list_applications(fetcher: Fetcher, params: dict[str, Any]) -> list[dict[str, Any]]:
    """Page through /applications with extra filter params."""
    out: list[dict[str, Any]] = []
    page = 0
    while True:
        d = fetcher.rest("/applications", {**params, "page": page, "size": 500})
        emb = (d.get("_embedded") or {}).get("applications") or []
        if not emb:
            break
        out.extend(a for a in emb if isinstance(a, dict))
        page += 1
        total_pages = (d.get("page") or {}).get("total_pages")
        if isinstance(total_pages, int) and page >= total_pages:
            break
        if page > 1000:
            log.warning("Stopped paging /applications after 1000 pages")
            break
    return out


def closest_names(name: str, names: list[str], n: int = 5) -> list[str]:
    """The n most similar profile names, case-insensitive."""
    key = name.casefold()
    scored = sorted(names, key=lambda x: (-difflib.SequenceMatcher(None, key, x.casefold()).ratio(), x))
    return scored[:n]


def resolve_app(fetcher: Fetcher, args: argparse.Namespace) -> tuple[AppInfo, list[DataNote]]:
    """Resolve --app / --app-id / --app-guid to exactly one profile."""
    notes: list[DataNote] = []
    if args.app_guid is not None:
        guid = str(args.app_guid).strip()
        if not _GUID_RE.match(guid):
            raise ResolutionError(f"--app-guid {term_safe(guid)!r} is not a GUID")
        d = fetcher.rest(f"/applications/{guid.lower()}")
        if not d:
            raise ResolutionError(f"No application profile with GUID {guid}")
        return normalise_application(d), notes

    if args.app_id is not None:
        rows = _list_applications(fetcher, {"legacy_id": int(args.app_id)})
        hits = [a for a in rows if str(a.get("id")) == str(args.app_id)]
        if not hits:
            raise ResolutionError(f"No application profile with app_id {args.app_id}")
        if len(hits) > 1:
            raise ResolutionError(f"app_id {args.app_id} matched {len(hits)} profiles",
                                  [_describe(normalise_application(a)) for a in hits])
        return normalise_application(hits[0]), notes

    name = str(args.app)
    want = name.casefold()
    rows = _list_applications(fetcher, {"name": name})
    hits = [a for a in rows if str((a.get("profile") or {}).get("name") or "").casefold() == want]
    if not hits:
        all_rows = _list_applications(fetcher, {})
        hits = [a for a in all_rows if str((a.get("profile") or {}).get("name") or "").casefold() == want]
        if hits:
            notes.append(DataNote("Resolution", "The ?name= filter returned no exact match "
                                  "but the full listing did; the server-side filter may be "
                                  "case-sensitive on this tenant."))
        else:
            names = [str((a.get("profile") or {}).get("name") or "") for a in all_rows]
            raise ResolutionError(f"No application profile named {term_safe(name)!r}",
                                  closest_names(name, [n for n in names if n]))
    if len(hits) > 1:
        raise ResolutionError(f"{len(hits)} profiles match {term_safe(name)!r} case-insensitively",
                              [_describe(normalise_application(a)) for a in hits])
    return normalise_application(hits[0]), notes


def _describe(a: AppInfo) -> str:
    return f"{term_safe(a.name)}  guid={a.guid}  app_id={a.legacy_id}"


def resolve_sandbox(fetcher: Fetcher, app: AppInfo, name: str) -> dict[str, str]:
    """Exact, case-insensitive sandbox match."""
    fr = fetcher.xml("getsandboxlist.do", {"app_id": app.legacy_id}, app_id=str(app.legacy_id))
    if not fr.ok or fr.root is None:
        raise FatalAPIError(f"Could not list sandboxes: {fr.error}")
    sbs = sh.parse_sandbox_list(fr.root)
    hits = [s for s in sbs if s["name"].casefold() == name.casefold()]
    if not hits:
        raise ResolutionError(f"No sandbox named {term_safe(name)!r} on {term_safe(app.name)}",
                              closest_names(name, [s["name"] for s in sbs if s["name"]]))
    if len(hits) > 1:
        raise ResolutionError(f"{len(hits)} sandboxes match {term_safe(name)!r}",
                              [f"{term_safe(s['name'])}  sandbox_id={s['id']}" for s in hits])
    return hits[0]


def resolve_sandbox_by_id(fetcher: Fetcher, app_id: int, sandbox_id: str) -> dict[str, str]:
    """The sandbox with this id on this application, from getsandboxlist.do."""
    fr = fetcher.xml("getsandboxlist.do", {"app_id": app_id}, app_id=str(app_id))
    if not fr.ok or fr.root is None:
        raise FatalAPIError(f"Could not list sandboxes: {fr.error}")
    for s in sh.parse_sandbox_list(fr.root):
        if str(s["id"]) == sandbox_id:
            return s
    raise ResolutionError(f"No sandbox with sandbox_id {sandbox_id} on app_id {app_id}")


_BUILD_KNOWN = frozenset({
    "build_id", "version", "submitter", "platform", "lifecycle_stage", "policy_name",
    "policy_version", "policy_compliance_status", "rules_status", "grace_period_expired",
    "scan_overdue", "legacy_scan_engine", "results_ready", "sca_results_ready",
    "policy_updated_date", "launch_date",
})
_AU_KNOWN = frozenset({"analysis_type", "status", "engine_version", "published_date", "eta_status"})


def classify_status(status: str, published: str | None) -> str:
    """Map a getbuildinfo analysis_unit status to a coarse class."""
    s = re.sub(r"[\s\-_]", "", (status or "").lower())
    if published or s == "resultsready":
        return "published"
    if "fail" in s or s == "nomodulesdefined":
        return "failed"
    if "cancel" in s:
        return "cancelled"
    if s == "incomplete":
        return "incomplete"
    if s:
        return "in_progress"
    return "unknown"


def parse_build_info_full(root: ET.Element, build_id: str) -> BuildRef:
    """getbuildinfo.do with every documented build and analysis_unit attribute."""
    b = root.find(".//build")
    au = root.find(".//analysis_unit")
    ref = BuildRef(build_id=build_id)
    if b is not None:
        _log_unknown_attrs("build", b, _BUILD_KNOWN)
        ref.build_id = b.get("build_id") or build_id
        ref.version = _txt(b, "version") or ""
        ref.policy_updated_date = iso_utc(b.get("policy_updated_date"))
        ref.submitter = _txt(b, "submitter")
        ref.platform = _txt(b, "platform")
        ref.lifecycle_stage = _txt(b, "lifecycle_stage")
        ref.policy_name = _txt(b, "policy_name")
        ref.policy_version = b.get("policy_version")
        ref.policy_compliance_status = b.get("policy_compliance_status")
        ref.rules_status = b.get("rules_status")
        ref.grace_period_expired = _bool_attr(b.get("grace_period_expired"))
        ref.scan_overdue = _bool_attr(b.get("scan_overdue"))
        ref.legacy_scan_engine = _bool_attr(b.get("legacy_scan_engine"))
        ref.results_ready = _bool_attr(b.get("results_ready"))
        ref.sca_results_ready = _bool_attr(b.get("sca_results_ready"))
    if au is not None:
        _log_unknown_attrs("analysis_unit", au, _AU_KNOWN)
        ref.analysis_type = au.get("analysis_type")
        ref.status = au.get("status", "")
        ref.engine_version = au.get("engine_version")
        ref.published = iso_utc(au.get("published_date"))
    ref.status_class = classify_status(ref.status, ref.published)
    return ref


@dataclass
class Enumeration:
    """Result of walking the build list."""
    published: list[BuildRef] = field(default_factory=list)
    other: list[BuildRef] = field(default_factory=list)
    skipped_non_static: int = 0
    list_total: int = 0
    list_error: str = ""
    walk_truncated: bool = False


def enumerate_builds(fetcher: Fetcher, app: AppInfo, sandbox_id: str | None,
                     target: int, since: date | None,
                     cfg: dict[str, Any] | None = None,
                     older_than: int | None = None) -> Enumeration:
    """Find up to `target` published static builds, newest first."""
    cfg = cfg or APP_REPORT_CONFIG
    en = Enumeration()
    params: dict[str, Any] = {"app_id": app.legacy_id}
    if sandbox_id:
        params["sandbox_id"] = sandbox_id
    fr = fetcher.xml("getbuildlist.do", params, app_id=str(app.legacy_id))
    if not fr.ok or fr.root is None:
        en.list_error = fr.error or "no response"
        return en
    rows = sh.parse_build_list(fr.root)
    en.list_total = len(rows)
    ids: list[tuple[int, dict[str, Any]]] = []
    for r in rows:
        bid = str(r.get("build_id") or "")
        if bid.isdigit():
            ids.append((int(bid), r))
        else:
            log.debug("getbuildlist: ignoring non-numeric build_id %r", bid)
    ids.sort(key=lambda t: t[0], reverse=True)
    if older_than is not None:
        ids = [t for t in ids if t[0] < older_than]

    unpublished_seen = 0
    for _, row in ids:
        if len(en.published) >= target:
            break
        if unpublished_seen >= cfg["max_unpublished_walk"]:
            en.walk_truncated = True
            break
        bid = str(row["build_id"])
        info_params: dict[str, Any] = {"app_id": app.legacy_id, "build_id": bid}
        if sandbox_id:
            info_params["sandbox_id"] = sandbox_id
        # Cached only once published, so reading without expiry is safe.
        ir = fetcher.xml("getbuildinfo.do", info_params, app_id=str(app.legacy_id),
                         build_id=bid, cache_policy="read_only")
        if not ir.ok or ir.root is None:
            ref = BuildRef(build_id=bid, version=html.unescape(row.get("version", "")),
                           policy_updated_date=iso_utc(row.get("policy_updated_date")),
                           info_error=ir.error or "no response")
            en.other.append(ref)
            unpublished_seen += 1
            continue
        ref = parse_build_info_full(ir.root, bid)
        if not ref.version:
            ref.version = html.unescape(row.get("version", ""))
        if ref.policy_updated_date is None:
            ref.policy_updated_date = iso_utc(row.get("policy_updated_date"))
        if ref.analysis_type is not None and ref.analysis_type.strip().lower() != "static":
            en.skipped_non_static += 1
            continue
        if ref.status_class == "published":
            fetcher.store(ir, str(app.legacy_id), bid)
            if since is not None:
                pub = parse_iso(ref.published)
                if pub is not None and pub.date() < since:
                    break
            en.published.append(ref)
        else:
            en.other.append(ref)
            unpublished_seen += 1
    return en


def latest_build_fallback(fetcher: Fetcher, app: AppInfo, sandbox_id: str | None) -> BuildRef | None:
    """When getbuildlist fails: getbuildinfo.do without build_id returns the most recent static scan
    (documented default)."""
    params: dict[str, Any] = {"app_id": app.legacy_id}
    if sandbox_id:
        params["sandbox_id"] = sandbox_id
    ir = fetcher.xml("getbuildinfo.do", params, app_id=str(app.legacy_id))
    if not ir.ok or ir.root is None:
        return None
    b = ir.root.find(".//build")
    bid = (b.get("build_id") if b is not None else None) or ""
    if not bid:
        return None
    return parse_build_info_full(ir.root, bid)


_ROOT_KNOWN = frozenset({
    "report_format_version", "account_id", "app_name", "app_id", "analysis_id",
    "static_analysis_unit_id", "sandbox_id", "sandbox_name", "first_build_submitted_date",
    "version", "build_id", "submitter", "platform", "assurance_level",
    "business_criticality", "generation_date", "veracode_level", "total_flaws",
    "flaws_not_mitigated", "teams", "life_cycle_stage", "planned_deployment_date",
    "last_update_time", "is_latest_build", "policy_name", "policy_version",
    "policy_compliance_status", "policy_rules_status", "grace_period_expired",
    "scan_overdue", "business_owner", "business_unit", "tags", "legacy_scan_engine",
    "any_type_scan_due",
})
_SA_KNOWN = frozenset({
    "rating", "score", "submitted_date", "published_date", "version", "next_scan_due",
    "analysis_size_bytes", "engine_version", "mitigated_rating", "mitigated_score",
})
_MOD_KNOWN = frozenset({
    "name", "compiler", "os", "architecture", "loc", "score", "numflawssev0",
    "numflawssev1", "numflawssev2", "numflawssev3", "numflawssev4", "numflawssev5",
    "target_url", "domain",
})
_FS_KNOWN = frozenset({
    "new", "reopen", "open", "cannot-reproduce", "fixed", "total", "not_mitigated",
    "sev-1-change", "sev-2-change", "sev-3-change", "sev-4-change", "sev-5-change",
})


def parse_report_meta(root: ET.Element) -> dict[str, Any]:
    """Fields read from detailedreport.do or summaryreport.do beyond what
    scan_health.parse_detailed_report extracts."""
    _log_unknown_attrs("report", root, _ROOT_KNOWN)
    sa = root.find("static-analysis")
    if sa is None:
        sa = root.find(".//static-analysis")
    out: dict[str, Any] = {
        "account_id": root.get("account_id"),
        "policy_name": _txt(root, "policy_name"),
        "policy_version": root.get("policy_version"),
        "policy_compliance_status": root.get("policy_compliance_status"),
        "policy_rules_status": root.get("policy_rules_status"),
        "grace_period_expired": _bool_attr(root.get("grace_period_expired")),
        "scan_overdue": _bool_attr(root.get("scan_overdue")),
        "is_latest_build": _bool_attr(root.get("is_latest_build")),
        "legacy_scan_engine": _bool_attr(root.get("legacy_scan_engine")),
        "business_criticality": _txt(root, "business_criticality"),
        "submitter": _txt(root, "submitter"),
        "platform": _txt(root, "platform"),
        "lifecycle_stage": _txt(root, "life_cycle_stage"),
        "first_build_submitted_date": iso_utc(root.get("first_build_submitted_date")),
        "last_update_time": iso_utc(root.get("last_update_time")),
        "total_flaws": sh._si_or_none(root.get("total_flaws")),
        "flaws_not_mitigated": sh._si_or_none(root.get("flaws_not_mitigated")),
        "has_static_analysis": sa is not None,
    }
    if sa is not None:
        _log_unknown_attrs("static-analysis", sa, _SA_KNOWN)
        out.update({
            "version": _txt(sa, "version"),
            "submitted_raw": sa.get("submitted_date"),
            "published_raw": sa.get("published_date"),
            "submitted": iso_utc(sa.get("submitted_date")),
            "published": iso_utc(sa.get("published_date")),
            "analysis_size_bytes": sh._si_or_none(sa.get("analysis_size_bytes")),
            "engine_version": sa.get("engine_version"),
            "score": sh._si_or_none(sa.get("score")),
            "rating": (sa.get("rating") or "").strip() or None,
            "mitigated_score": sh._si_or_none(sa.get("mitigated_score")),
            "mitigated_rating": (sa.get("mitigated_rating") or "").strip() or None,
        })
        mods: list[ModuleStat] = []
        for m in sa.findall("./modules/module"):
            _log_unknown_attrs("module", m, _MOD_KNOWN)
            mods.append(ModuleStat(
                name=_txt(m, "name") or "", compiler=_txt(m, "compiler") or "",
                os=_txt(m, "os") or "", architecture=_txt(m, "architecture") or "",
                loc=sh._si_or_none(m.get("loc")), score=sh._si_or_none(m.get("score")),
                numflawssev=[sh._si_or_none(m.get(f"numflawssev{i}")) for i in range(6)]))
        out["modules"] = mods
    fs = root.find("flaw-status")
    if fs is None:
        fs = root.find(".//flaw-status")
    if fs is not None:
        _log_unknown_attrs("flaw-status", fs, _FS_KNOWN)
        out["flaw_status"] = FlawStatus(
            new=sh._si_or_none(fs.get("new")), reopen=sh._si_or_none(fs.get("reopen")),
            open=sh._si_or_none(fs.get("open")),
            cannot_reproduce=sh._si_or_none(fs.get("cannot-reproduce")),
            fixed=sh._si_or_none(fs.get("fixed")), total=sh._si_or_none(fs.get("total")),
            not_mitigated=sh._si_or_none(fs.get("not_mitigated")),
            sev_change={str(i): sh._si_or_none(fs.get(f"sev-{i}-change")) for i in range(1, 6)})
    sca = root.find(".//software_composition_analysis")
    if sca is not None:
        out["sca_enabled"] = sca.get("sca_service_available", "true").lower() != "false"
        out["sca_vulnerable_components"] = len(sca.findall(".//vulnerable_components/component"))
    return out


class OutcomeRecorder(sh.CheckObserver):
    """Records each check's result and, before it runs, the items it judges (evidence), computed on
    exactly the state the check sees."""

    def __init__(self) -> None:
        self.results: dict[int, tuple[list[sh.Issue], list[str], Exception | None]] = {}
        self.evidence: dict[int, list[str]] = {}

    def before(self, num: int, name: str, files: list[dict[str, Any]],
               modules: list[dict[str, Any]]) -> None:
        try:
            self.evidence[num] = ana.evidence_for(num, files, modules)
        except Exception as e:
            log.debug("Evidence for check #%d failed: %s", num, e)

    def after(self, num: int, name: str, issues: list[sh.Issue], recs: list[str],
              error: Exception | None) -> None:
        self.results[num] = (list(issues), list(recs), error)


def _blank_outcome(num: int, name: str, status: str, reason: str) -> CheckOutcome:
    label, max_sev = sh.CHECK_CATALOG.get(num, (name, "medium"))
    return CheckOutcome(check_num=num, check_name=name, label=label,
                        category=sh.CHECK_CATEGORIES.get(num, "Other"),
                        max_severity=max_sev, status=status, reason=reason)


def outcomes_unavailable(reason: str, status: str = "Unavailable") -> list[CheckOutcome]:
    """All checks marked with one status, for builds whose inputs are missing."""
    return [_blank_outcome(n, nm, status, reason) for n, nm, _ in sh.CHECK_REGISTRY]


def run_build_checks(files: list[dict[str, Any]], merged: list[dict[str, Any]],
                     dr: dict[str, Any], scan_meta: dict[str, Any], recency_date: str,
                     skip: set[int], na_reasons: dict[int, str]
                     ) -> tuple[list[CheckOutcome], list[sh.Issue]]:
    """Run scan_health's 31 checks once, unchanged, and label each outcome."""
    rec = OutcomeRecorder()
    issues, _recs, _check_recs = sh.run_checks(
        files, merged, dr["flaws"], scan_meta, dr.get("sca_on", False),
        dr.get("sca_comps", []), recency_date, skip, observer=rec)
    out: list[CheckOutcome] = []
    for num, name, _ in sh.CHECK_REGISTRY:
        if num in skip:
            out.append(_blank_outcome(num, name, "Skipped", "Excluded by --skip-checks"))
            continue
        iss, rcs, err = rec.results.get(num, ([], [], None))
        if err is not None:
            out.append(_blank_outcome(num, name, "Error", f"{type(err).__name__}: {err}"))
            continue
        if iss:
            o = _blank_outcome(num, name, "Fail", "")
            ev = rec.evidence.get(num, [])
            if ev:
                o.evidence = ev[:ana.ANALYTICS_CONFIG["evidence_limit"]]
                o.evidence_total = len(ev)
            o.severity = "high" if any(i.severity == "high" for i in iss) else (
                "medium" if any(i.severity == "medium" for i in iss) else "low")
            o.issues = [i.description for i in iss]
            o.recommendations = list(rcs)
            out.append(o)
            continue
        if num in na_reasons:
            out.append(_blank_outcome(num, name, "N/A", na_reasons[num]))
            continue
        out.append(_blank_outcome(num, name, "Pass", ""))
    return out, issues


# Pages Veracode's scan_health accepts; all use Page:account:app:build:...
SCAN_PAGES: tuple[str, ...] = (
    "ReviewResultsStaticFlaws", "ReviewResultsAllFlaws", "AnalyzeAppModuleList",
    "StaticOverview", "AnalyzeAppSourceFiles", "ViewReportsResultSummary",
    "ViewReportsDetailedReport", "ReviewResultsSCA",
)
SCAN_HOSTS: dict[str, str] = {
    "analysiscenter.veracode.com": "commercial",
    "analysiscenter.veracode.eu": "eu",
}


@dataclass(frozen=True)
class ScanTarget:
    """What a --scan value identifies."""
    build_id: str
    app_id: int | None = None
    region: str | None = None
    page: str | None = None
    sandbox_id: str | None = None


# #SandboxView:<account>:<app>:<sandbox>; field 3 is a sandbox id, not a build.
SANDBOX_PAGE = "SandboxView"


def _sandbox_fields(fields: list[str]) -> tuple[str, str] | None:
    """(app_id, sandbox_id) when the fragment is a valid SandboxView link."""
    if fields[0] != SANDBOX_PAGE or len(fields) < 4:
        return None
    app_id, sbx = fields[2], fields[3]
    if not (app_id.isdigit() and sbx.isdigit()) or len(app_id) > 12 or len(sbx) > 12:
        return None
    if int(app_id) <= 0 or int(sbx) <= 0:
        return None
    return app_id, str(int(sbx))


def clean_link(value: str) -> str:
    """Undo common copy-and-paste damage: surrounding quotes or angle brackets, and a '#' that an email
    client or chat tool encoded as %23."""
    v = value.strip().strip("'\"<>").strip()
    if "#" not in v and "%23" in v.lower():
        v = unquote(v)
    return v


def _location(parts: SplitResult) -> str | None:
    """The page part of a platform link: the '#' fragment of /auth/index.jsp, or the loc= parameter of
    a deep link (https://analysiscenter.veracode.com/ ?loc=HomeAppProfile:<account>:<app>), which
    the platform turns into the same fragment after sign-in."""
    loc = parse_qs(parts.query).get("loc")
    if loc:
        return loc[0].strip().lstrip("#").rstrip("#")
    if parts.path.lower() == "/auth/index.jsp":
        return parts.fragment
    return None


def link_problem(value: str, kind: str) -> str:
    """Why a link cannot be used, in plain words, for kind "scan" (--scan) or "app" (--app)."""
    v = _with_scheme(clean_link(value))
    try:
        parts = urlsplit(v)
        host = (parts.hostname or "").lower()
    except ValueError:
        return "This is not a valid link."
    if not host or "." not in host:
        return ("This is neither a Veracode Platform link nor a build ID." if kind == "scan"
                else "This is not a Veracode Platform link.")
    if host == "analysiscenter.veracode.us":
        return ("Links to the US (FedRAMP) region are not supported; this tool supports the "
                "commercial and eu regions.")
    if host not in SCAN_HOSTS:
        return (f"{host} is not the Veracode Platform. Copy the link from analysiscenter.veracode.com "
                "(or .eu).")
    if parts.scheme.lower() != "https":
        return "Use the https:// link."
    location = _location(parts)
    if location is None:
        return ("This points at another part of the Veracode site. Expected a link like "
                "https://analysiscenter.veracode.com/auth/index.jsp#Page:...")
    fields = location.split(":") if location else []
    if not fields:
        return ("The link has no page part after '#'. Copy the whole address from the browser's "
                "address bar (some tools cut links at '#').")
    page = fields[0]
    app_hint = (f" To analyse the whole application, use --app-id {fields[2]}."
                if len(fields) > 2 and fields[2].isdigit() else "")
    if re.search(r"dynamic|dast|manual|discovery", page, re.IGNORECASE):
        return f"{page} is a dynamic or manual analysis page; only static (SAST) scans are supported."
    if kind == "app":
        return ("This link does not carry an application ID. Copy the link of the application, a "
                "sandbox or any of its scans, or use the profile name or --app-id.")
    if page == "HomeAppProfile":
        return ("This links to the application, not to a scan. Use --app with this link for the "
                "application report, or open one of its scans (for example Triage Flaws) and copy "
                "that link.")
    if page == SANDBOX_PAGE:
        return "This sandbox link is cut short or damaged; it needs the sandbox ID at the end."
    if page in SCAN_PAGES:
        if len(fields) < 4 or not fields[3]:
            return "The link is cut short: it has no build ID. Copy the whole address."
        return "The IDs in this link are not valid numbers; the link looks damaged. Copy it again."
    return (f"{page} is not a scan page this tool can read. Open the scan's Triage Flaws, Review "
            f"Modules or Static Overview page and copy that link.{app_hint}")


def _invalid_link(value: str) -> ValueError:
    return ValueError(f"{link_problem(value, 'scan')}\n    Link: {term_safe(value)!r}\n"
                      "    Supported pages: " + ", ".join((*SCAN_PAGES, SANDBOX_PAGE)))


def parse_scan_target(value: str) -> ScanTarget:
    """Parse a platform scan link or a bare build id, as Veracode's scan_health tool does: https, a
    known Veracode host, path /auth/index.jsp, a supported page, app id and build id in fragment
    fields 2 and 3."""
    v = clean_link(value)
    if v.isdigit():
        if int(v) <= 0 or len(v) > 12:
            raise ValueError("Build ID must be a positive number")
        return ScanTarget(build_id=str(int(v)))
    region, fragment = _split_platform_link(v, _invalid_link)
    fields = fragment.split(":")
    sb = _sandbox_fields(fields)
    if sb is not None:
        return ScanTarget(build_id="", app_id=int(sb[0]), region=region, page=SANDBOX_PAGE,
                          sandbox_id=sb[1])
    page = next((p for p in SCAN_PAGES if fragment.startswith(p)), None)
    if page is None or len(fields) < 4:
        raise _invalid_link(v)
    app_id, build_id = fields[2], fields[3]
    if not (app_id.isdigit() and build_id.isdigit()) or len(build_id) > 12 or len(app_id) > 12:
        raise _invalid_link(v)
    if int(build_id) <= 0 or int(app_id) <= 0:
        raise _invalid_link(v)
    return ScanTarget(build_id=str(int(build_id)), app_id=int(app_id), region=region, page=page)


def _with_scheme(v: str) -> str:
    """Browsers hide https:// in the address bar, so a link copied from the visible text may lack it."""
    return "https://" + v if v.lower().startswith("analysiscenter.veracode.") else v


def _split_platform_link(v: str, invalid: Callable[[str], ValueError]) -> tuple[str, str]:
    """(region, page part) of a Veracode Platform link: https, a known Veracode host, and
    /auth/index.jsp#..."""
    v = _with_scheme(v)
    try:
        parts = urlsplit(v)
        host = (parts.hostname or "").lower()
    except ValueError as e:
        raise invalid(v) from e
    if parts.scheme.lower() != "https":
        raise invalid(v)
    if host == "analysiscenter.veracode.us":
        raise ValueError("Links to the US (FedRAMP) region are not supported; this tool "
                         "supports the commercial and eu regions.")
    region = SCAN_HOSTS.get(host)
    location = _location(parts)
    if region is None or location is None:
        raise invalid(v)
    return region, location


def is_link(value: str) -> bool:
    """True when an --app value is a URL rather than a profile name."""
    return clean_link(value).lower().startswith(("https://", "http://", "analysiscenter.veracode."))


def _invalid_app_link(value: str) -> ValueError:
    return ValueError(f"{link_problem(value, 'app')}\n    Link: {term_safe(value)!r}\n"
                      "    Expected https://analysiscenter.veracode.com/auth/index.jsp#<Page>:"
                      "<account_id>:<app_id>... (the application, a sandbox or any scan page)")


def parse_app_link(value: str) -> ScanTarget:
    """App id and region from any Veracode Platform link that carries them."""
    v = clean_link(value)
    region, fragment = _split_platform_link(v, _invalid_app_link)
    fields = fragment.split(":")
    if len(fields) < 3 or not re.fullmatch(r"[A-Za-z]+", fields[0]):
        raise _invalid_app_link(v)
    sb = _sandbox_fields(fields)
    if sb is not None:
        return ScanTarget(build_id="", app_id=int(sb[0]), region=region, page=SANDBOX_PAGE,
                          sandbox_id=sb[1])
    app_id = fields[2]
    if not app_id.isdigit() or len(app_id) > 12 or int(app_id) <= 0:
        raise _invalid_app_link(v)
    build = fields[3] if len(fields) > 3 and fields[3].isdigit() else ""
    return ScanTarget(build_id=build, app_id=int(app_id), region=region, page=fields[0])


@dataclass
class ScanResolution:
    """Everything resolve_scan learned about the one build to analyse."""
    app: AppInfo
    context: dict[str, Any]
    enumeration: Enumeration
    report: FetchResult | None
    is_latest_build: bool | None
    notes: list[DataNote] = field(default_factory=list)


def _app_from_rest(fetcher: Fetcher, app_id: int) -> tuple[AppInfo | None, str]:
    """Profile details by legacy id."""
    try:
        d = fetcher.rest("/applications", {"legacy_id": app_id}, auth_retry=False)
    except (requests.RequestException, sh.TransientAuthError) as e:
        return None, f"{type(e).__name__}: {e}"
    for a in (d.get("_embedded") or {}).get("applications") or []:
        if isinstance(a, dict) and str(a.get("id")) == str(app_id):
            return normalise_application(a), ""
    return None, "no profile with this app_id in the REST listing"


def resolve_scan(fetcher: Fetcher, t: ScanTarget) -> ScanResolution:
    """Identify the application, context and status of one build."""
    notes: list[DataNote] = []
    bid = t.build_id
    sandbox: dict[str, str] | None = None
    walked: Enumeration | None = None
    context: dict[str, Any]
    if t.sandbox_id and t.app_id:
        # A sandbox link names no scan: use its latest published one.
        sandbox = resolve_sandbox_by_id(fetcher, t.app_id, t.sandbox_id)
        walked = enumerate_builds(fetcher, AppInfo(guid="", legacy_id=t.app_id, name=""),
                                  t.sandbox_id, 1, None)
        if walked.list_error:
            raise FatalAPIError(f"Could not list the scans in sandbox "
                                f"{term_safe(sandbox['name'])}: {walked.list_error}")
        context = {"type": "sandbox", "sandbox_name": sandbox["name"], "sandbox_id": sandbox["id"]}
        if not walked.published:
            notes.append(DataNote("Scan", f"Sandbox {term_safe(sandbox['name'])} has no published "
                                  "static scan. Nothing to analyse yet; this is an absence of "
                                  "results, not a failure.", "warning"))
            app, why = _app_from_rest(fetcher, t.app_id)
            if app is None:
                notes.append(DataNote("Resolution", f"Application profile details were not "
                                      f"available from the REST API ({why}).", "warning"))
                app = AppInfo(guid="", legacy_id=t.app_id, name=f"app_id {t.app_id}")
            return ScanResolution(app=app, context=context, enumeration=walked, report=None,
                                  is_latest_build=None, notes=notes)
        bid = walked.published[0].build_id
        notes.append(DataNote("Scan", f"Sandbox link: analysing the latest published scan in "
                              f"sandbox {term_safe(sandbox['name'])} (build {bid})."))
    rep = fetcher.xml("detailedreport.do", {"build_id": bid},
                      app_id=str(t.app_id or ""), build_id=bid,
                      cache_policy="refresh" if t.app_id else "none")
    dr = sh.parse_detailed_report(rep.root) if rep.ok and rep.root is not None else None
    meta = parse_report_meta(rep.root) if dr is not None and rep.root is not None else {}
    no_report = not rep.ok and sh.NO_REPORT_AVAILABLE in rep.error

    app_id = t.app_id
    if dr is not None:
        rid = str(dr.get("app_id") or "")
        if app_id is None:
            if not rid.isdigit():
                raise FatalAPIError("detailedreport.do did not include an app_id")
            app_id = int(rid)
            fetcher.store(rep, str(app_id), bid)
        elif rid and rid != str(app_id):
            raise ResolutionError(f"The link's app_id {app_id} does not match build {bid}, "
                                  f"which belongs to app_id {term_safe(rid)}")
    elif app_id is None:
        if no_report:
            raise ResolutionError("Could not resolve the application because only a build ID was "
                                  "given and that scan has no published results. Use the platform "
                                  "URL instead.")
        raise FatalAPIError(f"detailedreport.do failed: {rep.error}")
    elif not no_report:
        notes.append(DataNote("API errors", f"detailedreport.do failed ({rep.error}).", "warning"))

    sandbox_name = (sandbox["name"] if sandbox is not None
                    else str((dr or {}).get("sandbox_name") or ""))
    info_params: dict[str, Any] = {"app_id": app_id, "build_id": bid}
    if sandbox is not None:
        info_params["sandbox_id"] = sandbox["id"]
    elif sandbox_name and (dr or {}).get("sandbox_id"):
        info_params["sandbox_id"] = (dr or {})["sandbox_id"]
    ir = fetcher.xml("getbuildinfo.do", info_params, app_id=str(app_id), build_id=bid,
                     cache_policy="read_only")
    if ir.ok and ir.root is not None:
        ir_app = ir.root.get("app_id")
        if ir_app and ir_app != str(app_id):
            raise ResolutionError(f"Build {bid} belongs to app_id {term_safe(ir_app)}, not {app_id}")
        ref = parse_build_info_full(ir.root, bid)
        if ref.analysis_type is not None and ref.analysis_type.strip().lower() != "static":
            raise ResolutionError(f"Build {bid} is a {term_safe(ref.analysis_type)} scan; "
                                  "only static (SAST) scans are supported")
        if ref.status_class == "published":
            fetcher.store(ir, str(app_id), bid)
    elif dr is not None:
        notes.append(DataNote("API errors", f"getbuildinfo.do failed ({ir.error}); build status "
                              "is taken from the detailed report.", "warning"))
        ref = BuildRef(build_id=bid, version=str(meta.get("version") or ""), status="Results Ready",
                       published=meta.get("published"), status_class="published")
    else:
        raise FatalAPIError(f"Could not retrieve build {bid}: {ir.error}")

    app, why = _app_from_rest(fetcher, app_id)
    if app is None:
        notes.append(DataNote("Resolution", f"Application profile details were not available from "
                              f"the REST API ({why}). Name and business unit come from the "
                              "detailed report; GUID, teams and business criticality are "
                              "unavailable.", "warning"))
        app = AppInfo(guid="", legacy_id=app_id,
                      name=str((dr or {}).get("app_name") or f"app_id {app_id}"),
                      business_unit=str((dr or {}).get("bu") or ""),
                      policy=str((dr or {}).get("policy_name") or ""))

    if sandbox is not None:
        context = {"type": "sandbox", "sandbox_name": sandbox["name"], "sandbox_id": sandbox["id"]}
    elif dr is None:
        context = {"type": "unknown", "sandbox_name": None, "sandbox_id": None}
    elif sandbox_name:
        context = {"type": "sandbox", "sandbox_name": sandbox_name,
                   "sandbox_id": str(dr.get("sandbox_id") or "") or None}
    else:
        context = {"type": "policy", "sandbox_name": None, "sandbox_id": None}

    en = Enumeration(list_total=1)
    (en.published if ref.status_class == "published" else en.other).append(ref)
    if walked is not None:
        en.other.extend(walked.other)
        en.list_total = walked.list_total
    if ref.status_class != "published":
        notes.append(DataNote("Scan", f"Build {bid} has no published results "
                              f"(status: {term_safe(ref.status) or 'unknown'}). Nothing to analyse "
                              "yet; this is an absence of results, not a failure.", "warning"))
    is_latest = True if walked is not None else meta.get("is_latest_build")
    if is_latest is False:
        where = "sandbox" if sandbox_name else "policy context"
        notes.append(DataNote("Scan", f"This is not the latest SAST scan in this {where}. "
                              "Scan recency (check #30) is not evaluated.", "warning"))
    return ScanResolution(app=app, context=context, enumeration=en,
                          report=rep if dr is not None else None,
                          is_latest_build=is_latest, notes=notes)


def _overview_url(base: str, dr: dict[str, Any], bid: str) -> str:
    """StaticOverview deep link, same shape as scan_health.platform_urls."""
    acct = dr.get("account_id", "")
    if not acct:
        return ""
    return (f"{base}/auth/index.jsp#StaticOverview:{acct}:{dr.get('app_id', '')}:{bid}:"
            f"{dr.get('analysis_id', '')}:{dr.get('sau_id', '')}::::{dr.get('sandbox_id', 0)}")


def collect_snapshot(fetcher: Fetcher, app: AppInfo, ref: BuildRef, *,
                     is_latest: bool, mode: str, skip: set[int],
                     sandbox_name: str = "",
                     recency_applicable: bool | None = None,
                     prefetched_report: FetchResult | None = None) -> BuildSnapshot:
    """Fetch and assemble one published build."""
    aid = str(app.legacy_id)
    bid = ref.build_id
    eff_mode = "full" if (is_latest or mode == "full") else "light"
    snap = BuildSnapshot(build_id=bid, version=ref.version, sandbox=sandbox_name,
                         is_latest=is_latest, mode=eff_mode, status=ref.status,
                         engine_version=ref.engine_version, submitter=ref.submitter,
                         platform=ref.platform, lifecycle_stage=ref.lifecycle_stage,
                         policy_name=ref.policy_name, policy_version=ref.policy_version,
                         policy_compliance_status=ref.policy_compliance_status,
                         policy_rules_status=ref.rules_status,
                         grace_period_expired=ref.grace_period_expired,
                         scan_overdue=ref.scan_overdue,
                         legacy_scan_engine=ref.legacy_scan_engine,
                         published=ref.published)
    snap.sources["status"] = "getbuildinfo.do"
    report_policy = "refresh" if is_latest else "ttl"
    report_ep = "detailedreport.do" if eff_mode == "full" else "summaryreport.do"
    if prefetched_report is not None and prefetched_report.endpoint == report_ep:
        rep = prefetched_report
    else:
        rep = fetcher.xml(report_ep, {"build_id": bid}, app_id=aid, build_id=bid,
                          cache_policy=report_policy)
    if rep.from_cache:
        snap.cache_hits.append(report_ep)
    meta: dict[str, Any] = {}
    dr: dict[str, Any] | None = None
    if rep.ok and rep.root is not None:
        meta = parse_report_meta(rep.root)
        if eff_mode == "full":
            dr = sh.parse_detailed_report(rep.root)
            if dr is None:
                snap.errors[report_ep] = "report has no static-analysis element"
    else:
        snap.errors[report_ep] = rep.error

    if meta:
        _apply_meta(snap, meta, report_ep)
        if meta.get("flaw_status") is not None:
            snap.flaw_status = meta["flaw_status"]
            snap.flaw_status_source = report_ep
    if eff_mode == "full" and rep.ok and snap.flaw_status is None:
        sr = fetcher.xml("summaryreport.do", {"build_id": bid}, app_id=aid, build_id=bid,
                         cache_policy=report_policy)
        if sr.from_cache:
            snap.cache_hits.append("summaryreport.do")
        if sr.ok and sr.root is not None:
            fs = parse_report_meta(sr.root).get("flaw_status")
            if fs is not None:
                snap.flaw_status = fs
                snap.flaw_status_source = "summaryreport.do"
        else:
            snap.errors["summaryreport.do"] = sr.error

    if dr is not None:
        fl: sh.FlawSummary = dr["flaws"]
        snap.sources["open_by_severity"] = "detailedreport.do (individual flaws)"
        if fl.sev_available:
            snap.open_by_severity = {"very_high": fl.open_vhigh, "high": fl.open_high,
                                     "medium": fl.open_med, "low": fl.open_low}
            snap.open_policy_flaws = fl.open_pol
            snap.mitigated_flaws = fl.mitigated
        snap.sca_components = list(dr.get("sca_comps") or [])
        rv, tr = sh.platform_urls(fetcher.client.base, dr, bid)
        snap.review_url, snap.triage_url = rv, tr
        snap.overview_url = _overview_url(fetcher.client.base, dr, bid)

    if eff_mode != "full":
        snap.checks = outcomes_unavailable("Light history mode: checks run on the latest build only",
                                           status="Not run")
        return snap

    fl_res = fetcher.xml("getfilelist.do", {"app_id": app.legacy_id, "build_id": bid},
                         app_id=aid, build_id=bid, cache_policy="immutable")
    ps_res = fetcher.xml("getprescanresults.do", {"app_id": app.legacy_id, "build_id": bid},
                         app_id=aid, build_id=bid, cache_policy="immutable")
    for r in (fl_res, ps_res):
        if r.from_cache:
            snap.cache_hits.append(r.endpoint)
        if not r.ok:
            snap.errors[r.endpoint] = r.error
    files = sh.parse_file_list(fl_res.root) if fl_res.ok and fl_res.root is not None else None
    prescan = sh.parse_prescan(ps_res.root) if ps_res.ok and ps_res.root is not None else None
    if files is not None:
        snap.files_uploaded = len(files)
        snap.sources["files_uploaded"] = "getfilelist.do"
    if prescan is not None:
        snap.prescan_module_count = len(prescan)
        sizes = [sh._parse_module_size(m.get("size", "")) for m in prescan]
        snap.prescan_total_bytes = sum(sizes)
        snap.sources["prescan_total_bytes"] = "getprescanresults.do (module size attribute)"

    if dr is None or files is None or prescan is None:
        missing = [ep for ep, ok in ((report_ep, dr is not None),
                                     ("getfilelist.do", files is not None),
                                     ("getprescanresults.do", prescan is not None)) if not ok]
        snap.checks = outcomes_unavailable("Inputs unavailable: " + ", ".join(missing))
        return snap

    merged = sh._merge_modules(dr["dr_modules"], prescan)
    snap.detail = BuildDetail(files=files, prescan_modules=prescan, merged_modules=merged)
    scan_meta = {"review_url": snap.review_url, "triage_url": snap.triage_url,
                 "analysis_size": dr.get("analysis_size", 0)}
    na: dict[int, str] = {}
    if sandbox_name:
        recency = ""
        na[30] = "Sandbox scans are excluded from scan recency (as in bulk mode)"
    # Check 30 only makes sense on the latest build; on older ones it always fires.
    elif not (is_latest if recency_applicable is None else recency_applicable):
        recency = ""
        na[30] = "Scan recency is only meaningful for the latest build"
    else:
        recency = dr.get("published", "")
    if not dr.get("sca_on", False):
        na[9] = "SCA is not enabled for this scan (sca_service_available is false or absent)"
    outcomes, issues = run_build_checks(files, merged, dr, scan_meta, recency, skip, na)
    snap.checks = outcomes
    snap.checks_ran = True
    hi = sum(1 for i in issues if i.severity == "high")
    mi = sum(1 for i in issues if i.severity == "medium")
    snap.high_issues, snap.medium_issues = hi, mi
    snap.health = "Good" if not issues else ("Poor" if hi else ("Fair" if mi else "Good"))
    snap.selected_module_count = sum(1 for m in merged if m.get("is_selected"))
    return snap


def _apply_meta(snap: BuildSnapshot, meta: dict[str, Any], source: str) -> None:
    """Copy report fields onto the snapshot."""
    if meta.get("version"):
        snap.version = meta["version"]
    snap.submitted = meta.get("submitted")
    if meta.get("published"):
        snap.published = meta["published"]
    for k in ("analysis_size_bytes", "score", "rating", "mitigated_score", "mitigated_rating",
              "business_criticality", "first_build_submitted_date",
              "last_update_time", "total_flaws", "flaws_not_mitigated", "is_latest_build"):
        setattr(snap, k, meta.get(k))
    for k in ("engine_version", "policy_name", "policy_version", "policy_compliance_status",
              "policy_rules_status", "grace_period_expired", "scan_overdue",
              "legacy_scan_engine", "submitter", "platform", "lifecycle_stage"):
        if meta.get(k) is not None:
            setattr(snap, k, meta[k])
    mods: list[ModuleStat] = meta.get("modules") or []
    snap.modules = mods
    if mods:
        snap.selected_module_count = len(mods)
        locs = [m.loc for m in mods]
        snap.loc_total = sum(x for x in locs if x is not None) if any(x is not None for x in locs) else None
    if meta.get("sca_enabled") is not None:
        snap.sca_enabled = meta["sca_enabled"]
        snap.sca_vulnerable_components = meta.get("sca_vulnerable_components")
    sub, pub = parse_iso(snap.submitted), parse_iso(snap.published)
    if sub and pub and pub >= sub:
        snap.analysis_seconds = int((pub - sub).total_seconds())
    snap.analysis_duration = ("Unavailable" if snap.analysis_seconds is None
                              else sh._fmt_seconds(snap.analysis_seconds))
    for k in ("analysis_seconds", "analysis_size_bytes", "engine_version", "score",
              "rating", "modules", "loc_total"):
        snap.sources[k] = f"{source} static-analysis"
    snap.sources["policy_compliance_status"] = f"{source} root"


def plan_calls(n_builds: int, mode: str,
               cached_reports: int = 0, cached_xml: int = 0) -> dict[str, int]:
    """Calls per bucket still to be made for collection."""
    if n_builds <= 0:
        return {"report": 0, "xml": 0, "rest": 0}
    if mode == "full":
        report, xml = n_builds, 2 * n_builds
    else:
        report, xml = n_builds, 2
    return {"report": max(0, report - cached_reports),
            "xml": max(0, xml - cached_xml), "rest": 0}


def estimate_seconds(calls: dict[str, int], budget_pct: float) -> float:
    """Wall time at the configured budget, bounded by the slowest bucket."""
    worst = 0.0
    for b, n in calls.items():
        rpm = sh.RateLimiter.LIMITS[b] * budget_pct / 100.0
        if n and rpm:
            worst = max(worst, n / rpm * 60.0)
    return worst


def count_cached(fetcher: Fetcher, app: AppInfo, refs: list[BuildRef], mode: str) -> tuple[int, int]:
    """(reports, xml) responses already in the cache for the planned builds."""
    cache = fetcher.cache
    if cache.mode != "use":
        return 0, 0
    reports = xml = 0
    for i, ref in enumerate(refs):
        full = i == 0 or mode == "full"
        ep = "detailedreport.do" if full else "summaryreport.do"
        try:
            if i > 0:
                p = cache.path(fetcher.region, str(app.legacy_id), ref.build_id, ep)
                if p.exists() and (time.time() - p.stat().st_mtime) <= cache.ttl_seconds:
                    reports += 1
            if full:
                for x in ("getfilelist.do", "getprescanresults.do"):
                    if cache.path(fetcher.region, str(app.legacy_id), ref.build_id, x).exists():
                        xml += 1
        except (ValueError, OSError):
            continue
    return reports, xml


def report_to_dict(report: AppReport) -> dict[str, Any]:
    """The JSON document, built from the same Analysis the HTML renders."""
    latest = report.latest
    an = report.analysis
    hist = {h.check_num: h for h in an.check_history} if an else {}
    checks = []
    for c in (latest.checks if latest else []):
        d = asdict(c)
        h = hist.get(c.check_num)
        d["lifecycle"] = h.lifecycle if h else "Unknown"
        d["consecutive_failing"] = h.consecutive_failing if h else 0
        checks.append(d)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated": report.generated,
        "tool": TOOL_NAME,
        "complete": report.complete,
        "app": asdict(report.app),
        "context": report.context,
        "parameters": report.parameters,
        "history_status": report.history_status,
        "verdict": [asdict(v) for v in an.verdicts] if an else None,
        "actions": [asdict(a) for a in an.actions] if an else None,
        "checks": checks,
        "builds": [b.to_dict() for b in report.builds],
        "other_builds": [asdict(b) for b in report.other_builds],
        "duration": asdict(an.duration) if an else None,
        "cadence": asdict(an.cadence) if an else None,
        "findings": asdict(an.findings) if an else None,
        "diffs": asdict(an.diffs) if an else None,
        "check_history": [asdict(h) for h in an.check_history] if an else None,
        "data_notes": [asdict(n) for n in report.data_notes],
        "collection": report.collection,
    }


def render_json(report: AppReport) -> str:
    """Serialise the report."""
    return json.dumps(report_to_dict(report), indent=2, sort_keys=False, default=str)


def _current_umask() -> int:
    """The process umask (os.umask can only be read by setting it)."""
    mask = os.umask(0o022)
    os.umask(mask)
    return mask


def write_atomic(path: Path, text: str) -> None:
    """Write via temp file + rename so a reader never sees a partial report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        # Reports are shared: normal permissions, not mkstemp's 0600.
        with contextlib.suppress(OSError):
            os.chmod(tmp, 0o666 & ~_current_umask())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


SUPPORTED_FORMATS = ("html", "xlsx", "json", "md")
IMPLEMENTED_FORMATS = ("html", "json")


def validate_args(args: argparse.Namespace) -> list[str]:
    """Argument errors for single-application mode (empty list when valid)."""
    errs: list[str] = []
    if args.history < 0:
        errs.append("--history must be >= 0")
    if args.baseline_window < 1:
        errs.append("--baseline-window must be >= 1")
    if args.history_since:
        try:
            date.fromisoformat(args.history_since)
        except ValueError:
            errs.append("--history-since must be YYYY-MM-DD")
    fmts = [f.strip().lower() for f in str(args.formats).split(",") if f.strip()]
    bad = [f for f in fmts if f not in SUPPORTED_FORMATS]
    if bad or not fmts:
        errs.append(f"--formats must be a comma list of {', '.join(SUPPORTED_FORMATS)}")
    if args.no_cache and args.refresh_cache:
        errs.append("--no-cache and --refresh-cache are mutually exclusive")
    if getattr(args, "scan", None) is not None and args.sandbox:
        errs.append("--sandbox cannot be combined with --scan: the link already identifies the build")
    return errs


def resolve_region(args: argparse.Namespace, scan: ScanTarget | None) -> str:
    """Region for this run."""
    explicit = bool(getattr(args, "region_explicit", False))
    if scan is not None and scan.region is not None:
        if explicit and args.region != scan.region:
            raise ValueError(f"The region from the link ({scan.region}) does not match "
                             f"--region {args.region}")
        return scan.region
    return str(args.region or "commercial")


def history_target(args: argparse.Namespace, cfg: dict[str, Any] | None = None
                   ) -> tuple[int, date | None, list[DataNote]]:
    """Number of published builds to collect, the optional since-date, and notes."""
    cfg = cfg or APP_REPORT_CONFIG
    cap = cfg["history_hard_cap"]
    notes: list[DataNote] = []
    since = date.fromisoformat(args.history_since) if args.history_since else None
    if since is not None:
        return cap, since, notes
    n = 1 if args.history == 0 else args.history
    if n > cap:
        notes.append(DataNote("Parameters", f"--history {args.history} clamped to the hard cap of {cap}.",
                              "warning"))
        n = cap
    return n, None, notes


def history_record(report: AppReport) -> dict[str, Any] | None:
    """Compact point-in-time snapshot of the latest build for history.jsonl."""
    b = report.latest
    if b is None:
        return None
    return {
        "recorded": report.generated, "region": report.app.region,
        "app_guid": report.app.guid, "app_id": report.app.legacy_id,
        "app_name": report.app.name, "context": report.context.get("type"),
        "sandbox": report.context.get("sandbox_name") or "",
        "build_id": b.build_id, "version": b.version, "published": b.published,
        "analysis_seconds": b.analysis_seconds, "analysis_size_bytes": b.analysis_size_bytes,
        "loc_total": b.loc_total, "engine_version": b.engine_version, "score": b.score,
        "policy_compliance_status": b.policy_compliance_status, "health": b.health,
        "open_by_severity": b.open_by_severity,
        "flaw_status": asdict(b.flaw_status) if b.flaw_status else None,
    }


def history_status(report: AppReport, target: int, since: date | None, en: Enumeration) -> str:
    """One label for how much history the report actually holds."""
    if en.list_error:
        return "Unavailable"
    if not report.builds:
        return "No published builds"
    if any(b.errors for b in report.builds) or len(report.builds) < len(en.published):
        return "Partial"
    if target == 1 and since is None:
        return "Latest only"
    return "Complete"


def _standard_notes(report: AppReport) -> None:
    report.note("Analysis time", "Analysis time is published_date minus submitted_date from "
                "the static-analysis element. It excludes upload and prescan.")
    report.note("Mitigation state", "Mitigation state on historical builds may reflect the "
                "current state rather than the state at scan time. This has not been verified "
                "against a live tenant and is not asserted either way.")
    report.note("Fixed counts", "Veracode advises against relying on remediation_status=\"fixed\" "
                "in detailedreport. Fixed counts come from the flaw-status element; each build "
                "records which report supplied it in flaw_status_source.")
    report.note("Module flaw counts", "Per-module numflawssev0..5 are reported as the platform "
                "supplies them. Whether they count open flaws only is not documented, so they "
                "are never used as open-flaw counts.")
    report.note("Units", "MB in this report means 10^6 bytes. The bulk workbook's "
                "\"Analysis Size (MB)\" column uses 2^20.")


def _add_scan_trend(fetcher: Fetcher, app: AppInfo, context: dict[str, Any], en: Enumeration,
                    target: int, since: date | None, report: AppReport) -> None:
    """Append the published builds before the linked one, in the same policy or sandbox context, so a
    single scan gets its trend."""
    if target <= 1 and since is None:
        return
    linked = en.published[0].build_id
    prior = enumerate_builds(fetcher, app, context.get("sandbox_id"),
                             target - 1, since, older_than=int(linked))
    where = ("sandbox " + term_safe(context.get("sandbox_name") or "")
             if context.get("type") == "sandbox" else "the policy context")
    if prior.list_error:
        report.note("History", f"Trend unavailable: getbuildlist.do failed ({prior.list_error}). "
                    f"Only build {linked} is analysed.", "warning")
        return
    en.published.extend(prior.published)
    en.skipped_non_static += prior.skipped_non_static
    en.walk_truncated = en.walk_truncated or prior.walk_truncated
    for r in prior.other:
        if r.info_error:
            report.note("History", f"Build {r.build_id}: getbuildinfo.do failed "
                        f"({r.info_error}); it is excluded from the trend.", "warning")
    n = len(prior.published)
    if n:
        report.note("History", f"Trend: build {linked} plus {n} earlier published build(s) in "
                    f"{where}. Checks and the action plan are for build {linked}.")
    else:
        report.note("History", f"Build {linked} is the first published build in {where}; "
                    "there is no earlier build to trend against.")


def _print_plan(report: AppReport, en: Enumeration, calls: dict[str, int],
                budget: float, used: dict[str, int]) -> None:
    app = report.app
    print(f"Application: {term_safe(app.name)}  guid={app.guid}  app_id={app.legacy_id}")
    ctx = report.context
    print(f"Context:     {ctx['type']}" + (f" '{term_safe(ctx.get('sandbox_name', ''))}'"
                                         if ctx["type"] == "sandbox" else ""))
    scan = report.parameters.get("scan")
    if scan:
        print(f"Scan:        build {scan['build_id'] or '(none published)'} from a {scan['input']}"
              + (f" ({scan['page']})" if scan.get("page") else "") + f", region {scan['region']}")
        if len(en.published) > 1:
            print(f"Trend:       {len(en.published) - 1} earlier published build(s) in this context")
    else:
        print(f"Builds:      {len(en.published)} published to analyse "
              f"({en.list_total} in build list, {len(en.other)} not published, "
              f"{en.skipped_non_static} non-static skipped)")
    for r in en.published:
        print(f"  {r.build_id}  {r.published or 'unknown date':<22}  {term_safe(r.version)}")
    for r in en.other:
        print(f"  {r.build_id}  [{r.status_class}: {term_safe(r.status) or r.info_error}]  "
              f"{term_safe(r.version)}")
    print(f"API calls so far: report {used['report']}, xml {used['xml']}, rest {used['rest']}")
    secs = estimate_seconds(calls, budget)
    print(f"API calls planned: report {calls['report']}, xml {calls['xml']}, rest {calls['rest']} "
          f"(rate pacing alone about {sh._hms(secs)} at {budget:.0f}% of the published limits, "
          "excluding response time; cached responses cost 0)")


def run(args: argparse.Namespace, skip_checks: set[int] | None = None) -> int:
    """Entry point from scan_health.main()."""
    skip = set(skip_checks or set())
    errs = validate_args(args)
    if errs:
        for e in errs:
            log.error("%s", e)
        return EXIT_RESOLVE
    fmts = [f.strip().lower() for f in str(args.formats).split(",") if f.strip()]
    target, since, pre_notes = history_target(args)
    scan: ScanTarget | None = None
    app_link: ScanTarget | None = None
    try:
        if getattr(args, "scan", None) is not None:
            scan = parse_scan_target(str(args.scan))
        elif args.app is not None and is_link(str(args.app)):
            app_link = parse_app_link(str(args.app))
            args = argparse.Namespace(**{**vars(args), "app": None, "app_id": app_link.app_id})
        region = resolve_region(args, scan or app_link)
    except ValueError as e:
        log.error("%s", e)
        return EXIT_RESOLVE

    cache_mode = "off" if args.no_cache else ("refresh" if args.refresh_cache else "use")
    hist = getattr(args, "history_dir", None)
    cache = ResponseCache(Path(args.cache_dir).expanduser() if cache_mode != "off" else None,
                          cache_mode, APP_REPORT_CONFIG["report_cache_ttl_hours"],
                          history_root=Path(hist).expanduser() if hist else None)

    client = sh.VeracodeClient(region, timeout=args.timeout, pool_size=16,
                               rate_budget=args.rate_budget, max_retries=args.max_retries,
                               backoff_factor=args.retry_backoff,
                               auth_retry_window=args.auth_retry_window,
                               report_timeout=getattr(args, "report_timeout", 600))
    fetcher = Fetcher(client, cache, region)
    fetcher.fail_fast = True
    report: AppReport | None = None
    exit_code = EXIT_OK
    started = time.monotonic()
    try:
        en: Enumeration | None = None
        resolved: ScanResolution | None = None
        try:
            if scan is not None:
                resolved = resolve_scan(fetcher, scan)
                app, res_notes, en = resolved.app, resolved.notes, resolved.enumeration
            else:
                app, res_notes = resolve_app(fetcher, args)
        except ResolutionError as e:
            print(f"[!] {e}")
            if e.candidates:
                print("Closest matches:" if args.app is not None else "Candidates:")
                for c in e.candidates:
                    print(f"  {term_safe(c)}")
            return EXIT_RESOLVE
        except (requests.RequestException, sh.TransientAuthError) as e:
            log.error("Application lookup failed: %s", e)
            return EXIT_FATAL
        app.region = region
        app.teams = visible_teams(app.teams, getattr(args, "hide_teams", None))
        if not app.legacy_id:
            log.error("Profile %s has no legacy app_id; the XML APIs cannot be used.", app.guid)
            return EXIT_FATAL

        context: dict[str, Any] = {"type": "policy", "sandbox_name": None, "sandbox_id": None}
        if resolved is not None:
            context = resolved.context
        elif app_link is not None and app_link.sandbox_id:
            if args.sandbox:
                log.error("--sandbox cannot be combined with a sandbox link; the link already "
                          "names the sandbox")
                return EXIT_RESOLVE
            try:
                sb = resolve_sandbox_by_id(fetcher, app.legacy_id, app_link.sandbox_id)
            except ResolutionError as e:
                print(f"[!] {e}")
                return EXIT_RESOLVE
            context = {"type": "sandbox", "sandbox_name": sb["name"], "sandbox_id": sb["id"]}
        elif args.sandbox:
            try:
                sb = resolve_sandbox(fetcher, app, args.sandbox)
            except ResolutionError as e:
                print(f"[!] {e}")
                for c in e.candidates:
                    print(f"  {term_safe(c)}")
                return EXIT_RESOLVE
            context = {"type": "sandbox", "sandbox_name": sb["name"], "sandbox_id": sb["id"]}

        params = {"history": args.history, "history_since": args.history_since,
                  "history_mode": args.history_mode, "baseline_window": args.baseline_window,
                  "findings_age": args.findings_age, "reporting_api": args.reporting_api,
                  "skip_checks": sorted(skip), "formats": fmts, "cache": cache_mode,
                  "rate_budget": args.rate_budget}
        if scan is not None:
            pub = resolved.enumeration.published if resolved is not None else []
            params["scan"] = {"build_id": pub[0].build_id if pub else scan.build_id,
                              "app_id": app.legacy_id, "region": region, "page": scan.page,
                              "sandbox_id": context.get("sandbox_id"),
                              "input": "platform link" if scan.page else "build id"}
        if app_link is not None:
            params["app_input"] = {"input": "platform link", "page": app_link.page,
                                   "app_id": app_link.app_id, "region": region,
                                   "sandbox_id": app_link.sandbox_id}
            if app_link.build_id:
                res_notes.append(DataNote("Parameters", f"The link points at build "
                                          f"{app_link.build_id}; --app analyses the application's "
                                          "build history. Use --scan with the same link to analyse "
                                          "only that build."))
        report = AppReport(app=app, context=context, parameters=params)
        for n in pre_notes + res_notes:
            report.note(n.topic, n.message, n.level)
        _standard_notes(report)

        if en is None:
            en = enumerate_builds(fetcher, app, context.get("sandbox_id"), target, since)
        if en.list_error:
            report.history_status = "Unavailable"
            report.note("History", f"History unavailable: getbuildlist.do failed ({en.list_error}). "
                        "Falling back to the latest build only.", "warning")
            ref = latest_build_fallback(fetcher, app, context.get("sandbox_id"))
            if ref is not None:
                (en.published if ref.status_class == "published" else en.other).append(ref)
        if en.walk_truncated:
            report.note("History", "Stopped walking the build list after "
                        f"{APP_REPORT_CONFIG['max_unpublished_walk']} unpublished builds.", "warning")
        if en.skipped_non_static:
            report.note("History", f"{en.skipped_non_static} non-static build(s) in the build "
                        "list were skipped.")
        report.other_builds = en.other
        for r in en.other:
            if r.info_error:
                report.note("History", f"Build {r.build_id}: getbuildinfo.do failed "
                            f"({r.info_error}); its publication state is unknown and it is "
                            "excluded from the analysis.", "warning")

        if scan is not None and en.published:
            _add_scan_trend(fetcher, app, context, en, target, since, report)

        cached_r, cached_x = count_cached(fetcher, app, en.published, args.history_mode)
        calls = plan_calls(len(en.published), args.history_mode, cached_r, cached_x)
        if resolved is not None and resolved.report is not None and calls["report"]:
            calls["report"] -= 1
        _print_plan(report, en, calls, args.rate_budget, dict(fetcher.calls))
        if args.dry_run:
            report = None
            return EXIT_OK
        fetcher.fail_fast = False

        if scan is not None:
            pass
        elif not en.published:
            report.note("History", "No published static build was found in this context. "
                        "This is an absence of results, not a retrieval failure."
                        if not en.list_error else "No build could be enumerated.", "warning")
        elif not en.list_error and since is None and len(en.published) < target:
            report.note("History", f"Requested {target} published builds; "
                        f"{len(en.published)} exist in this context.")

        for i, ref in enumerate(en.published):
            log.info("[*] Build %s (%d/%d): fetching results (large reports can take minutes)",
                     ref.build_id, i + 1, len(en.published))
            snap = collect_snapshot(
                fetcher, app, ref, is_latest=(i == 0), mode=args.history_mode, skip=skip,
                sandbox_name=context.get("sandbox_name") or "",
                recency_applicable=(None if resolved is None or i > 0
                                    else resolved.is_latest_build is True),
                prefetched_report=resolved.report if resolved is not None and i == 0 else None)
            # Older builds only need summaries; dropping file lists bounds memory.
            if i >= 2:
                snap.detail = None
            report.builds.append(snap)
            for ep, err in snap.errors.items():
                report.note("API errors", f"Build {snap.build_id}: {ep} failed ({err}).", "warning")
            log.info("[*] Build %s (%d/%d): %s, health %s%s", snap.build_id, i + 1,
                     len(en.published), snap.analysis_duration, snap.health,
                     f", cache hits {len(snap.cache_hits)}" if snap.cache_hits else "")

        report.history_status = (history_status(report, target, since, en)
                                 if scan is None or len(en.published) > 1
                                 else ("Single scan" if report.builds else "No published builds"))

        # Only the latest build with a GUID: a linked older build would corrupt the series.
        rec = history_record(report)
        if resolved is not None and (resolved.is_latest_build is not True or not app.guid):
            rec = None
        if rec is not None:
            hp = cache.append_history(app.guid, rec)
            if hp is None:
                report.note("Point-in-time history", "history.jsonl not written "
                            "(cache disabled or not writable).")
            else:
                log.info("[+] History: %s", hp)
        if cache.mode != "off" and cache.root is not None:
            log.info("[*] Cache: %d response(s) saved, %d reused (%s)", cache.writes, cache.hits,
                     cache.root)
    except AccessDenied as e:
        print(f"[!] {e}")
        report = None
        exit_code = EXIT_RESOLVE
    except sh.AuthError as e:
        log.error("FATAL: %s", e)
        exit_code = EXIT_FATAL
        if report is not None:
            report.complete = False
            report.note("Collection", f"Stopped by an authentication failure: {e}", "warning")
    except FatalAPIError as e:
        log.error("FATAL: %s", e)
        exit_code = EXIT_FATAL
    except KeyboardInterrupt:
        exit_code = EXIT_INTERRUPT
        log.warning("[!] Interrupted; writing a partial report.")
        if report is not None:
            report.complete = False
            report.note("Collection", "Interrupted before collection finished; this report "
                        "is partial.", "warning")
    finally:
        if report is not None:
            if not report.complete:
                report.history_status = "Partial" if report.builds else "Unavailable"
            report.collection = {
                "api_calls": dict(fetcher.calls),
                "cache": {"mode": cache.mode, "hits": cache.hits, "misses": cache.misses,
                          "writes": cache.writes, "write_errors": cache.write_errors},
                "elapsed_seconds": round(time.monotonic() - started, 1),
                "rate": client.limiter.report(),
                "throttle_events": client.throttle_events,
            }
            try:
                out_dir = _write_outputs(report, args, fmts)
                print(f"[+] Report written to {out_dir}")
                if (out_dir / "report.html").exists():
                    print(f"    Open {out_dir / 'report.html'} in a browser")
            except OSError as e:
                log.error("Report write failed: %s", e)
                exit_code = exit_code or EXIT_WRITE
        client.close()
    return exit_code


def default_report_dir(app: AppInfo, build_id: str | None = None) -> Path:
    """./app_report_<slug>_<UTC timestamp>/, or ..._build<id>_..."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    mid = f"_build{build_id}" if build_id else ""
    return Path(f"app_report_{slugify(app.name)}{mid}_{ts}")


def _write_outputs(report: AppReport, args: argparse.Namespace, fmts: list[str]) -> Path:
    scan_info = report.parameters.get("scan") or {}
    if args.report_dir:
        out_dir = Path(args.report_dir)
    elif getattr(args, "out_dir", None):
        from . import output_layout
        out_dir = output_layout.app_report_dir(args.out_dir, slugify(report.app.name),
                                               report.app.legacy_id, scan_info.get("build_id"))
    else:
        out_dir = default_report_dir(report.app, scan_info.get("build_id"))
    out_dir.mkdir(parents=True, exist_ok=True)
    pending = [f for f in fmts if f not in IMPLEMENTED_FORMATS]
    if pending:
        report.note("Outputs", f"Format(s) not yet implemented in this build: {', '.join(pending)}.",
                    "warning")
    if report.analysis is None:
        try:
            report.analysis = ana.analyse(report, int(getattr(args, "baseline_window", 10)))
        except Exception as e:
            log.warning("Analysis failed; writing collected data only: %s", e)
            report.note("Analysis", f"Analysis failed ({type(e).__name__}: {e}); "
                        "collected data is still included.", "warning")
    if "html" in fmts and report.analysis is not None:
        from . import app_report_html
        write_atomic(out_dir / "report.html", app_report_html.render_html(report, report.analysis))
    if "json" in fmts or pending == fmts:
        write_atomic(out_dir / "report.json", render_json(report))
    return out_dir
