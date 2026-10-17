"""
Where scan_health.py writes things. One root folder (default
./scan_health_output, --out-dir to change it):

    scan_health_output/
      tenant/<region>/<YYYY-MM-DD_HHMMSS>/     one folder per bulk run
      apps/<app>_<app_id>/<YYYY-MM-DD_HHMMSS>/  --app reports
      apps/<app>_<app_id>/scan_<build>_<ts>/    --scan reports
      history/tenant/<region>/<account>/        tenant snapshots (keep: trends)
      history/apps/<app guid>.jsonl             per-app history (keep: trends)
      cache/<region>/<app_id>/<build>/          raw API responses (safe to delete)

Explicit --output, --report-dir, --cache-dir and --snapshot-dir always win.
Works the same on Windows, Linux and macOS: folder names use only letters,
digits, "_" and "-", and stay short.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("scan_health.layout")

DEFAULT_OUT_DIR = "scan_health_output"
LEGACY_CACHE_DIR = "scan_health_cache"
RUN_FILE = "run.json"
STAMP = "%Y-%m-%d_%H%M%S"
# An unfinished bulk run older than this is not resumed, so a weekly schedule
# never folds last week's partial data into this week's report.
RESUME_MAX_AGE = timedelta(hours=72)
_RUN_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{6}(-\d+)?$")
_EXT = {"xlsx": "xlsx", "csv": "csv", "json": "json"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def resolve(args: Any) -> None:
    """Fill in the derived folders on the parsed arguments. Explicit values are
    kept; anything left at None defaults under --out-dir."""
    out = Path(getattr(args, "out_dir", None) or DEFAULT_OUT_DIR).expanduser()
    args.out_dir = str(out)
    args.cache_dir_explicit = getattr(args, "cache_dir", None) is not None
    args.snapshot_dir_explicit = getattr(args, "snapshot_dir", None) is not None
    if not args.cache_dir_explicit:
        args.cache_dir = str(out / "cache")
    if not getattr(args, "history_dir", None):
        args.history_dir = str(out / "history" / "apps")
    if not args.snapshot_dir_explicit:
        args.snapshot_dir = str(out / "history" / "tenant")


# ==========================================================================
# One-time move from the old ./scan_health_cache layout
# ==========================================================================

def migrate_legacy(args: Any, legacy: Path | None = None) -> list[str]:
    """Move an old ./scan_health_cache (responses, <guid>/history.jsonl and
    snapshots/) into the new layout, once. Only when the new defaults are in
    use and the target does not exist yet; never fatal. Returns what moved."""
    legacy = legacy or Path(LEGACY_CACHE_DIR)
    moved: list[str] = []
    old_snaps = legacy.parent / "scan_health_snapshots"      # phase 1 default
    if (not args.snapshot_dir_explicit and old_snaps.is_dir()
            and not Path(args.snapshot_dir).exists()):
        try:
            Path(args.snapshot_dir).parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(old_snaps), str(args.snapshot_dir))
            moved.append(f"{old_snaps} -> {args.snapshot_dir}")
        except OSError as e:
            log.warning("Could not move %s: %s", old_snaps, e)
    if not legacy.is_dir() or Path(args.out_dir).resolve() == legacy.resolve():
        if moved:
            log.info("[*] Moved %s into %s", old_snaps, args.snapshot_dir)
        return moved

    def move(src: Path, dst: Path) -> None:
        if dst.exists():
            return
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dst))
            moved.append(f"{src} -> {dst}")
        except OSError as e:
            log.warning("Could not move %s to %s: %s", src, dst, e)

    try:
        if not args.snapshot_dir_explicit and (legacy / "snapshots").is_dir():
            move(legacy / "snapshots", Path(args.snapshot_dir))
        hist = Path(args.history_dir)
        for d in legacy.iterdir():
            if (d / "history.jsonl").is_file():
                move(d / "history.jsonl", hist / f"{d.name}.jsonl")
                with contextlib.suppress(OSError):
                    d.rmdir()
        if not args.cache_dir_explicit:
            for region in ("commercial", "eu"):
                if (legacy / region).is_dir():
                    move(legacy / region, Path(args.cache_dir) / region)
        rest = [p for p in legacy.iterdir() if p.name != ".gitignore"]
        if not rest:
            with contextlib.suppress(OSError):
                (legacy / ".gitignore").unlink()
                legacy.rmdir()
    except OSError as e:
        log.warning("Old cache folder %s left as is: %s", legacy, e)
    if moved:
        log.info("[*] Moved %d item(s) from the old %s folder into %s", len(moved), legacy,
                 args.out_dir)
    return moved


# ==========================================================================
# Bulk run folders
# ==========================================================================

def _read_run(d: Path) -> dict[str, Any] | None:
    try:
        doc = json.loads((d / RUN_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def _write_run(d: Path, doc: dict[str, Any]) -> None:
    tmp = d / f".{RUN_FILE}.tmp"
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, d / RUN_FILE)


def find_resumable(base: Path, scope: dict[str, Any], output_format: str,
                   now: datetime | None = None) -> tuple[Path | None, str]:
    """Newest unfinished run folder with the same scope and format, if recent
    enough. Returns (folder or None, a note explaining a skipped old run)."""
    now = now or _now()
    if not base.is_dir():
        return None, ""
    for d in sorted((p for p in base.iterdir() if p.is_dir() and _RUN_RE.match(p.name)),
                    key=lambda p: p.name, reverse=True):
        doc = _read_run(d)
        if doc is None or doc.get("status") == "complete":
            continue
        if doc.get("scope") != scope or doc.get("output_format") != output_format:
            continue
        try:
            updated = datetime.fromisoformat(str(doc.get("updated")))
        except ValueError:
            continue
        if now - updated > RESUME_MAX_AGE:
            return None, (f"Unfinished run {d} is older than {int(RESUME_MAX_AGE.total_seconds() // 3600)}"
                          " hours and was not resumed; starting a new run.")
        return d, ""
    return None, ""


def new_run_dir(base: Path, now: datetime | None = None) -> Path:
    """A fresh, not yet created, run folder name under base."""
    name = (now or _now()).strftime(STAMP)
    d, n = base / name, 1
    while d.exists():
        d = base / f"{name}-{n}"
        n += 1
    return d


def bulk_output(args: Any, scope: dict[str, Any], *, create: bool) -> tuple[Path, bool, str]:
    """Run folder and main output file for a bulk run with the default layout.
    Returns (output file, resumed?, note). Creates the folder and its run.json
    only when create is True (never on a dry run)."""
    fmt = str(getattr(args, "output_format", "xlsx"))
    base = Path(args.out_dir) / "tenant" / str(scope.get("region") or "commercial")
    d, note = (None, "") if getattr(args, "restart", False) else find_resumable(base, scope, fmt)
    resumed = d is not None
    if d is None:
        d = new_run_dir(base)
    out = d / f"scan_health.{_EXT.get(fmt, 'xlsx')}"
    if create:
        d.mkdir(parents=True, exist_ok=True)
        doc = _read_run(d) or {"created": _now().isoformat(), "scope": scope, "output_format": fmt}
        doc.update({"status": "running", "updated": _now().isoformat()})
        _write_run(d, doc)
    return out, resumed, note


def mark_run(output: Path, status: str) -> None:
    """Record a bulk run's final status ("complete" or "partial") next to it."""
    d = output.parent
    doc = _read_run(d)
    if doc is None:
        return
    doc.update({"status": status, "updated": _now().isoformat()})
    with contextlib.suppress(OSError):
        _write_run(d, doc)


# ==========================================================================
# Application report folders
# ==========================================================================

def app_report_dir(out_dir: str | Path, slug: str, app_id: Any, build_id: str | None = None,
                   now: datetime | None = None) -> Path:
    """apps/<slug>_<app_id>/<timestamp>, or .../scan_<build>_<timestamp> for --scan."""
    ts = (now or _now()).strftime(STAMP)
    aid = str(app_id) if str(app_id).isdigit() else "unknown"
    leaf = f"scan_{build_id}_{ts}" if build_id and str(build_id).isdigit() else ts
    base = Path(out_dir) / "apps" / f"{slug}_{aid}"
    d, n = base / leaf, 1
    while d.exists():
        d = base / f"{leaf}-{n}"
        n += 1
    return d
