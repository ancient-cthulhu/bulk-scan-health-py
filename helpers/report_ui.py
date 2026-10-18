"""Shared HTML helpers: escaping, safe links, chips, SVG charts."""

from __future__ import annotations

import base64
import hashlib
import html
import math
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import scan_health as sh

LEVEL_LABEL = {"GREEN": ("ok", "✓"), "YELLOW": ("warn", "!"), "ORANGE": ("serious", "!"),
               "RED": ("crit", "✕"), "GRAY": ("unknown", "?")}
SAFE_LINK_HOSTS = {"analysiscenter.veracode.com", "analysiscenter.veracode.eu",
                   "docs.veracode.com", "community.veracode.com"}


def e(v: object) -> str:
    """HTML-escape any value; None renders as 'Unavailable'."""
    if v is None:
        return "Unavailable"
    return html.escape(str(v), quote=True)


def link(url: str | None, text: str) -> str:
    """An <a> only for https links on Veracode hosts; plain text otherwise."""
    if url:
        try:
            p = urlsplit(url)
        except ValueError:
            return e(text)
        if p.scheme == "https" and (p.hostname or "").lower() in SAFE_LINK_HOSTS:
            return f'<a href="{e(url)}" rel="noopener noreferrer">{e(text)}</a>'
    return e(text)


def fmt_dt(iso: str | None, with_time: bool = False) -> str:
    if not iso:
        return "Unavailable"
    d = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return d.strftime("%Y-%m-%d %H:%M UTC") if with_time else d.strftime("%Y-%m-%d")


def short_date(iso: str | None) -> str:
    if not iso:
        return "?"
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%b %d")


def fmt_mb(n: int | float | None) -> str:
    return "Unavailable" if n is None else f"{n / 1e6:,.1f} MB"


def fmt_num(n: object) -> str:
    if n is None:
        return '<span class="na">n/a</span>'
    if isinstance(n, float):
        return f"{n:,.1f}"
    if isinstance(n, int):
        return f"{n:,}"
    return e(n)


def fmt_signed(n: int | None, fmt: str = "{:+,}") -> str:
    return "n/a" if n is None else fmt.format(n)


def chip(level: str, text: str) -> str:
    """Status chip: icon + label + color, never color alone."""
    cls, icon = LEVEL_LABEL.get(level, LEVEL_LABEL["GRAY"])
    return f'<span class="chip {cls}"><span class="ic" aria-hidden="true">{icon}</span>{e(text)}</span>'


STATUS_LEVEL = {"Pass": "GREEN", "Fail": "RED", "Error": "ORANGE", "N/A": "GRAY",
                "Skipped": "GRAY", "Unavailable": "GRAY", "Not run": "GRAY", "Unknown": "GRAY"}


# Drawn at display size so text renders about 1:1.
FULL, HALF = (1040, 260), (500, 230)
ML, MR, MT, MB = 52, 16, 34, 34


def _nice_ticks(vmax: float, n: int = 4, integer: bool = False) -> list[float]:
    """Round axis ticks from 0."""
    if vmax <= 0:
        return [0.0, 1.0]
    raw = vmax / n
    mag = 10 ** math.floor(math.log10(raw))
    steps = (1, 2, 5, 10) if integer else (1, 2, 2.5, 5, 10)
    step = next(m * mag for m in steps if m * mag >= raw)
    if integer:
        step = max(step, 1.0)
    return [step * i for i in range(math.ceil(vmax / step) + 1)]


def _count_tick(t: float) -> str:
    """Axis label for counts: whole numbers as integers, 7.5 stays 7.5."""
    return f"{t:,.0f}" if t == int(t) else f"{t:,.1f}"


def _x_positions(n: int, w: int) -> list[float]:
    inner = w - ML - MR
    if n == 1:
        return [ML + inner / 2]
    pad = 12
    return [ML + pad + (inner - 2 * pad) * i / (n - 1) for i in range(n)]


def _band_positions(n: int, w: int) -> tuple[list[float], float]:
    inner = w - ML - MR
    band = inner / max(n, 1)
    return [ML + band * (i + 0.5) for i in range(n)], band


def _y(v: float, ymax: float, h: int) -> float:
    return MT + (h - MT - MB) * (1 - v / ymax)


def _axes(ticks: list[float], fmt: Any, labels: list[str], xs: list[float], title: str,
          w: int, h: int) -> str:
    ymax = ticks[-1]
    out = [f'<text class="axt" x="0" y="14">{e(title)}</text>']
    for t in ticks:
        y = _y(t, ymax, h)
        out.append(f'<line class="grid" x1="{ML}" x2="{w - MR}" y1="{y:.1f}" y2="{y:.1f}"/>')
        out.append(f'<text class="tick" x="{ML - 8}" y="{y + 4:.1f}" text-anchor="end">{e(fmt(t))}</text>')
    out.append(f'<line class="base" x1="{ML}" x2="{w - MR}" y1="{h - MB}" y2="{h - MB}"/>')
    min_px = 64
    every = max(1, math.ceil(len(labels) * min_px / max(w - ML - MR, 1)))
    for i, (lab, x) in enumerate(zip(labels, xs, strict=True)):
        if i % every == 0 or i == len(labels) - 1:
            out.append(f'<text class="tick" x="{x:.1f}" y="{h - MB + 18}" text-anchor="middle">{e(lab)}</text>')
    return "".join(out)


def line_chart(title: str, labels: list[str], values: list[float | None], tips: list[str],
               fmt: Any, size: tuple[int, int] = FULL, unit: str = "",
               band: tuple[float, float] | None = None,
               threshold: float | None = None, flag_last: str = "") -> str:
    """Single-series line, optional baseline band and threshold line."""
    w, h = size
    pts = [(i, v) for i, v in enumerate(values) if v is not None]
    if not pts:
        return '<p class="na">No data to chart.</p>'
    top = max([v for _, v in pts] + ([band[1]] if band else []) + ([threshold] if threshold else []))
    ticks = _nice_ticks(top * 1.12)
    ymax = ticks[-1]
    xs = _x_positions(len(values), w)
    out = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="{e(title)}">',
           _axes(ticks, fmt, labels, xs, title, w, h)]
    if band:
        y1, y2 = _y(band[1], ymax, h), _y(max(band[0], 0), ymax, h)
        out.append(f'<rect class="band" x="{ML}" y="{y1:.1f}" width="{w - ML - MR}" '
                   f'height="{max(y2 - y1, 1):.1f}"><title>Baseline range</title></rect>')
    if threshold:
        yt = _y(threshold, ymax, h)
        out.append(f'<line class="thr" x1="{ML}" x2="{w - MR}" y1="{yt:.1f}" y2="{yt:.1f}"/>'
                   f'<text class="tick" x="{ML + 6}" y="{yt - 6:.1f}">regression threshold '
                   f'{e(fmt(threshold))}{e(unit)}</text>')
    path = " ".join(f"{'M' if k == 0 else 'L'}{xs[i]:.1f},{_y(v, ymax, h):.1f}" for k, (i, v) in enumerate(pts))
    out.append(f'<path class="ln s1" d="{path}"/>')
    for i, v in pts:
        last = i == pts[-1][0]
        y = _y(v, ymax, h)
        out.append(f'<g><circle class="dot s1" cx="{xs[i]:.1f}" cy="{y:.1f}" r="{5 if last else 4}"/>'
                   f'<circle class="hit" cx="{xs[i]:.1f}" cy="{y:.1f}" r="12">'
                   f'<title>{e(tips[i])}</title></circle></g>')
    li, lv = pts[-1]
    lab = e(fmt(lv) + unit) + (f" ({e(flag_last)})" if flag_last else "")
    anchor = "end" if xs[li] > w - 140 else "start"
    dx = -10 if anchor == "end" else 10
    out.append(f'<text class="vlab" x="{xs[li] + dx:.1f}" y="{_y(lv, ymax, h) - 10:.1f}" '
               f'text-anchor="{anchor}">{lab}</text>')
    out.append("</svg>")
    return "".join(out)


def _bar_path(x: float, y: float, w: float, h: float, r: float) -> str:
    """Rect with rounded top corners only (data end), square at the base."""
    r = min(r, w / 2, h)
    return (f"M{x:.1f},{y + h:.1f}V{y + r:.1f}Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f}"
            f"H{x + w - r:.1f}Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f}V{y + h:.1f}Z")


def stacked_columns(title: str, labels: list[str], series: list[tuple[str, str, list[int | None]]],
                    tips: list[str], size: tuple[int, int] = HALF) -> str:
    """Stacked columns, 2px surface gap between segments, rounded top only, total labelled on the cap."""
    w, h = size
    totals = [sum((vals[i] or 0) for _, _, vals in series) for i in range(len(labels))]
    if not any(totals):
        return '<p class="na">No open flaws with severity data to chart.</p>'
    ticks = _nice_ticks(max(totals) * 1.15, integer=True)
    ymax = ticks[-1]
    xs, band = _band_positions(len(labels), w)
    bw = min(24.0, band * 0.6)
    out = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="{e(title)}">',
           _axes(ticks, _count_tick, labels, xs, title, w, h)]
    for i, x in enumerate(xs):
        y_cur = float(h - MB)
        segs = [(name, cls, vals[i] or 0) for name, cls, vals in series if (vals[i] or 0) > 0]
        for k, (name, cls, v) in enumerate(segs):
            sh_ = (h - MT - MB) * v / ymax
            top = k == len(segs) - 1
            gap = 0 if k == 0 else 2
            y = y_cur - sh_
            hh = max(sh_ - gap, 0.5)
            shape = (f'<path class="{cls}" d="{_bar_path(x - bw / 2, y, bw, hh, 4)}"/>' if top
                     else f'<rect class="{cls}" x="{x - bw / 2:.1f}" y="{y:.1f}" width="{bw:.1f}" height="{hh:.1f}"/>')
            out.append(f"<g>{shape}<title>{e(name)}: {v:,} ({e(tips[i])})</title></g>")
            y_cur = y
        if totals[i]:
            out.append(f'<text class="vlab" x="{x:.1f}" y="{y_cur - 6:.1f}" text-anchor="middle">{totals[i]:,}</text>')
    out.append("</svg>")
    return "".join(out)


def grouped_bars(title: str, labels: list[str], series: list[tuple[str, str, list[int | None]]],
                 tips: list[str], size: tuple[int, int] = HALF) -> str:
    """Bars side by side per category, 2px gap, rounded data end."""
    w, h = size
    vals = [v or 0 for _, _, vs in series for v in vs]
    if not any(vals):
        return '<p class="na">No values to chart.</p>'
    ticks = _nice_ticks(max(vals) * 1.15, integer=True)
    ymax = ticks[-1]
    xs, band = _band_positions(len(labels), w)
    n = len(series)
    bw = max(4.0, min(18.0, (band * 0.7 - 2 * (n - 1)) / n))
    out = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="{e(title)}">',
           _axes(ticks, _count_tick, labels, xs, title, w, h)]
    for i, x in enumerate(xs):
        x0 = x - (n * bw + 2 * (n - 1)) / 2
        for k, (name, cls, vs) in enumerate(series):
            v = vs[i]
            if v is None:
                continue
            bx = x0 + k * (bw + 2)
            bh = (h - MT - MB) * v / ymax
            shape = f'<path class="{cls}" d="{_bar_path(bx, h - MB - bh, bw, bh, 4)}"/>' if v > 0 else ""
            out.append(f'<g>{shape}<rect class="hit" x="{bx:.1f}" y="{MT}" width="{bw:.1f}" '
                       f'height="{h - MT - MB}"><title>{e(name)}: {v:,} ({e(tips[i])})</title></rect></g>')
    out.append("</svg>")
    return "".join(out)


def timeline(attempts: list[dict[str, Any]], longest_gap: tuple[str, str] | None) -> tuple[str, int]:
    """Scan attempts on a time axis: filled = published, hollow = not published."""
    dated = [(datetime.fromisoformat(a["date"]), a) for a in attempts if a.get("date")]
    undated = len(attempts) - len(dated)
    if not dated:
        return '<p class="na">No dated scan attempts.</p>', undated
    dated.sort(key=lambda t: t[0])
    t0, t1 = dated[0][0], dated[-1][0]
    first, last = t0, t1
    # Under a day of history: centre the dots on a one-day axis.
    if (t1 - t0).total_seconds() < 86400.0:
        mid = t0 + (t1 - t0) / 2
        t0, t1 = mid - timedelta(hours=12), mid + timedelta(hours=12)
    span = (t1 - t0).total_seconds()
    w, h = FULL[0], 86
    inner = w - 2 * ML

    def x(d: datetime) -> float:
        return ML + inner * (d - t0).total_seconds() / span

    out = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="Scan attempts over time">',
           f'<line class="base" x1="{ML}" x2="{w - ML}" y1="44" y2="44"/>']
    gx = None
    if longest_gap:
        # Gap ends are calendar dates (midnight): clamp them to the axis.
        g0, g1 = (min(max(datetime.fromisoformat(g + "T00:00:00+00:00"), first), last)
                  for g in longest_gap)
        if x(g1) - x(g0) >= 4:
            gx = (g0, g1)
    if gx:
        g0, g1 = gx
        out.append(f'<line class="gap" x1="{x(g0):.1f}" x2="{x(g1):.1f}" y1="24" y2="24"/>'
                   f'<line class="gap" x1="{x(g0):.1f}" x2="{x(g0):.1f}" y1="20" y2="28"/>'
                   f'<line class="gap" x1="{x(g1):.1f}" x2="{x(g1):.1f}" y1="20" y2="28"/>'
                   f'<text class="tick" x="{(x(g0) + x(g1)) / 2:.1f}" y="16" text-anchor="middle">'
                   f'longest gap</text>')
    for d, a in dated:
        cls = "dot s1" if a["state"] == "published" else "dot hollow"
        tip = f"Build {a['build_id']}: {a['state']}" + (f" ({a.get('status')})" if a.get("status") else "")
        out.append(f'<g><circle class="{cls}" cx="{x(d):.1f}" cy="44" r="5"/>'
                   f'<circle class="hit" cx="{x(d):.1f}" cy="44" r="12"><title>{e(tip)}, '
                   f'{d.date().isoformat()}</title></circle></g>')
    if first.date() == last.date():
        out.append(f'<text class="tick" x="{w / 2:.1f}" y="74" text-anchor="middle">'
                   f'{first.date().isoformat()}</text>')
    else:
        out.append(f'<text class="tick" x="{ML}" y="74" text-anchor="middle">{t0.date().isoformat()}</text>'
                   f'<text class="tick" x="{w - ML}" y="74" text-anchor="middle">{t1.date().isoformat()}</text>')
    out.append("</svg>")
    return "".join(out), undated


def rec_html(text: str) -> str:
    """Recommendation text with only its URL (if any) linked."""
    url = sh._extract_url(text)
    if not url:
        return e(text)
    i = text.find(url)
    return e(text[:i]) + link(url, url) + e(text[i + len(url):])


CSS = """
:root{color-scheme:light;
--page:#f9f9f7;--surface:#fcfcfb;--card:#ffffff;--ink:#0b0b0b;--ink2:#52514e;--muted:#6f6d68;
--grid:#e1e0d9;--axis:#c3c2b7;--ring:rgba(11,11,11,.10);--wash:rgba(42,120,214,.10);
--s1:#2a78d6;--s2:#eb6834;--s3:#1baf7a;
--v1:#0d366b;--v2:#1c5cab;--v3:#3987e5;--v4:#86b6ef;
--good:#0ca30c;--warn:#fab219;--serious:#ec835a;--crit:#d03b3b;--unk:#898781;--link:#1c5cab}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;
--page:#0d0d0d;--surface:#1a1a19;--card:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--muted:#a3a29b;
--grid:#2c2c2a;--axis:#383835;--ring:rgba(255,255,255,.10);--wash:rgba(57,135,229,.14);
--s1:#3987e5;--s2:#d95926;--s3:#199e70;
--v1:#b7d3f6;--v2:#6da7ec;--v3:#2a78d6;--v4:#184f95;--link:#86b6ef}}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1120px;margin:0 auto;padding:28px 16px 64px}
a{color:var(--link)}
h1{font-size:28px;line-height:1.2;margin:0 0 4px;overflow-wrap:anywhere}
h2{font-size:19px;margin:0 0 4px}
h3{font-size:15px;margin:18px 0 6px}
.sub{color:var(--ink2);margin:0}
.meta{display:flex;flex-wrap:wrap;gap:6px 22px;margin:14px 0 0;color:var(--ink2);font-size:13.5px}
.meta b{color:var(--ink);font-weight:600}
section{background:var(--card);border:1px solid var(--ring);border-radius:12px;padding:20px 22px;margin:18px 0}
.lead{color:var(--ink2);margin:0 0 14px;font-size:14px}
.verdicts{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:22px 0 0}
.v{background:var(--card);border:1px solid var(--ring);border-radius:12px;padding:14px 16px}
.v .k{font-size:12.5px;color:var(--ink2);text-transform:uppercase;letter-spacing:.04em}
.v .val{font-size:22px;font-weight:600;margin:6px 0 2px;display:flex;align-items:center;gap:8px}
.v .why{font-size:13px;color:var(--ink2);overflow-wrap:anywhere}
.chip{display:inline-flex;align-items:center;gap:6px;font-size:13px;font-weight:600;white-space:nowrap}
.chip .ic{display:inline-grid;place-items:center;width:18px;height:18px;border-radius:50%;color:#fff;font-size:11px;font-weight:700}
.ok .ic{background:var(--good)} .warn .ic{background:var(--warn);color:#0b0b0b}
.serious .ic{background:var(--serious);color:#0b0b0b} .crit .ic{background:var(--crit)} .unknown .ic{background:var(--unk)}
.dotv{width:10px;height:10px;border-radius:50%;display:inline-block}
.actions{display:grid;gap:12px}
.act{border:1px solid var(--ring);border-radius:10px;padding:14px 16px;background:var(--surface)}
.act header{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px}
.act h3{margin:0;font-size:16px;flex:1 1 280px}
.pill{font-size:12px;font-weight:700;border-radius:999px;padding:2px 9px;border:1px solid var(--ring)}
.P1{background:var(--crit);color:#fff;border-color:transparent}
.P2{background:var(--warn);color:#0b0b0b;border-color:transparent}
.P3{background:var(--grid);color:var(--ink)}
.tag{font-size:12.5px;color:var(--ink2)}
.act dl{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:4px 14px;margin:10px 0 0;font-size:14px}
.act dt{color:var(--ink2)} .act dd{margin:0;overflow-wrap:anywhere;min-width:0}
.act ul{margin:0;padding-left:18px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:18px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:8px 0 14px}
.stat{border:1px solid var(--ring);border-radius:10px;padding:10px 12px;background:var(--surface)}
.stat .k{font-size:12.5px;color:var(--ink2)} .stat .n{font-size:20px;font-weight:600}
.stat .s{font-size:12.5px;color:var(--muted);min-height:1em}
td.nw{white-space:nowrap}
.tw{overflow-x:auto;margin:6px 0}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--grid);vertical-align:top}
th{font-size:12px;color:var(--ink2);text-transform:uppercase;letter-spacing:.03em;font-weight:600;white-space:nowrap}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td.name{overflow-wrap:anywhere;max-width:420px}
.na{color:var(--muted)}
details{margin:4px 0} summary{cursor:pointer;color:var(--link)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:13px;color:var(--ink2);margin:2px 0 6px}
.legend span{display:inline-flex;align-items:center;gap:6px}
.sw{width:12px;height:12px;border-radius:3px;display:inline-block}
.sw.s1,.sw.v1{background:var(--s1)} .sw.s2{background:var(--s2)} .sw.s3{background:var(--s3)}
.sw.v1{background:var(--v1)} .sw.v2{background:var(--v2)} .sw.v3{background:var(--v3)} .sw.v4{background:var(--v4)}
.sw.hollow{background:transparent;border:2px solid var(--crit);border-radius:50%}
svg{width:100%;height:auto;display:block;overflow:visible}
svg .grid{stroke:var(--grid);stroke-width:1}
svg .base{stroke:var(--axis);stroke-width:1}
svg .tick,svg .axt{fill:var(--muted);font-size:12px}
svg .axt{fill:var(--ink2);font-weight:600;font-size:13px}
svg .vlab{fill:var(--ink);font-size:12px;font-weight:600}
svg .ln{fill:none;stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
svg .ln.s1{stroke:var(--s1)}
svg .dot{stroke:var(--surface);stroke-width:2}
svg .dot.s1{fill:var(--s1)}
svg .dot.hollow{fill:var(--surface);stroke:var(--crit);stroke-width:2}
svg .hit{fill:transparent}
svg .band{fill:var(--wash)}
svg .thr{stroke:var(--muted);stroke-width:1}
svg .gap{stroke:var(--muted);stroke-width:1}
svg path.s2,svg rect.s2{fill:var(--s2)} svg path.s3,svg rect.s3{fill:var(--s3)}
svg path.v1,svg rect.v1{fill:var(--v1)} svg path.v2,svg rect.v2{fill:var(--v2)}
svg path.v3,svg rect.v3{fill:var(--v3)} svg path.v4,svg rect.v4{fill:var(--v4)}
.disclaimer{font-size:13px;color:var(--ink2);border-left:3px solid var(--axis);padding:4px 10px;margin:12px 0 0}
footer{color:var(--muted);font-size:12.5px;text-align:center;margin-top:28px}
@media print{body{background:#fff}section,.v{break-inside:avoid;border-color:#ccc}
details{display:block} details>summary{display:none} details>*{display:block}
a{color:inherit;text-decoration:none} main{max-width:none;padding:0}}
@media (max-width:640px){h1{font-size:22px} section{padding:16px} .act dl{grid-template-columns:minmax(0,1fr)}
.act dt{margin-top:6px}}
"""


def multi_line_chart(title: str, labels: list[str],
                     series: list[tuple[str, str, list[float | None]]], tips: list[str],
                     fmt: Any, size: tuple[int, int] = HALF, unit: str = "") -> str:
    """Several series on one axis (2 or 3 at most)."""
    w, h = size
    allv = [v for _, _, vals in series for v in vals if v is not None]
    if not allv:
        return '<p class="na">No data to chart.</p>'
    ticks = _nice_ticks(max(allv) * 1.12 or 1.0)
    ymax = ticks[-1]
    xs = _x_positions(len(labels), w)
    out = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="{e(title)}">',
           _axes(ticks, fmt, labels, xs, title, w, h)]
    last_ys: list[float] = []
    for name, cls, vals in series:
        pts = [(i, v) for i, v in enumerate(vals) if v is not None]
        if not pts:
            continue
        path = " ".join(f"{'M' if k == 0 else 'L'}{xs[i]:.1f},{_y(v, ymax, h):.1f}"
                        for k, (i, v) in enumerate(pts))
        out.append(f'<path class="ln {cls}" d="{path}"/>')
        for i, v in pts:
            y = _y(v, ymax, h)
            out.append(f'<g><circle class="dot {cls}" cx="{xs[i]:.1f}" cy="{y:.1f}" r="4"/>'
                       f'<circle class="hit" cx="{xs[i]:.1f}" cy="{y:.1f}" r="11">'
                       f'<title>{e(name)}: {e(fmt(v))}{e(unit)} ({e(tips[i])})</title></circle></g>')
        li, lv = pts[-1]
        y = _y(lv, ymax, h) - 9
        while any(abs(y - o) < 13 for o in last_ys):
            y -= 13
        last_ys.append(y)
        anchor = "end" if xs[li] > w - 120 else "start"
        dx = -9 if anchor == "end" else 9
        out.append(f'<text class="vlab" x="{xs[li] + dx:.1f}" y="{y:.1f}" '
                   f'text-anchor="{anchor}">{e(fmt(lv) + unit)}</text>')
    out.append("</svg>")
    return "".join(out)


def hbars(rows: list[tuple[str, float | int | None, str, str]], fmt: Any = None) -> str:
    """Horizontal bars as HTML (label, value, colour class, optional note)."""
    fmt = fmt or (lambda v: f"{v:,}")
    vals = [v for _, v, _, _ in rows if v is not None]
    top = max(vals) if vals else 0
    out = ['<div class="hbars" role="list">']
    for label, v, cls, note in rows:
        pct = 0.0 if not top or v is None else max(100.0 * v / top, 0.8 if v else 0.0)
        val = '<span class="na">n/a</span>' if v is None else e(fmt(v))
        nt = f' <span class="na">{e(note)}</span>' if note else ""
        out.append(f'<div class="hb" role="listitem"><span class="lab">{e(label)}</span>'
                   f'<span class="bar"><i class="{e(cls)}" style="width:{pct:.1f}%"></i></span>'
                   f'<span class="val">{val}{nt}</span></div>')
    out.append("</div>")
    return "".join(out)


def mix_bar(parts: list[tuple[str, int, str]]) -> str:
    """One stacked share bar (class, count, label) with a text equivalent."""
    total = sum(n for _, n, _ in parts)
    if not total:
        return '<span class="na">n/a</span>'
    txt = ", ".join(f"{lab} {n}" for _, n, lab in parts if n)
    segs = "".join(f'<i class="{e(cls)}" style="width:{100.0 * n / total:.2f}%"></i>'
                   for cls, n, _ in parts if n)
    return f'<span class="mix" role="img" aria-label="{e(txt)}" title="{e(txt)}">{segs}</span>'


# Browser print dialog: exact PDF, no library or network. Hidden until the script runs.
PDF_SCRIPT = ('(function () { var b = document.getElementById("save-pdf"); if (!b) { return; } '
              'b.hidden = false; b.addEventListener("click", function () { window.print(); }); }());')


def pdf_button() -> str:
    return ('<div class="toolbar"><button type="button" id="save-pdf" class="pdfbtn" hidden '
            'title="Opens the print dialog; choose Save as PDF">Save as PDF</button></div>')


def script_hash(script: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")


def csp_meta(script: str) -> str:
    """Content-Security-Policy that allows exactly this inline script and nothing else: no other
    script, no network, no frames, no forms."""
    csp = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
           f"script-src '{script_hash(script)}'; base-uri 'none'; form-action 'none'")
    return f'<meta http-equiv="Content-Security-Policy" content="{csp}"><meta name="referrer" content="no-referrer">'


PRINT_CSS = """
.toolbar{float:right;margin:0 0 8px 16px}
.pdfbtn{font:inherit;font-size:14px;font-weight:600;color:var(--link);background:var(--card);border:1px solid var(--s1);border-radius:8px;padding:6px 14px;cursor:pointer}
.pdfbtn:hover{background:var(--wash)}
.pdfbtn:focus-visible{outline:2px solid var(--s1);outline-offset:2px}
@page{size:A4;margin:14mm}
@media print{.toolbar{display:none} *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
main{max-width:none;padding:0} section,.part,main>section{break-inside:auto!important;margin:14px 0}
h1,h2,h3,summary{break-after:avoid} tr,svg,.v,.act,.stat,.kpi,.panel,.q,figure{break-inside:avoid}
body{font-size:12.5px} .grid2,.cols2{grid-template-columns:repeat(2,minmax(0,1fr))!important}}
"""
