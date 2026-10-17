"""
Components for the redesigned reports (app, scan and tenant).

Everything is static HTML and SVG (no script). Every value
goes through report_ui.e(); links go through report_ui.link().
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import scan_health as sh

from . import app_report_analytics as ana
from .report_ui import chip, e, link, rec_html

# ==========================================================================
# Lenses and result coverage
# ==========================================================================

LENS_SCAN = "scan"
LENS_POSTURE = "posture"
LENS_NAME = {LENS_SCAN: "Scan health", LENS_POSTURE: "Security posture"}

# Inline glyphs, drawn in currentColor: a gauge for scan health, a shield for
# security posture. Decorative (the lens name is always written next to them).
_GLYPH = {
    LENS_SCAN: ('<svg class="glyph" viewBox="0 0 20 20" aria-hidden="true"><path d="M3 14a7 7 0 1 1 14 0" '
                'fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>'
                '<path d="M10 14l3.2-4.2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>'
                '<circle cx="10" cy="14" r="1.6" fill="currentColor"/></svg>'),
    LENS_POSTURE: ('<svg class="glyph" viewBox="0 0 20 20" aria-hidden="true"><path d="M10 2.5l6 2.3v4.6c0 '
                   '3.9-2.6 6.6-6 8.1-3.4-1.5-6-4.2-6-8.1V4.8z" fill="none" stroke="currentColor" '
                   'stroke-width="1.8" stroke-linejoin="round"/></svg>'),
}

# Checks whose failure means part of the application may not have been
# analysed (category "Results accuracy" in the action rubric).
_ACCURACY = {n for n, (_, _, cat) in ana._CHECK_META.items() if cat == "Results accuracy"}
_ACCURACY_MAJOR = _ACCURACY & ana._P1_ACCURACY
_CHECK_LABELS = {n: label for n, (label, _) in sh.CHECK_CATALOG.items()}


@dataclass
class Coverage:
    """How completely the uploaded and selected code represents the
    application, from the accuracy checks only. A tool heuristic: it says
    nothing about the quality of Veracode's analysis of what was scanned."""
    level: str        # GREEN | YELLOW | ORANGE | GRAY
    label: str        # Complete | Partial | At risk | Unknown
    reason: str


def result_coverage(failed: list[int] | set[int], checks_ran: bool,
                    labels: dict[int, str] | None = None) -> Coverage:
    """Coverage of the findings, from the failing accuracy checks."""
    if not checks_ran:
        return Coverage("GRAY", "Unknown", "The scan health checks could not run on this build.")
    labels = labels or _CHECK_LABELS
    failed = set(failed)
    major = sorted(failed & _ACCURACY_MAJOR)
    minor = sorted((failed & _ACCURACY) - _ACCURACY_MAJOR)

    def name(n: int) -> str:
        return f"#{n} {labels.get(n, '')}".strip()

    if major:
        return Coverage("ORANGE", "At risk", "Findings reflect what was uploaded and selected; "
                        + "; ".join(name(n) for n in major[:2]) + ".")
    if minor:
        return Coverage("YELLOW", "Partial", "Findings reflect what was uploaded and selected; "
                        + "; ".join(name(n) for n in minor[:2]) + ".")
    return Coverage("GREEN", "Complete", "No check found missing or unanalysed code.")


def action_lens(check_num: int | None, category: str) -> str:
    """Scan health for anything raised by a check or about scan performance
    and cadence; security posture for findings and policy actions."""
    if check_num is not None or category != "Security exposure":
        return LENS_SCAN
    return LENS_POSTURE


def lens_label(lens: str) -> str:
    return f'<span class="lens">{_GLYPH[lens]}{e(LENS_NAME[lens])}</span>'


# ==========================================================================
# Lens panel with lab-style results
# ==========================================================================

@dataclass
class Result:
    """One measurement: value against its reference, with a flag when out of
    range. value_html/reference_html are already safe HTML."""
    label: str
    value_html: str
    reference_html: str = ""
    flag: str = ""          # e.g. "High", "New", "Not met"; "" when in range
    level: str = "GRAY"     # level of the flag chip


def results_table(rows: list[Result]) -> str:
    body = "".join(
        f'<tr><th scope="row">{e(r.label)}</th><td class="val">{r.value_html}</td>'
        f'<td class="ref">{r.reference_html}</td>'
        f'<td class="flag">{chip(r.level, r.flag) if r.flag else ""}</td></tr>'
        for r in rows)
    return f'<table class="results"><tbody>{body}</tbody></table>'


def lens_panel(lens: str, grade_level: str, grade: str, sentence: str, results: list[Result],
               trend_svg: str = "", trend_caption: str = "", do_first_html: str = "") -> str:
    """One of the two peer panels at the top of a report."""
    trend = (f'<figure class="trend">{trend_svg}<figcaption>{e(trend_caption)}</figcaption></figure>'
             if trend_svg else "")
    first = f'<p class="first"><span class="k">Do first</span> {do_first_html}</p>' if do_first_html else ""
    return (f'<section class="panel" aria-label="{e(LENS_NAME[lens])}"><header>'
            f'<h2>{_GLYPH[lens]}{e(LENS_NAME[lens])}</h2>{chip(grade_level, grade)}</header>'
            f'<p class="say">{e(sentence)}</p>{results_table(results)}{trend}{first}</section>')


# ==========================================================================
# Sparkline and bullet chart
# ==========================================================================

def sparkline(values: Sequence[float | None], tips: list[str], label: str, fmt: Any,
              w: int = 168, h: int = 34) -> str:
    """Small trend line: de-emphasised line, latest point in the accent and
    labelled. Every point has a tooltip; the full chart lives further down."""
    pts = [(i, v) for i, v in enumerate(values) if v is not None]
    if len(pts) < 2:
        return ""
    lo, hi = min(v for _, v in pts), max(v for _, v in pts)
    span = (hi - lo) or 1.0
    pad, lab_w = 4, 46
    inner_w = w - 2 * pad - lab_w

    def xy(i: int, v: float) -> tuple[float, float]:
        x = pad + inner_w * (i / max(len(values) - 1, 1))
        y = pad + (h - 2 * pad) * (1 - (v - lo) / span)
        return x, y

    path = " ".join(f"{'M' if k == 0 else 'L'}{xy(i, v)[0]:.1f},{xy(i, v)[1]:.1f}"
                    for k, (i, v) in enumerate(pts))
    dots = "".join(f'<circle class="hit" cx="{xy(i, v)[0]:.1f}" cy="{xy(i, v)[1]:.1f}" r="7">'
                   f'<title>{e(tips[i])}: {e(fmt(v))}</title></circle>' for i, v in pts)
    li, lv = pts[-1]
    lx, ly = xy(li, lv)
    first = pts[0][1]
    aria = f"{label}: from {fmt(first)} to {fmt(lv)} over {len(pts)} points"
    return (f'<svg class="spark" viewBox="0 0 {w} {h}" role="img" aria-label="{e(aria)}">'
            f'<path class="sl" d="{path}"/>{dots}<circle class="sd" cx="{lx:.1f}" cy="{ly:.1f}" r="3.5"/>'
            f'<text class="sv" x="{lx + 8:.1f}" y="{min(max(ly + 4, 12), h - 3):.1f}">{e(fmt(lv))}</text></svg>')


def bullet(label: str, value: float, band: tuple[float, float] | None, limit: float | None,
           fmt: Any, w: int = 520, h: int = 58) -> str:
    """One-row position chart: the value as a bar, the normal range as a band,
    the limit as a tick. For "latest against baseline and threshold"."""
    top = max([value] + ([band[1]] if band else []) + ([limit] if limit else [])) * 1.1 or 1.0
    x0, x1 = 4, w - 4

    def x(v: float) -> float:
        return x0 + (x1 - x0) * max(v, 0) / top

    out = [f'<svg class="bullet" viewBox="0 0 {w} {h}" role="img" aria-label="{e(label)}: '
           f'{e(fmt(value))}{"; normal range " + e(fmt(band[0])) + " to " + e(fmt(band[1])) if band else ""}'
           f'{"; limit " + e(fmt(limit)) if limit else ""}">',
           f'<rect class="track" x="{x0}" y="18" width="{x1 - x0}" height="14" rx="3"/>']
    if band:
        out.append(f'<rect class="band" x="{x(band[0]):.1f}" y="18" width="{max(x(band[1]) - x(band[0]), 1):.1f}" '
                   f'height="14"><title>Normal range {e(fmt(band[0]))} to {e(fmt(band[1]))}</title></rect>')
    out.append(f'<rect class="bar" x="{x0}" y="22" width="{max(x(value) - x0, 2):.1f}" height="6" rx="2">'
               f'<title>{e(label)}: {e(fmt(value))}</title></rect>')
    if limit:
        out.append(f'<line class="lim" x1="{x(limit):.1f}" x2="{x(limit):.1f}" y1="14" y2="36"/>'
                   f'<text class="tk" x="{x(limit):.1f}" y="52" text-anchor="middle">limit {e(fmt(limit))}</text>')
    vx = x(value)
    anchor = "end" if vx > w - 90 else "start"
    out.append(f'<text class="bv" x="{vx + (-4 if anchor == "end" else 6):.1f}" y="12" '
               f'text-anchor="{anchor}">{e(fmt(value))}</text>')
    out.append(f'<text class="tk" x="{x0}" y="52">0</text></svg>')
    if band:
        out.append(f'<p class="small">Shaded: normal range {e(fmt(band[0]))} to {e(fmt(band[1]))}.'
                   + (f" Red tick: limit {e(fmt(limit))}." if limit else "") + "</p>")
    return "".join(out)


# ==========================================================================
# Actions
# ==========================================================================

@dataclass
class ActionView:
    """An action, ready to render. fix_html entries are safe HTML."""
    priority: str
    title: str
    lens: str
    owner: str
    effort: str
    why: str
    evidence: list[str] = field(default_factory=list)
    fix_html: list[str] = field(default_factory=list)
    verify: str = ""
    effect: str = ""
    links: list[tuple[str, str]] = field(default_factory=list)
    note: str = ""          # e.g. "failing 6 scans", "138 profiles"
    anchor: str = ""
    more_html: str = ""     # safe HTML, e.g. a link that filters the fix list


def action_list(items: list[ActionView], open_first: int = 3) -> str:
    """Compact action rows: one line each, expanding to the detail. The first
    `open_first` are expanded; print expands all."""
    if not items:
        return '<p class="empty">Nothing to do: every measured dimension is in range.</p>'
    rows = []
    for i, a in enumerate(items):
        ev = "".join(f"<li>{e(x)}</li>" for x in a.evidence[:8])
        fx = "".join(f"<li>{x}</li>" for x in a.fix_html) or "<li>See the check documentation.</li>"
        lk = ", ".join(link(u, lbl) for lbl, u in a.links)
        aid = f' id="{e(a.anchor)}"' if a.anchor else ""
        rows.append(
            f'<details class="act"{aid}{" open" if i < open_first else ""}><summary>'
            f'<span class="pri {e(a.priority)}">{e(a.priority)}</span>'
            f'<span class="t">{e(a.title)}</span>'
            f'<span class="m">{lens_label(a.lens)}<span>{e(a.owner)}</span>'
            f'<span>Effort {e(a.effort)}</span>{"<span>" + e(a.note) + "</span>" if a.note else ""}</span>'
            f'</summary><dl><dt>Why</dt><dd>{e(a.why)}</dd>'
            + (f"<dt>Evidence</dt><dd><ul>{ev}</ul></dd>" if ev else "")
            + f"<dt>How to fix</dt><dd><ul>{fx}</ul></dd>"
            + (f"<dt>Done when</dt><dd>{e(a.verify)}</dd>" if a.verify else "")
            + (f"<dt>Expected effect</dt><dd>{e(a.effect)}</dd>" if a.effect else "")
            + (f"<dt>Links</dt><dd>{lk}</dd>" if lk else "")
            + (f"<dt>Find them</dt><dd>{a.more_html}</dd>" if a.more_html else "")
            + "</dl></details>")
    return f'<div class="actions">{"".join(rows)}</div>'


def fix_html(texts: list[str]) -> list[str]:
    """Recommendation strings as safe HTML with their documentation link."""
    return [rec_html(t) for t in texts]


# ==========================================================================
# Checks-by-builds matrix
# ==========================================================================

_CELL = {"Pass": ("ok", "\u2713", "Pass"), "Fail": ("crit", "\u2715", "Fail")}


@dataclass
class MatrixRow:
    check: int
    label: str
    category: str
    cells: list[str]          # status per build, oldest first ("" when not analysed)
    lifecycle: str = ""
    severity: str = ""
    detail_html: str = ""     # safe HTML shown when the row is expanded


def check_matrix(builds: list[str], rows: list[MatrixRow], caption: str) -> str:
    """Rows are checks, columns are builds (oldest to newest). Each cell has
    an icon and a text alternative, so color never carries meaning alone."""
    head = "".join(f'<th scope="col" class="b">{e(b)}</th>' for b in builds)
    body = []
    for r in rows:
        cells = []
        for b, st in zip(builds, r.cells, strict=False):
            cls, icon, txt = _CELL.get(st, ("na", "\u00b7", st or "Not evaluated"))
            cells.append(f'<td class="c {cls}" title="Build {e(b)}: {e(txt)}">'
                         f'<span aria-hidden="true">{icon}</span><span class="sr">{e(txt)}</span></td>')
        det = (f'<details><summary>Details</summary>{r.detail_html}</details>' if r.detail_html else "")
        body.append(f'<tr><td class="n">{e(r.check)}</td><th scope="row" class="name">{e(r.label)}'
                    f'<div class="sub">{e(r.category)}{", " + e(r.severity) if r.severity else ""}</div>{det}</th>'
                    + "".join(cells) + f'<td class="life">{e(r.lifecycle)}</td></tr>')
    return (f'<div class="tw"><table class="matrix"><caption>{e(caption)}</caption><thead><tr>'
            f'<th scope="col" class="n">#</th><th scope="col">Check</th>{head}'
            f'<th scope="col">Lifecycle</th></tr></thead><tbody>{"".join(body)}</tbody></table></div>')


# ==========================================================================
# Heatmap and priority matrix
# ==========================================================================

def filter_link(text_html: str, target: str, flt: str, title: str = "") -> str:
    """In-page link that the tenant report's script turns into a filter on
    the target table; without script it just jumps to the table."""
    t = f' title="{e(title)}"' if title else ""
    return f'<a href="#{e(target)}" data-filter="{e(flt)}"{t}>{text_html}</a>'


# Heatmap colours: one blue hue, blended through three stops in OKLab so
# the middle of the scale stays saturated instead of turning grey. Light
# mode grows darker with the share, dark mode grows lighter. Each tile gets
# its exact colour for both modes and the text colour (ink or inverse) with
# the better contrast against it.
_HM: dict[str, dict[str, Any]] = {"light": {"stops": ("#e6effc", "#3987e5", "#0b2a55"), "ink": "#141413", "inv": "#ffffff"},
       "dark": {"stops": ("#1a2b40", "#2f7ad8", "#c4dcfb"), "ink": "#efeee9", "inv": "#141413"}}


# Scale position of the smallest share shown: the first step clears 2:1
# against the page in both themes (palette validator, ordinal check).
HEAT_START = 0.3


def _lin(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _gam(c: float) -> float:
    c = min(max(c, 0.0), 1.0)
    return 12.92 * c if c <= 0.0031308 else 1.055 * c ** (1 / 2.4) - 0.055


def _to_oklab(hexc: str) -> tuple[float, float, float]:
    r, g, b = (_lin(int(hexc[i:i + 2], 16) / 255) for i in (1, 3, 5))
    lm = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b) ** (1 / 3)
    mm = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b) ** (1 / 3)
    sm = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b) ** (1 / 3)
    return (0.2104542553 * lm + 0.7936177850 * mm - 0.0040720468 * sm,
            1.9779984951 * lm - 2.4285922050 * mm + 0.4505937099 * sm,
            0.0259040371 * lm + 0.7827717662 * mm - 0.8086757660 * sm)


def _from_oklab(lab: tuple[float, float, float]) -> str:
    L, a, b = lab
    lm = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3
    mm = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3
    sm = (L - 0.0894841775 * a - 1.2914855480 * b) ** 3
    r = 4.0767416621 * lm - 3.3077115913 * mm + 0.2309699292 * sm
    g = -1.2684380046 * lm + 2.6097574011 * mm - 0.3413193965 * sm
    bb = -0.0041960863 * lm - 0.7034186147 * mm + 1.7076147010 * sm
    return "#" + "".join(f"{round(_gam(v) * 255):02x}" for v in (r, g, bb))


def heat_colour(t: float, mode: str) -> str:
    """Colour at position t (0..1) of the heatmap scale for a theme."""
    lo, mid, hi = (_to_oklab(x) for x in _HM[mode]["stops"])
    a, b, u = (lo, mid, t * 2) if t <= 0.5 else (mid, hi, t * 2 - 1)
    return _from_oklab(tuple(x + (y - x) * u for x, y in zip(a, b, strict=True)))  # type: ignore[arg-type]


def _lum(hexc: str) -> float:
    r, g, b = (_lin(int(hexc[i:i + 2], 16) / 255) for i in (1, 3, 5))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast(a: str, b: str) -> float:
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def _tile_style(t: float) -> tuple[str, str]:
    """(inline style, classes) for a tile: background per theme and whether
    the text should use the inverse colour in each theme."""
    lc, dc = heat_colour(t, "light"), heat_colour(t, "dark")
    lm, dm = _HM["light"], _HM["dark"]
    cls = []
    if _contrast(lm["inv"], lc) > _contrast(lm["ink"], lc):
        cls.append("il")
    if _contrast(dm["inv"], dc) > _contrast(dm["ink"], dc):
        cls.append("id")
    return f"--c:{lc};--cd:{dc}", " ".join(cls)


def _ramp_style() -> str:
    steps = [HEAT_START + (1 - HEAT_START) * k / 6 for k in range(7)]
    lg = ",".join(heat_colour(t, "light") for t in steps)
    dk = ",".join(heat_colour(t, "dark") for t in steps)
    return f"--g:linear-gradient(90deg,{lg});--gd:linear-gradient(90deg,{dk})"


def heatmap(caption: str, cols: list[str], rows: list[tuple[str, list[tuple[float | None, int, int]]]],
            row_head: str, filters: list[list[str | None]] | None = None, target: str = "fix",
            totals: list[tuple[int, str | None]] | None = None, total_head: str = "Profiles") -> str:
    """Tile heatmap of shares on one sequential hue, scaled from 0 to the
    largest share shown so differences stay visible on any tenant (the
    legend states the range). Every tile prints its value; tiles with a
    filter link open the matching list. Optional row totals add a bar
    column on the right."""
    shares = [sh_ for _, cells in rows for sh_, _, _ in cells if sh_]
    vmax = max(shares) if shares else 0.0
    other = {i for i, c in enumerate(cols) if c.split(" (")[0] == "Other"}
    head = "".join(f'<th scope="col" class="hc{" oth" if i in other else ""}"><span>{e(c)}</span></th>'
                   for i, c in enumerate(cols))
    tmax = max((n for n, _ in totals), default=0) if totals else 0
    body: list[str] = []
    for ri, (label, cells) in enumerate(rows):
        tds: list[str] = []
        for ci, (share, n, total) in enumerate(cells):
            col = cols[ci] if ci < len(cols) else ""
            if share is None:
                tds.append('<td class="hm hn"></td>')
                continue
            tip = f"{label} in {col}: {n:,} of {total:,} profiles ({share:.1f}%)"
            if share <= 0:
                tds.append(f'<td class="hm h0" title="{e(tip)}"><span aria-hidden="true">\u00b7</span>'
                           f'<span class="sr">0%</span></td>')
                continue
            t = min(share / vmax, 1.0) if vmax else 0.0
            style, cls = _tile_style(HEAT_START + (1 - HEAT_START) * t)
            txt = f"{share:.0f}%" if share >= 1 else "<1%"
            flt = filters[ri][ci] if filters else None
            inner = filter_link(e(txt), target, flt, tip) if flt else e(txt)
            tds.append(f'<td class="hm {cls}" style="{style}" title="{e(tip)}">{inner}</td>')
        tot = ""
        if totals:
            n, flt = totals[ri]
            w = 100 * n / tmax if tmax else 0
            num = filter_link(f"{n:,}", target, flt, f"Show the {n:,} profiles") if flt else f"{n:,}"
            tot = (f'<td class="tot"><span class="tbar" aria-hidden="true"><i style="width:{w:.0f}%"></i>'
                   f'</span>{num}</td>')
        body.append(f'<tr><th scope="row" class="name">{e(label)}</th>{"".join(tds)}{tot}</tr>')
    th_tot = f'<th scope="col" class="ht">{e(total_head)}</th>' if totals else ""
    legend = (f'<div class="heatlegend"><span><i class="hm0"></i>none</span>'
              f'<span class="ramp"><span>&gt;0%</span><i aria-hidden="true" style="{_ramp_style()}"></i>'
              f'<span>{vmax:.0f}%</span></span>'
              '<span class="small">Stronger colour means a larger share of the team\'s profiles fail the check. '
              'Click a tile for that team\'s fix list.</span></div>')
    return (f'<p class="small">{e(caption)}</p>'
            f'<div class="tw heatwrap"><table class="heat"><thead><tr>'
            f'<th scope="col" class="hr">{e(row_head)}</th>{head}{th_tot}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>{legend}')


QUADRANTS = [
    ("Immediate", "RED", "Real risk on a scan that needs work: fix both."),
    ("Review", "ORANGE", "Trustworthy scan with real findings: remediate."),
    ("Attention", "YELLOW", "Fix the scan first: low findings may be false comfort."),
    ("Monitor", "GREEN", "In range on both lenses."),
]


def priority_matrix(counts: dict[str, int], total: int, href: dict[str, str] | None = None,
                    filters: dict[str, str] | None = None) -> str:
    """2x2 of findings risk (rows) by scan health risk (columns), using the
    workbook's quadrant values. Cells can link to a filtered list."""
    href = href or {}
    q = {name: (lvl, txt) for name, lvl, txt in QUADRANTS}

    def cell(name: str) -> str:
        lvl, txt = q[name]
        n = counts.get(name, 0)
        share = f"{100 * n / total:.0f}%" if total else "n/a"
        inner = (f'<div class="qh">{chip(lvl, name)}<span class="qn">{n:,}</span>'
                 f'<span class="qs">{e(share)}</span></div><p>{e(txt)}</p>')
        h = href.get(name)
        flt = (filters or {}).get(name)
        df = f' data-filter="{e(flt)}"' if flt else ""
        return (f'<a class="q" href="{e(h)}"{df}>{inner}</a>' if h and h.startswith("#")
                else f'<div class="q">{inner}</div>')

    other = counts.get("Insufficient Data", 0)
    foot = (f'<p class="small">{other:,} profile(s) have insufficient data for either lens.</p>'
            if other else "")
    return ('<div class="quad" role="group" aria-label="Priority matrix">'
            '<div class="ax y">Findings risk: high</div>'
            f'{cell("Review")}{cell("Immediate")}'
            '<div class="ax y">Findings risk: low</div>'
            f'{cell("Monitor")}{cell("Attention")}'
            '<div></div><div class="ax x">Scan health: in range</div><div class="ax x">Scan health: needs work</div>'
            f'</div>{foot}')


# ==========================================================================
# Small inline marks
# ==========================================================================

# ==========================================================================
# Stylesheet for the redesigned reports
# ==========================================================================

DESIGN_CSS = """
:root{color-scheme:light;
--page:#f7f7f4;--surface:#fdfdfb;--card:#ffffff;--ink:#141413;--ink2:#4e4d49;--muted:#73716b;
--grid:#e4e3dc;--axis:#c3c2b7;--ring:rgba(20,20,19,.12);--wash:rgba(42,120,214,.10);
--s1:#2a78d6;--s2:#eb6834;--s3:#1baf7a;
--v1:#0d366b;--v2:#1c5cab;--v3:#3987e5;--v4:#86b6ef;
--good:#0ca30c;--warn:#fab219;--serious:#ec835a;--crit:#d03b3b;--unk:#898781;--link:#1c5cab;
--hm-zero:#ecebe5;--hm-ink:#141413}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;
--page:#121211;--surface:#1a1a19;--card:#1e1e1d;--ink:#efeee9;--ink2:#c3c2b7;--muted:#a3a29b;
--grid:#2e2e2b;--axis:#3a3a37;--ring:rgba(255,255,255,.12);--wash:rgba(57,135,229,.16);
--s1:#3987e5;--s2:#d95926;--s3:#199e70;
--v1:#b7d3f6;--v2:#6da7ec;--v3:#2a78d6;--v4:#184f95;--link:#86b6ef;
--hm-zero:#262624;--hm-ink:#efeee9}}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1120px;margin:0 auto;padding:32px 20px 72px}
a{color:var(--link);text-underline-offset:2px}
:focus-visible{outline:2px solid var(--s1);outline-offset:2px;border-radius:3px}
h1{font-size:30px;line-height:1.15;letter-spacing:-.01em;margin:0;font-weight:650;overflow-wrap:anywhere}
h2{font-size:20px;line-height:1.25;margin:0 0 6px;font-weight:650}
h3{font-size:15.5px;margin:22px 0 8px;font-weight:650}
.ctx{color:var(--ink2);margin:6px 0 0;font-size:14px}
.ctx b{color:var(--ink);font-weight:600}
.state{font-size:18px;line-height:1.45;margin:18px 0 0;max-width:62ch}
.links{margin:10px 0 0;font-size:14px;display:flex;flex-wrap:wrap;gap:4px 18px}
.small,.sub{font-size:13px;color:var(--muted)}
.na,.empty{color:var(--muted)}
.lead{color:var(--ink2);margin:0 0 14px;max-width:75ch}
.part{margin:44px 0 0;padding-top:20px;border-top:1px solid var(--grid)}
.part>header{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:6px}
.part>header h2{display:flex;align-items:center;gap:8px}
.glyph{width:20px;height:20px;flex:none;color:var(--ink2);vertical-align:-4px}
.lens{display:inline-flex;align-items:center;gap:5px}
.lens .glyph{width:15px;height:15px}
/* two peer panels */
.lenses{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin:24px 0 0}
.panel{background:var(--card);border:1px solid var(--ring);border-radius:14px;padding:18px 20px 16px;min-width:0;display:flex;flex-direction:column}
.panel>header{display:flex;justify-content:space-between;align-items:center;gap:10px}
.panel h2{display:flex;align-items:center;gap:8px;font-size:17px;margin:0}
.panel .say{margin:10px 0 12px;color:var(--ink2);font-size:14.5px}
.results{width:100%;border-collapse:collapse;font-size:14px}
.results th,.results td{padding:6px 0;border-top:1px solid var(--grid);vertical-align:baseline;text-align:left}
.results th{font-weight:400;color:var(--ink2);padding-right:10px}
.results .val{font-weight:600;font-variant-numeric:tabular-nums;white-space:nowrap;padding-right:10px}
.results .ref{color:var(--muted);font-size:13px;padding-right:8px}
.results .flag{text-align:right;white-space:nowrap}
.trend{margin:12px 0 14px;display:flex;align-items:center;gap:10px}
.trend figcaption{font-size:12.5px;color:var(--muted)}
.first{margin:auto 0 0;padding-top:10px;border-top:1px solid var(--grid);font-size:14px}
.first .k{font-weight:600;margin-right:6px}
/* chips */
.chip{display:inline-flex;align-items:center;gap:6px;font-size:13px;font-weight:600;white-space:nowrap}
.chip .ic{display:inline-grid;place-items:center;width:18px;height:18px;border-radius:50%;color:#fff;font-size:11px;font-weight:700}
.ok .ic{background:var(--good)} .warn .ic{background:var(--warn);color:#141413}
.serious .ic{background:var(--serious);color:#141413} .crit .ic{background:var(--crit)} .unknown .ic{background:var(--unk)}
/* actions */
.actions{display:grid;gap:8px}
.act{border:1px solid var(--ring);border-radius:10px;background:var(--card)}
.act>summary{list-style:none;cursor:pointer;color:inherit;display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:4px 12px;align-items:center;padding:10px 14px}
.act>summary::-webkit-details-marker{display:none}
.act>summary::after{content:"";width:8px;height:8px;border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);transform:rotate(-45deg);grid-column:3;grid-row:1}
.act[open]>summary::after{transform:rotate(45deg)}
.act .t{font-weight:600;overflow-wrap:anywhere}
.act .m{grid-column:2/3;display:flex;flex-wrap:wrap;gap:2px 14px;font-size:12.5px;color:var(--muted)}
.pri{grid-row:1/3;align-self:start;font-size:12px;font-weight:700;border-radius:6px;padding:2px 7px;margin-top:1px}
.P1{background:var(--crit);color:#fff} .P2{background:var(--warn);color:#141413} .P3{background:var(--grid);color:var(--ink)}
.act dl{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:6px 16px;margin:0;padding:4px 14px 14px 58px;font-size:14px}
.act dt{color:var(--muted)} .act dd{margin:0;overflow-wrap:anywhere;min-width:0}
.act ul{margin:0;padding-left:18px}
/* tables */
.tw{overflow-x:auto;margin:6px 0}
table{border-collapse:collapse;width:100%;font-size:13.5px}
caption{text-align:left;font-size:13px;color:var(--muted);padding:0 0 6px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--grid);vertical-align:top}
thead th{font-size:12.5px;color:var(--ink2);font-weight:600;white-space:nowrap}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.name{overflow-wrap:anywhere;font-weight:400}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
/* matrix */
.matrix th.b{text-align:center;font-weight:500;font-size:12px;color:var(--muted)}
.matrix td.c{text-align:center;font-weight:700;width:36px;padding:7px 2px}
.matrix td.c.ok{color:var(--good)} .matrix td.c.crit{color:var(--crit)} .matrix td.c.na{color:var(--unk)}
.matrix td.c.crit span[aria-hidden]{display:inline-grid;place-items:center;width:20px;height:20px;border-radius:5px;background:var(--crit);color:#fff;font-size:11px}
.matrix .life{white-space:nowrap;color:var(--ink2)}
.matrix details{margin-top:4px;font-size:13px}
/* heatmap */
.heatwrap{padding:0 40px 4px 0}
.heat{border-collapse:separate;border-spacing:3px;width:auto}
.heat th,.heat td{border:0;padding:0}
.heat caption{padding:0 0 10px}
.heat th.hr{vertical-align:bottom;padding:0 10px 6px 0;font-size:12.5px;color:var(--ink2)}
.heat th.name{font-weight:400;font-size:13.5px;padding:0 14px 0 0;vertical-align:middle;white-space:nowrap;position:sticky;left:0;z-index:1;background:var(--page)}
@media (max-width:640px){.heat th.name{white-space:normal;min-width:128px;max-width:150px;font-size:12.5px;line-height:1.3} .heatwrap{padding-right:16px}}
.heat th.hc{position:relative;height:112px;width:58px;min-width:58px;max-width:58px;padding:0}
.heat th.hc>span{position:absolute;left:24px;bottom:8px;transform:rotate(-38deg);transform-origin:0 100%;white-space:nowrap;font-size:12px;font-weight:500;color:var(--ink2)}
.heat th.hc.oth>span{color:var(--muted);font-style:italic}
.heat th.ht{vertical-align:bottom;padding:0 0 6px 12px;font-size:12.5px;color:var(--ink2);text-align:left}
.heat td.hm{width:58px;min-width:58px;height:38px;text-align:center;vertical-align:middle;border-radius:7px;
font-size:12.5px;font-variant-numeric:tabular-nums;color:var(--hm-ink);background:var(--c);transition:box-shadow .12s}
.heat td.hm.il{color:#fff;font-weight:600}
.heat td.hm.h0{background:var(--hm-zero);color:var(--muted)}
.heat td.hm.hn{background:transparent}
.heat td.hm:hover{box-shadow:inset 0 0 0 2px var(--ink)}
.heat td.hm a{display:grid;place-items:center;height:38px;color:inherit;text-decoration:none}
.heat tbody tr:hover th.name{color:var(--link)}
.heat td.tot{padding:0 0 0 12px;white-space:nowrap;font-size:13px;font-variant-numeric:tabular-nums;vertical-align:middle}
.heat .tbar{display:inline-block;width:72px;height:8px;border-radius:3px;background:var(--grid);overflow:hidden;margin-right:8px;vertical-align:middle}
.heat .tbar i{display:block;height:100%;background:var(--v2)}
.heatlegend{display:flex;flex-wrap:wrap;align-items:center;gap:8px 18px;margin:8px 0 0;font-size:13px;color:var(--ink2)}
.heatlegend>span{display:inline-flex;align-items:center;gap:6px}
.heatlegend i.hm0{display:inline-block;width:16px;height:16px;border-radius:4px;background:var(--hm-zero)}
.heatlegend .ramp i{display:inline-block;width:140px;height:12px;border-radius:4px;background:var(--g)}
@media (prefers-color-scheme:dark){.heat td.hm{background:var(--cd);color:var(--hm-ink);font-weight:400} .heat td.hm.id{color:#141413;font-weight:600} .heatlegend .ramp i{background:var(--gd)}}
/* priority matrix */
.quad{display:grid;grid-template-columns:max-content repeat(2,minmax(0,1fr));gap:8px;align-items:stretch}
.quad .q{display:block;border:1px solid var(--ring);border-radius:12px;padding:14px 16px;background:var(--card);color:inherit;text-decoration:none}
.quad a.q:hover{border-color:var(--s1)}
.quad .qh{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.quad .qn{font-size:26px;font-weight:650;margin-left:auto}
.quad .qs{font-size:13px;color:var(--muted)}
.quad p{margin:6px 0 0;font-size:13.5px;color:var(--ink2)}
.quad .ax{font-size:12.5px;color:var(--muted)}
.quad .ax.y{writing-mode:vertical-rl;transform:rotate(180deg);text-align:center}
.quad .ax.x{text-align:center}
i.v1{background:var(--v1)} i.v2{background:var(--v2)} i.v3{background:var(--v3)} i.v4{background:var(--v4)}
/* svg */
svg{display:block;overflow:visible}
.spark{width:168px;height:34px;flex:none}
.spark .sl{fill:none;stroke:var(--axis);stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
.spark .sd{fill:var(--s1);stroke:var(--card);stroke-width:2}
.spark .sv{fill:var(--ink);font-size:12px;font-weight:600}
.spark .hit,.bullet .hit{fill:transparent}
.bullet{width:100%;max-width:560px;height:auto}
.bullet .track{fill:var(--grid)} .bullet .band{fill:var(--wash);stroke:var(--v4);stroke-width:1}
.bullet .bar{fill:var(--ink)} .bullet .lim{stroke:var(--crit);stroke-width:2}
.bullet .tk{fill:var(--muted);font-size:12px} .bullet .bv{fill:var(--ink);font-size:12.5px;font-weight:600}
.matrix summary{cursor:pointer;color:var(--link)}
footer{color:var(--muted);font-size:12.5px;margin-top:40px}
@media print{body{background:#fff} .panel,.act,.q{break-inside:avoid}
details>summary::after{display:none} details{display:block} details>*{display:block}
a{color:inherit;text-decoration:none}}
@media (min-width:761px){.results th{white-space:nowrap}}
@media (max-width:760px){.results tr{display:grid;grid-template-columns:minmax(0,1fr) auto;column-gap:10px;border-top:1px solid var(--grid);padding:7px 0}
.results th,.results td{border:0;padding:0} .results th{grid-column:1;grid-row:1} .results .flag{grid-column:2;grid-row:1}
.results .val{grid-column:1/-1;grid-row:2} .results .ref{grid-column:1/-1;grid-row:3}}
@media (max-width:760px){.lenses{grid-template-columns:minmax(0,1fr)} h1{font-size:24px} .state{font-size:16.5px}
.act dl{grid-template-columns:minmax(0,1fr);padding-left:14px} .quad{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}
.quad .ax.y{display:none} .quad>div:nth-last-child(3){display:none}}
"""

# Styles for the chart helpers and blocks of report_ui that the redesigned
# pages keep using (trend charts, distributions, KPI tiles, tables, filters).
COMPAT_CSS = """
.nav{display:flex;flex-wrap:wrap;gap:4px 18px;margin:16px 0 0;font-size:14px}
.nav a{text-decoration:none} .nav a:hover{text-decoration:underline}
.kpis,.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:8px 0 16px}
.kpi,.stat{border:1px solid var(--ring);border-radius:10px;padding:10px 12px;background:var(--card)}
.kpi .k,.stat .k{font-size:13px;color:var(--ink2)} .kpi .n,.stat .n{font-size:22px;font-weight:600}
.kpi .d,.stat .s{font-size:12.5px;color:var(--muted)}
.worse{color:var(--crit);font-weight:600} .better{color:var(--good);font-weight:600} .flat{color:var(--muted)}
.cols2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px 22px}
.moves{display:grid;grid-template-columns:minmax(0,1fr);gap:10px}
.moves details{border:1px solid var(--ring);border-radius:10px;padding:10px 12px;background:var(--card);margin:0}
.moves summary{font-weight:600;cursor:pointer}
.hbars{display:grid;gap:6px;margin:6px 0 12px}
.hb{display:grid;grid-template-columns:minmax(96px,30%) minmax(0,1fr) minmax(64px,max-content);gap:10px;align-items:center;font-size:13.5px}
.hb .lab{overflow-wrap:anywhere}
.hb .bar{height:12px;border-radius:3px;background:var(--wash);overflow:hidden}
.hb .bar i{display:block;height:100%;border-radius:0 3px 3px 0}
.hb .val{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
i.s1{background:var(--s1)} i.s2{background:var(--s2)} i.s3{background:var(--s3)}
i.hg{background:var(--good)} i.hf{background:var(--warn)} i.hp{background:var(--crit)} i.hu{background:var(--unk)}
.mix{display:inline-flex;width:120px;height:10px;border-radius:3px;overflow:hidden;gap:1px;vertical-align:middle;background:var(--grid)}
.mix i{display:block;height:100%}
.share{display:inline-flex;align-items:center;gap:8px;white-space:nowrap}
.share .bar{display:inline-block;width:70px;height:8px;border-radius:3px;background:var(--wash);overflow:hidden}
.share .bar i{display:block;height:100%;background:var(--s1)}
.sw{width:12px;height:12px;border-radius:3px;display:inline-block}
.sw.s1{background:var(--s1)} .sw.s2{background:var(--s2)} .sw.s3{background:var(--s3)}
.sw.v1{background:var(--v1)} .sw.v2{background:var(--v2)} .sw.v3{background:var(--v3)} .sw.v4{background:var(--v4)}
.sw.hg{background:var(--good)} .sw.hf{background:var(--warn)} .sw.hp{background:var(--crit)} .sw.hu{background:var(--unk)}
.cmd{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;background:var(--wash);border-radius:4px;padding:1px 6px;white-space:nowrap;user-select:all}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
td.nw,.nw{white-space:nowrap}
details{margin:4px 0} summary{cursor:pointer;color:var(--link)}
.disclaimer{font-size:13px;color:var(--ink2);border-left:3px solid var(--axis);padding:4px 10px;margin:12px 0 0}
svg{width:100%;height:auto}
svg .grid{stroke:var(--grid);stroke-width:1} svg .base{stroke:var(--axis);stroke-width:1}
svg .tick,svg .axt{fill:var(--muted);font-size:12px} svg .axt{fill:var(--ink2);font-weight:600;font-size:13px}
svg .vlab{fill:var(--ink);font-size:12px;font-weight:600}
svg .ln{fill:none;stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
svg .ln.s1{stroke:var(--s1)} svg .ln.s2{stroke:var(--s2)} svg .ln.s3{stroke:var(--s3)}
svg .dot{stroke:var(--card);stroke-width:2} svg .dot.s1{fill:var(--s1)} svg .dot.s2{fill:var(--s2)} svg .dot.s3{fill:var(--s3)}
svg .dot.hollow{fill:var(--card);stroke:var(--crit);stroke-width:2}
svg .hit{fill:transparent} svg .band{fill:var(--wash)} svg .thr,svg .gap{stroke:var(--muted);stroke-width:1}
svg path.s2,svg rect.s2{fill:var(--s2)} svg path.s3,svg rect.s3{fill:var(--s3)}
svg path.v1,svg rect.v1{fill:var(--v1)} svg path.v2,svg rect.v2{fill:var(--v2)}
svg path.v3,svg rect.v3{fill:var(--v3)} svg path.v4,svg rect.v4{fill:var(--v4)}
svg path.hg,svg rect.hg{fill:var(--good)} svg path.hf,svg rect.hf{fill:var(--warn)}
svg path.hp,svg rect.hp{fill:var(--crit)} svg path.hu,svg rect.hu{fill:var(--unk)}
.spark{width:168px;height:34px} .bullet{width:100%;max-width:560px}
.tools{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px 12px;margin:4px 0 10px;font-size:13px}
.tools label{display:grid;gap:3px;color:var(--ink2)}
.tools input,.tools select,.pager select{font:inherit;color:var(--ink);background:var(--card);border:1px solid var(--axis);border-radius:6px;padding:5px 8px;min-width:0}
.tools .ck{display:flex;align-items:center;gap:6px;align-self:end;padding-bottom:6px}
.pager{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin:8px 0 0;font-size:13px;color:var(--ink2)}
.pager button,.btn{font:inherit;color:var(--link);background:var(--card);border:1px solid var(--ring);border-radius:6px;padding:4px 12px;cursor:pointer}
.btn{font-weight:600;border-color:var(--s1)}
.pager button[disabled]{color:var(--muted);cursor:default}
.linkbtn{font:inherit;color:var(--link);background:none;border:0;padding:0;cursor:pointer;text-decoration:underline;text-underline-offset:2px}
th button{font:inherit;color:inherit;background:none;border:0;padding:0;cursor:pointer;font-weight:600}
th[aria-sort=ascending] button::after{content:" \\25B2"} th[aria-sort=descending] button::after{content:" \\25BC"}
.js-only{display:none} .has-js .js-only{display:block} .has-js .no-js{display:none}
.appflt{background:var(--wash);border-radius:8px;padding:6px 10px;font-size:13.5px}
table.fix td.found{max-width:340px;overflow-wrap:anywhere;color:var(--ink2);font-size:13px}
table.fix .pri{display:inline-block} table.fix summary{white-space:nowrap}
#apps td.name:first-child,table.fix td.name:nth-child(2){min-width:132px}
table.fix td:nth-child(3){min-width:170px} table.fix td.found{min-width:200px}
@media print{.nav{display:none} .js-only{display:none!important} .no-js{display:block!important}}
@media (max-width:760px){.cols2{grid-template-columns:minmax(0,1fr)}}
@media (max-width:640px){.hb{grid-template-columns:minmax(0,1fr) max-content} .hb .bar{grid-column:1/-1;order:3}}
"""
