"""HTML renderer for the app report."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import scan_health as sh

from . import app_report_analytics as ana
from .report_ui import (
    CSS,
    HALF,
    PDF_SCRIPT,
    PRINT_CSS,
    STATUS_LEVEL,
    chip,
    csp_meta,
    e,
    fmt_dt,
    fmt_mb,
    fmt_num,
    fmt_signed,
    grouped_bars,
    line_chart,
    link,
    pdf_button,
    rec_html,
    short_date,
    stacked_columns,
    timeline,
)

if TYPE_CHECKING:
    from .app_report import AppReport
    from .app_report_analytics import Analysis

def _header(r: AppReport) -> str:
    a, b = r.app, r.latest
    ctx = r.context
    where = ("Sandbox " + e(ctx.get("sandbox_name"))) if ctx.get("type") == "sandbox" else "Policy scans"
    scan = r.parameters.get("scan")
    if scan and len(r.builds) > 1:
        scope = (f"Scan build {e(scan.get('build_id'))} with {len(r.builds) - 1} earlier "
                 f"build(s) for trend ({e(r.history_status)})")
    elif scan:
        scope = f"Single scan, build {e(scan.get('build_id'))}"
    else:
        hs = "" if r.history_status == "Complete" else f" ({e(r.history_status.lower())})"
        scope = f"{len(r.builds)} published build(s) analysed{hs}"
    links = []
    if b is not None:
        links = [link(b.overview_url, "Static Overview"), link(b.review_url, "Review Modules"),
                 link(b.triage_url, "Triage Flaws")]
        links = [x for x in links if x.startswith("<a")]
    meta = [
        ("Business unit", e(a.business_unit or "Unavailable")),
        ("Policy", e(a.policy or (b.policy_name if b else None) or "Unavailable")),
        ("Business criticality", e(a.business_criticality or (b.business_criticality if b else None)
                                   or "Unavailable")),
        ("Teams", e(teams_label(a))),
        ("Region", e(a.region)),
        ("App ID", e(a.legacy_id)),
        ("Scanned build" if scan else "Latest build",
         e(f"{b.build_id} ({b.version})" if b else "None")),
        ("Generated", e(fmt_dt(r.generated, True))),
    ]
    m = "".join(f"<span>{k} <b>{v}</b></span>" for k, v in meta)
    lk = (" &middot; ".join(links)) if links else ""
    partial = ('<p class="disclaimer">This report is partial: collection did not finish.</p>'
               if not r.complete else "")
    jump = ""
    if b is not None:
        jump = '<nav class="jump" aria-label="Sections">' + "".join(
            f'<a href="#{i}">{t}</a>' for i, t in _SECTIONS) + "</nav>"
    return (f'<header><p class="sub">Veracode scan health report</p><h1>{e(a.name)}</h1>'
            f'<p class="sub">{where} &middot; {scope}</p><div class="meta">{m}</div>'
            f'{"<p class=meta>Open in Veracode: " + lk + "</p>" if lk else ""}'
            f'<p class="na scope">{e(scope_note(r))}</p>{partial}{jump}</header>')


_SECTIONS = (("actions", "Actions"), ("changes", "What changed"), ("checks", "Health checks"),
             ("performance", "Scan time"), ("cadence", "Cadence"), ("findings", "Findings"),
             ("composition", "Modules"), ("appendix", "Builds"), ("notes", "About this data"))


def _verdicts(an: Analysis) -> str:
    cards = []
    for v in an.verdicts:
        cards.append(f'<div class="v"><div class="k">{e(v.label or v.name)}</div>'
                     f'<div class="val">{chip(v.level, v.display or v.value)}</div>'
                     f'<div class="why">{e(v.reason)}</div></div>')
    return f'<div class="verdicts">{"".join(cards)}</div>' + (
        f'<p class="disclaimer">{e(sh.DISCLAIMER)}</p>')


def _action_card(a: Any) -> str:
    found = ([a.why] if a.why else []) + list(a.evidence)
    ev = "".join(f"<li>{e(x)}</li>" for x in found[:5])
    fix = "".join(f"<li>{rec_html(x)}</li>" for x in a.how_to_fix) or "<li>See the check documentation.</li>"
    lk = " &middot; ".join(link(u, lbl) for lbl, u in a.links)
    rec = (f'<span class="tag">failing {a.consecutive_failing} scans in a row</span>'
           if a.consecutive_failing > 1 else "")
    return (f'<article class="act"><header><span class="pill {e(a.priority)}">{e(a.priority)}</span>'
            f'<h3>{e(a.title)}</h3><span class="tag">'
            f'{e(ana.EFFORT_NAME.get(a.effort, a.effort))} effort</span>{rec}</header><dl>'
            + (f"<dt>Why</dt><dd>{e(a.priority_why)}</dd>" if a.priority_why else "")
            + (f"<dt>Found</dt><dd><ul>{ev}</ul></dd>" if ev else "")
            + f"<dt>Fix</dt><dd><ul>{fix}</ul></dd>"
            + (f"<dt>Done when</dt><dd>{e(a.verify)}</dd>" if a.verify else "")
            + (f"<dt>Open</dt><dd>{lk}</dd>" if lk else "") + "</dl></article>")


def _actions(an: Analysis) -> str:
    if not an.actions:
        return ('<section id="actions"><h2>Top actions</h2><p class="lead">No actions: every '
                'measured dimension is healthy.</p></section>')
    top = "".join(_action_card(a) for a in an.actions[:5])
    rest = ""
    if len(an.actions) > 5:
        rest = (f"<details><summary>{len(an.actions) - 5} more action(s)</summary>"
                f'<div class="actions">{"".join(_action_card(a) for a in an.actions[5:])}</div></details>')
    return (f'<section id="actions"><h2>Top actions</h2>{_priority_key()}'
            f'<div class="actions">{top}</div>{rest}</section>')


def _priority_key() -> str:
    """Priorities and effort in one short legend (same rule as the tenant report)."""
    p = "".join(f'<span><span class="pill {k}">{k}</span> {e(v)}</span>' for k, v in ana.PRIORITY_MEANING.items())
    ef = " &middot; ".join(e(v) for v in ana.EFFORT_MEANING.values())
    return f'<p class="pkey">{p}<span class="na">Effort: {ef}</span></p>'


def _ptable(head: list[str], rows: list[list[str]], num: tuple[int, ...] = (), note: str = "") -> str:
    """A narrow summary table that only prints (PDF); cells are escaped HTML. The screen keeps the
    full table, which has a Copy button."""
    if not rows:
        return ""
    h = "".join(f'<th{" class=n" if i in num else ""}>{x}</th>' for i, x in enumerate(head))
    b = "".join("<tr>" + "".join(f'<td{" class=n" if i in num else ""}>{x}</td>' for i, x in enumerate(r))
                + "</tr>" for r in rows)
    return (f'<div class="print-only"><table class="ptab"><thead><tr>{h}</tr></thead><tbody>{b}'
            f'</tbody></table>{"<p class=na>" + note + "</p>" if note else ""}</div>')


def _short(text: str, n: int = 160) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1].rstrip() + "\u2026"


FULL_IN_HTML = "The HTML report has the full table, with a Copy button."


def _list_or_none(items: list[str], limit: int = 25) -> str:
    if not items:
        return '<span class="na">None</span>'
    shown = ", ".join(f"<code>{e(x)}</code>" for x in items[:limit])
    more = f" and {len(items) - limit} more" if len(items) > limit else ""
    return shown + more


def _changes(r: AppReport, an: Analysis) -> str:
    d = an.diffs
    if d.previous_build is None:
        return (f'<section id="changes"><h2>What changed since the previous scan</h2>'
                f'<p class="lead">{e(d.reason)}.</p></section>')
    lab = {c.check_num: c.label for c in (r.latest.checks if r.latest else [])}

    def checks(ns: list[int]) -> str:
        return ", ".join(f"#{n} {e(lab.get(n, ''))}" for n in ns)

    # (label, value, changed). Unknown values are shown, never counted as unchanged.
    rows: list[tuple[str, str, bool]] = [
        ("Checks now failing", checks(d.checks_new), bool(d.checks_new)),
        ("Checks now passing", checks(d.checks_resolved), bool(d.checks_resolved)),
        ("Policy status", f"{e(d.policy[0])} to {e(d.policy[1])}", d.policy[0] != d.policy[1]),
        ("Total flaws", f"{fmt_num(d.flaws_total[0])} to {fmt_num(d.flaws_total[1])}",
         d.flaws_total[0] != d.flaws_total[1]),
        ("Veracode engine", f"{e(d.engine[0])} to {e(d.engine[1])}", d.engine[0] != d.engine[1]),
        ("Analysis size", _signed_mb(d.analysis_size_delta), _moved(d.analysis_size_delta)),
        ("Uploaded module size", _signed_mb(d.prescan_size_delta), _moved(d.prescan_size_delta)),
    ]
    if d.available:
        rows += [
            ("Selected modules added", _list_or_none(d.modules_added), bool(d.modules_added)),
            ("Selected modules removed", _list_or_none(d.modules_removed), bool(d.modules_removed)),
            ("New first-party modules not selected", _list_or_none(d.new_unselected_first_party),
             bool(d.new_unselected_first_party)),
            ("Files added", f"{len(d.files_added):,} {_ext_counts(d.ext_added)}", bool(d.files_added)),
            ("Files removed", f"{len(d.files_removed):,} {_ext_counts(d.ext_removed)}", bool(d.files_removed)),
            ("Files changed (same name, new content)", f"{len(d.files_changed):,}", bool(d.files_changed)),
        ]
    else:
        rows.append(("Modules and files", f'<span class="na">{e(d.reason or "Not compared")}</span>', True))
    body = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v, ch in rows if ch)
    same = [k for k, _, ch in rows if not ch]
    same_txt = (f'<p class="na">No change: {e(", ".join(same).lower())}.</p>' if same else "")
    files = ""
    if d.available and (d.files_added or d.files_removed or d.files_changed):
        files = (f'<details class="screen-only"><summary>File names</summary><h3>Added</h3>'
                 f"<p>{_list_or_none(d.files_added, 200)}</p>"
                 f"<h3>Removed</h3><p>{_list_or_none(d.files_removed, 200)}</p>"
                 f"<h3>Changed</h3><p>{_list_or_none(d.files_changed, 200)}</p></details>")
    return (f'<section id="changes"><h2>What changed since the previous scan</h2>'
            f'<p class="lead">Build {e(r.latest.build_id if r.latest else "")} compared with build '
            f'{e(d.previous_build)}.</p>'
            + (f'<div class="tw"><table data-copy>{body}</table></div>' if body else "")
            + f'{same_txt}{files}</section>')


def _moved(n: int | None) -> bool:
    """A size change worth showing: unknown, or at least 0.1 MB either way."""
    return n is None or abs(n) >= 50_000


def _signed_mb(n: int | None) -> str:
    return "Unavailable" if n is None else f"{n / 1e6:+,.1f} MB"


def _ext_counts(c: dict[str, int]) -> str:
    if not c:
        return ""
    return "(" + ", ".join(f"{e(k)} {v}" for k, v in list(c.items())[:6]) + ")"


def _checks(r: AppReport, an: Analysis) -> str:
    b = r.latest
    if b is None:
        return ""
    hist = {h.check_num: h for h in an.check_history}
    order = {"Fail": 0, "Error": 1, "Unavailable": 2, "Not run": 2, "Pass": 3, "N/A": 4, "Skipped": 5}
    rows: list[str] = []
    quiet: list[str] = []
    prows: list[list[str]] = []
    pquiet: dict[str, list[int]] = {}
    for c in sorted(b.checks, key=lambda c: (order.get(c.status, 9),
                                             0 if c.severity == "high" else 1, c.check_num)):
        h = hist.get(c.check_num)
        trail = ""
        trail_txt = ""
        if h and h.statuses:
            recent = h.statuses[-10:]
            trail = "".join(f'<span class="dotv" title="{e(bid)}: {e(st)}" style="background:var(--'
                            f'{ {"Pass": "good", "Fail": "crit"}.get(st, "unk") })"></span> '
                            for bid, st in recent)
            trail_txt = f"failed {sum(1 for _, st in recent if st == 'Fail')} of last {len(recent)}"
        detail = ""
        detail_txt = " ".join(c.issues) if c.status == "Fail" else (c.reason or "")
        if c.status == "Fail":
            ev = ""
            if c.evidence:
                more = (f"<p class=na>Showing {len(c.evidence)} of {c.evidence_total}.</p>"
                        if (c.evidence_total or 0) > len(c.evidence) else "")
                ev = (f"<details><summary>Evidence ({e(c.evidence_total)})</summary><ul>"
                      + "".join(f"<li><code>{e(x)}</code></li>" for x in c.evidence) + f"</ul>{more}</details>")
            recs = "".join(f"<li>{rec_html(x)}</li>" for x in c.recommendations)
            detail = ("".join(f"<div>{e(i)}</div>" for i in c.issues) + ev
                      + (f"<details><summary>Recommendation</summary><ul>{recs}</ul></details>" if recs else ""))
        elif c.reason:
            detail = f'<span class="na">{e(c.reason)}</span>'
        sev_word = c.severity.capitalize() if c.severity else f"up to {c.max_severity}"
        sev = e(sev_word) if c.severity else f'<span class="na">{e(sev_word)}</span>'
        row = (f'<tr><td class=n>{c.check_num}</td><td data-v="{e(c.label)}">{e(c.label)}'
               f'<div class=na>{e(c.category)}</div></td>'
               f"<td>{chip(STATUS_LEVEL.get(c.status, 'GRAY'), c.status)}</td><td class=nw>{sev}</td>"
               f"<td class=nw>{e(h.lifecycle if h else 'Unknown')}</td>"
               f'<td class=nw data-v="{e(trail_txt)}">{trail}</td><td data-v="{e(detail_txt)}">{detail}</td></tr>')
        if c.status in ("Pass", "N/A", "Skipped"):
            quiet.append(row)
            pquiet.setdefault({"Pass": "Passing", "N/A": "Not applicable"}.get(c.status, c.status),
                              []).append(c.check_num)
        else:
            rows.append(row)
            res = [c.status, sev_word]
            if c.status == "Fail":
                res.append(ana.check_priority(c.check_num, c.severity)[0])
            found = _short(c.issues[0]) if c.issues else _short(c.reason or "")
            if len(c.issues) > 1:
                found += f" (+{len(c.issues) - 1} more)"
            prows.append([str(c.check_num), e(c.label), e(" \u00b7 ".join(res)), e(found)])
    failing = sum(1 for c in b.checks if c.status == "Fail")
    head = ("<thead><tr><th class=n>#</th><th>Check</th><th>Status</th><th>Severity</th><th>Lifecycle</th>"
            "<th>History</th><th>Details</th></tr></thead>")
    main = (f'<div class="tw screen-only"><table data-copy>{head}<tbody>{"".join(rows)}</tbody></table></div>'
            if rows else '<p class="lead">No check is failing on this build.</p>')
    rest = (f'<details class="screen-only"><summary>{len(quiet)} passing, not applicable or skipped '
            f'checks</summary><div class="tw"><table data-copy>{head}<tbody>{"".join(quiet)}</tbody></table>'
            f'</div></details>' if quiet else "")
    quiet_txt = " ".join(f"<b>{e(k)}:</b> {', '.join(f'#{n}' for n in sorted(v))}." for k, v in pquiet.items())
    printed = (_ptable(["#", "Check", "Result", "What was found"], prows, (0,))
               + (f'<p class="print-only na">{quiet_txt}</p>' if quiet_txt else ""))
    return (f'<section id="checks"><h2>Health checks</h2><p class="lead">All 31 checks on build '
            f'{e(b.build_id)}: {failing} failing.<span class="screen-only"> History: one dot per recent '
            f'scan, oldest first (green pass, red fail, grey not evaluated).</span></p>'
            f'{main}{rest}{printed}</section>')


def _performance(an: Analysis) -> str:
    d = an.duration
    if not d.points:
        return (f'<section id="performance"><h2>Scan performance</h2>'
                f'<p class="lead">{e(d.reason or "No timing data.")}</p></section>')
    labels = [short_date(p.published) for p in d.points]
    tips = [f"Build {p.build_id}, {sh._fmt_seconds(p.seconds)}, engine {p.engine or 'n/a'}" for p in d.points]
    band = None
    if d.baseline_median is not None and d.baseline_mad is not None:
        k = 3 * 1.4826 * d.baseline_mad
        band = ((d.baseline_median - k) / 60, (d.baseline_median + k) / 60)
    dur = line_chart("Analysis time (minutes)", labels, [p.seconds / 60 for p in d.points], tips,
                     lambda v: f"{v:,.0f}", unit=" min", band=band,
                     threshold=d.threshold / 60 if d.threshold else None,
                     flag_last="slower than usual" if d.status == "Regression" else "")
    spm = line_chart("Seconds per MB analysed", labels, [p.sec_per_mb for p in d.points], tips,
                     lambda v: f"{v:,.0f}", size=HALF, unit=" s/MB")
    size = line_chart("Analysis size (MB)", labels, [p.size_mb for p in d.points], tips,
                      lambda v: f"{v:,.0f}", size=HALF, unit=" MB")
    loc = line_chart("Lines of code (thousands)", labels,
                     [p.loc / 1000 if p.loc else None for p in d.points], tips,
                     lambda v: f"{v:,.0f}", size=HALF, unit="K")
    skpl = line_chart("Seconds per thousand lines", labels, [p.sec_per_kloc for p in d.points], tips,
                      lambda v: f"{v:,.0f}", size=HALF, unit=" s")
    usual = d.baseline_median
    change = (f"{(d.latest - usual) / usual:+.0%}" if d.latest is not None and usual else "n/a")
    top = [("Latest", sh._fmt_seconds(d.latest) if d.latest is not None else "n/a", ""),
           ("Usual", sh._fmt_seconds(int(usual)) if usual is not None else "n/a", "median of earlier scans"),
           ("Change", change, "slower than usual" if d.status == "Regression" else "latest vs usual")]
    stats = [("Median (p50)", sh._fmt_seconds(int(d.p50)) if d.p50 is not None else "n/a", ""),
             ("p90", sh._fmt_seconds(int(d.p90)) if d.p90 is not None else "n/a", ""),
             ("Fastest", sh._fmt_seconds(d.min or 0), f"build {d.fastest_build}"),
             ("Slowest", sh._fmt_seconds(d.max or 0), f"build {d.slowest_build}"),
             ("Trend (Theil-Sen)", f"{d.slope_min_per_scan:+.1f} min" if d.slope_min_per_scan
              is not None else "n/a", "per scan")]
    def tiles(rows: list[tuple[str, str, str]]) -> str:
        return "".join(f'<div class="stat"><div class="k">{e(k)}</div><div class="n">{e(v)}</div>'
                       f'<div class="s">{e(sub)}</div></div>' for k, v, sub in rows)
    yours = [x for x in d.drivers if not x.startswith("Engine")]
    veracode = [x for x in d.drivers if x.startswith("Engine")]
    causes = ""
    if d.status == "Regression":
        causes = ("<h3>Changed at the same time</h3><ul>"
                  + "".join(f"<li>In your upload: {e(x)}</li>" for x in yours)
                  + "".join(f"<li>Veracode side: {e(x)}</li>" for x in veracode)
                  + ("" if yours else "<li>Nothing in the upload grew. Analysis time also depends on "
                     "Veracode's engine and platform load, which you cannot change; no action needed "
                     "unless it persists.</li>") + "</ul>")
    level = ("YELLOW" if d.status == "Regression" and not d.has_size_or_module_driver
             else {"Regression": "RED", "Normal": "GREEN"}.get(d.status, "GRAY"))
    label = {"Regression": "Slower than usual", "Normal": "Normal"}.get(d.status, d.status)
    return (f'<section id="performance"><h2>Scan time {chip(level, label)}</h2><p class="lead">'
            f'Analysis time: from submission to published results; upload and prescan are not '
            f'included.</p><div class="stats">{tiles(top)}</div>'
            + (f'{dur}<p class="na">Shaded band: the usual range. Line: the slow threshold.</p>'
               if len(d.points) > 1 else "")
            + f'{causes}'
            f'<details class="screen-only"><summary>More timing detail</summary><div class="stats">{tiles(stats)}</div>'
            f'<div class="grid2 screen-only"><div>{spm}</div><div>{skpl}</div></div>'
            f'<div class="grid2 screen-only"><div>{size}</div><div>{loc}</div></div></details></section>')


def _cadence(an: Analysis, r: AppReport) -> str:
    c = an.cadence

    def days(x: float | None) -> str:
        return "n/a" if x is None else f"{x:g} days"

    stats = [("Since last scan", days(c.days_since_last)), ("Usually every", days(c.median_interval_days)),
             ("Longest gap", days(c.max_interval_days)), ("Scans, last 90 days", fmt_num(c.scans_last_90d))]
    st = "".join(f'<div class="stat"><div class="k">{e(k)}</div><div class="n">{v}</div></div>'
                 for k, v in stats)
    tl, undated = timeline(c.attempts, c.longest_gap)
    gap = (f"Longest gap: {e(c.longest_gap[0])} to {e(c.longest_gap[1])}." if c.longest_gap else "")
    if undated:
        gap += f" {undated} undated attempt(s) are listed under Builds."
    fr = (f"Failed or cancelled: {e(c.failure_rate_note)} ({c.failure_rate:.0%})."
          if c.failure_rate is not None else f"Failed or cancelled: {e(c.failure_rate_note)}.")
    legend = ('<div class="legend"><span><i class="sw s1" style="border-radius:50%"></i>Published</span>'
              '<span><i class="sw hollow"></i>Not published (failed, cancelled or in progress)</span></div>')
    return (f'<section id="cadence"><h2>Cadence</h2><div class="stats">{st}</div>{legend}'
            f'{tl}<p class="na">{gap} {fr}</p></section>')


def _findings(an: Analysis) -> str:
    rows = an.findings.rows
    if not rows:
        return ""
    labels = [short_date(x.published) for x in rows]
    tips = [f"build {x.build_id}" for x in rows]
    sev = stacked_columns("Open flaws by severity", labels,
                          [("Low", "v4", [x.low for x in rows]), ("Medium", "v3", [x.medium for x in rows]),
                           ("High", "v2", [x.high for x in rows]), ("Very High", "v1", [x.very_high for x in rows])],
                          tips)
    legend_sev = ('<div class="legend">' + "".join(f'<span><i class="sw {c}"></i>{n}</span>' for n, c in
                  (("Very High", "v1"), ("High", "v2"), ("Medium", "v3"), ("Low", "v4"))) + "</div>")
    nf = grouped_bars("New and fixed flaws per scan", labels,
                      [("New", "s2", [x.new for x in rows]), ("Fixed", "s3", [x.fixed for x in rows])], tips)
    legend_nf = ('<div class="legend"><span><i class="sw s2"></i>New</span>'
                 '<span><i class="sw s3"></i>Fixed</span></div>')
    eng = f'<p class="disclaimer">{e(an.findings.engine_effect)}</p>' if an.findings.engine_effect else ""
    other = _other_changes(an, {x.build_id: short_date(x.published) for x in rows})
    head = ("<tr><th>Build</th><th>Published</th><th class=n>Very High</th><th class=n>High</th>"
            "<th class=n>Medium</th><th class=n>Low</th><th class=n>Open policy</th><th class=n>Mitigated</th>"
            "<th class=n>Total</th><th class=n>New</th><th class=n>Reopened</th><th class=n>Fixed</th>"
            "<th class=n>Net change</th><th class=n>Score</th><th>Policy</th></tr>")
    body = "".join(
        f"<tr><td class=mono>{e(x.build_id)}</td><td>{e(fmt_dt(x.published))}</td>"
        f"<td class=n>{fmt_num(x.very_high)}</td><td class=n>{fmt_num(x.high)}</td><td class=n>{fmt_num(x.medium)}</td>"
        f"<td class=n>{fmt_num(x.low)}</td><td class=n>{fmt_num(x.open_policy)}</td><td class=n>{fmt_num(x.mitigated)}</td>"
        f"<td class=n>{fmt_num(x.total)}</td><td class=n>{fmt_num(x.new)}</td><td class=n>{fmt_num(x.reopen)}</td>"
        f"<td class=n>{fmt_num(x.fixed)}</td><td class=n>{e(fmt_signed(x.net_change))}</td><td class=n>{fmt_num(x.score)}</td>"
        f"<td>{chip(sh._policy_level(x.policy or ''), x.policy or 'Unknown')}</td></tr>" for x in reversed(rows))
    return (f'<section id="findings"><h2>Findings</h2><p class="lead">Open: not fixed and not '
            f'covered by an accepted mitigation.</p>'
            f'<div class="grid2"><div>{legend_sev}{sev}</div><div>{legend_nf}{nf}</div></div>'
            f'{eng}{other}'
            f'<details class="screen-only"><summary>Findings table</summary><div class="tw">'
            f'<table data-copy><thead>{head}</thead><tbody>{body}</tbody></table></div></details>'
            + _ptable(["Build", "Published", "Very High", "High", "Medium", "Low", "New", "Fixed", "Policy"],
                      [[e(x.build_id), e(short_date(x.published)), fmt_num(x.very_high), fmt_num(x.high),
                        fmt_num(x.medium), fmt_num(x.low), fmt_num(x.new), fmt_num(x.fixed),
                        e(x.policy or "Unknown")] for x in list(reversed(rows))[:8]],
                      (2, 3, 4, 5, 6, 7), FULL_IN_HTML if len(rows) > 8 else "")
            + "</section>")


def _other_changes(an: Analysis, dates: dict[str, str]) -> str:
    """Besides code, what moved results in this window: engine updates, policy changes, deadlines."""
    groups: dict[str, list[str]] = {}
    for x in an.findings.events:
        ev, when = x["event"], dates.get(x["build_id"], "") or f"build {x['build_id']}"
        kind = ("Veracode engine updated" if ev.startswith("Engine") else
                "Policy changed" if ev.startswith("Policy") else ev)
        groups.setdefault(kind, []).append(when)
    if not groups:
        return ""
    parts = "; ".join(f"{e(k)}: {e(', '.join(v))}" for k, v in groups.items())
    return (f'<p class="na"><b>Besides code changes:</b> {parts}. An engine or policy update can '
            "change findings or policy status without any code change.</p>")


def _composition(an: Analysis, r: AppReport) -> str:
    rows = an.modules
    if not rows:
        return ""
    limit = 300
    body = []
    for m in rows[:limit]:
        sev = m["flaws_by_sev"]
        sev_txt = " / ".join("n/a" if x is None else str(x) for x in sev) if sev else "n/a"
        flags = [t for t, on in (("selected", m["selected"]), ("dependency", m["dependency"]),
                                 ("third-party", m["third_party"]), ("fatal", m["fatal"])) if on]
        iss = (f"<details><summary>{len(m['issues'])} issue(s)</summary><ul>"
               + "".join(f"<li>{e(i)}</li>" for i in m["issues"]) + "</ul></details>") if m["issues"] else ""
        body.append(f"<tr><td class=name><code>{e(m['name'])}</code></td><td>{e(', '.join(flags) or 'not selected')}</td>"
                    f"<td class=n>{fmt_num(m['loc'])}</td><td class=n>{e(sev_txt)}</td><td>{e(m['size'] or 'n/a')}</td>"
                    f'<td>{e(m["compiler"] or m["platform"] or "")}</td>'
                    f'<td data-v="{e(" ".join(m["issues"]))}">{iss}</td></tr>')
    sel = [m for m in rows if m["selected"]]
    prow = [[f"<code>{e(_short(m['name'], 60))}</code>", e(", ".join(t for t, on in (
        ("selected", m["selected"]), ("dependency", m["dependency"]), ("third-party", m["third_party"]),
        ("fatal", m["fatal"])) if on) or "not selected"), fmt_num(m["loc"]),
        e(" / ".join("n/a" if x is None else str(x) for x in m["flaws_by_sev"]) if m["flaws_by_sev"] else "n/a"),
        e(f"{len(m['issues'])}" if m["issues"] else "")] for m in rows[:15]]
    printed = (f'<p class="print-only">{len(rows):,} module(s), {len(sel):,} selected.</p>'
               + _ptable(["Module", "Role", "LOC", "Flaws VH/H/M/L", "Prescan issues"], prow, (2, 3, 4),
                         FULL_IN_HTML if len(rows) > 15 else ""))
    more = f"<p class=na>Showing {limit} of {len(rows)} modules.</p>" if len(rows) > limit else ""
    b = r.latest
    sca = ""
    if b is not None:
        if b.sca_enabled is None:
            sca = "SCA status unavailable."
        elif not b.sca_enabled:
            sca = "SCA is not enabled for this scan."
        else:
            sca = _sca_table(b)
    return (f'<section id="composition"><h2>Modules</h2><p class="lead">Modules in the latest build, '
            f'selected first. Flaw counts are the platform\'s per-module figures (Very High / High / '
            f'Medium / Low).</p><div class="tw screen-only"><table data-copy><thead><tr><th>Module</th>'
            f'<th>Role</th><th class=n>LOC</th><th class=n>Flaws VH/H/M/L</th><th>Size</th>'
            f'<th>Compiler / platform</th><th>Prescan</th></tr></thead><tbody>{"".join(body)}</tbody></table>'
            f'</div>{more}{printed}'
            f'<h3>Software composition analysis</h3>{sca}</section>')


_SCA_COLS = [("file_name", "Component file", ""), ("library", "Library", ""), ("version", "Version", ""),
             ("vendor", "Vendor", ""), ("max_cvss_score", "Max CVSS", "n"),
             ("vulnerabilities", "Vulnerabilities", "n"),
             ("component_affects_policy_compliance", "Affects policy", ""), ("new", "New", "")]


def _sca_table(b: Any) -> str:
    """Vulnerable components, collapsed; columns appear only when the report supplies them."""
    rows = b.sca_details or [{"file_name": c} for c in b.sca_components or []]
    n = b.sca_vulnerable_components if b.sca_vulnerable_components is not None else len(rows)
    if not rows:
        return f"<p>{n or 0} vulnerable component(s).</p>"
    cols = [c for c in _SCA_COLS if any(r.get(c[0]) not in (None, "") for r in rows)]
    def cell(k: str, v: Any) -> str:
        if v in (None, ""):
            return '<span class="na">n/a</span>'
        if k == "max_cvss_score":
            return e(f"{v:.1f}")
        if k in ("component_affects_policy_compliance", "new"):
            return e("Yes" if str(v).lower() == "true" else "No" if str(v).lower() == "false" else v)
        return f"<code>{e(v)}</code>" if k == "file_name" else e(v)
    head = "".join(f'<th{" class=n" if c else ""}>{e(lab)}</th>' for _, lab, c in cols)
    body = "".join("<tr>" + "".join(f'<td{" class=n" if c else ""}>{cell(k, r.get(k))}</td>'
                                    for k, _, c in cols) + "</tr>" for r in rows[:200])
    more = f'<p class="na">and {len(rows) - 200:,} more.</p>' if len(rows) > 200 else ""
    pcols = [k for k in ("version", "max_cvss_score", "vulnerabilities") if any(c[0] == k for c in cols)]
    prow = [[f"<code>{e(_short(r.get('library') or r.get('file_name') or '', 60))}</code>"]
            + [cell(k, r.get(k)) for k in pcols] for r in rows[:10]]
    phead = ["Component"] + [{"version": "Version", "max_cvss_score": "Max CVSS",
                              "vulnerabilities": "Vulnerabilities"}[k] for k in pcols]
    return (f'<details class="screen-only"><summary>{n:,} vulnerable component(s), highest CVSS first'
            f'</summary><div class="tw"><table data-copy><thead><tr>{head}</tr></thead><tbody>{body}'
            f'</tbody></table></div>{more}</details>'
            f'<p class="print-only">{n:,} vulnerable component(s), highest CVSS first.</p>'
            + _ptable(phead, prow, tuple(i + 1 for i, k in enumerate(pcols) if k != "version"),
                      FULL_IN_HTML if len(rows) > 10 else ""))


def _notes(r: AppReport) -> str:
    warn = [n for n in r.data_notes if n.level == "warning"]
    info = [n for n in r.data_notes if n.level != "warning"]

    def row(n: Any) -> str:
        return f"<tr><td>{e(n.topic)}</td><td>{e(n.message)}</td></tr>"

    c = r.collection or {}
    calls = c.get("api_calls", {})
    cache = c.get("cache", {})
    coll = (f"API calls: report {e(calls.get('report', 0))}, xml {e(calls.get('xml', 0))}, rest "
            f"{e(calls.get('rest', 0))}. Cache: {e(cache.get('mode', 'n/a'))}, {e(cache.get('hits', 0))} hit(s).")
    warn_html = (f'<h3>{chip("ORANGE", "Gaps in this report")}</h3><div class="tw"><table><tbody>'
                 + "".join(row(n) for n in warn) + "</tbody></table></div>") if warn else ""
    return (f'<section id="notes"><h2>About this data</h2><p class="lead">Why a value may show as '
            f'Unavailable, and how figures are measured.</p>{warn_html}'
            f'<details><summary>How figures are measured ({len(info)})</summary><div class="tw"><table><tbody>'
            + "".join(row(n) for n in info) + f'</tbody></table></div><p class="na">{coll}</p></details></section>')


def _appendix(r: AppReport) -> str:
    head = ("<tr><th>Build</th><th>Version</th><th>Published</th><th class=n>Analysis time</th>"
            "<th class=n>Size</th><th class=n>LOC</th><th class=n>Selected modules</th><th class=n>Files</th>"
            "<th>Engine</th><th>Health</th><th>Policy</th></tr>")
    body = "".join(
        f"<tr><td class=mono>{e(b.build_id)}</td><td class=name>{e(b.version)}</td><td>{e(fmt_dt(b.published))}</td>"
        f"<td class=n>{e(b.analysis_duration)}</td><td class=n>{e(fmt_mb(b.analysis_size_bytes))}</td>"
        f"<td class=n>{fmt_num(b.loc_total)}</td><td class=n>{fmt_num(b.selected_module_count)}</td>"
        f"<td class=n>{fmt_num(b.files_uploaded)}</td><td class=mono>{e(b.engine_version)}</td>"
        f"<td>{chip({'Good': 'GREEN', 'Fair': 'YELLOW', 'Poor': 'RED'}.get(b.health, 'GRAY'), b.health)}</td>"
        f"<td>{e(b.policy_compliance_status or 'Unknown')}</td></tr>" for b in r.builds)
    other = "".join(f"<tr><td class=mono>{e(o.build_id)}</td><td class=name>{e(o.version)}</td>"
                    f"<td colspan=9>{e(o.status_class)}: {e(o.status or o.info_error)}</td></tr>"
                    for o in r.other_builds)
    prow = [[e(b.build_id), e(short_date(b.published)), e(b.analysis_duration or "n/a"),
             e(fmt_mb(b.analysis_size_bytes)), e(b.health), e(b.policy_compliance_status or "Unknown")]
            for b in r.builds]
    prow += [[e(o.build_id), "", "", "", e(o.status_class), e(o.status or o.info_error or "")]
             for o in r.other_builds]
    return (f'<section id="appendix"><h2>Builds</h2><div class="tw screen-only"><table data-copy>'
            f'<thead>{head}</thead><tbody>{body}{other}</tbody></table></div>'
            + _ptable(["Build", "Published", "Analysis time", "Size", "Health", "Policy"], prow, (2, 3))
            + "</section>")


def render_html(report: AppReport, analysis: Analysis) -> str:
    """The complete report page."""
    r, an = report, analysis
    if r.latest is None:
        body = (_header(r) + '<section><h2>No published scan</h2><p class="lead">There is nothing to '
                'evaluate in this context yet. See the data notes.</p></section>' + _notes(r) + _appendix(r))
    else:
        body = _header(r) + _verdicts(an) + _actions(an) + _chapters(r, an)
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"{csp_meta(PDF_SCRIPT)}"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>{e(_title(r))}</title><style>{CSS}{PRINT_CSS}</style></head><body><main>"
            f"{pdf_button()}{body}"
            f"<footer>Generated by scan_health.py on {e(fmt_dt(r.generated, True))}. "
            "Not an official Veracode product.</footer></main>"
            f"<script>{PDF_SCRIPT}</script></body></html>")


# PDF pagination. About 55 lines of body text fit on an A4 page. Sections are grouped into chapters;
# a chapter of half a page or more starts on a new page. A section that fits on a page is kept whole.
PAGE_LINES = 55
NEW_PAGE_LINES = 26


def _print_lines(r: AppReport, an: Analysis) -> dict[str, int]:
    """Rough printed length of each section, in lines of body text."""
    b = r.latest
    fails = [c for c in (b.checks if b else []) if c.status not in ("Pass", "N/A", "Skipped")]
    chart = 14
    sca = len((b.sca_details or b.sca_components or []) if b else [])
    d = an.diffs
    return {
        "changes": 5 + (14 if d.available else 8),
        "checks": 6 + 2 * len(fails),
        "performance": (chart + 10 + len(an.duration.drivers)) if len(an.duration.points) > 1 else 6,
        "cadence": 14,
        "findings": (chart + 8 + min(len(an.findings.rows), 8)) if len(an.findings.rows) > 1 else 8,
        "composition": 5 + int(1.5 * min(len(an.modules), 15)) + (4 + min(sca, 10) if sca else 0),
        "appendix": 4 + len(r.builds) + len(r.other_builds),
        "notes": 4 + len(r.data_notes),
    }


def _chapters(r: AppReport, an: Analysis) -> str:
    lines = _print_lines(r, an)
    parts = {"changes": _changes(r, an), "checks": _checks(r, an), "performance": _performance(an),
             "cadence": _cadence(an, r), "findings": _findings(an), "composition": _composition(an, r),
             "appendix": _appendix(r), "notes": _notes(r)}
    groups = (("changes", "checks"), ("performance", "cadence"), ("findings",),
              ("composition", "appendix", "notes"))
    out = []
    for g in groups:
        present = [k for k in g if parts[k]]
        new_page = sum(lines[k] for k in present) >= NEW_PAGE_LINES
        for i, k in enumerate(present):
            cls = (["newpage"] if new_page and i == 0 else []) + (["keep"] if lines[k] < PAGE_LINES else [])
            out.append(parts[k].replace("<section ", f'<section class="{" ".join(cls)}" ', 1)
                       if cls else parts[k])
    return "".join(out)


def scope_note(r: AppReport) -> str:
    """Stated once, under the title: what every comparison in the report uses."""
    if r.parameters.get("scan") and len(r.builds) <= 1:
        return "Single scan: nothing earlier to compare with."
    if r.context.get("type") == "sandbox":
        return (f"All comparisons use only earlier scans in sandbox {r.context.get('sandbox_name') or ''} "
                "of this application; policy scans and other sandboxes are not mixed in.")
    return ("All comparisons use only earlier policy scans of this application; sandbox scans are not "
            "mixed in.")


def teams_label(a: Any) -> str:
    """Teams from the Applications REST API, minus hidden patterns."""
    if a.teams:
        return ", ".join(a.teams)
    return "None assigned" if a.guid else "Unavailable"


def _title(r: AppReport) -> str:
    """Page title, which browsers also offer as the PDF file name."""
    parts = [f"Scan health {r.app.name}"]
    if r.context.get("type") == "sandbox":
        parts.append(f"sandbox {r.context.get('sandbox_name') or ''}".strip())
    scan = r.parameters.get("scan")
    if scan and scan.get("build_id"):
        parts.append(f"build {scan['build_id']}")
    parts.append(fmt_dt(r.generated))
    return " - ".join(parts)
