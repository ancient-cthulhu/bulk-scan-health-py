"""HTML renderer for the app report. Self-contained; all values escaped."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import scan_health as sh

from . import app_report_analytics as ana
from . import report_kit as kit
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
        scope = f"{len(r.builds)} published build(s) analysed ({e(r.history_status)})"
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
        ("Teams", e(", ".join(a.teams) or (b.teams if b else None) or "Unavailable")),
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
    return (f'<header><p class="sub">Veracode scan health report</p><h1>{e(a.name)}</h1>'
            f'<p class="sub">{where} &middot; {scope}</p><div class="meta">{m}</div>'
            f'{"<p class=meta>" + lk + "</p>" if lk else ""}{partial}</header>')


def _verdicts(an: Analysis) -> str:
    cards = []
    for v in an.verdicts:
        cards.append(f'<div class="v"><div class="k">{e(v.name)}</div>'
                     f'<div class="val">{chip(v.level, v.value)}</div>'
                     f'<div class="why">{e(v.reason)}</div></div>')
    return f'<div class="verdicts">{"".join(cards)}</div>' + (
        f'<p class="disclaimer">{e(sh.DISCLAIMER)}</p>')


def _action_card(a: Any) -> str:
    ev = "".join(f"<li>{e(x)}</li>" for x in a.evidence[:8])
    fix = "".join(f"<li>{rec_html(x)}</li>" for x in a.how_to_fix) or "<li>See the check documentation.</li>"
    lk = " &middot; ".join(link(u, lbl) for lbl, u in a.links)
    rec = (f'<span class="tag">failing {a.consecutive_failing} consecutive scans</span>'
           if a.consecutive_failing > 1 else "")
    return (f'<article class="act"><header><span class="pill {e(a.priority)}">{e(a.priority)}</span>'
            f'<h3>{e(a.title)}</h3><span class="tag">{e(a.owner_role)} &middot; effort {e(a.effort)} '
            f'&middot; {e(a.category)}</span>{rec}</header>'
            f'<dl><dt>Why</dt><dd>{e(a.why)}</dd>'
            f'<dt>Evidence</dt><dd><ul>{ev}</ul></dd>'
            f'<dt>How to fix</dt><dd><ul>{fix}</ul></dd>'
            f'<dt>Verify</dt><dd>{e(a.verify)}</dd>'
            f'<dt>Expected effect</dt><dd>{e(a.expected_effect)}</dd>'
            + (f"<dt>Links</dt><dd>{lk}</dd>" if lk else "") + "</dl></article>")


def _actions(an: Analysis) -> str:
    if not an.actions:
        return ('<section id="actions"><h2>Top actions</h2><p class="lead">No actions: every '
                'measured dimension is healthy.</p></section>')
    top = "".join(_action_card(a) for a in an.actions[:5])
    rest = ""
    if len(an.actions) > 5:
        rest = (f"<details><summary>{len(an.actions) - 5} more action(s)</summary>"
                f'<div class="actions">{"".join(_action_card(a) for a in an.actions[5:])}</div></details>')
    return (f'<section id="actions"><h2>Top actions</h2><p class="lead">Ranked by impact on results '
            f'accuracy, exposure and scan time. Effort is an estimate.</p>'
            f'<div class="actions">{top}</div>{rest}</section>')


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
    rows = [
        ("Engine", f"{e(d.engine[0])} to {e(d.engine[1])}" if d.engine[0] != d.engine[1] else "Unchanged"),
        ("Policy status", f"{e(d.policy[0])} to {e(d.policy[1])}" if d.policy[0] != d.policy[1] else e(d.policy[1])),
        ("Total flaws", f"{fmt_num(d.flaws_total[0])} to {fmt_num(d.flaws_total[1])}"),
        ("Analysis size", _signed_mb(d.analysis_size_delta)),
        ("Uploaded module size (prescan)", _signed_mb(d.prescan_size_delta)),
        ("Checks now failing", ", ".join(f"#{n} {e(lab.get(n, ''))}" for n in d.checks_new) or "None"),
        ("Checks resolved", ", ".join(f"#{n} {e(lab.get(n, ''))}" for n in d.checks_resolved) or "None"),
    ]
    if d.available:
        rows += [
            ("Selected modules added", _list_or_none(d.modules_added)),
            ("Selected modules removed", _list_or_none(d.modules_removed)),
            ("New unselected first-party modules", _list_or_none(d.new_unselected_first_party)),
            ("Files added", f"{len(d.files_added):,} {_ext_counts(d.ext_added)}"),
            ("Files removed", f"{len(d.files_removed):,} {_ext_counts(d.ext_removed)}"),
            ("Files changed (same name, different MD5)", f"{len(d.files_changed):,}"),
        ]
    body = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows)
    files = ""
    if d.available and (d.files_added or d.files_removed or d.files_changed):
        files = (f"<details><summary>File names</summary><h3>Added</h3><p>{_list_or_none(d.files_added, 200)}</p>"
                 f"<h3>Removed</h3><p>{_list_or_none(d.files_removed, 200)}</p>"
                 f"<h3>Changed</h3><p>{_list_or_none(d.files_changed, 200)}</p></details>")
    return (f'<section id="changes"><h2>What changed since the previous scan</h2>'
            f'<p class="lead">Build {e(r.latest.build_id if r.latest else "")} compared with build '
            f'{e(d.previous_build)}.</p><div class="tw"><table>{body}</table></div>{files}</section>')


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
    for c in sorted(b.checks, key=lambda c: (order.get(c.status, 9),
                                             0 if c.severity == "high" else 1, c.check_num)):
        h = hist.get(c.check_num)
        trail = ""
        if h and h.statuses:
            trail = "".join(f'<span class="dotv" title="{e(bid)}: {e(st)}" style="background:var(--'
                            f'{ {"Pass": "good", "Fail": "crit"}.get(st, "unk") })"></span> '
                            for bid, st in h.statuses[-10:])
        detail = ""
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
        sev = e(c.severity.capitalize()) if c.severity else f'<span class="na">up to {e(c.max_severity)}</span>'
        row = (f"<tr><td class=n>{c.check_num}</td><td>{e(c.label)}<div class=na>{e(c.category)}</div></td>"
               f"<td>{chip(STATUS_LEVEL.get(c.status, 'GRAY'), c.status)}</td><td class=nw>{sev}</td>"
               f"<td class=nw>{e(h.lifecycle if h else 'Unknown')}</td><td class=nw>{trail}</td><td>{detail}</td></tr>")
        (quiet if c.status in ("Pass", "N/A", "Skipped") else rows).append(row)
    failing = sum(1 for c in b.checks if c.status == "Fail")
    head = ("<thead><tr><th class=n>#</th><th>Check</th><th>Status</th><th>Severity</th><th>Lifecycle</th>"
            "<th>History</th><th>Details</th></tr></thead>")
    main = (f'<div class="tw"><table>{head}<tbody>{"".join(rows)}</tbody></table></div>' if rows
            else '<p class="lead">No check is failing on this build.</p>')
    rest = (f'<details><summary>{len(quiet)} passing, not applicable or skipped checks</summary>'
            f'<div class="tw"><table>{head}<tbody>{"".join(quiet)}</tbody></table></div></details>'
            if quiet else "")
    return (f'<section id="checks"><h2>Health checks</h2><p class="lead">All 31 checks on build '
            f'{e(b.build_id)}: {failing} failing. History shows recent scans, oldest to newest '
            f'(hover a dot for the build; green pass, red fail, grey not evaluated).</p>{main}{rest}</section>')


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
                     flag_last="regression" if d.status == "Regression" else "")
    spm = line_chart("Seconds per MB analysed", labels, [p.sec_per_mb for p in d.points], tips,
                     lambda v: f"{v:,.0f}", size=HALF, unit=" s/MB")
    size = line_chart("Analysis size (MB)", labels, [p.size_mb for p in d.points], tips,
                      lambda v: f"{v:,.0f}", size=HALF, unit=" MB")
    loc = line_chart("Lines of code (thousands)", labels,
                     [p.loc / 1000 if p.loc else None for p in d.points], tips,
                     lambda v: f"{v:,.0f}", size=HALF, unit="K")
    skpl = line_chart("Seconds per thousand lines", labels, [p.sec_per_kloc for p in d.points], tips,
                      lambda v: f"{v:,.0f}", size=HALF, unit=" s")
    stats = [("Latest", sh._fmt_seconds(d.latest) if d.latest is not None else "n/a", ""),
             ("Median (p50)", sh._fmt_seconds(int(d.p50)) if d.p50 is not None else "n/a", ""),
             ("p90", sh._fmt_seconds(int(d.p90)) if d.p90 is not None else "n/a", ""),
             ("Fastest", sh._fmt_seconds(d.min or 0), f"build {d.fastest_build}"),
             ("Slowest", sh._fmt_seconds(d.max or 0), f"build {d.slowest_build}"),
             ("Trend (Theil-Sen)", f"{d.slope_min_per_scan:+.1f} min" if d.slope_min_per_scan
              is not None else "n/a", "per scan")]
    st = "".join(f'<div class="stat"><div class="k">{e(k)}</div><div class="n">{e(v)}</div>'
                 f'<div class="s">{e(sub)}</div></div>' for k, v, sub in stats)
    drivers = ("<h3>Probable drivers</h3><p class=na>Correlated changes in the latest build, largest "
               "first. Correlation, not proven cause.</p><ul>"
               + "".join(f"<li>{e(x)}</li>" for x in d.drivers) + "</ul>") if d.drivers else ""
    return (f'<section id="performance"><h2>Scan performance</h2><p class="lead">Analysis time is '
            f'submit to publish and excludes upload and prescan. Status: {chip({"Regression": "RED", "Normal": "GREEN"}.get(d.status, "GRAY"), d.status)} '
            f'{e(d.reason)}</p><div class="stats">{st}</div>{dur}'
            f'<p class="na">Shaded band: baseline median plus or minus 3 scaled MAD over the previous '
            f'{d.baseline_n} build(s). Line: regression threshold.</p>{drivers}'
            f'<h3>Normalised throughput and size</h3>'
            f'<div class="grid2"><div>{spm}</div><div>{skpl}</div></div>'
            f'<div class="grid2"><div>{size}</div><div>{loc}</div></div></section>')


def _cadence(an: Analysis, r: AppReport) -> str:
    c = an.cadence
    stats = [("Days since last scan", c.days_since_last), ("Published scans in window", c.published_count),
             ("Median interval (days)", c.median_interval_days), ("Longest interval (days)", c.max_interval_days),
             ("Scans, last 30 days", c.scans_last_30d), ("Scans, last 90 days", c.scans_last_90d)]
    st = "".join(f'<div class="stat"><div class="k">{e(k)}</div><div class="n">{fmt_num(v)}</div></div>'
                 for k, v in stats)
    tl, undated = timeline(c.attempts, c.longest_gap)
    gap = (f"Longest gap: {e(c.longest_gap[0])} to {e(c.longest_gap[1])}." if c.longest_gap else "")
    if undated:
        gap += f" {undated} attempt(s) without a date are not on the timeline (see the appendix)."
    fr = (f"Scan failure rate: {c.failure_rate:.0%} ({e(c.failure_rate_note)})."
          if c.failure_rate is not None else f"Scan failure rate: {e(c.failure_rate_note)}.")
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
                 '<span><i class="sw s3"></i>Fixed (flaw-status)</span></div>')
    score = line_chart("Veracode score", labels, [float(x.score) if x.score is not None else None for x in rows],
                       [f"build {x.build_id}, score {x.score}, rating {x.rating}" for x in rows],
                       lambda v: f"{v:,.0f}", size=HALF)
    ev = "".join(f"<li>Build {e(x['build_id'])}: {e(x['event'])}</li>" for x in an.findings.events)
    eng = f'<p class="disclaimer">{e(an.findings.engine_effect)}</p>' if an.findings.engine_effect else ""
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
    return (f'<section id="findings"><h2>Findings</h2><p class="lead">Open means neither fixed nor '
            f'covered by an accepted mitigation. Fixed counts come from the flaw-status element.</p>'
            f'<div class="grid2"><div>{legend_sev}{sev}</div><div>{legend_nf}{nf}</div></div>'
            f'<div class="grid2"><div>{score}</div><div><h3>Timeline events</h3>'
            f'<ul>{ev or "<li class=na>None</li>"}</ul></div></div>{eng}'
            f'<details><summary>Findings table</summary><div class="tw"><table><thead>{head}</thead>'
            f'<tbody>{body}</tbody></table></div></details>'
            f'<p class="na">Flaw aging (Findings API) is not included in this version.</p></section>')


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
                    f"<td>{e(m['compiler'] or m['platform'] or '')}</td><td>{iss}</td></tr>")
    more = f"<p class=na>Showing {limit} of {len(rows)} modules.</p>" if len(rows) > limit else ""
    b = r.latest
    sca = ""
    if b is not None:
        if b.sca_enabled is None:
            sca = "SCA status unavailable."
        elif not b.sca_enabled:
            sca = "SCA is not enabled for this scan."
        else:
            comps = ", ".join(f"<code>{e(c)}</code>" for c in (b.sca_components or [])[:30])
            sca = f"{b.sca_vulnerable_components or 0} vulnerable component(s)" + (f": {comps}" if comps else ".")
    return (f'<section id="composition"><h2>Composition</h2><p class="lead">Modules in the latest build, '
            f'selected first. Flaw counts are the platform\'s per-module figures (Very High / High / '
            f'Medium / Low).</p><div class="tw"><table><thead><tr><th>Module</th><th>Role</th>'
            f'<th class=n>LOC</th><th class=n>Flaws VH/H/M/L</th><th>Size</th><th>Compiler / platform</th>'
            f'<th>Prescan</th></tr></thead><tbody>{"".join(body)}</tbody></table></div>{more}'
            f'<h3>Software composition analysis</h3><p>{sca}</p></section>')


def _notes(r: AppReport) -> str:
    items = "".join(f"<tr><td>{e(n.topic)}</td><td>{chip('ORANGE' if n.level == 'warning' else 'GRAY', n.level)}</td>"
                    f"<td>{e(n.message)}</td></tr>" for n in r.data_notes)
    c = r.collection or {}
    calls = c.get("api_calls", {})
    cache = c.get("cache", {})
    coll = (f"API calls: report {e(calls.get('report', 0))}, xml {e(calls.get('xml', 0))}, rest "
            f"{e(calls.get('rest', 0))}. Cache: {e(cache.get('mode', 'n/a'))}, {e(cache.get('hits', 0))} hit(s).")
    return (f'<section id="notes"><h2>Data notes</h2><p class="lead">Sources, gaps and caveats. Any value '
            f'shown as Unavailable is explained here.</p><div class="tw"><table><tbody>{items}</tbody></table></div>'
            f'<p class="na">{coll}</p></section>')


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
    return (f'<section id="appendix"><h2>Appendix: builds</h2><div class="tw"><table><thead>{head}</thead>'
            f'<tbody>{body}{other}</tbody></table></div></section>')


def render_html(report: AppReport, analysis: Analysis) -> str:
    """The complete report page."""
    r, an = report, analysis
    if r.latest is None:
        body = (_header(r) + '<section><h2>No published scan</h2><p class="lead">There is nothing to '
                'evaluate in this context yet. See the data notes.</p></section>' + _notes(r) + _appendix(r))
    else:
        body = (_header(r) + _verdicts(an) + _actions(an) + _changes(r, an) + _checks(r, an)
                + _performance(an) + _cadence(an, r) + _findings(an) + _composition(an, r)
                + _notes(r) + _appendix(r))
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"{csp_meta(PDF_SCRIPT)}"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>{e(_title(r))}</title><style>{CSS}{PRINT_CSS}</style></head><body><main>"
            f"{pdf_button()}{body}"
            f"<footer>Generated by scan_health.py on {e(fmt_dt(r.generated, True))}. "
            "Not an official Veracode product.</footer></main>"
            f"<script>{PDF_SCRIPT}</script></body></html>")


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


# ==========================================================================
# Redesign (in progress): two-lens overview, compact actions, check matrix.
# Not yet wired into render_html; rendered by the component gallery.
# ==========================================================================


_HEALTH_LEVEL = {"Good": "GREEN", "Fair": "YELLOW", "Poor": "RED"}
_HEALTH_SAY = {"Good": "The scan is in good shape", "Fair": "The scan needs attention",
               "Poor": "The scan needs work"}


def _policy_say(status: str | None) -> str:
    lv = sh._policy_level(status or "")
    return {"GREEN": "policy is met", "YELLOW": "policy is conditionally met",
            "RED": "policy is not met"}.get(lv, "the policy outcome is unknown")


def action_views(r: AppReport, an: Analysis) -> list[kit.ActionView]:
    """The analytics action plan as compact rows, each tagged with its lens."""
    out = []
    for i, a in enumerate(an.actions):
        note = (f"failing {a.consecutive_failing} scans in a row" if a.consecutive_failing > 1 else "")
        out.append(kit.ActionView(
            priority=a.priority, title=(f"#{a.check_num} " if a.check_num else "") + a.title,
            lens=kit.action_lens(a.check_num, a.category), owner=a.owner_role, effort=a.effort,
            why=a.why, evidence=list(a.evidence), fix_html=kit.fix_html(a.how_to_fix),
            verify=a.verify, effect=("" if a.expected_effect.startswith("Not quantifiable")
                                     else a.expected_effect),
            links=list(a.links), note=note, anchor=f"action-{i + 1}"))
    return out


def _first(views: list[kit.ActionView], lens: str) -> str:
    v = next((x for x in views if x.lens == lens), None)
    return (f'<a href="#{e(v.anchor)}">{e(v.title)}</a> <span class="small">{e(v.owner)}, effort '
            f'{e(v.effort)}</span>' if v else '<span class="na">Nothing to do in this lens.</span>')


def overview(r: AppReport, an: Analysis) -> str:
    """Header, one-sentence state and the two lens panels."""
    a, b = r.app, r.latest
    if b is None:
        return _header(r)
    views = action_views(r, an)
    scan = r.parameters.get("scan")
    ctx = r.context
    where = (f"Sandbox <b>{e(ctx.get('sandbox_name'))}</b>" if ctx.get("type") == "sandbox"
             else "Policy scans")
    scope = (f"scanned build <b>{e(b.build_id)}</b>" if scan else f"latest build <b>{e(b.build_id)}</b>")
    hist = (f", {len(r.builds) - 1} earlier build(s) for trend" if len(r.builds) > 1 else "")
    meta = [("Business unit", a.business_unit), ("Policy", a.policy or b.policy_name),
            ("Business criticality", a.business_criticality or b.business_criticality),
            ("Teams", ", ".join(a.teams) or b.teams), ("Region", a.region), ("App ID", a.legacy_id)]
    ctx_line = "&emsp;".join(f"{e(k)} <b>{e(v) if v else 'Unavailable'}</b>" for k, v in meta)
    links = [link(b.overview_url, "Static Overview"), link(b.review_url, "Review Modules"),
             link(b.triage_url, "Triage Flaws")]
    links = [x for x in links if x.startswith("<a")]

    failing = [c for c in b.checks if c.status == "Fail"]
    life = {h.check_num: h.lifecycle for h in an.check_history}
    new_fail = sum(1 for c in failing if life.get(c.check_num) in ("New", "Regressed"))
    top = views[0].title if views else ""
    state = (f"{_HEALTH_SAY.get(b.health, 'Scan health is unknown')}"
             f"{f' ({len(failing)} check(s) failing)' if failing else ''} and "
             f"{_policy_say(b.policy_compliance_status)}."
             + (f" Start with {top}." if top else ""))

    # ---- scan health lens
    d, c = an.duration, an.cadence
    rows: list[kit.Result] = [kit.Result(
        "Checks failing", f"{len(failing)} of {len(b.checks)}" if b.checks_ran else "Not run",
        "none expected", f"{new_fail} new" if new_fail else ("" if not failing else "Recurring"),
        "ORANGE" if new_fail else "YELLOW")]
    if d.latest is not None:
        ref = (f"normal up to {sh._fmt_seconds(int(d.threshold))}, baseline "
               f"{sh._fmt_seconds(int(d.baseline_median or 0))}" if d.threshold else e(d.status))
        rows.append(kit.Result("Analysis time", e(sh._fmt_seconds(d.latest)), e(ref),
                               "High" if d.status == "Regression" else "",
                               "RED" if d.status == "Regression" else "GRAY"))
    if scan and b.is_latest_build is False:
        rows.append(kit.Result("Recency", "Newer scan exists", "recency is not evaluated",
                               "Not latest", "GRAY"))
    elif c.days_since_last is not None:
        stale = c.days_since_last > ana.ANALYTICS_CONFIG["stale_days"]
        rows.append(kit.Result("Last policy scan" if ctx.get("type") != "sandbox" else "Last scan",
                               f"{c.days_since_last} days ago",
                               f"within {ana.ANALYTICS_CONFIG['stale_days']} days",
                               "Stale" if stale else "", "ORANGE" if stale else "GRAY"))
    if an.diffs.engine and an.diffs.engine[0] != an.diffs.engine[1]:
        rows.append(kit.Result("Engine", e(an.diffs.engine[1]), f"was {e(an.diffs.engine[0])}",
                               "Changed", "GRAY"))
    spark_s = kit.sparkline([p.seconds / 60 for p in d.points],
                            [f"Build {p.build_id}" for p in d.points], "Analysis time",
                            lambda v: f"{v:,.0f} min") if len(d.points) > 1 else ""
    scan_panel = kit.lens_panel(
        kit.LENS_SCAN, _HEALTH_LEVEL.get(b.health, "GRAY"), b.health,
        "Whether the scan analysed the right code, efficiently and recently.", rows, spark_s,
        "Analysis time per build" if spark_s else "", _first(views, kit.LENS_SCAN))

    # ---- security posture lens
    sev = b.open_by_severity or {}
    cov = kit.result_coverage([x.check_num for x in failing], b.checks_ran,
                              {x.check_num: x.label for x in b.checks})
    fr = an.findings.rows
    prev_score = next((x.score for x in reversed(fr[:-1]) if x.score is not None), None)
    pol = b.policy_compliance_status or "Unknown"
    prows = [
        kit.Result("Policy", e(pol), e(f"{b.policy_name or 'Policy'}, rules {b.policy_rules_status or 'unknown'}"),
                   "Not met" if sh._policy_level(pol) == "RED" else "",
                   "RED"),
        kit.Result("Open Very High", fmt_num(sev.get("very_high")) if sev else "Unavailable",
                   "not fixed and not mitigated"),
        kit.Result("Open High", fmt_num(sev.get("high")) if sev else "Unavailable",
                   f"Medium {fmt_num(sev.get('medium'))}, Low {fmt_num(sev.get('low'))}" if sev else ""),
    ]
    if b.score is not None:
        delta = b.score - prev_score if prev_score is not None else None
        prows.append(kit.Result("Veracode score", fmt_num(b.score),
                                f"was {prev_score}" if prev_score is not None else "",
                                f"Down {-delta}" if delta and delta < 0 else "", "YELLOW"))
    if fr and fr[-1].new is not None:
        prows.append(kit.Result("New flaws this scan", fmt_num(fr[-1].new),
                                f"fixed {fmt_num(fr[-1].fixed)}" if fr[-1].fixed is not None else "", "", "GRAY"))
    for flag, txt in ((b.grace_period_expired, "Grace period expired"), (b.scan_overdue, "Scan overdue")):
        if flag:
            prows.append(kit.Result(txt, "Yes", "per policy", "Not met", "RED"))
    prows.append(kit.Result("Result coverage", chip(cov.level, cov.label), e(cov.reason)))
    vh = [None if x.very_high is None else (x.very_high or 0) + (x.high or 0) for x in fr]
    spark_p = kit.sparkline(vh, [f"Build {x.build_id}" for x in fr], "Open Very High and High",
                            lambda v: f"{v:,.0f}") if len(fr) > 1 else ""
    posture_panel = kit.lens_panel(
        kit.LENS_POSTURE, sh._policy_level(pol), pol,
        "What the scan found and whether it meets policy.", prows, spark_p,
        "Open Very High and High per build" if spark_p else "", _first(views, kit.LENS_POSTURE))

    lk = f'<p class="links">{"".join(links)}</p>' if links else ""
    partial = ('<p class="small">This report is partial: collection did not finish.</p>'
               if not r.complete else "")
    return (f'<header><h1>{e(a.name)}</h1><p class="ctx">{where}, {scope}{hist}</p>'
            f'<p class="ctx">{ctx_line}</p>{lk}<p class="state">{e(state)}</p>{partial}</header>'
            f'<div class="lenses">{scan_panel}{posture_panel}</div>')


def matrix(r: AppReport, an: Analysis, max_builds: int = 10) -> str:
    """Checks by builds: failing or changed checks, passing ones summarised."""
    b = r.latest
    if b is None or not an.check_history:
        return ""
    builds = [bid for bid, _ in an.check_history[0].statuses][-max_builds:]
    by = {c.check_num: c for c in b.checks}
    order = {"Fail": 0, "Error": 1, "Unavailable": 2, "Not run": 2}
    rows, quiet = [], 0
    for h in sorted(an.check_history, key=lambda h: (order.get(by[h.check_num].status, 5)
                                                     if h.check_num in by else 9, h.check_num)):
        st = dict(h.statuses)
        cells = [st.get(x, "") for x in builds]
        c = by.get(h.check_num)
        if "Fail" not in cells:
            quiet += 1
            continue
        detail = ""
        if c is not None and c.status == "Fail":
            ev = "".join(f"<li><code>{e(x)}</code></li>" for x in c.evidence[:10])
            detail = ("".join(f"<p>{e(i)}</p>" for i in c.issues)
                      + (f"<ul>{ev}</ul>" if ev else "")
                      + "".join(f"<p>{rec_html(x)}</p>" for x in c.recommendations))
        rows.append(kit.MatrixRow(h.check_num, h.label, c.category if c else "", cells,
                                  h.lifecycle, (c.severity.title() if c and c.severity else ""), detail))
    body = kit.check_matrix(builds, rows, "Checks that failed on any analysed build, oldest build "
                            "on the left. The other checks passed or did not apply.")
    return body + (f'<p class="small">{quiet} check(s) passed or did not apply on every analysed build.</p>'
                   if quiet else "")
