"""HTML renderer for the tenant report."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any
from urllib.parse import quote

import scan_health as sh

from . import app_report_analytics as ana
from . import report_kit as kit
from . import tenant_analytics as ta
from .report_ui import (
    FULL,
    HALF,
    chip,
    e,
    fmt_dt,
    fmt_num,
    hbars,
    line_chart,
    link,
    mix_bar,
    multi_line_chart,
    rec_html,
    short_date,
    stacked_columns,
)

STATIC_ROWS = 500
_BAND_LEVEL = {b[2]: b[3] for b in sh.DASHBOARD_CONFIG["attention_bands"]}
HEALTH_LEVEL = {"Good": "GREEN", "Fair": "YELLOW", "Poor": "RED"}
SEV_LEVEL = {"HIGH": "ORANGE", "MEDIUM": "YELLOW", "LOW": "GRAY"}
_HOST = {"commercial": "https://analysiscenter.veracode.com",
         "eu": "https://analysiscenter.veracode.eu"}
_KPI_TILES = [("profiles", "Profiles", 0), ("good", "Good", 1), ("poor", "Poor", -1),
              ("stale", "Stale", -1), ("policy_pass_pct", "Policy pass %", 1),
              ("apps_with_open_vh", "Apps with open Very High", -1), ("open_vh", "Open Very High", -1),
              ("never_scanned", "Never scanned", -1), ("errors", "Errors", -1)]


def platform_base(region: str, tenant_key: str) -> str:
    """Prefix of an application's platform link, or "" when unknown."""
    host = _HOST.get(region)
    if not host or not tenant_key.isdigit():
        return ""
    return f"{host}/auth/index.jsp#HomeAppProfile:{tenant_key}:"


def _app_url(base: str, app_id: Any) -> str | None:
    if base and isinstance(app_id, int) and app_id > 0:
        return f"{base}{app_id}"
    return None


def _app_cell(ref: dict[str, Any], base: str) -> str:
    return link(_app_url(base, ref.get("app_id")), str(ref.get("name") or ""))


def _hchip(health: Any) -> str:
    h = str(health or "Unknown")
    return chip(HEALTH_LEVEL.get(h, "GRAY"), h)


def _pct(v: float | None) -> str:
    return '<span class="na">n/a</span>' if v is None else f"{v:g}%"


def _delta(v: float | int | None, direction: int, suffix: str = "") -> str:
    """Signed change with its meaning in words, not colour alone."""
    if v is None:
        return '<span class="flat">n/a</span>'
    if not v:
        return '<span class="flat">no change</span>'
    txt = f"{v:+,g}{suffix}" if isinstance(v, float) else f"{v:+,}{suffix}"
    if direction == 0:
        return f'<span class="flat">{e(txt)}</span>'
    good = (v > 0) == (direction > 0)
    cls, word, arrow = ("better", "better", "&#9650;" if v > 0 else "&#9660;") if good else \
        ("worse", "worse", "&#9650;" if v > 0 else "&#9660;")
    return f'<span class="{cls}">{arrow} {e(txt)} <span class="small">{word}</span></span>'


def _dur(secs: Any) -> str:
    return '<span class="na">n/a</span>' if secs is None else e(sh._hms(float(secs)))


def _mib(v: Any) -> str:
    return '<span class="na">n/a</span>' if v is None else f"{float(v):,.1f} MiB"


def _cmd(ref: dict[str, Any]) -> str:
    aid = ref.get("app_id")
    if not isinstance(aid, int) or aid <= 0:
        return '<span class="na">n/a</span>'
    return (f'<span class="cmd" title="python scan_health.py --app-id {aid}">'
            f'scan_health.py --app-id {aid}</span>')


def _dual(bu_html: str, team_html: str, inline: bool = True) -> str:
    """Both groupings; the Group by switch shows one (business unit unless Team is chosen)."""
    t = "span" if inline else "div"
    return f'<{t} class="by-bu">{bu_html}</{t}><{t} class="by-team">{team_html}</{t}>'


def _group_cell(r: dict[str, Any]) -> str:
    teams = r.get("teams") or [ta.NO_TEAM]
    return _dual(e(r.get("bu")), e(", ".join(teams)))


GROUP_HEAD = _dual("Business unit", "Team")


def _ref_table(refs: list[dict[str, Any]], base: str, extra: list[tuple[str, Any]],
               more: int = 0) -> str:
    """Compact table of app references with extra columns (header, render)."""
    if not refs:
        return '<p class="na">None.</p>'
    head = f"<tr><th>Application</th><th>{GROUP_HEAD}</th>" + "".join(
        f'<th{" class=n" if h.endswith(" ") else ""}>{e(h.strip())}</th>' for h, _ in extra) + "</tr>"
    body = "".join(
        f"<tr><td class=name>{_app_cell(r, base)}</td><td class=name>{_group_cell(r)}</td>"
        + "".join(f'<td{" class=n" if h.endswith(" ") else ""}>{fn(r)}</td>' for h, fn in extra)
        + "</tr>" for r in refs)
    tail = f'<p class="small">and {more:,} more.</p>' if more > 0 else ""
    return f'<div class="tw"><table><thead>{head}</thead><tbody>{body}</tbody></table></div>{tail}'


def _section(id_: str, title: str, lead: str, body: str, lens: str | None = None,
             title_html: str | None = None) -> str:
    """One report section; lead (and title_html, when given) is safe HTML."""
    glyph = kit._GLYPH[lens] if lens else ""
    lp = f'<p class="lead">{lead}</p>' if lead else ""
    return (f'<section class="part" id="{e(id_)}"><header><h2>{glyph}{title_html or e(title)}</h2></header>'
            f'{lp}{body}</section>')


def _changes(rep: ta.TenantReport, base: str) -> str:
    mv = rep.movement
    k = rep.kpis
    if mv is None:
        tiles = "".join(f'<div class="kpi"><div class="k">{e(lab)}</div>'
                        f'<div class="n">{_kpi_val(key, k.get(key))}</div></div>'
                        for key, lab, _ in _KPI_TILES)
        return _section("changes", "What changed since the last run",
                        "This is the first comparable run, so there is nothing to compare yet. "
                        "Run the same command again (weekly works well) and this section will show "
                        "what moved.", f'<div class="kpis">{tiles}</div>')
    d = mv["kpi_deltas"]
    tiles = "".join(
        f'<div class="kpi"><div class="k">{e(lab)}</div><div class="n">{_kpi_val(key, k.get(key))}</div>'
        f'<div class="d">{_delta(d.get(key), sgn, " pp" if key.endswith("_pct") else "")}</div></div>'
        for key, lab, sgn in _KPI_TILES)
    c = mv["counts"]

    def block(key: str, title: str, lead: str, cols: list[tuple[str, Any]]) -> str:
        n = c[key]
        body = _ref_table(mv[key], base, cols, n - len(mv[key])) if n else '<p class="na">None.</p>'
        op = " open" if key == "degraded" and n else ""
        return (f'<details{op}><summary>{e(title)} ({n:,})</summary>'
                f'<p class="small">{e(lead)}</p>{body}</details>')

    reasons = ("What changed", lambda r: e("; ".join(r.get("reasons") or []))
               + (f' <span class="small">(also better: {e("; ".join(r["also_better"]))})</span>'
                  if r.get("also_better") else ""))
    att = ("Attention change ", lambda r: _delta(r.get("attention_delta"), -1))
    lists = "".join([
        block("degraded", "Degraded", "Health worse, more high-severity check failures, policy "
              "now Did Not Pass, or more open Very High.", [reasons, att]),
        block("improved", "Improved", "Better on those measures, and worse on none.", [reasons, att]),
        block("new_apps", "New profiles", "Present now, not in the baseline.",
              [("Health", lambda r: _hchip(r.get("health")))]),
        block("newly_scanned", "Newly scanned", "First published scan since the baseline.",
              [("Health", lambda r: _hchip(r.get("health")))]),
        block("newly_stale", "Newly stale", f"Last scan crossed {ta.TENANT_CONFIG['stale_days']} "
              "days since the baseline.", [("Scan age ", lambda r: f"{fmt_num(r.get('scan_age_days'))} d")]),
        block("renamed", "Renamed", "Same profile (matched by GUID), new name.",
              [("Previous name", lambda r: e(r.get("previous_name")))]),
        block("no_longer_listed", "No longer listed", "In the baseline, not in this run: deleted, "
              "renamed out of the name filter, or access removed. Not counted as fixed.",
              [("Health then", lambda r: _hchip(r.get("health")))]),
    ])
    lead = (f"Compared with the run of {e(fmt_dt(mv['baseline'], True))}. "
            f"{mv['rescanned']:,} profile(s) were rescanned in between.")
    return _section("changes", "What changed since the last run", lead,
                    f'<div class="kpis">{tiles}</div><div class="moves">{lists}</div>')


def _kpi_val(key: str, v: Any) -> str:
    return _pct(v) if key.endswith("_pct") else fmt_num(v)


def _trends(rep: ta.TenantReport) -> str:
    s = rep.series
    if len(s) < 2:
        return _section("trends", "Trends", "Trends start from the next comparable run. Each bulk "
                        "run saves a small snapshot; charts appear once there are two.", "")
    labels = [short_date(p["generated"]) for p in s]
    tips = [fmt_dt(p["generated"], True) + ("" if p["complete"] else " (partial run)") for p in s]

    def ser(k: str) -> list[float | None]:
        return [p.get(k) for p in s]

    def ints(k: str) -> list[int | None]:
        return [p.get(k) for p in s]

    mix = stacked_columns("Profiles by scan health", labels,
                          [("Good", "hg", ints("good")), ("Fair", "hf", ints("fair")),
                           ("Poor", "hp", ints("poor")), ("Unknown", "hu", ints("unknown"))],
                          tips, FULL)
    legend = ('<div class="legend"><span><i class="sw hg"></i>Good</span><span><i class="sw hf"></i>'
              'Fair</span><span><i class="sw hp"></i>Poor</span><span><i class="sw hu"></i>Unknown</span></div>')
    vh = multi_line_chart("Open flaws", labels, [("Very High", "s2", ser("open_vh")),
                                                 ("High", "s1", ser("open_h"))],
                          tips, lambda v: f"{v:,.0f}", HALF)
    vh_legend = ('<div class="legend"><span><i class="sw s2"></i>Very High</span>'
                 '<span><i class="sw s1"></i>High</span></div>')
    charts = [
        f"<div>{vh_legend}{vh}</div>",
        line_chart("Policy pass rate (%)", labels, ser("policy_pass_pct"), tips,
                   lambda v: f"{v:,.0f}", HALF, unit="%"),
        line_chart(f"Stale profiles (scan over {ta.TENANT_CONFIG['stale_days']} days)", labels,
                   ser("stale"), tips, lambda v: f"{v:,.0f}", HALF),
        line_chart("Profiles in scope", labels, ser("profiles"), tips, lambda v: f"{v:,.0f}", HALF),
    ]
    movers = ""
    if rep.movement and rep.movement["checks"]:
        top = rep.movement["checks"][:8]
        hdr = "".join(f"<th class=n>{e(lab)}</th>" for lab in labels)
        rows = "".join(
            f"<tr><td>#{e(c['check'])} {e(c['label'])}</td>"
            + "".join(f"<td class=n>{fmt_num(p['checks'].get(str(c['check'])))}</td>" for p in s)
            + f"<td>{_delta(c['delta'], -1)}</td></tr>" for c in top)
        movers = (f'<h3>Checks that moved most since the last run</h3><div class="tw"><table><thead>'
                  f'<tr><th>Check</th>{hdr}<th>Change</th></tr></thead><tbody>{rows}</tbody></table></div>')
    partial = sum(1 for p in s if not p["complete"])
    note = (f" {partial} partial run(s) are included; hover a point to see which." if partial else "")
    return _section("trends", "Trends",
                    f"{len(s)} comparable runs, oldest to newest.{note}",
                    f"{legend}{mix}<div class=cols2>{''.join(charts)}</div>{movers}")


def _checks(rep: ta.TenantReport, base: str) -> str:
    hit = sorted((c for c in rep.checks if c["apps"]), key=lambda c: (-c["apps"], c["check"]))
    top_share = max((c["share"] or 0 for c in hit), default=0) or 1
    zero = [c for c in rep.checks if not c["apps"]]
    rows = []
    for c in hit:
        names = "".join(f"<li>{_app_cell(r, base)} <span class=small>{e(r['bu'])}</span></li>"
                        for r in c["affected"])
        more = f'<li class="na">and {c["affected_more"]:,} more</li>' if c["affected_more"] else ""
        bus = ", ".join(f"{b['bu']} ({b['apps']})" for b in c["top_bus"])
        tms = ", ".join(f"{b['bu']} ({b['apps']})" for b in c.get("top_teams") or [])
        rec = (f"<p>{rec_html(c['recommendation'])}</p>" if c["recommendation"] else "")
        share = 100.0 * (c["share"] or 0) / top_share
        rows.append(
            f"<tr><td class=n>{e(c['check'])}</td><td class=name>{e(c['label'])}"
            f"<div class=small>{e(c['category'])} &middot; {e(c['owner'])}</div></td>"
            f"<td>{chip(SEV_LEVEL.get(c['severity'], 'GRAY'), c['severity'].title())}</td>"
            f"<td class=n>{kit.filter_link(fmt_num(c['apps']), 'fix', 'check=' + str(c['check']), 'Show in the fix list')}</td>"
            f'<td><span class="share"><span class="bar"><i style="width:{min(share, 100):.1f}%"></i></span>'
            f"{_pct(c['share'])}</span></td><td class=nw>{_delta(c['delta'], -1)}</td>"
            f"<td class=name>{_dual(e(bus), e(tms))}</td>"
            f"<td class=nw><details><summary>{c['apps']:,} apps</summary>{rec}<ul>{names}{more}</ul></details></td></tr>")
    table = ('<div class="tw"><table><thead><tr><th class=n>#</th><th>Check</th><th>Severity</th>'
             '<th class=n>Apps</th><th>Share</th><th>Change</th><th>{_dual("Top business units", "Top teams")}</th>'
             f'<th>Affected</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>')
    if not hit:
        table = '<p class="na">No health check fails on any profile.</p>'
    z = ""
    if zero:
        z = (f"<details><summary>{len(zero)} check(s) fail on no profile</summary><p>"
             + ", ".join(f"#{c['check']} {e(c['label'])}" for c in zero) + "</p></details>")
    return _section("checks", "Health checks across the tenant",
                    "Each of the 31 checks: how many profiles fail it, the trend, and where. "
                    "Severity is the highest seen across profiles.", table + z)


_TABLE_SCRIPT = r"""(function () {
  "use strict";
  function $(id) { return document.getElementById(id); }
  function load(id) {
    var n = $(id);
    if (!n) { return null; }
    try { return JSON.parse(n.textContent); } catch (err) { return null; }
  }
  var A = load("apps-data"), F = load("fix-data");
  if (!A || !Array.isArray(A.cols) || !Array.isArray(A.rows)) { return; }
  var FRAG = /^[A-Za-z]{1,40}:[0-9:]{1,80}$/;
  var DOCS = /https:\/\/docs\.veracode\.com\/[A-Za-z0-9_\-\/.#?=&%]*[A-Za-z0-9_\-\/#=&%]/;
  var BASE = (typeof A.base === "string" &&
    /^https:\/\/analysiscenter\.veracode\.(com|eu)\/auth\/index\.jsp#HomeAppProfile:\d+:$/.test(A.base)) ? A.base : "";
  var LV = { GREEN: ["ok", "\u2713"], YELLOW: ["warn", "!"], ORANGE: ["serious", "!"],
             RED: ["crit", "\u2715"], GRAY: ["unknown", "?"] };
  var HL = { Good: "GREEN", Fair: "YELLOW", Poor: "RED" };
  var RANK = { health: { Good: 0, Fair: 1, Poor: 2, Unknown: 3 }, pri: { P1: 0, P2: 1, P3: 2 },
               sev: { HIGH: 0, MEDIUM: 1, LOW: 2 }, cov: { "At risk": 0, Partial: 1, Complete: 2, Unknown: 3 } };
  var CHG = { Degraded: "RED", Improved: "GREEN", New: "GRAY", "Newly scanned": "GRAY", "Newly stale": "YELLOW" };
  var QL = { Immediate: "RED", Review: "ORANGE", Attention: "YELLOW", Monitor: "GREEN" };
  var CL = { "At risk": "ORANGE", Partial: "YELLOW", Complete: "GREEN" };
  var SL = { HIGH: "ORANGE", MEDIUM: "YELLOW", LOW: "GRAY" };

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) { n.className = cls; }
    if (text !== undefined && text !== null) { n.textContent = String(text); }
    return n;
  }
  function chip(level, text) {
    var l = LV[level] || LV.GRAY, s = el("span", "chip " + l[0]), i = el("span", "ic", l[1]);
    i.setAttribute("aria-hidden", "true");
    s.appendChild(i);
    s.appendChild(document.createTextNode(String(text)));
    return s;
  }
  function num(v) { return (v === null || v === undefined) ? "n/a" : Number(v).toLocaleString("en-US"); }
  function cell(tr, content, cls) {
    var td = el("td", cls || null);
    if (content instanceof Node) { td.appendChild(content); } else { td.textContent = content; }
    tr.appendChild(td);
    return td;
  }
  function options(sel, values) {
    values.forEach(function (v) {
      var o = el("option", null, Array.isArray(v) ? v[1] : v);
      o.value = Array.isArray(v) ? v[0] : v;
      sel.appendChild(o);
    });
  }
  function has(sel, v) {
    return Array.prototype.some.call(sel.options, function (o) { return o.value === v; });
  }

  var AC = {};
  A.cols.forEach(function (c, i) { AC[c] = i; });
  var APPS = A.rows;
  APPS.forEach(function (r, i) { r.__i = i; });
  var PAGE = BASE ? BASE.slice(0, BASE.indexOf("#") + 1) : "";
  function platformUrl(r) {
    var f = r[AC.url];
    return (PAGE && typeof f === "string" && FRAG.test(f)) ? PAGE + f : "";
  }

  function appLink(r) {
    var url = platformUrl(r), id = r[AC.id], a;
    if (url) {
      a = el("a", null, r[AC.name]);
      a.href = url;
    } else if (BASE && typeof id === "number" && id > 0 && Math.floor(id) === id) {
      a = el("a", null, r[AC.name]);
      a.href = BASE + String(id);
    } else { return el("span", null, r[AC.name]); }
    a.rel = "noopener noreferrer";
    return a;
  }
  function teamsOf(app) { return Array.isArray(app[AC.tm]) ? app[AC.tm] : []; }
  function teamText(app) { var t = teamsOf(app); return t.length ? t.join(", ") : "No team"; }
  function command(r) {
    var id = r[AC.id];
    return (typeof id === "number" && id > 0) ? "scan_health.py --app-id " + id : "";
  }

  function Table(o) {
    var t = { page: 0, size: 25, col: o.col, dir: o.dir, view: o.rows.slice() };
    var timer = null;
    function cmp(a, b) {
      var x = o.val(a, t.col), y = o.val(b, t.col);
      var xn = (x === null || x === undefined || x === ""), yn = (y === null || y === undefined || y === "");
      if (xn || yn) { return xn === yn ? a.__i - b.__i : (xn ? 1 : -1); }
      if (typeof x === "string") { x = x.toLowerCase(); y = String(y).toLowerCase(); }
      return (x < y ? -1 : x > y ? 1 : a.__i - b.__i) * t.dir;
    }
    t.apply = function () {
      var q = o.q.value.trim().toLowerCase();
      t.view = o.rows.filter(function (r) { return o.keep(r, q); });
      t.view.sort(cmp);
      t.page = 0;
      t.draw();
    };
    t.draw = function () {
      var start = t.page * t.size, frag = document.createDocumentFragment();
      t.view.slice(start, start + t.size).forEach(function (r) { frag.appendChild(o.row(r)); });
      o.body.replaceChildren(frag);
      var total = t.view.length, last = Math.min(start + t.size, total);
      o.info.textContent = total ? ("Showing " + num(start + 1) + " to " + num(last) + " of " + num(total) +
        " matching (" + num(o.rows.length) + " in total)") : "Nothing matches these filters.";
      o.prev.disabled = t.page === 0;
      o.next.disabled = last >= total;
      if (o.after) { o.after(t); }
    };
    o.q.addEventListener("input", function () { clearTimeout(timer); timer = setTimeout(t.apply, 150); });
    o.filters.forEach(function (f) { f.addEventListener("change", t.apply); });
    o.prev.addEventListener("click", function () { if (t.page > 0) { t.page -= 1; t.draw(); } });
    o.next.addEventListener("click", function () {
      if ((t.page + 1) * t.size < t.view.length) { t.page += 1; t.draw(); }
    });
    o.sizeSel.addEventListener("change", function () {
      var n = parseInt(o.sizeSel.value, 10);
      if (n === 25 || n === 50 || n === 100 || n === 250) { t.size = n; t.page = 0; t.draw(); }
    });
    var heads = o.root.querySelectorAll("th[data-col]");
    Array.prototype.forEach.call(heads, function (th) {
      th.querySelector("button").addEventListener("click", function () {
        var col = th.getAttribute("data-col");
        if (t.col === col) { t.dir = -t.dir; } else { t.col = col; t.dir = o.asc.indexOf(col) >= 0 ? 1 : -1; }
        Array.prototype.forEach.call(heads, function (h) { h.removeAttribute("aria-sort"); });
        th.setAttribute("aria-sort", t.dir > 0 ? "ascending" : "descending");
        t.apply();
      });
    });
    o.root.classList.add("has-js");
    return t;
  }

  var fixes = null, setApp = null;
  if (F && Array.isArray(F.rows) && $("fix")) {
    var FC = {};
    F.cols.forEach(function (c, i) { FC[c] = i; });
    var CK = F.checks || {}, RECS = Array.isArray(F.recs) ? F.recs : [],
        FOUND = Array.isArray(F.found) ? F.found : [];
    var FROWS = F.rows.filter(function (r) { return APPS[r[FC.app]] && CK[r[FC.check]]; });
    FROWS.forEach(function (r, i) {
      r.__i = i;
      var app = APPS[r[FC.app]], ck = CK[r[FC.check]];
      r.__q = [app[AC.name], app[AC.bu], app[AC.sbx], teamsOf(app).join(" "), "#" + r[FC.check], ck[0],
               FOUND[r[FC.found]] || ""]
        .join("\u0001").toLowerCase();
    });
    var fq = $("x-q"), fcheck = $("x-check"), fbu = $("x-bu"), fpri = $("x-pri"), fown = $("x-team"),
        fsev = $("x-sev"), fchg = $("x-change"), fquick = $("x-quick"), fapp = $("x-app"), fappTxt = $("x-app-name");
    var counts = {};
    FROWS.forEach(function (r) { counts[r[FC.check]] = (counts[r[FC.check]] || 0) + 1; });
    options(fcheck, Object.keys(counts).map(Number).sort(function (a, b) { return counts[b] - counts[a]; })
      .map(function (c) { return [String(c), "#" + c + " " + CK[c][0] + " (" + num(counts[c]) + ")"]; }));
    var bus = {}, teams = {}, noTeam = false;
    FROWS.forEach(function (r) {
      var app = APPS[r[FC.app]], t = teamsOf(app);
      bus[app[AC.bu]] = 1;
      if (!t.length) { noTeam = true; }
      t.forEach(function (x) { teams[x] = 1; });
    });
    options(fbu, Object.keys(bus).sort(function (a, b) { return a.localeCompare(b); }));
    options(fown, Object.keys(teams).sort(function (a, b) { return a.localeCompare(b); }));
    if (noTeam) { options(fown, [["__no_team__", "No team"]]); }
    var appIx = -1;
    setApp = function (v) {
      var i = parseInt(v, 10);
      appIx = (String(i) === String(v) && APPS[i]) ? i : -1;
      fapp.hidden = appIx < 0;
      fappTxt.textContent = appIx >= 0 ? APPS[appIx][AC.name] : "";
    };
    $("x-app-clear").addEventListener("click", function () { setApp(""); fixes.apply(); });
    function docsLink(text) {
      var p = el("p"), m = DOCS.exec(text || "");
      if (!m) { p.textContent = text || ""; return p; }
      p.appendChild(document.createTextNode(text.slice(0, m.index)));
      var a = el("a", null, m[0]);
      a.href = m[0];
      a.rel = "noopener noreferrer";
      p.appendChild(a);
      p.appendChild(document.createTextNode(text.slice(m.index + m[0].length)));
      return p;
    }
    fixes = Table({
      root: $("fix"), rows: FROWS, body: $("x-body"), info: $("x-info"), prev: $("x-prev"),
      next: $("x-next"), sizeSel: $("x-size"), q: fq, col: "pri", dir: 1, asc: ["pri", "app", "bu", "check", "sev"],
      filters: [fcheck, fbu, fpri, fown, fsev, fchg, fquick],
      val: function (r, col) {
        var app = APPS[r[FC.app]];
        if (col === "pri") { return RANK.pri[r[FC.pri]] * 10 + (RANK.sev[r[FC.sev]] || 0); }
        if (col === "app") { return app[AC.name]; }
        if (col === "bu") { return app[AC.bu]; }
        if (col === "check") { return r[FC.check]; }
        if (col === "sev") { return RANK.sev[r[FC.sev]]; }
        if (col === "att") { return app[AC.att]; }
        return "";
      },
      keep: function (r, q) {
        var app = APPS[r[FC.app]], ck = CK[r[FC.check]];
        if (q && r.__q.indexOf(q) < 0) { return false; }
        if (appIx >= 0 && r[FC.app] !== appIx) { return false; }
        if (fcheck.value && String(r[FC.check]) !== fcheck.value) { return false; }
        if (fbu.value && app[AC.bu] !== fbu.value) { return false; }
        if (fpri.value && r[FC.pri] !== fpri.value) { return false; }
        if (fown.value === "__no_team__" && teamsOf(app).length) { return false; }
        if (fown.value && fown.value !== "__no_team__" && teamsOf(app).indexOf(fown.value) < 0) { return false; }
        if (fsev.value && r[FC.sev] !== fsev.value) { return false; }
        if (fchg.value && (r[FC.chg] || "") !== fchg.value) { return false; }
        if (fquick.checked && ck[2] !== "S") { return false; }
        return true;
      },
      row: function (r) {
        var app = APPS[r[FC.app]], ck = CK[r[FC.check]], tr = el("tr");
        cell(tr, el("span", "pri " + r[FC.pri], r[FC.pri]));
        var a = el("td", "name");
        a.appendChild(appLink(app));
        a.appendChild(el("div", "small", app[AC.bu] + (app[AC.sbx] ? ", sandbox " + app[AC.sbx] : "")));
        tr.appendChild(a);
        var c = el("td", "name");
        c.appendChild(el("div", null, "#" + r[FC.check] + " " + ck[0]));
        var meta = el("div", "small");
        meta.appendChild(chip(SL[r[FC.sev]] || "GRAY", (r[FC.sev] || "").charAt(0) + (r[FC.sev] || "").slice(1).toLowerCase()));
        c.appendChild(meta);
        tr.appendChild(c);
        var found = FOUND[r[FC.found]] || "";
        var f = el("td", "found", found || "See the check details in the platform.");
        if (found) { f.title = found; }
        tr.appendChild(f);
        var o = el("td", "name");
        o.appendChild(el("div", teamsOf(app).length ? null : "na", teamText(app)));
        o.appendChild(el("div", "small", "Effort " + ck[2] + (ck[2] === "S" ? ", quick win" : "")));
        tr.appendChild(o);
        cell(tr, r[FC.chg] === "New" ? chip("YELLOW", "New") : (r[FC.chg] || ""), "small");
        var d = el("details"), s = el("summary", null, "How to fix");
        d.appendChild(s);
        d.appendChild(docsLink(RECS[r[FC.rec]] || ""));
        var cmd = command(app);
        if (cmd) {
          var p = el("p", "small", "Deep dive: ");
          p.appendChild(el("span", "cmd", cmd));
          d.appendChild(p);
        }
        cell(tr, d);
        return tr;
      }
    });
    $("x-csv").addEventListener("click", function () {
      function safe(v) {
        var s = (v === null || v === undefined) ? "" : String(v);
        if (/^[=+\-@\t\r]/.test(s)) { s = "'" + s; }
        return '"' + s.replace(/"/g, '""') + '"';
      }
      var lines = [["Priority", "Application", "Business unit", "Sandbox", "Check", "Severity", "Found",
                    "Team", "Effort", "Change", "How to fix", "Platform link", "Deep dive"].map(safe).join(",")];
      fixes.view.forEach(function (r) {
        var app = APPS[r[FC.app]], ck = CK[r[FC.check]];
        lines.push([r[FC.pri], app[AC.name], app[AC.bu], app[AC.sbx], "#" + r[FC.check] + " " + ck[0],
                    r[FC.sev], FOUND[r[FC.found]] || "", teamsOf(app).join("; "), ck[2], r[FC.chg],
                    RECS[r[FC.rec]] || "",
                    platformUrl(app), command(app)].map(safe).join(","));
      });
      var blob = new Blob(["\ufeff" + lines.join("\r\n") + "\r\n"], { type: "text/csv;charset=utf-8" });
      var a = el("a");
      a.href = URL.createObjectURL(blob);
      a.download = "scan_health_fix_list.csv";
      document.body.appendChild(a);
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
    });
  }

  var aq = $("f-q"), abu = $("f-bu"), ateam = $("f-team"), ah = $("f-health"), ap = $("f-policy"), ab = $("f-band"),
      ac = $("f-change"), as = $("f-stale"), aquad = $("f-quad"), acov = $("f-cov");
  var seen = {};
  APPS.forEach(function (r) { seen[r[AC.bu]] = true; });
  options(abu, Object.keys(seen).sort(function (a, b) { return a.localeCompare(b); }));
  var aseenT = {}, anoT = false;
  APPS.forEach(function (r) { var t = teamsOf(r); if (!t.length) { anoT = true; } t.forEach(function (x) { aseenT[x] = 1; }); });
  options(ateam, Object.keys(aseenT).sort(function (a, b) { return a.localeCompare(b); }));
  if (anoT) { options(ateam, [["__no_team__", "No team"]]); }
  APPS.forEach(function (r) {
    r.__q = [r[AC.name], r[AC.bu], r[AC.sbx], r[AC.top] || "", teamsOf(r).join(" ")].join("\u0001").toLowerCase();
  });
  var apps = Table({
    root: $("apps"), rows: APPS, body: $("apps-body"), info: $("apps-info"), prev: $("apps-prev"),
    next: $("apps-next"), sizeSel: $("apps-size"), q: aq, col: "att", dir: -1,
    asc: ["name", "bu", "pol", "top", "health", "cov", "quad"],
    filters: [abu, ateam, ah, ap, ab, ac, as, aquad, acov],
    val: function (r, col) {
      if (col === "health") { return RANK.health[r[AC.health]]; }
      if (col === "cov") { return RANK.cov[r[AC.cov]]; }
      return r[AC[col]];
    },
    keep: function (r, q) {
      if (q && r.__q.indexOf(q) < 0) { return false; }
      if (abu.value && r[AC.bu] !== abu.value) { return false; }
      if (ateam.value === "__no_team__" && teamsOf(r).length) { return false; }
      if (ateam.value && ateam.value !== "__no_team__" && teamsOf(r).indexOf(ateam.value) < 0) { return false; }
      if (ah.value && r[AC.health] !== ah.value) { return false; }
      if (ap.value && r[AC.pl] !== ap.value) { return false; }
      if (ab.value && r[AC.band] !== ab.value) { return false; }
      if (ac.value && (r[AC.chg] || "") !== ac.value) { return false; }
      if (aquad.value && r[AC.quad] !== aquad.value) { return false; }
      if (acov.value && r[AC.cov] !== acov.value) { return false; }
      if (as.checked && !(r[AC.age] !== null && r[AC.age] > A.stale)) { return false; }
      return true;
    },
    row: function (r) {
      var tr = el("tr"), nameTd = el("td", "name");
      nameTd.appendChild(appLink(r));
      if (r[AC.sbx]) { nameTd.appendChild(el("div", "small", "Sandbox: " + r[AC.sbx])); }
      tr.appendChild(nameTd);
      var g = el("td", "name");
      g.appendChild(el("span", "by-bu", r[AC.bu]));
      g.appendChild(el("span", "by-team", teamText(r)));
      tr.appendChild(g);
      cell(tr, chip(HL[r[AC.health]] || "GRAY", r[AC.health]));
      var fx = el("td", "n");
      if (r[AC.fails] > 0 && fixes) {
        var b = el("button", "linkbtn", num(r[AC.fails]));
        b.type = "button";
        b.title = "Show this profile's fixes";
        b.addEventListener("click", function () { route("fix", "app=" + r.__i); });
        fx.appendChild(b);
      } else { fx.textContent = num(r[AC.fails]); }
      tr.appendChild(fx);
      cell(tr, r[AC.cov] ? chip(CL[r[AC.cov]] || "GRAY", r[AC.cov]) : "");
      var att = el("td", "nw");
      att.appendChild(chip(r[AC.lvl] || "GRAY", num(r[AC.att])));
      att.appendChild(el("div", "small", r[AC.band] || ""));
      tr.appendChild(att);
      cell(tr, r[AC.age] === null ? "n/a" : num(r[AC.age]) + " d", "n");
      cell(tr, r[AC.quad] ? chip(QL[r[AC.quad]] || "GRAY", r[AC.quad]) : "");
      cell(tr, r[AC.pol] || "Unknown");
      ["vh", "h"].forEach(function (k) { cell(tr, num(r[AC[k]]), "n"); });
      var ch = el("td");
      if (r[AC.chg]) {
        var c = chip(CHG[r[AC.chg]] || "GRAY", r[AC.chg]);
        if (r[AC.why]) { c.title = r[AC.why]; }
        ch.appendChild(c);
      }
      tr.appendChild(ch);
      return tr;
    }
  });

  function route(target, query) {
    var p = {};
    String(query || "").split("&").forEach(function (kv) {
      var i = kv.indexOf("=");
      if (i > 0) {
        try { p[kv.slice(0, i)] = decodeURIComponent(kv.slice(i + 1)); } catch (err) { /* ignore */ }
      }
    });
    if (target === "fix" && fixes) {
      fq.value = "";
      [[fcheck, "check"], [fbu, "bu"], [fpri, "pri"], [fown, "team"], [fsev, "sev"], [fchg, "change"]]
        .forEach(function (x) { x[0].value = (p[x[1]] !== undefined && has(x[0], p[x[1]])) ? p[x[1]] : ""; });
      fquick.checked = p.quick === "1";
      setApp(p.app || "");
      fixes.apply();
      $("fix").scrollIntoView();
    } else if (target === "apps") {
      aq.value = "";
      [[abu, "bu"], [ateam, "team"], [ah, "health"], [ap, "policy"], [ab, "band"], [ac, "change"], [aquad, "quad"], [acov, "cov"]]
        .forEach(function (x) { x[0].value = (p[x[1]] !== undefined && has(x[0], p[x[1]])) ? p[x[1]] : ""; });
      as.checked = p.stale === "1";
      apps.apply();
      $("apps").scrollIntoView();
    }
  }
  document.addEventListener("click", function (ev) {
    var a = ev.target && ev.target.closest ? ev.target.closest("a[data-filter]") : null;
    if (!a) { return; }
    var target = (a.getAttribute("href") || "").slice(1);
    if (target !== "fix" && target !== "apps") { return; }
    ev.preventDefault();
    route(target, a.getAttribute("data-filter"));
  });
  if (fixes) { fixes.apply(); }
  apps.apply();
}());"""


_APP_COLS = ["name", "bu", "sbx", "health", "att", "band", "lvl", "age", "vh", "h", "m", "l",
             "pol", "pl", "top", "chg", "why", "id", "fails", "cov", "quad", "url", "tm"]
_FIX_COLS = ["app", "check", "sev", "pri", "found", "rec", "chg"]
_FRAG_RE = re.compile(r"^[A-Za-z]{1,40}:[0-9:]{1,80}$")
FIX_STATIC_ROWS = 300
FOUND_BUDGET = 2_500_000


def json_for_script(obj: Any) -> str:
    """JSON that can sit inside a <script> block: no value can produce "</", "<!--", an HTML entity or
    a JavaScript line terminator."""
    s = json.dumps(obj, ensure_ascii=True, separators=(",", ":"))
    return s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def script_hash(script: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")


def _why(st: dict[str, Any]) -> str:
    parts = []
    if st.get("worse"):
        parts.append("Worse: " + "; ".join(st["worse"]))
    if st.get("better"):
        parts.append("Better: " + "; ".join(st["better"]))
    return ". ".join(parts)


def _coverage_label(a: dict[str, Any]) -> str:
    if not a.get("published") or a.get("status") == "Error":
        return "Unknown"
    return kit.result_coverage(a.get("failed_checks") or [], True).label


def _fragment(url: str) -> str:
    """The part after '#' of a Veracode Platform link (the page and its ids), or "" for anything else."""
    head, sep, frag = url.partition("#")
    if sep and head in {f"{h}/auth/index.jsp" for h in _HOST.values()} and _FRAG_RE.match(frag):
        return frag
    return ""


def _app_rows(rep: ta.TenantReport) -> list[list[Any]]:
    status = (rep.movement or {}).get("app_status") or {}
    out = []
    for a in rep.apps:
        st = status.get(a.get("key")) or {}
        pl = {"GREEN": "Pass", "YELLOW": "Conditional", "RED": "Did not pass"}.get(
            sh._policy_level(str(a.get("policy_status") or "")), "Unknown")
        sev = bool(a.get("sev_available"))
        out.append([
            str(a.get("name") or ""), ta._bu(a), str(a.get("sandbox") or ""),
            str(a.get("health") or "Unknown"), a.get("attention"),
            str(a.get("attention_band") or ""),
            str(a.get("attention_level") or _BAND_LEVEL.get(str(a.get("attention_band")), "GRAY")),
            ta.scan_age_days(a, rep.generated),
            a.get("open_vh") if sev else None, a.get("open_h") if sev else None,
            a.get("open_m") if sev else None, a.get("open_l") if sev else None,
            str(a.get("policy_status") or ""), pl, str(a.get("top_issue") or ""),
            str(st.get("tag") or ""), _why(st),
            a.get("app_id") if isinstance(a.get("app_id"), int) else None,
            len(a.get("failed_checks") or []), _coverage_label(a),
            str(a.get("quadrant") or ""), _fragment(rep.links.get(str(a.get("key") or ""), "")),
            [str(t) for t in a.get("teams") or []],
        ])
    return out


def _fix_data(rep: ta.TenantReport, index: dict[str, int]) -> dict[str, Any]:
    recs: list[str] = []
    rec_ix: dict[str, int] = {}
    found: list[str] = []
    found_ix: dict[str, int] = {}
    rows = []
    for f in rep.fixes:
        ai = index.get(str(f["key"]))
        if ai is None:
            continue
        r = f["recommendation"] or ""
        if r not in rec_ix:
            rec_ix[r] = len(recs)
            recs.append(r)
        fd = f["found"] or ""
        if fd not in found_ix:
            found_ix[fd] = len(found)
            found.append(fd)
        rows.append([ai, f["check"], f["severity"], f["priority"], found_ix[fd], rec_ix[r], f["change"]])
    checks = {str(n): [lab, *ana._CHECK_META.get(n, ("AppSec", "M", "Results accuracy"))]
              for n, (lab, _) in sh.CHECK_CATALOG.items()}
    # Shared budget keeps very large tenants usable; the workbook has the full text.
    total = sum(len(x) for x in found)
    if total > FOUND_BUDGET:
        cap = max(60, FOUND_BUDGET // max(len(found), 1))
        found = [x if len(x) <= cap else x[:cap - 1].rstrip() + "\u2026" for x in found]
    return {"v": 1, "cols": _FIX_COLS, "rows": rows, "recs": recs, "found": found, "checks": checks,
            "trimmed": total > FOUND_BUDGET}


def _pager(prefix: str) -> str:
    return (f'<div class="pager"><button type="button" id="{prefix}-prev">Previous</button>'
            f'<button type="button" id="{prefix}-next">Next</button><label>Rows per page '
            f'<select id="{prefix}-size"><option>25</option><option>50</option><option>100</option>'
            f'<option>250</option></select></label><span id="{prefix}-info" aria-live="polite"></span></div>')


def _fix_section(rep: ta.TenantReport, base: str, app_index: dict[str, int]) -> tuple[str, str]:
    """The fix list: every failing check on every profile, filterable, with a CSV download of the
    filtered list."""
    data = _fix_data(rep, app_index)
    n = len(data["rows"])
    tools = (
        '<div class="tools">'
        '<label>Search<input id="x-q" type="search" placeholder="Application, team, check, file name" '
        'autocomplete="off"></label>'
        '<label>Check<select id="x-check"><option value="">All checks</option></select></label>'
        '<label>Business unit<select id="x-bu"><option value="">All</option></select></label>'
        '<label>Priority<select id="x-pri"><option value="">All</option><option>P1</option>'
        '<option>P2</option><option>P3</option></select></label>'
        '<label>Team<select id="x-team"><option value="">All</option></select></label>'
        '<label>Severity<select id="x-sev"><option value="">All</option><option value="HIGH">High</option>'
        '<option value="MEDIUM">Medium</option></select></label>'
        '<label>Since last run<select id="x-change"><option value="">All</option><option>New</option>'
        '<option>Recurring</option></select></label>'
        '<label class="ck"><input id="x-quick" type="checkbox"> Quick wins only</label>'
        '</div><p class="appflt" id="x-app" hidden>Showing one profile: <b id="x-app-name"></b> '
        '<button type="button" class="linkbtn" id="x-app-clear">Show all profiles</button></p>')
    heads = [("pri", "Priority"), ("app", "Application"), ("check", "Check"), ("", "What was found"),
             ("", "Team"), ("", "Since last run"), ("", "Fix")]
    th = "".join(f'<th data-col="{k}"><button type="button">{lab}</button></th>' if k else f"<th>{lab}</th>"
                 for k, lab in heads)
    js = (f'<div class="js-only">{tools}<div class="tw"><table class="fix"><thead><tr>{th}</tr></thead>'
          f'<tbody id="x-body"></tbody></table></div>{_pager("x")}'
          '<p><button type="button" class="btn" id="x-csv">Download this list (CSV)</button> '
          '<span class="small">Exactly the rows matching the filters, ready to hand to the owner.</span></p></div>')
    static_rows = []
    for f in rep.fixes[:FIX_STATIC_ROWS]:
        ref = {"name": f["name"], "app_id": f["app_id"]}
        static_rows.append(
            f'<tr><td><span class="pri {e(f["priority"])}">{e(f["priority"])}</span></td>'
            f'<td class="name">{_app_cell(ref, base)}<div class="small">{e(f["bu"])}</div></td>'
            f'<td class="name">#{e(f["check"])} {e(f["label"])}</td>'
            f'<td class="found">{e(f["found"] or "See the check details in the platform.")}</td>'
            f'<td class="name">{e(", ".join(f.get("teams") or []) or "No team")}</td><td>{e(f["change"])}</td>'
            f'<td class="name">{rec_html(f["recommendation"]) if f["recommendation"] else ""}</td></tr>')
    shown = min(n, FIX_STATIC_ROWS)
    nojs = (f'<div class="no-js"><p class="small">Showing the {shown:,} highest-priority fixes of {n:,}. '
            'Open this file in a browser with JavaScript to filter and download the full list; the '
            'workbook has every issue.</p><div class="tw"><table class="fix"><thead><tr>'
            '<th>Priority</th><th>Application</th><th>Check</th><th>What was found</th><th>Team</th>'
            f'<th>Since last run</th><th>Fix</th></tr></thead><tbody>{"".join(static_rows)}</tbody></table></div></div>')
    lead = (f"Every failing scan health check on every profile ({n:,}), highest priority first. "
            "Filter to what you own, open the profile in the Veracode Platform, and download the list "
            "to hand it off.")
    if not n:
        body = '<p class="empty">No scan health check fails on any profile.</p>'
    else:
        body = js + nojs
    section = _section("fix", "Fix list", lead, body, kit.LENS_SCAN)
    return section, f'<script type="application/json" id="fix-data">{json_for_script(data)}</script>'


def _apps(rep: ta.TenantReport, base: str) -> tuple[str, dict[str, int]]:
    """The applications section (data block included) and the row index by key."""
    rows = _app_rows(rep)
    index = {str(a.get("key") or ""): i for i, a in enumerate(rep.apps)}
    stale = ta.TENANT_CONFIG["stale_days"]
    data = json_for_script({"v": 2, "base": base, "stale": stale, "cols": _APP_COLS, "rows": rows})
    c = {k: i for i, k in enumerate(_APP_COLS)}

    def static_row(r: list[Any]) -> str:
        url = (_HOST.get(rep.region, "") + "/auth/index.jsp#" + r[c["url"]]) if r[c["url"]] else _app_url(base, r[c["id"]])
        sbx = f'<div class=small>Sandbox: {e(r[c["sbx"]])}</div>' if r[c["sbx"]] else ""
        age = "n/a" if r[c["age"]] is None else f"{r[c['age']]:,} d"
        return (f"<tr><td class=name>{link(url, r[c['name']])}{sbx}</td><td class=name>{e(r[c['bu']])}</td>"
                f"<td>{_hchip(r[c['health']])}</td><td class=n>{fmt_num(r[c['fails']])}</td>"
                f"<td>{e(r[c['cov']])}</td><td class=nw>{chip(r[c['lvl']], fmt_num(r[c['att']]))}</td>"
                f"<td class=n>{e(age)}</td><td>{e(r[c['quad']])}</td><td>{e(r[c['pol']] or 'Unknown')}</td>"
                f"<td class=n>{fmt_num(r[c['vh']])}</td><td class=n>{fmt_num(r[c['h']])}</td>"
                f"<td>{e(r[c['chg']])}</td></tr>")

    heads = [("name", "Application", ""), ("bu", GROUP_HEAD, ""), ("health", "Scan health", ""),
             ("fails", "Failing checks", "n"), ("cov", "Coverage", ""), ("att", "Attention", ""),
             ("age", "Scan age", "n"), ("quad", "Priority box", ""), ("pol", "Policy", ""),
             ("vh", "Open VH", "n"), ("h", "Open H", "n"), ("chg", "Since last run", "")]
    th_js = "".join(f'<th data-col="{k}"{" class=n" if cls else ""}'
                    f'{" aria-sort=descending" if k == "att" else ""}><button type="button">{lab}</button></th>'
                    for k, lab, cls in heads)
    th_static = "".join(f'<th{" class=n" if cls else ""}>{lab}</th>' for _, lab, cls in heads)
    shown = min(len(rows), STATIC_ROWS)
    bands = "".join(f"<option>{e(b[2])}</option>" for b in sh.DASHBOARD_CONFIG["attention_bands"])
    quads = "".join(f"<option>{e(q)}</option>" for q, _, _ in kit.QUADRANTS) + "<option>Insufficient Data</option>"
    tools = (
        '<div class="tools">'
        '<label>Search<input id="f-q" type="search" placeholder="Name, business unit, issue" '
        'autocomplete="off"></label>'
        '<label>Business unit<select id="f-bu"><option value="">All</option></select></label>'
        '<label>Team<select id="f-team"><option value="">All</option></select></label>'
        '<label>Scan health<select id="f-health"><option value="">All</option><option>Good</option>'
        '<option>Fair</option><option>Poor</option><option>Unknown</option></select></label>'
        '<label>Coverage<select id="f-cov"><option value="">All</option><option>At risk</option>'
        '<option>Partial</option><option>Complete</option><option>Unknown</option></select></label>'
        f'<label>Priority box<select id="f-quad"><option value="">All</option>{quads}</select></label>'
        '<label>Policy<select id="f-policy"><option value="">All</option><option>Pass</option>'
        '<option>Conditional</option><option>Did not pass</option><option>Unknown</option></select></label>'
        f'<label>Attention band<select id="f-band"><option value="">All</option>{bands}</select></label>'
        '<label>Since last run<select id="f-change"><option value="">All</option>'
        '<option>Degraded</option><option>Improved</option><option>New</option>'
        '<option>Newly scanned</option><option>Newly stale</option></select></label>'
        f'<label class="ck"><input id="f-stale" type="checkbox"> Stale only (over {stale} days)</label>'
        '</div>')
    js = (f'<div class="js-only">{tools}<div class="tw"><table><thead><tr>{th_js}</tr></thead>'
          f'<tbody id="apps-body"></tbody></table></div>{_pager("apps")}</div>')
    nojs = (f'<div class="no-js"><p class="small">Showing the {shown:,} profiles needing most '
            f'attention of {len(rows):,}. Open this file in a browser with JavaScript for search, '
            'sorting and filters over every profile; the workbook has the full list.</p>'
            f'<div class="tw"><table><thead><tr>{th_static}</tr></thead><tbody>'
            f'{"".join(static_row(r) for r in rows[:STATIC_ROWS])}</tbody></table></div></div>')
    lead = (f"Every profile in scope ({len(rows):,}), both lenses side by side. Click a column to sort; "
            "click a failing-checks count to see that profile's fixes. Names open the analysed build in "
            "the Veracode Platform.")
    section = _section("apps", "Applications", lead,
                       f'{js}{nojs}<script type="application/json" id="apps-data">{data}</script>')
    return section, index


def _group_table(rep: ta.TenantReport, bus: list[dict[str, Any]], head: str, noun: str) -> str:
    cap = 150
    labels = [short_date(p["generated"]) for p in rep.series]
    rows = "".join(
        f"<tr><td class=name>{e(b['bu'])}</td><td class=n>{fmt_num(b['apps'])}</td>"
        f"<td>{mix_bar([('hg', b['good'], 'Good'), ('hf', b['fair'], 'Fair'), ('hp', b['poor'], 'Poor'), ('hu', b['unknown'], 'Unknown')])}</td>"
        f"<td class=n>{_pct(b['poor_share'])}</td><td>{_delta(b['poor_share_delta'], -1, ' pp')}</td>"
        f"<td class=n>{_pct(b['policy_pass_pct'])}</td><td class=n>{fmt_num(b['open_vh'])}</td>"
        f"<td>{_delta(b['open_vh_delta'], -1)}</td><td class=n>{fmt_num(b['stale'])}</td>"
        f"<td>{kit.sparkline(b.get('poor_trend') or [], labels, 'Poor share per run', lambda x: f'{x:,.0f}%', 110, 26) or '<span class=na>n/a</span>'}</td></tr>"
        for b in bus[:cap])
    more = f'<p class="small">and {len(bus) - cap:,} more {noun}.</p>' if len(bus) > cap else ""
    return (f'<div class="tw"><table><thead><tr><th>{head}</th><th class=n>Apps</th>'
            '<th>Health mix</th><th class=n>Poor</th><th>Change</th><th class=n>Policy pass</th>'
            '<th class=n>Open VH</th><th>Change</th><th class=n>Stale</th><th>Poor, per run</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>{more}')


def _business_units(rep: ta.TenantReport) -> str:
    legend = ('<div class="legend"><span><i class="sw hg"></i>Good</span><span><i class="sw hf"></i>'
              'Fair</span><span><i class="sw hp"></i>Poor</span><span><i class="sw hu"></i>Unknown</span></div>')
    bu = _group_table(rep, rep.business_units, "Business unit", "business units")
    if not rep.has_teams:
        return _section("bus", "Business units", "Ordered by share of Poor profiles. Changes are "
                        "against the last complete run.", legend + bu)
    tm = _group_table(rep, rep.teams, "Team", "teams")
    return _section("bus", "Business units",
                    _dual("Ordered by share of Poor profiles. Changes are against the last complete run.",
                          "Ordered by share of Poor profiles. A profile in several teams counts in "
                          "each. Changes are against the last complete run."),
                    legend + _dual(bu, tm, inline=False),
                    title_html=_dual("Business units", "Teams"))


def _own_history(p: dict[str, Any], base: str) -> str:
    v = p["vs_own"]
    rule = (f"Latest scan at least {v['ratio']:g}x and {v['min_extra_seconds'] // 60} min slower than the "
            f"median of the same profile's earlier scans (same sandbox), from previous runs. Needs "
            f"{v['min_history']} earlier scans of that profile.")
    if not v["compared"]:
        return (f'<h3>Slower than their own history</h3><p class="small">{e(rule)} No profile has '
                'enough earlier scans yet; this fills in as weekly runs accumulate.</p>')
    if not v["slower"]:
        return (f'<h3>Slower than their own history</h3><p class="small">{e(rule)} None of the '
                f'{v["compared"]:,} profiles with enough history got slower.</p>')
    tbl = _ref_table(v["apps"], base, [
        ("Now ", lambda r: _dur(r.get("duration_seconds"))),
        ("Usual ", lambda r: _dur(r.get("baseline_seconds"))),
        ("Ratio ", lambda r: e(f"{r['ratio']:g}x")),
        ("Size now ", lambda r: _mib(r.get("analysis_size_mib"))),
        ("Size usual ", lambda r: _mib(r.get("baseline_size_mib")))])
    return (f'<h3>Slower than their own history ({v["slower"]:,} of {v["compared"]:,})</h3>'
            f'<p class="small">{e(rule)} A larger size now than usual usually explains it.</p>{tbl}')


def _checks_list(nums: Any) -> str:
    return ", ".join(f"#{n} {sh.CHECK_CATALOG[n][0]}" for n in sorted(nums) if n in sh.CHECK_CATALOG)


def _r(term: str, rule: str) -> tuple[str, str]:
    return term, rule


def _rules(title: str, lens: str | None, items: list[tuple[str, str]]) -> str:
    glyph = kit._GLYPH[lens] if lens else ""
    dl = "".join(f"<dt>{e(t)}</dt><dd>{d}</dd>" for t, d in items)
    return f'<div class="panel rules"><h3>{glyph}{e(title)}</h3><dl>{dl}</dl></div>'


def _classification() -> str:
    """How every label in the report is decided, one rule per label, from the live configuration."""
    d = sh.DASHBOARD_CONFIG
    f, a, v = d["flaws"], d["attention_score"], ta.TENANT_CONFIG["verdict"]
    w = f["severity_weights"]
    stale = ta.TENANT_CONFIG["stale_days"]
    perf = ta.TENANT_CONFIG
    bands = ", ".join(f"{lab} {lo}-{hi}" for lo, hi, lab, _ in d["attention_bands"])
    wide = d["issue_prevalence"]["widespread_pct"]
    scan = _rules("Scan health: can the results be trusted?", kit.LENS_SCAN, [
        _r("Health (per profile)", "From the 31 scan health checks on the latest published scan. "
         "<b>Poor</b>: at least one high-severity check fails. <b>Fair</b>: a medium-severity check "
         "fails, none high. <b>Good</b>: nothing fails (or only low). <b>Unknown</b>: no published "
         "static scan, or retrieval failed."),
        _r("Stale", f"The latest published scan is older than {stale} days. With --include-sandboxes, "
         "each sandbox is a row of its own and is judged on its own scans."),
        _r("Never scanned / Errors", "No published static scan exists / the API calls for that profile "
         "failed this run (rerun to retry). Neither is counted as Good."),
        _r("Result coverage", "Findings only cover what was uploaded and selected. <b>At risk</b>: fails "
         f"{e(_checks_list(kit._ACCURACY_MAJOR))}. <b>Partial</b>: fails one of the other "
         f"{len(kit._ACCURACY - kit._ACCURACY_MAJOR)} accuracy checks. <b>Complete</b>: none fail."),
        _r("Analysis time", "Never averaged across the tenant. Each profile is compared with its own "
         f"earlier scans (slower = {perf['perf_slower_ratio']:g}x and {perf['perf_min_extra'] // 60} "
         "min above its usual), and profiles are grouped by analysis size."),
    ])
    posture = _rules("Policy and findings: what did the scans find?", kit.LENS_POSTURE, [
        _r("Policy", "Veracode's own policy evaluation of the latest policy scan: Pass, Conditional "
         "Pass (inside a grace period) or Did Not Pass. Not evaluated is Unknown and left out of "
         "the pass rate."),
        _r("Open findings", "Not fixed and not covered by an <b>accepted</b> mitigation; proposed or "
         "rejected mitigations stay open. Very High is severity 5, High is severity 4."),
        _r("Findings risk (per profile)", f"<b>Red</b>: {f['very_high_red']}+ open Very High or "
         f"{f['high_red']}+ open High, or a Veracode score under {f['score_yellow']}. <b>Orange</b>: "
         "any open Very High or High; size never lowers this. <b>Yellow</b>: score "
         f"{f['score_yellow']}-{f['score_green'] - 1}. <b>Green</b>: otherwise. Without a score, "
         f"weighted open flaws per MiB analysed (Very High {w['very_high']:g}, High {w['high']:g}, "
         f"Medium {w['medium']:g}, Low {w['low']:g}): yellow from {f['density_yellow']:g}, red from "
         f"{f['density_red']:g}. <b>Gray</b>: severity not available."),
    ])
    groups = _rules("How profiles are grouped", None, [
        _r("Priority box", "Puts the two sides together without merging them. Scan health is bad when "
         "the profile is Poor; findings are bad when findings risk is Orange or Red. <b>Immediate</b>: "
         "both. <b>Review</b>: findings only. <b>Attention</b>: scan health only. <b>Monitor</b>: "
         "neither. <b>Insufficient data</b>: neither side known."),
        _r("Attention score (0-100)", f"Scan health {a['scan_health_weight']}, scan age "
         f"{a['scan_age_weight']}, findings {a['flaw_weight']}, high-severity checks "
         f"{a['high_severity_issue_weight']}, trend {a['trend_weight']}, data quality "
         f"{a['data_quality_weight']}. Missing inputs are left out, never counted as healthy. "
         f"Never-scanned profiles are capped at {a['never_scanned_cap']}. Bands: {e(bands)}."),
        _r("Fix list priority", f"<b>P1</b>: checks that can hide code from analysis "
         f"({e(_checks_list(ana._P1_ACCURACY))}). <b>P2</b>: other accuracy and efficiency checks. "
         f"<b>P3</b>: the rest. Raised one level when a check fails on {wide:g}% or more of profiles."),
        _r("Business unit and team", "As set on the application profile in Veracode. Access teams named "
         "Service Delivery - * are not shown."),
        _r("Headline chips", f"Scan health: green up to {v['poor_share_green']:g}% Poor, yellow up to "
         f"{v['poor_share_yellow']:g}%. Policy: green from {v['policy_pass_green']:g}% pass, yellow from "
         f"{v['policy_pass_yellow']:g}%. Freshness: green up to {v['stale_share_green']:g}% stale, "
         f"yellow up to {v['stale_share_yellow']:g}%, orange up to {v['stale_share_orange']:g}%. "
         "These are this tool's defaults, not Veracode guidance."),
    ])
    return _section("how", "How results are classified",
                    "Scan health and policy/findings are classified separately; only the priority box "
                    "and attention score look at both.",
                    f'<div class="rulegrid">{scan}{posture}{groups}</div>')


def _performance(rep: ta.TenantReport, base: str) -> str:
    p = rep.performance
    v = p["vs_own"]
    stats = [("Measured", fmt_num(p["measured"]), "profiles with an analysis time"),
             ("Slower than own history", fmt_num(v["slower"]) if v["compared"] else "n/a",
              f"of {v['compared']:,} with enough history" if v["compared"] else "needs earlier runs"),
             ("Slowest", _dur(p["max_seconds"]), "single profile"),
             ("Over size threshold", fmt_num(p["over_size_threshold"]), "check #31")]
    tiles = "".join(f'<div class="stat"><div class="k">{e(k)}</div><div class="n">{v}</div>'
                    f'<div class="s">{e(s)}</div></div>' for k, v, s in stats)
    bands = "".join(f'<tr><td>{e(b["band"])}</td><td class=n>{fmt_num(b["apps"])}</td>'
                    f'<td class=n>{_dur(b["p50_seconds"])}</td><td class=n>{_dur(b["p90_seconds"])}</td></tr>'
                    for b in p["by_size"])
    by_size = ('<h3>Analysis time by size</h3><p class="small">Profiles are only compared with '
               'profiles of similar analysis size; a tenant-wide average mixes very different '
               'applications.</p><div class="tw"><table><thead><tr><th>Analysis size</th>'
               '<th class=n>Profiles</th><th class=n>Typical (median)</th><th class=n>Slow end (p90)</th>'
               f'</tr></thead><tbody>{bands}</tbody></table></div>')
    hist = hbars([(h["bucket"], h["apps"], "s1", "") for h in p["histogram"]])
    slow = _ref_table(p["slowest"], base, [("Analysis time ", lambda r: _dur(r.get("duration_seconds"))),
                                           ("Size ", lambda r: _mib(r.get("analysis_size_mib")))])
    big = _ref_table(p["largest"], base, [("Size ", lambda r: _mib(r.get("analysis_size_mib"))),
                                          ("Analysis time ", lambda r: _dur(r.get("duration_seconds")))])
    return _section("performance", "Scan performance",
                    "Analysis time of each profile's latest published scan (submit to publish; "
                    "excludes upload and prescan).",
                    f'<div class="stats">{tiles}</div>{_own_history(p, base)}{by_size}'
                    f'<h3>Analysis time distribution</h3>{hist}'
                    f'<div class="cols2"><div><h3>Slowest scans</h3>{slow}</div>'
                    f'<div><h3>Largest analysis sizes</h3>{big}</div></div>')


def _findings(rep: ta.TenantReport, base: str) -> str:
    f = rep.findings
    t = f["totals"]
    stats = [("Open Very High", fmt_num(t["vh"])), ("Open High", fmt_num(t["h"])),
             ("Open Medium", fmt_num(t["m"])), ("Open Low", fmt_num(t["l"])),
             ("Apps with open VH", fmt_num(f["apps_with_open_vh"])),
             ("Severity data", f"{f['severity_available']:,} apps")]
    tiles = "".join(f'<div class="stat"><div class="k">{e(k)}</div><div class="n">{v}</div></div>'
                    for k, v in stats)
    pcls = {"GREEN": "hg", "YELLOW": "hf", "RED": "hp", "GRAY": "hu"}
    pol = hbars([(m["status"], m["apps"], pcls[sh._policy_level(m["status"])], "")
                 for m in f["policy_mix"]])
    score = hbars([(b["bucket"], b["apps"], "s1", "") for b in f["score_buckets"]])
    vh = _ref_table(f["top_open_vh"], base, [("Open VH ", lambda r: fmt_num(r.get("open_vh"))),
                                             ("Open H ", lambda r: fmt_num(r.get("open_h"))),
                                             ("Policy", lambda r: e(r.get("policy_status") or "Unknown")),
                                             ("Deep dive", _cmd)],
                    f["apps_with_open_vh"] - len(f["top_open_vh"]))
    return _section("findings", "Findings and policy",
                    "Open flaws (not fixed, not mitigated) on each profile's latest published scan. "
                    "Profiles without severity data are excluded from the totals, never counted as zero.",
                    f'<div class="stats">{tiles}</div><div class="cols2"><div><h3>Policy outcome</h3>{pol}</div>'
                    f'<div><h3>Veracode score</h3><p class="small">{f["score_measured"]:,} profiles '
                    f'report a score.</p>{score}</div></div><h3>Profiles with open Very High flaws</h3>{vh}')


def _coverage(rep: ta.TenantReport, base: str) -> str:
    cv = rep.coverage
    k = rep.kpis

    def block(key: str, title: str, lead: str) -> str:
        b = cv[key]
        body = _ref_table(b["apps"], base, [("Status", lambda r: e(r.get("status") or "None"))],
                          b["count"] - len(b["apps"]))
        return (f'<details><summary>{e(title)} ({b["count"]:,})</summary><p class="small">{e(lead)}</p>'
                f'{body}</details>')

    stats = [("Never scanned", k["never_scanned"]), ("Errors", k["errors"]),
             ("Severity unavailable", k["severity_unavailable"]), ("Missing SCA", k["missing_sca"]),
             ("Sandboxes evaluated", cv["sandboxes"])]
    tiles = "".join(f'<div class="stat"><div class="k">{e(a)}</div><div class="n">{fmt_num(b)}</div></div>'
                    for a, b in stats)
    return _section("coverage", "Coverage and data quality",
                    "Gaps that limit what this report can say. An error is a failed retrieval, "
                    "never a healthy or empty result.",
                    f'<div class="stats">{tiles}</div><div class="moves">'
                    + block("never_scanned", "Never scanned", "No published static scan, "
                            "including profiles whose retrieval failed in this run (also listed "
                            "under Errors).")
                    + block("errors", "Errors", "Results could not be retrieved in this run; rerun "
                            "to retry. Their previous values are not reused.")
                    + block("severity_unavailable", "Flaw severity unavailable",
                            "The scan published but the severity breakdown was not available.")
                    + "</div>")


def _notes(rep: ta.TenantReport, collection: dict[str, Any] | None) -> str:
    rows = "".join(f"<tr><td>{e(n['topic'])}</td><td>{chip('ORANGE' if n['level'] == 'warning' else 'GRAY', n['level'])}</td>"
                   f"<td>{e(n['message'])}</td></tr>" for n in rep.notes)
    snaps = "".join(f"<li>{e(fmt_dt(p['generated'], True))}{'' if p['complete'] else ' (partial)'}</li>"
                    for p in rep.series)
    coll = ""
    if collection:
        coll = "<p class=small>" + " &middot; ".join(f"{e(k)}: {e(v)}" for k, v in collection.items()) + "</p>"
    return _section("notes", "Data notes",
                    "Sources, gaps and caveats. The workbook, CSV and JSON outputs hold the full "
                    "per-profile data.",
                    f'<div class="tw"><table><tbody>{rows}</tbody></table></div>{coll}'
                    f"<details><summary>Snapshots used ({len(rep.series)})</summary><ul>{snaps}</ul></details>")


def _chg(v: float | int | None, direction: int, suffix: str = "") -> tuple[str, str]:
    """(flag text, level) for a change since the last run; ("", "") if none."""
    if not v:
        return "", "GRAY"
    worse = (v > 0) != (direction > 0)
    txt = (f"{v:+,g}{suffix}" if isinstance(v, float) else f"{v:+,}{suffix}")
    return txt, ("RED" if worse else "GREEN")


def _group_inputs(rep: ta.TenantReport) -> str:
    """Radio inputs for the Group by switch; they precede every section so plain CSS can switch views."""
    team = rep.has_teams and rep.group_default == "team"
    return (f'<input type="radio" name="grp" id="grp-bu" class="grp-in"{"" if team else " checked"}>'
            f'<input type="radio" name="grp" id="grp-team" class="grp-in"{" checked" if team else ""}>')


def _group_switch(rep: ta.TenantReport) -> str:
    if not rep.has_teams:
        return ""
    return ('<div class="grpsw" role="group" aria-label="Group by"><span>Group by</span>'
            '<label for="grp-bu">Business unit</label><label for="grp-team">Team</label></div>')


def overview(rep: ta.TenantReport) -> str:
    """Header, one-sentence state and the two lens panels."""
    k = rep.kpis
    d = (rep.movement or {}).get("kpi_deltas") or {}
    v = {x.name: x for x in rep.verdicts}
    scanned = k["scanned"] or 0
    poor_pct = f"{100 * k['poor'] / scanned:.1f}%" if scanned else "n/a"
    issues = rep.actions["issues"]
    top = issues[0] if issues else None
    state = (f"{poor_pct} of scanned profiles have Poor scan health, and "
             f"{k['apps_with_open_vh']:,} have open Very High flaws."
             + (f" Start with #{top['check']} {top['label'].lower()} across {top['apps']:,} profiles."
                if top else ""))

    def res(label: str, value: str, ref: str, key: str | None = None, direction: int = -1,
            suffix: str = "") -> kit.Result:
        flag, lvl = _chg(d.get(key), direction, suffix) if key else ("", "GRAY")
        return kit.Result(label, value, ref, flag, lvl)

    perf = rep.performance
    common = max(rep.checks, key=lambda c: c["apps"]) if rep.checks else None
    stale_pct = f" ({100 * k['stale'] / scanned:.1f}%)" if scanned else ""
    srows = [
        res("Poor", kit.filter_link(f"{k['poor']:,} ({poor_pct})", "apps", "health=Poor"),
            f"of {scanned:,} scanned", "poor"),
        res("Stale", kit.filter_link(f"{k['stale']:,}{stale_pct}", "apps", "stale=1"),
            f"last scan over {ta.TENANT_CONFIG['stale_days']} days ago", "stale"),
        res("Never scanned", f"{k['never_scanned']:,}", "no published static scan", "never_scanned"),
        res("Errors", f"{k['errors']:,}", "retrieval failed this run; rerun to retry", "errors"),
    ]
    if perf["vs_own"]["compared"]:
        srows.append(kit.Result("Slower than own history",
                                f'<a href="#performance">{perf["vs_own"]["slower"]:,}</a>',
                                f"of {perf['vs_own']['compared']:,} profiles with enough history"))
    if common and common["apps"]:
        srows.append(kit.Result("Most common issue",
                                kit.filter_link(f"{common['apps']:,} profiles", "fix", f"check={common['check']}"),
                                e(f"#{common['check']} {common['label']}")))
    labels = [short_date(p["generated"]) for p in rep.series]
    spark_s = kit.sparkline([p.get("poor") for p in rep.series], labels, "Poor profiles",
                            lambda x: f"{x:,.0f}")
    first_s = (kit.filter_link(f"#{e(top['check'])} {e(top['label'])}", "fix", f"check={top['check']}")
               + f' <span class="small">{e(top["owner"])}, {top["apps"]:,} profiles</span>'
               if top else '<span class="na">No check fails on any profile.</span>')
    vs = v.get("Scan health")
    scan_panel = kit.lens_panel(kit.LENS_SCAN, vs.level if vs else "GRAY", vs.label if vs else "Unknown",
                                "Whether scans analyse the right code, efficiently and recently.",
                                srows, spark_s, "Poor profiles per run" if spark_s else "", first_s)

    cov: dict[str, int] = {}
    for a in rep.apps:
        lab = _coverage_label(a)
        cov[lab] = cov.get(lab, 0) + 1
    known = k["policy_pass"] + k["policy_conditional"] + k["policy_fail"]
    prows = [
        res("Policy pass", f"{k['policy_pass_pct']:g}%" if k["policy_pass_pct"] is not None else "n/a",
            f"{k['policy_pass']:,} of {known:,} with a known outcome", "policy_pass_pct", 1, " pp"),
        res("Profiles with open Very High", f"{k['apps_with_open_vh']:,}",
            f"{fmt_num(k['open_vh'])} open in total", "apps_with_open_vh"),
        res("Open High", fmt_num(k["open_h"]), "across profiles with severity data", "open_h"),
        kit.Result("Severity unavailable", f"{k['severity_unavailable']:,}", "excluded from totals"),
        kit.Result("Result coverage", kit.filter_link(f"{cov.get('At risk', 0):,} at risk", "apps", "cov=At%20risk"),
                   f"{cov.get('Partial', 0):,} partial, {cov.get('Complete', 0):,} complete "
                   "(from the accuracy checks)",
                   "Check scans" if cov.get("At risk") else "", "ORANGE"),
    ]
    spark_p = kit.sparkline([p.get("open_vh") for p in rep.series], labels, "Open Very High flaws",
                            lambda x: f"{x:,.0f}")
    worst = rep.findings["top_open_vh"][0] if rep.findings["top_open_vh"] else None
    first_p = (f'<a href="#findings">Open Very High flaws in {e(worst["name"])}</a> '
               f'<span class="small">{fmt_num(worst["open_vh"])} open, {_group_cell(worst)}</span>'
               if worst else '<span class="na">No open Very High flaws.</span>')
    vp = v.get("Policy compliance")
    posture_panel = kit.lens_panel(kit.LENS_POSTURE, vp.level if vp else "GRAY",
                                   vp.label if vp else "Unknown",
                                   "What scans found and whether profiles meet policy.", prows, spark_p,
                                   "Open Very High per run" if spark_p else "", first_p)
    base = f"vs {fmt_dt(rep.baseline, True)}" if rep.baseline else "first comparable run"
    sc = rep.scope
    scope = "policy scans and sandboxes" if sc.get("include_sandboxes") else "policy scans"
    if sc.get("app_name_filter"):
        scope += f", name filter {sc['app_name_filter']}"
    ctx = (f"Region <b>{e(rep.region)}</b>&emsp;Profiles <b>{k['profiles']:,}</b> ({e(scope)})&emsp;"
           f"Runs in trend <b>{len(rep.series)}</b>&emsp;Compared <b>{e(base)}</b>&emsp;"
           f"Generated <b>{e(fmt_dt(rep.generated, True))}</b>")
    partial = ('<p class="small">This run did not finish: counts cover the profiles processed.</p>'
               if not rep.complete else "")
    nav = "".join(f'<a href="#{i}">{t}</a>' for i, t in (
        ("fix", "Fix list"), ("org", "Fix once, repair many"), ("teams", "By group"),
        ("priority", "Priority by profile"), ("apps", "Applications"), ("changes", "What changed"), ("trends", "Trends"),
        ("checks", "All checks"), ("findings", "Findings and policy"), ("how", "How it's classified"),
        ("notes", "Data notes")))
    return (f'<header><h1>Scan health report</h1><p class="ctx">{ctx}</p>'
            f'<p class="state">{e(state)}</p>{partial}<nav class="nav" aria-label="Sections">{nav}</nav>'
            f'{_group_switch(rep)}</header>'
            f'<div class="lenses">{scan_panel}{posture_panel}</div>')


def priority(rep: ta.TenantReport) -> str:
    counts = {q["quadrant"]: q["apps"] for q in rep.distributions["quadrants"]}
    return kit.priority_matrix(counts, rep.kpis["profiles"],
                               {n: "#apps" for n, _, _ in kit.QUADRANTS},
                               {n: f"quad={n}" for n, _, _ in kit.QUADRANTS})


def org_actions(rep: ta.TenantReport) -> list[kit.ActionView]:
    out = []
    for i, it in enumerate(rep.actions["issues"]):
        bus = ", ".join(f"{b['bu']} ({b['apps']})" for b in it["top_bus"])
        tms = ", ".join(f"{b['bu']} ({b['apps']})" for b in it.get("top_teams") or [])
        ex = ", ".join(r["name"] for r in it["examples"])
        out.append(kit.ActionView(
            priority=it["priority"], title=f"#{it['check']} {it['label']}", lens=kit.LENS_SCAN,
            owner=it["owner"], effort=f"{it['effort']} per profile", why=it["why"],
            evidence=[x for x in (it["evidence"], f"Most affected business units: {bus}" if bus else "",
                                  f"Most affected teams: {tms}" if tms and rep.has_teams else "",
                                  f"For example: {ex}" if ex else "") if x],
            fix_html=kit.fix_html([it["recommendation"]]) if it["recommendation"] else [],
            verify=it["verify"], note=f"{it['apps']:,} profiles" + (", quick win" if it["quick_win"] else ""),
            anchor=f"org-{i + 1}",
            more_html=kit.filter_link(f"Show the {it['apps']:,} profiles in the fix list", "fix",
                                      f"check={it['check']}")))
    return out


def _filter_value(dim: str, group: str) -> str:
    """The filter value for a group: "No team" is a sentinel in the team selects."""
    return "__no_team__" if dim == "team" and group == ta.NO_TEAM else group


def heat(rep: ta.TenantReport, dim: str = "bu") -> str:
    m = ta.check_bu_matrix(rep.apps, dim=dim)
    if not m["rows"]:
        return '<p class="empty">No check fails on any profile.</p>'
    rows = [(f"#{r['check']} {r['label']}", r["cells"]) for r in m["rows"]]
    cols = [f"{c} ({t:,})" for c, t in zip(m["cols"], m["totals"], strict=True)]
    filters: list[list[str | None]] = [
        [f"check={r['check']}&{dim}={quote(_filter_value(dim, c), safe='')}" if c != "Other"
         else f"check={r['check']}" for c in m["cols"]] for r in m["rows"]]
    totals: list[tuple[int, str | None]] = [(int(r["apps"]), f"check={r['check']}") for r in m["rows"]]
    what = ("business unit's profiles", "largest business units") if dim == "bu" else \
        ("team's profiles (a profile counts in each of its teams)", "largest teams")
    return kit.heatmap(f"Share of each {what[0]} failing the check: the most common failing checks, "
                       f"the {what[1]}, the rest folded into Other.",
                       cols, rows, "Check", filters, totals=totals, total_head="Profiles failing")


def render_html(rep: ta.TenantReport, collection: dict[str, Any] | None = None) -> str:
    """The complete tenant report page."""
    base = platform_base(rep.region, rep.tenant_key)
    apps_html, index = _apps(rep, base)
    fix_html, fix_data = _fix_section(rep, base, index)
    org = kit.action_list(org_actions(rep), open_first=1)
    more = (f'<p class="small">{rep.actions["issues_more"]} more check(s) fail on at least one profile; '
            'see <a href="#checks">All checks</a>.</p>' if rep.actions["issues_more"] else "")
    body = (_group_inputs(rep) + overview(rep)
            + fix_html
            + _section("org", "Fix once, repair many",
                       "Build and packaging patterns that fail across many profiles: fixing the pattern "
                       "once repairs every profile that shares it.", org + more, kit.LENS_SCAN)
            + _section("teams", "Which business unit has which problem",
                       _dual("Send each business unit its own list.", "Send each team its own list."),
                       _dual(heat(rep), heat(rep, "team"), inline=False) if rep.has_teams else heat(rep),
                       kit.LENS_SCAN,
                       title_html=_dual("Which business unit has which problem",
                                        "Which team has which problem"))
            + _section("priority", "Priority by profile",
                       "Scan health risk against findings risk for every profile. Click a box to list "
                       "those profiles.", priority(rep))
            + apps_html
            + _changes(rep, base) + _trends(rep) + _checks(rep, base) + _business_units(rep)
            + _performance(rep, base) + _findings(rep, base) + _coverage(rep, base)
            + _classification() + _notes(rep, collection))
    script = _TABLE_SCRIPT
    csp = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
           f"script-src '{script_hash(script)}'; base-uri 'none'; form-action 'none'")
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            f'<meta http-equiv="Content-Security-Policy" content="{csp}">'
            '<meta name="referrer" content="no-referrer">'
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>Scan health report</title><style>{kit.DESIGN_CSS}{kit.COMPAT_CSS}</style></head>"
            f"<body><main>{body}<footer>Generated by scan_health.py on {e(fmt_dt(rep.generated, True))}. "
            "Not an official Veracode product.</footer></main>"
            f"{fix_data}<script>{script}</script></body></html>")
