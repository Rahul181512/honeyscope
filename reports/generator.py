"""Security Report Generator.

Produces a timestamped, self-contained HTML report (Chart.js inlined so the
file works completely offline) plus a Markdown summary:
    reports/out/security_report_YYYYMMDD_HHMMSS.html
    reports/out/security_report_YYYYMMDD_HHMMSS.md
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from core.config import CHART_JS_PATH, REPORT_OUT_DIR

WEAK_PASSWORDS = {
    "123456", "password", "admin", "root", "toor", "123456789", "1234",
    "password1", "qwerty", "abc123", "111111", "12345678", "raspberry",
    "ubnt", "admin123", "default", "", "test", "guest",
}

SEV_COLORS = {
    "LOW": "#22c55e", "MEDIUM": "#eab308",
    "HIGH": "#f97316", "CRITICAL": "#ef4444",
}


def _recommendations(stats: dict, top_passwords: list[dict],
                     patterns: dict[str, int]) -> list[tuple[str, str]]:
    """Rule-based defensive recommendations derived from observed data."""
    recs: list[tuple[str, str]] = []

    if patterns.get("brute_force"):
        recs.append((
            "Brute-force activity detected",
            "Deploy fail2ban or account lockout policies on real services; "
            "enforce a minimum 12-character password policy and rate-limit "
            "authentication endpoints."))
    if patterns.get("credential_stuffing"):
        recs.append((
            "Credential stuffing observed",
            "Attackers are replaying known username/password pairs. Enforce "
            "multi-factor authentication, block breached-password lists and "
            "apply per-IP login throttling."))
    if patterns.get("port_scan"):
        recs.append((
            "Port scanning detected",
            "Close unused ports on the perimeter firewall, disable unused "
            "services and consider a network IDS such as Suricata to alert "
            "on scanning behaviour."))
    web_attacks = sum(patterns.get(k, 0) for k in
                      ("sql_injection", "xss", "path_traversal",
                       "webshell_probing"))
    if web_attacks:
        recs.append((
            "Web application attacks captured",
            f"{web_attacks} malicious HTTP payloads were recorded. Apply "
            "input validation and parameterised queries on real apps, place a "
            "WAF in front of public web services and keep software patched."))
    weak = [row["value"] for row in top_passwords
            if row["value"].lower() in WEAK_PASSWORDS]
    if weak:
        recs.append((
            "Weak/default credentials attempted",
            f"Common passwords ({', '.join(sorted(set(weak))[:5])}) were used "
            "by attackers. Remove default credentials from all devices and "
            "rotate any account that has ever used them."))
    if stats.get("commands_captured"):
        recs.append((
            "Interactive attacker commands captured",
            "Segment the honeypot on its own VLAN with restricted egress so a "
            "compromised decoy can never reach real systems; monitor outbound "
            "traffic for pivoting attempts."))
    recs.append((
        "Continuous monitoring",
        "Keep the honeypot running and review the dashboard daily; feed new "
        "attacker IPs into firewall deny lists and consider integrating free "
        "threat-intelligence feeds (e.g. AbuseIPDB) as a future extension."))
    return recs


def generate_report(db, chart_js_path: Path | None = None) -> dict[str, str]:
    chart_js_path = chart_js_path or CHART_JS_PATH
    REPORT_OUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    stats = db.stats()
    top_ips = db.top_ips(10)
    top_users = db.top_usernames(10)
    top_pass = db.top_passwords(10)
    combos = db.credential_combos(10)
    intel = db.ip_intel(15)
    timeline = db.timeline(hours=72, buckets=72)

    with_db = db._conn
    with db._lock:
        row = with_db.execute(
            "SELECT MIN(ts) AS first, MAX(ts) AS last FROM events").fetchone()
    period_first, period_last = row["first"], row["last"]

    patterns = {k.lower(): v for k, v in stats.get("by_pattern", {}).items()}
    recs = _recommendations(stats, top_pass, patterns)

    chart_data = {
        "timeline": timeline,
        "severity": stats.get("by_severity", {}),
        "service": stats.get("by_service", {}),
        "patterns": patterns,
        "topUsers": [{"value": r["value"], "count": r["count"]}
                     for r in top_users],
        "topPasswords": [{"value": r["value"], "count": r["count"]}
                         for r in top_pass],
        "colors": SEV_COLORS,
    }

    html = _render_html(stamp, period_first, period_last, stats, top_ips,
                        top_users, top_pass, combos, intel, recs, chart_data,
                        chart_js_path)
    md = _render_markdown(stamp, period_first, period_last, stats, top_ips,
                          top_users, top_pass, recs)

    html_path = REPORT_OUT_DIR / f"security_report_{stamp}.html"
    md_path = REPORT_OUT_DIR / f"security_report_{stamp}.md"
    html_path.write_text(html, encoding="utf-8")
    md_path.write_text(md, encoding="utf-8")
    return {"html": str(html_path), "markdown": str(md_path)}


def latest_report() -> Path | None:
    candidates = sorted(REPORT_OUT_DIR.glob("security_report_*.html"))
    return candidates[-1] if candidates else None


# --------------------------------------------------------------------- HTML
def _render_html(stamp, first, last, stats, top_ips, top_users, top_pass,
                 combos, intel, recs, chart_data, chart_js_path) -> str:
    try:
        chart_js = chart_js_path.read_text(encoding="utf-8")
    except OSError:
        chart_js = ("console.warn('chart.js not vendored - charts disabled');"
                    "window.Chart=null;")
    rows_top_ips = "".join(
        f"<tr><td>{r['ip']}</td>"
        f"<td><span class='sev sev-{r['max_severity'].lower()}'>"
        f"{r['max_severity']}</span></td><td>{r['count']}</td>"
        f"<td>{r.get('country') or '—'}</td><td>{r['last_seen']}</td></tr>"
        for r in top_ips) or "<tr><td colspan=5>No data yet.</td></tr>"
    rows_users = "".join(
        f"<tr><td>{r['value']}</td><td>{r['count']}</td>"
        f"<td>{r['sources']}</td></tr>" for r in top_users) or \
        "<tr><td colspan=3>No credentials captured yet.</td></tr>"
    rows_pass = "".join(
        f"<tr><td>{r['value']}</td><td>{r['count']}</td>"
        f"<td>{r['sources']}</td></tr>" for r in top_pass) or \
        "<tr><td colspan=3>No credentials captured yet.</td></tr>"
    rows_recs = "".join(
        f"<li><b>{title}:</b> {body}</li>" for title, body in recs)

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>HoneyScope Security Report {stamp}</title>
<style>
 body{{font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;
      background:#0d1526;color:#dbe4f3;margin:0;padding:32px;line-height:1.55}}
 .wrap{{max-width:1000px;margin:auto}}
 h1{{color:#7dd3fc}} h2{{color:#93c5fd;border-bottom:1px solid #24344f;
   padding-bottom:6px;margin-top:36px}}
 .kpis{{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}}
 .kpi{{background:#16233c;border:1px solid #24344f;border-radius:10px;
      padding:14px 22px;min-width:150px}}
 .kpi b{{display:block;font-size:26px;color:#fff}}
 .kpi span{{font-size:12px;color:#8ea3c2;text-transform:uppercase}}
 table{{width:100%;border-collapse:collapse;margin:10px 0;font-size:13px}}
 th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid #24344f}}
 th{{color:#8ea3c2;text-transform:uppercase;font-size:11px}}
 .sev{{padding:2px 8px;border-radius:99px;font-size:11px;font-weight:700}}
 .sev-low{{background:#14351f;color:#4ade80}}.sev-medium{{background:#3a3010;color:#facc15}}
 .sev-high{{background:#3a2113;color:#fb923c}}.sev-critical{{background:#3d1416;color:#f87171}}
 ol.recs li{{margin:10px 0}}
 canvas{{background:#16233c;border:1px solid #24344f;border-radius:10px;
        margin:12px 0}}
 .charts{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
 .full{{grid-column:1/-1}}
 .meta{{color:#8ea3c2;font-size:12px}}
 footer{{margin-top:44px;border-top:1px solid #24344f;padding-top:14px;
        color:#66799a;font-size:12px}}
 @media print {{body{{background:#fff;color:#111}} .kpi,canvas{{border-color:#ccc;background:#f5f5f5}} .kpi b{{color:#000}} h2{{color:#333}}}}
</style></head><body><div class="wrap">
<h1>&#127857; HoneyScope &mdash; Automated Security Report</h1>
<p class="meta">Generated {stamp} UTC &middot; observation window: {first or 'n/a'} &rarr; {last or 'n/a'}</p>

<h2>Executive Summary</h2>
<div class="kpis">
 <div class="kpi"><b>{stats['total_events']}</b><span>Total events</span></div>
 <div class="kpi"><b>{stats['unique_ips']}</b><span>Unique source IPs</span></div>
 <div class="kpi"><b>{stats['critical_events']}</b><span>Critical events</span></div>
 <div class="kpi"><b>{stats['credentials_captured']}</b><span>Credential attempts</span></div>
 <div class="kpi"><b>{stats['commands_captured']}</b><span>Commands captured</span></div>
</div>

<h2>Attack Timeline (last 72 h)</h2>
<div class="charts"><canvas id="cTimeline" class="full" height="90"></canvas>
<canvas id="cSeverity" height="180"></canvas>
<canvas id="cService" height="180"></canvas>
<canvas id="cPatterns" height="180"></canvas>
<canvas id="cCreds" height="180"></canvas></div>

<h2>Top Attacker IPs</h2>
<table><tr><th>IP</th><th>Worst severity</th><th>Events</th><th>Country</th><th>Last seen</th></tr>
{rows_top_ips}</table>

<h2>Most Attempted Usernames</h2>
<table><tr><th>Username</th><th>Attempts</th><th>Distinct sources</th></tr>{rows_users}</table>

<h2>Most Attempted Passwords</h2>
<table><tr><th>Password</th><th>Attempts</th><th>Distinct sources</th></tr>{rows_pass}</table>

<h2>Defensive Recommendations</h2>
<ol class="recs">{rows_recs}</ol>

<footer>HoneyScope v1.0.0 &middot; B.Tech project - Honeypot with Attack
Visualization Dashboard. Data collected in an isolated lab environment only.
This file is fully self-contained (works offline).</footer>
<script>{chart_js}</script>
<script>
const DATA = {json.dumps(chart_data)};
(function draw(){{
  if (!window.Chart) return;
  Chart.defaults.color = '#8ea3c2'; Chart.defaults.borderColor = '#24344f';
  const labels = DATA.timeline.map(p => p.label);
  new Chart(document.getElementById('cTimeline'), {{type:'line',
    data:{{labels, datasets:[
     {{label:'Events', data:DATA.timeline.map(p=>p.count),
       borderColor:'#38bdf8', backgroundColor:'rgba(56,189,248,.15)', fill:true, tension:.3}},
     {{label:'Critical', data:DATA.timeline.map(p=>p.critical),
       borderColor:'#ef4444', tension:.3}}]}},
    options:{{plugins:{{legend:{{labels:{{boxWidth:12}}}}}}, scales:{{y:{{beginAtZero:true}}}}}}}});
  const donut=(id,obj,cmap)=>new Chart(document.getElementById(id),{{type:'doughnut',
    data:{{labels:Object.keys(obj), datasets:[{{data:Object.values(obj),
      backgroundColor:Object.keys(obj).map(k=>cmap?cmap[k]:'#3b82f6')}}]}},
    options:{{plugins:{{legend:{{position:'right'}}}}}}}});
  donut('cSeverity', DATA.severity, DATA.colors);
  const palette=['#38bdf8','#a78bfa','#34d399','#fbbf24','#fb7185','#60a5fa'];
  let i=0; const next=()=>palette[(i++)%palette.length];
  donut('cService', DATA.service);
  new Chart(document.getElementById('cPatterns'), {{type:'bar',
    data:{{labels:Object.keys(DATA.patterns),datasets:[{{label:'Events',
      data:Object.values(DATA.patterns),backgroundColor:Object.keys(DATA.patterns).map(next)}}]}},
    options:{{indexAxis:'y'}}}});
  new Chart(document.getElementById('cCreds'), {{type:'bar',
    data:{{labels:DATA.topUsers.map(r=>r.value),datasets:[{{label:'Username attempts',
      data:DATA.topUsers.map(r=>r.count),backgroundColor:'#a78bfa'}},
     {{label:'Password attempts', data:DATA.topPasswords.map(r=>r.count),
      backgroundColor:'#34d399'}}]}},
    options:{{indexAxis:'y'}}}});
}})();
</script></body></html>"""


# ------------------------------------------------------------------ Markdown
def _render_markdown(stamp, first, last, stats, top_ips, top_users, top_pass,
                     recs) -> str:
    lines = [
        f"# HoneyScope Security Report ({stamp} UTC)",
        "",
        f"- Observation window: **{first or 'n/a'}** to **{last or 'n/a'}**",
        f"- Total events captured: **{stats['total_events']}**",
        f"- Unique attacking IPs: **{stats['unique_ips']}**",
        f"- Critical events: **{stats['critical_events']}**",
        f"- Credential attempts: **{stats['credentials_captured']}**",
        f"- Commands captured: **{stats['commands_captured']}**",
        "",
        "## Top attacker IPs",
        "",
        "| IP | Worst severity | Events | Country |",
        "|---|---|---|---|",
    ]
    lines += [f"| {r['ip']} | {r['max_severity']} | {r['count']} "
              f"| {r.get('country') or '-'} |" for r in top_ips]
    lines += ["", "## Top usernames", ""]
    lines += [f"- `{r['value']}` - {r['count']} attempts" for r in top_users[:10]]
    lines += ["", "## Top passwords", ""]
    lines += [f"- `{r['value']}` - {r['count']} attempts" for r in top_pass[:10]]
    lines += ["", "## Recommendations", ""]
    lines += [f"1. **{t}:** {b}" for t, b in recs]
    lines += ["",
              "_Generated by HoneyScope v1.0.0 - academic honeypot lab project._"]
    return "\n".join(lines) + "\n"
