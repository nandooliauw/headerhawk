"""Report renderers: console text, Markdown, JSON and a self-contained HTML page."""

from __future__ import annotations

import html
import json

from .models import SEVERITY_ORDER, Report

STATUS_ICON = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "skip": "SKIP", "info": "INFO"}
SEVERITY_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


# --- console -----------------------------------------------------------------


def to_text(report: Report, colour: bool = True) -> str:
    codes = {
        "pass": "\033[32m",
        "warn": "\033[33m",
        "fail": "\033[31m",
        "skip": "\033[90m",
        "info": "\033[36m",
        "reset": "\033[0m",
        "bold": "\033[1m",
        "dim": "\033[90m",
    }
    if not colour:
        codes = {k: "" for k in codes}

    lines: list[str] = []
    lines.append(f"{codes['bold']}headerhawk{codes['reset']}  {codes['dim']}{report.generated_at}{codes['reset']}")
    lines.append(f"target    {report.target}")
    if report.final_url and report.final_url != report.target:
        lines.append(f"final     {report.final_url}")
    if report.response.error:
        lines.append(f"{codes['fail']}error     {report.response.error}{codes['reset']}")
    lines.append(f"status    HTTP {report.response.status}   redirects={max(0, len(report.response.hops) - 1)}")
    lines.append("")

    counts = report.counts
    lines.append(
        f"{codes['bold']}score {report.score}/100  grade {report.grade}{codes['reset']}   "
        f"{codes['pass']}{counts['pass']} pass{codes['reset']}  "
        f"{codes['warn']}{counts['warn']} warn{codes['reset']}  "
        f"{codes['fail']}{counts['fail']} fail{codes['reset']}  "
        f"{codes['skip']}{counts['skip']} skip{codes['reset']}"
    )
    lines.append("")

    width = max((len(c.title) for c in report.checks), default=20) + 2
    for check in report.checks:
        colour = codes.get(check.status, "")
        label = STATUS_ICON.get(check.status, check.status.upper())
        lines.append(f"{colour}{label:<5}{codes['reset']} {check.id:<7} {check.title:<{width}} {codes['dim']}{check.evidence}{codes['reset']}")

    failing = report.findings()
    if failing:
        lines.append("")
        lines.append(f"{codes['bold']}findings ({len(failing)}){codes['reset']}")
        for check in failing:
            lines.append(f"  [{SEVERITY_LABEL.get(check.severity, check.severity)}] {check.id} {check.title}")
            if check.remediation:
                lines.append(f"    {codes['dim']}fix: {check.remediation}{codes['reset']}")
    return "\n".join(lines)


# --- markdown ----------------------------------------------------------------


def to_markdown(report: Report) -> str:
    counts = report.counts
    lines = [
        "# headerhawk report",
        "",
        f"- **Target:** `{report.target}`",
        f"- **Final URL:** `{report.final_url}`",
        f"- **Generated:** {report.generated_at}",
        f"- **HTTP status:** {report.response.status}",
        f"- **Redirects:** {max(0, len(report.response.hops) - 1)}",
        "",
        f"## Score: {report.score}/100 (grade {report.grade})",
        "",
        f"`{counts['pass']} pass` · `{counts['warn']} warn` · `{counts['fail']} fail` · `{counts['skip']} skip`",
        "",
        "| Category | Score | Points |",
        "| --- | --- | --- |",
    ]
    for row in report.category_scores():
        lines.append(f"| {row['category']} | {row['score']} | {row['points']} |")

    lines += ["", "## Checks", "", "| ID | Check | Category | Status | Evidence |", "| --- | --- | --- | --- | --- |"]
    for check in report.checks:
        lines.append(
            f"| {check.id} | {check.title} | {check.category} | **{STATUS_ICON.get(check.status, check.status)}** | "
            f"{check.evidence.replace('|', '/')} |"
        )

    findings = report.findings()
    if findings:
        lines += ["", "## Findings", ""]
        for index, check in enumerate(findings, 1):
            lines.append(f"### {index}. {check.id} — {check.title}")
            lines.append("")
            lines.append(f"- **Severity:** {SEVERITY_LABEL.get(check.severity, check.severity)}")
            lines.append(f"- **Status:** {STATUS_ICON.get(check.status, check.status)}")
            lines.append(f"- **Evidence:** {check.evidence}")
            if check.remediation:
                lines.append(f"- **Remediation:** {check.remediation}")
            for ref in check.references:
                lines.append(f"- **Reference:** {ref}")
            lines.append("")

    if report.probed:
        lines += ["", "## Exposure probes", "", "| Path | Status | Confirmed |", "| --- | --- | --- |"]
        for probe in report.probed:
            lines.append(f"| `{probe['path']}` | {probe['status']} | {'YES' if probe['confirmed'] else 'no'} |")

    lines += [
        "",
        "## Raw response headers",
        "",
        "```http",
        f"HTTP/{'1.1'} {report.response.status}",
    ]
    for name, value in report.response.raw_headers:
        lines.append(f"{name}: {value}")
    lines += ["```", ""]

    tls = report.response.tls or {}
    if tls.get("version"):
        lines += [
            "## TLS",
            "",
            f"- Protocol: `{tls.get('version')}`",
            f"- Cipher: `{tls.get('cipher')}` ({tls.get('cipher_bits')} bit)",
            f"- Subject: `{tls.get('subject')}`",
            f"- Issuer: `{tls.get('issuer')}`",
            f"- Valid until: `{tls.get('not_after')}` ({tls.get('days_until_expiry')} days)",
            "",
        ]
    return "\n".join(lines)


# --- json --------------------------------------------------------------------


def to_json(report: Report) -> str:
    return json.dumps(report.as_dict(), indent=2, ensure_ascii=False)


# --- html --------------------------------------------------------------------

HTML_CSS = """
:root{--bg:#0b0f14;--panel:#111823;--line:#1e2a3a;--text:#dbe6f3;--dim:#7d8fa6;
--pass:#2ecc71;--warn:#f5b041;--fail:#e74c3c;--skip:#54657a;--accent:#4aa8ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:40px 22px 64px}
header{display:flex;flex-wrap:wrap;gap:22px;align-items:center;justify-content:space-between;
border-bottom:1px solid var(--line);padding-bottom:22px;margin-bottom:28px}
h1{font-size:22px;margin:0 0 6px;letter-spacing:.2px}
.meta{color:var(--dim);font-size:13px;word-break:break-all}
.grade{display:flex;align-items:center;gap:16px}
.dial{width:104px;height:104px;border-radius:50%;display:grid;place-items:center;
background:conic-gradient(var(--accent) calc(var(--pct)*1%),#1b2534 0);position:relative}
.dial::after{content:"";position:absolute;inset:9px;border-radius:50%;background:var(--bg)}
.dial span{position:relative;z-index:1;font-size:30px;font-weight:700}
.grade .label{font-size:13px;color:var(--dim)}
.grade .label b{display:block;font-size:20px;color:var(--text);margin-bottom:2px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:28px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .k{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.8px}
.card .v{font-size:22px;font-weight:600;margin-top:4px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
border-radius:10px;overflow:hidden;margin:14px 0 30px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);font-size:13.5px;vertical-align:top}
th{background:#0e1520;color:var(--dim);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.7px}
tr:last-child td{border-bottom:none}
code,.mono{font-family:Consolas,SFMono-Regular,Menlo,monospace;font-size:12.5px}
h2{font-size:16px;margin:34px 0 6px;letter-spacing:.3px}
h2 .hint{color:var(--dim);font-weight:400;font-size:13px;margin-left:8px}
.pill{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:700;letter-spacing:.5px}
.pass{background:rgba(46,204,113,.14);color:var(--pass)}
.warn{background:rgba(245,176,65,.14);color:var(--warn)}
.fail{background:rgba(231,76,60,.15);color:var(--fail)}
.skip{background:rgba(84,101,122,.2);color:var(--skip)}
.bar{height:6px;background:#1b2534;border-radius:99px;overflow:hidden;margin-top:6px}
.bar i{display:block;height:100%;background:var(--accent)}
.sev{font-weight:700;font-size:11.5px;letter-spacing:.6px}
.sev.critical,.sev.high{color:var(--fail)}
.sev.medium{color:var(--warn)}
.sev.low,.sev.info{color:var(--dim)}
.finding{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--accent);
border-radius:8px;padding:14px 16px;margin-bottom:12px}
.finding h3{margin:0 0 6px;font-size:14px}
.finding p{margin:6px 0;font-size:13.5px;color:#c2d0e0}
.finding .fix{border-top:1px dashed var(--line);margin-top:10px;padding-top:8px;color:var(--dim);font-size:13px}
pre{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;
overflow:auto;font-size:12.5px;color:#b9c9dc}
footer{margin-top:40px;border-top:1px solid var(--line);padding-top:16px;color:var(--dim);font-size:12px}
@media(max-width:600px){.wrap{padding:24px 14px 48px}th:nth-child(3),td:nth-child(3){display:none}}
"""


def _bar(pct: int) -> str:
    return f'<div class="bar"><i style="width:{max(0, min(100, pct))}%"></i></div>'


def to_html(report: Report) -> str:
    esc = html.escape
    counts = report.counts
    rows = []
    for check in report.checks:
        rows.append(
            "<tr>"
            f"<td class='mono'>{esc(check.id)}</td>"
            f"<td>{esc(check.title)}</td>"
            f"<td class='mono'>{esc(check.category)}</td>"
            f"<td><span class='pill {check.status}'>{STATUS_ICON.get(check.status, check.status)}</span></td>"
            f"<td class='mono'>{esc(check.evidence)}</td>"
            "</tr>"
        )

    findings_html = []
    for index, check in enumerate(report.findings(), 1):
        refs = "".join(f"<div class='mono'>{esc(r)}</div>" for r in check.references)
        findings_html.append(
            "<div class='finding'>"
            f"<h3>{index}. <span class='mono'>{esc(check.id)}</span> — {esc(check.title)}</h3>"
            f"<p><span class='sev {check.severity}'>{SEVERITY_LABEL.get(check.severity, check.severity)}</span> "
            f"· {STATUS_ICON.get(check.status, check.status)} · weight {check.weight}</p>"
            f"<p><b>Evidence:</b> <span class='mono'>{esc(check.evidence)}</span></p>"
            + (f"<p class='fix'><b>Remediation:</b> {esc(check.remediation)}</p>" if check.remediation else "")
            + (f"<p class='fix'>{refs}</p>" if refs else "")
            + "</div>"
        )

    categories = "".join(
        f"<div class='card'><div class='k'>{esc(row['category'])}</div>"
        f"<div class='v'>{row['score']}</div>{_bar(row['score'])}"
        f"<div class='meta mono'>{esc(row['points'])} pts</div></div>"
        for row in report.category_scores()
    )

    probes = ""
    if report.probed:
        probe_rows = "".join(
            f"<tr><td class='mono'>{esc(p['path'])}</td><td>{p['status']}</td>"
            f"<td>{'<span class=\"pill fail\">LEAK</span>' if p['confirmed'] else '<span class=\"pill pass\">clean</span>'}</td>"
            f"<td class='mono'>{esc((p.get('content_type') or '')[:60])}</td></tr>"
            for p in report.probed
        )
        probes = (
            "<h2>Exposure probes <span class='hint'>opt-in path checks</span></h2>"
            "<table><thead><tr><th>Path</th><th>HTTP</th><th>Result</th><th>Content-Type</th></tr></thead>"
            f"<tbody>{probe_rows}</tbody></table>"
        )

    headers = "\n".join(f"{n}: {v}" for n, v in report.response.raw_headers)
    tls = report.response.tls or {}
    tls_rows = ""
    if tls.get("version"):
        tls_rows = (
            "<h2>TLS</h2><table><tbody>"
            f"<tr><th>Protocol</th><td class='mono'>{esc(str(tls.get('version')))}</td></tr>"
            f"<tr><th>Cipher</th><td class='mono'>{esc(str(tls.get('cipher')))} ({tls.get('cipher_bits')} bit)</td></tr>"
            f"<tr><th>Subject</th><td class='mono'>{esc(str(tls.get('subject')))}</td></tr>"
            f"<tr><th>Issuer</th><td class='mono'>{esc(str(tls.get('issuer')))}</td></tr>"
            f"<tr><th>Expires</th><td class='mono'>{esc(str(tls.get('not_after')))} "
            f"({tls.get('days_until_expiry')} days)</td></tr>"
            "</tbody></table>"
        )

    error_banner = ""
    if report.response.error:
        error_banner = f"<div class='finding'><h3>Fetch error</h3><p class='mono'>{esc(report.response.error)}</p></div>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>headerhawk · {esc(report.final_url or report.target)}</title>
<style>{HTML_CSS}</style>
</head>
<body>
<div class="wrap">
<header>
  <div>
    <h1>headerhawk audit</h1>
    <div class="meta">{esc(report.target)}</div>
    <div class="meta">generated {esc(report.generated_at)} · HTTP {report.response.status} · redirects {max(0, len(report.response.hops) - 1)}</div>
  </div>
  <div class="grade">
    <div class="dial" style="--pct:{report.score}"><span>{report.score}</span></div>
    <div class="label"><b>Grade {report.grade}</b>{esc(_grade_label(report.grade))}</div>
  </div>
</header>

{error_banner}

<div class="cards">
  <div class="card"><div class="k">pass</div><div class="v" style="color:var(--pass)">{counts['pass']}</div></div>
  <div class="card"><div class="k">warn</div><div class="v" style="color:var(--warn)">{counts['warn']}</div></div>
  <div class="card"><div class="k">fail</div><div class="v" style="color:var(--fail)">{counts['fail']}</div></div>
  <div class="card"><div class="k">skip</div><div class="v" style="color:var(--skip)">{counts['skip']}</div></div>
</div>

<h2>Category scores</h2>
<div class="cards">{categories}</div>

<h2>Checks</h2>
<table>
<thead><tr><th>ID</th><th>Check</th><th>Category</th><th>Status</th><th>Evidence</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>

<h2>Findings <span class="hint">{len(report.findings())} item(s), worst first</span></h2>
{''.join(findings_html) or "<p class='meta'>No failing or warning checks.</p>"}

{probes}
{tls_rows}

<h2>Raw response headers</h2>
<pre>{esc(headers)}</pre>

<footer>
Generated by headerhawk — passive, read-only checks against a single URL.
Only audit systems you own or are authorised to test.
</footer>
</div>
</body>
</html>
"""


def _grade_label(grade: str) -> str:
    return {"A": "Hardened", "B": "Good", "C": "Needs work", "D": "Weak", "F": "Failing"}.get(grade, "")


def render(report: Report, fmt: str, colour: bool = True) -> str:
    if fmt == "md":
        return to_markdown(report)
    if fmt == "html":
        return to_html(report)
    if fmt == "json":
        return to_json(report)
    return to_text(report, colour=colour)


def sort_key(check) -> int:
    return SEVERITY_ORDER.get(check.severity, 9)
