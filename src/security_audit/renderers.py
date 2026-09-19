"""Output renderers: console (ANSI), Markdown, HTML, JSON, SARIF."""

from __future__ import annotations

import json
from dataclasses import asdict

from .model import Report, SEVERITIES


class Style:
    def __init__(self, enabled: bool):
        self.on = enabled

    def c(self, text, *codes):
        if not self.on:
            return text
        return f"\033[{';'.join(codes)}m{text}\033[0m"

    def bold(self, t):   return self.c(t, "1")
    def dim(self, t):    return self.c(t, "2")
    def red(self, t):    return self.c(t, "1;31")
    def orange(self, t): return self.c(t, "1;33")
    def yellow(self, t): return self.c(t, "33")
    def blue(self, t):   return self.c(t, "34")
    def green(self, t):  return self.c(t, "32")
    def cyan(self, t):   return self.c(t, "36")

    def sev(self, s):
        m = {"CRITICAL": self.red, "HIGH": self.orange, "MEDIUM": self.yellow,
             "LOW": self.blue, "INFO": self.dim}
        return m[s](f"{s:<8}")


DISCLAIMER = ("This is a SCANNING tool, not protection. Regex static analysis "
              "produces false positives — verify findings manually. "
              "A clean run does NOT mean the project is secure.")


def render_console(report: Report, st: Style, version: str) -> str:
    active = report.active()
    c = report.counts(active_only=True)
    base_c = {s: sum(1 for f in report.findings if f.baselined
                     and f.severity == s) for s in SEVERITIES}
    score = report.risk_score()
    bar_len = 24
    filled = int(bar_len * score / 100)
    bar = st.green("█" * (bar_len - filled)) + st.red("█" * filled)

    out = [st.cyan(
r"""
   ____                            _
  / ___|  ___  ___ _   _ _ __ ___| |_ _   _
  \___ \ / _ \/ __| | | | '__|_  / __| | | |
   ___) |  __/ (__| |_| | |   / /| |_| |_| |
  |____/ \___|\___|\__,_|_|  /___|\__|\__, |
              A U D I T               |___/
"""),
        st.bold(f" security-audit v{version} — scan report"),
        "",
        st.yellow(f" ⚠  {DISCLAIMER}"),
        "",
        f" {st.dim('Path')}       {report.stats.get('path', '-')}",
        f" {st.dim('Files')}      {report.stats.get('files', '-')} scanned"
        + (f"   {st.dim('since')} {report.stats['since']}"
           if report.stats.get('since') else ""),
        f" {st.dim('Duration')}   {report.stats.get('seconds', '-')}s",
        f" {st.dim('Started')}    {report.stats.get('started', '-')}",
        "",
        f" {st.bold('Risk')}      [{bar}] {st.bold(str(score))}/100 "
        f"({report.risk_label()})",
        ""]

    sev_parts = []
    for s in SEVERITIES:
        n = c[s]
        b = base_c[s]
        sev_parts.append(f"{st.sev(s).strip()}: {n}"
                         + (st.dim(f" (+{b} baselined)") if b else ""))
    out.append(" " + "  ".join(sev_parts))

    checks = {}
    for f in active:
        checks.setdefault(f.check, {s: 0 for s in SEVERITIES})
        checks[f.check][f.severity] += 1
    out += ["", st.bold(" By category"), st.dim(" " + "-" * 60)]
    for chk in sorted(checks):
        cdict = checks[chk]
        top = min((s for s in SEVERITIES if cdict[s]), key=SEVERITIES.index)
        out.append(f" {st.sev(top).strip():<12} {chk:<22} "
                   f"{sum(cdict.values())} finding(s)")

    for role, title in (("production", "PRODUCTION CODE"),
                        ("test", "TESTS (expected false positives)"),
                        ("tooling", "TOOLING / CI / SKILLS")):
        group = sorted((f for f in active if f.role == role),
                       key=lambda f: (SEVERITIES.index(f.severity), f.check))
        if not group:
            continue
        out += ["", st.bold(f" {title}"), st.dim(" " + "-" * 60)]
        for f in group:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            out += [f" {st.sev(f.severity)} {st.bold(f.check)}  {loc}",
                    st.dim(f"          rule: {f.rule_id}  "
                           f"fp: {f.fingerprint}"),
                    f"          {f.message}"]
            if f.remediation:
                out.append(st.cyan(f"          → fix: {f.remediation}"))

    n_base = sum(1 for f in report.findings if f.baselined)
    if n_base:
        out += ["", st.dim(f" {n_base} finding(s) accepted via baseline "
                           f"(not added to risk).")]
    if not active:
        out.append(st.green(" No active findings — but read the "
                            "disclaimer above."))
    return "\n".join(out)


MD_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
           "LOW": "🔵", "INFO": "⚪"}
ROLE_LABEL = {"production": "Production", "test": "Test",
              "tooling": "Tooling"}


def render_markdown(report: Report, version: str) -> str:
    c = report.counts(active_only=True)
    lines = [
        "# 🔒 Security Audit Report", "",
        f"- **Tool**: security-audit v{version}",
        f"- **Date**: {report.stats.get('started', '')}",
        f"- **Path**: `{report.stats.get('path', '')}`",
        f"- **Scope**: " +
        (f"diff since `{report.stats['since']}`"
         if report.stats.get("since") else "full project"),
        f"- **Files scanned**: {report.stats.get('files', '')}",
        f"- **Duration**: {report.stats.get('seconds', '')}s",
        f"- **Risk score**: **{report.risk_score()}/100** "
        f"({report.risk_label()})", "",
        f"> ⚠️ {DISCLAIMER}", "",
        "## Summary", "",
        "| Severity | Active | Baselined |", "|---|---|---|"]
    base_c = {s: sum(1 for f in report.findings if f.baselined
                     and f.severity == s) for s in SEVERITIES}
    for s in SEVERITIES:
        lines.append(f"| {MD_ICON[s]} {s} | {c[s]} | {base_c[s]} |")
    lines += ["", "## Findings", ""]
    for f in sorted(report.active(),
                    key=lambda x: (SEVERITIES.index(x.severity), x.check)):
        loc = f"{f.file}:{f.line}" if f.line else f.file
        lines += [f"### {MD_ICON[f.severity]} {f.check} — {f.severity}", "",
                  f"- **Rule**: `{f.rule_id}`",
                  f"- **Fingerprint**: `{f.fingerprint}`",
                  f"- **Location**: `{loc}`",
                  f"- **Role**: {ROLE_LABEL.get(f.role, f.role)}",
                  f"- **Finding**: {f.message}"]
        if f.remediation:
            lines.append(f"- **Remediation**: {f.remediation}")
        lines.append("")
    if not report.active():
        lines.append("_No active findings._")
    return "\n".join(lines)


def render_sarif(report: Report, version: str) -> dict:
    rules, results, seen = [], [], set()
    lvl = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
           "LOW": "note", "INFO": "none"}
    for f in report.findings:
        rid = f"security-audit/{f.rule_id}"
        if rid not in seen:
            seen.add(rid)
            rules.append({"id": rid, "name": f.rule_id.replace(".", "/"),
                          "shortDescription": {"text": f.message},
                          "help": {"text": f.remediation or f.message}})
        results.append({
            "ruleId": rid, "level": lvl[f.severity],
            "message": {"text": f"[{f.role}] {f.message}"
                        + (f" → {f.remediation}" if f.remediation else "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": max(f.line, 1)}}}]})
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                   "master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "security-audit", "version": version, "rules": rules}},
            "results": results}],
    }


def render_json(report: Report, version: str) -> dict:
    return {
        "tool": f"security-audit {version}", "stats": report.stats,
        "counts": report.counts(), "risk": report.risk_score(),
        "risk_label": report.risk_label(),
        "findings": [asdict(f) | {"fingerprint": f.fingerprint}
                     for f in report.findings],
    }


def render_html(report: Report, version: str) -> str:
    data = {
        "tool": f"security-audit {version}",
        "stats": report.stats,
        "risk": report.risk_score(),
        "riskLabel": report.risk_label(),
        "counts": report.counts(),
        "findings": [asdict(f) | {"fingerprint": f.fingerprint}
                     for f in report.findings],
    }
    payload = json.dumps(data, ensure_ascii=False)
    return HTML_TEMPLATE.replace("/*__DATA__*/null;", payload)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang=\"en\">
<head><meta charset=\"utf-8\"><title>Security Audit Report</title>
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<style>
:root{color-scheme:dark;--bg:#0d1117;--panel:#161b22;--border:#30363d;--text:#e6edf3;--dim:#8b949e;--crit:#f85149;--high:#db6d28;--med:#d29922;--low:#58a6ff;--info:#6e7681;--ok:#3fb950;}
*{box-sizing:border-box;}body{margin:0;font:15px/1.5 -apple-system,'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);}
header{padding:24px 32px;border-bottom:1px solid var(--border);display:flex;gap:32px;align-items:center;flex-wrap:wrap;}
h1{font-size:20px;margin:0;}.meta{color:var(--dim);font-size:13px;}
main{padding:24px 32px;max-width:1200px;margin:0 auto;}
.warn{background:#3d2d00;border:1px solid var(--med);padding:12px 16px;border-radius:8px;margin:16px 0;font-size:13px;}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0;}
button.chip{background:var(--panel);border:1px solid var(--border);color:var(--text);border-radius:999px;padding:6px 14px;cursor:pointer;font-size:13px;}
button.chip.on{border-color:var(--low);background:#0d2c4a;}
input#q{background:var(--panel);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:8px 12px;flex:1;min-width:220px;}
.finding{background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--dim);border-radius:8px;padding:14px 16px;margin:10px 0;}
.finding.CRITICAL{border-left-color:var(--crit);}.finding.HIGH{border-left-color:var(--high);}
.finding.MEDIUM{border-left-color:var(--med);}.finding.LOW{border-left-color:var(--low);}.finding.INFO{border-left-color:var(--info);}
.badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;margin-right:8px;}
.badge.CRITICAL{background:var(--crit);color:#fff;}.badge.HIGH{background:var(--high);color:#fff;}
.badge.MEDIUM{background:var(--med);color:#000;}.badge.LOW{background:var(--low);color:#000;}
.badge.INFO{background:var(--info);color:#fff;}
.role{font-size:11px;color:var(--dim);border:1px solid var(--border);border-radius:4px;padding:2px 6px;}
.loc{color:var(--low);font-family:ui-monospace,monospace;font-size:13px;}
.msg{margin:6px 0;}.fix{color:var(--ok);font-size:13px;}.fp{color:var(--dim);font-size:11px;font-family:monospace;}
.baselined{opacity:.45;}
.summary{display:flex;gap:16px;flex-wrap:wrap;margin:12px 0;}
.summary .pill{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:10px 16px;font-size:13px;}
</style></head>
<body>
<header><svg class=\"gauge\" viewBox=\"0 0 120 120\" id=\"gauge\" style=\"width:110px;height:110px\"></svg>
<div><h1>🔒 Security Audit Report</h1><div class=\"meta\" id=\"meta\"></div></div></header>
<main>
<div class=\"warn\">⚠️ This is a SCANNING tool, not protection. Regex static analysis produces false positives — verify findings manually. A clean run does NOT mean the project is secure.</div>
<div class=\"summary\" id=\"summary\"></div>
<div class=\"filters\" id=\"filters\"><input id=\"q\" placeholder=\"Search findings…\"></div>
<div id=\"list\"></div>
</main>
<script>
const DATA = /*__DATA__*/null;
const SEVS=["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
const SEV_COLOR={CRITICAL:"#f85149",HIGH:"#db6d28",MEDIUM:"#d29922",LOW:"#58a6ff",INFO:"#6e7681"};
const state={sev:null,role:null};
function gauge(){const r=DATA.risk,c=54,circ=2*Math.PI*c,off=circ*(1-r/100);const col=r>=50?"#f85149":r>=25?"#db6d28":r>=10?"#d29922":r>0?"#58a6ff":"#3fb950";document.getElementById("gauge").innerHTML=`<circle cx="60" cy="60" r="${c}" fill="none" stroke="#30363d" stroke-width="10"/><circle cx="60" cy="60" r="${c}" fill="none" stroke="${col}" stroke-width="10" stroke-dasharray="${circ}" stroke-dashoffset="${off}" stroke-linecap="round" transform="rotate(-90 60 60)"/><text x="60" y="58" text-anchor="middle" fill="${col}" font-size="26" font-weight="700">${r}</text><text x="60" y="76" text-anchor="middle" fill="#8b949e" font-size="11">${DATA.riskLabel}</text>`;}
function meta(){const s=DATA.stats;document.getElementById("meta").textContent=`${DATA.tool} · ${s.started} · ${s.files} files · ${s.seconds}s · ${s.path}`;}
function summary(){document.getElementById("summary").innerHTML=SEVS.map(s=>`<div class="pill" style="border-left:3px solid ${SEV_COLOR[s]}">${s}: <b>${DATA.counts[s]}</b></div>`).join("");}
function esc(s){const d=document.createElement("span");d.textContent=s;return d.innerHTML;}
function chip(label,kind,val){const b=document.createElement("button");b.className="chip"+(state[kind]===val?" on":"");b.textContent=label;b.onclick=()=>{state[kind]=state[kind]===val?null:val;render();};return b;}
function render(){const f=document.getElementById("filters");[...f.querySelectorAll("button")].forEach(b=>b.remove());f.appendChild(chip("All severities","sev",null));SEVS.forEach(s=>f.appendChild(chip(s,"sev",s)));["production","test","tooling"].forEach(r=>f.appendChild(chip(r,"role",r)));const q=document.getElementById("q").value.toLowerCase();const list=document.getElementById("list");const rows=DATA.findings.filter(x=>{if(state.sev&&x.severity!==state.sev)return false;if(state.role&&x.role!==state.role)return false;if(q&&!(x.file+" "+x.message+" "+x.rule_id).toLowerCase().includes(q))return false;return true;});list.innerHTML=`<p class="meta">${rows.length} of ${DATA.findings.length} findings</p>`;rows.forEach(x=>{const d=document.createElement("div");d.className="finding "+x.severity+(x.baselined?" baselined":"");d.innerHTML=`<span class="badge ${x.severity}">${x.severity}</span><span class="role">${x.role}</span>${x.baselined?'<span class="role">baselined</span>':''}<div class="loc">${x.file}${x.line?":"+x.line:""}</div><div class="msg"><b>${esc(x.check)}</b> — ${esc(x.message)}</div>${x.remediation?`<div class="fix">→ ${esc(x.remediation)}</div>`:""}<div class="fp">rule: ${x.rule_id} · fp: ${x.fingerprint}</div>`;list.appendChild(d);});}
document.getElementById("q").addEventListener("input",render);
gauge();meta();summary();render();
</script>
</body></html>"""
