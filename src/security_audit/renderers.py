"""Output renderers: console (ANSI), Markdown, JSON, SARIF."""

from __future__ import annotations

from dataclasses import asdict

from .model import Report, SEVERITIES, SEV_WEIGHT


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
                    st.dim(f"          rule: {f.rule_id}"),
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
                  f"- **Location**: `{loc}`",
                  f"- **Role**: {ROLE_LABEL.get(f.role, f.role)}",
                  f"- **Finding**: {f.message}"]
        if f.remediation:
            lines.append(f"- **Remediation**: {f.remediation}")
        lines.append("")
    if report.active() == [] and not any(f.baselined is False and
                                         f.severity != "INFO"
                                         for f in report.findings):
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
        "findings": [asdict(f) for f in report.findings],
    }


WEIGHT_DOC = {s: SEV_WEIGHT[s] for s in SEVERITIES}
