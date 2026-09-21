"""CLI entry point: orchestration, compound checks, report generation."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from . import __version__ as VERSION
from .config import Config
from .engine import (CODE_EXT, DEFAULT_BASELINE, apply_rules, classify,
                     iter_files, load_baseline, mark_baselined, read,
                     save_baseline)
from .engines import ENGINES, dedupe
from .model import Finding, Report, SEVERITIES
from .renderers import (Style, render_console, render_html, render_json,
                        render_markdown, render_sarif)


def apply_config(rep: Report, root: Path, config: Config) -> None:
    """Apply project-config overrides to findings (severity + role)."""
    if not (config.severity_overrides or config.role_overrides):
        return
    for f in rep.findings:
        if f.rule_id in config.severity_overrides:
            f.severity = config.severity_overrides[f.rule_id]
        for marker, role in config.role_overrides.items():
            if marker in f.file:
                f.role = role


# ---------------------------------------------------------------------------
# Compound checks
# ---------------------------------------------------------------------------

def check_cookie_flags(rep: Report, root: Path) -> None:
    for p, rel in iter_files(root):
        if p.suffix not in CODE_EXT:
            continue
        content = read(p)
        if not re.search(r"set_cookie|Set-Cookie|res\\.cookie", content, re.I):
            continue
        flags = sum(1 for fl in ("Secure", "HttpOnly", "SameSite")
                    if re.search(fl, content, re.I))
        if flags < 3:
            rep.findings.append(_f("compound.cookie-flags",
                "Secure Cookies", "HIGH", rel, 0,
                f"Cookie flags missing ({flags}/3 set)",
                "Set cookies with Secure, HttpOnly and SameSite (Lax/Strict).",
                classify(p)))


def check_file_upload(rep: Report, root: Path) -> None:
    upload = re.compile(r"(multipart|FileStorage|request\\.files|formData)", re.I)
    valid = re.compile(r"(ALLOWED_EXTENSIONS|allowed_extensions|magic|"
                       r"file-type|imghdr|content_type.*in\\s|\\.endswith\\()")
    has_up = has_val = False
    for p, _ in iter_files(root):
        c = read(p)
        if upload.search(c):
            has_up = True
            if valid.search(c):
                has_val = True
    if has_up and not has_val:
        rep.findings.append(_f("compound.upload-no-validation",
            "File Upload", "HIGH", "(project-wide)", 0,
            "File upload present but type/size validation not found",
            "Extension allowlist + magic-byte check + size limit",
            "production"))


def check_dependencies(rep: Report, root: Path) -> None:
    """Scan the TARGET project's Python dependencies — never the tool's venv."""
    if not _run_ok(["pip-audit", "--version"]):
        rep.findings.append(_f("compound.dep-python-skip",
            "Dependencies", "INFO", "(env)", 0,
            "pip-audit not available; python dependency scan skipped",
            "Install extras: pipx install 'security-audit-cli[deps-audit]'.",
            "tooling"))
        return

    req_files = [p for p in (root / "requirements.txt",
                             root / "backend" / "requirements.txt",
                             root / "requirements-dev.txt")
                 if p.exists()]
    venv_py = (root / ".venv" / "bin" / "python")
    venv = venv_py if venv_py.exists() else (
        root / "backend" / ".venv" / "bin" / "python")

    if req_files:
        cmd = ["pip-audit", "-r", str(req_files[0])]
    elif venv.exists():
        cmd = ["pip-audit", "--python", str(venv)]
    else:
        rep.findings.append(_f("compound.dep-python-nomanifest",
            "Dependencies", "INFO", "(project-wide)", 0,
            "No requirements.txt or .venv found — python dependency scan "
            "skipped (would have audited the wrong environment)",
            "Add a requirements.txt, or create a .venv with the project "
            "dependencies.", "tooling"))
        return

    audit = subprocess.run(cmd, capture_output=True, text=True, cwd=root)
    try:
        data = json.loads(audit.stdout or "[]")
        deps = (data.get("dependencies", []) if isinstance(data, dict)
                else data)
        for dep in deps:
            if not isinstance(dep, dict):
                continue
            for v in dep.get("vulns", []):
                if not isinstance(v, dict):
                    continue
                rep.findings.append(_f("compound.dep-python",
                    "Dependencies", "HIGH",
                    str(req_files[0].relative_to(root)) if req_files
                    else ".venv", 0,
                    f"{dep['name']} {dep['version']}: {v.get('id')}",
                    "Upgrade to the patched version cited by pip-audit.",
                    "production"))
    except (json.JSONDecodeError, KeyError):
        pass

    pkg = root / "package.json"
    if pkg.exists():
        backend = ("bun" if (root / "bun.lockb").exists()
                   or (root / "bun.lock").exists() else "npm")
        if _run_ok([backend, "--version"]):
            npm = subprocess.run([backend, "audit", "--json"],
                                 capture_output=True, text=True, cwd=root)
            try:
                data = json.loads(npm.stdout or "{}")
                v = data.get("metadata", {}).get("vulnerabilities", {})
                n = sum(v.get(k, 0) for k in ("critical", "high"))
                if n:
                    rep.findings.append(_f("compound.dep-js",
                        "Dependencies", "HIGH", "package.json", 0,
                        f"{backend} audit: {n} critical/high vulnerabilities",
                        f"Run `{backend} audit fix`, review the rest.",
                        "production"))
            except json.JSONDecodeError:
                pass


def check_cicd(rep: Report, root: Path) -> None:
    ci_files = []
    wf = root / ".github" / "workflows"
    if wf.exists():
        ci_files += list(wf.glob("*.yml")) + list(wf.glob("*.yaml"))
        ci_files = [f for f in ci_files if f.name != "security.yml"]
    if (root / ".gitlab-ci.yml").exists():
        ci_files.append(root / ".gitlab-ci.yml")
    if not ci_files:
        rep.findings.append(_f("compound.cicd-missing",
            "CI/CD Security", "LOW", "(project-wide)", 0,
            "No CI pipeline found",
            "Add CI with lint, tests and security gates.", "tooling"))
        return
    all_ci = "\n".join(read(f) for f in ci_files).lower()
    for rx, label, remed in [
        ("gitleaks|trufflehog|detect-secrets", "secret scanning",
         "Add a gitleaks step to CI."),
        ("trivy|grype|checkov|semgrep|bandit|codeql", "SAST scanner",
         "Add Semgrep/CodeQL or Trivy to CI."),
        ("pip-audit|npm audit|bun audit|snyk|dependabot", "dependency scan",
         "Enable Dependabot or an audit job."),
        ("security-audit", "this tool", "Run `security-audit` in CI with "
         "`--fail-on HIGH` as a merge gate."),
    ]:
        if not re.search(rx, all_ci):
            rep.findings.append(_f(f"compound.cicd-{label.split()[0]}",
                "CI/CD Security", "MEDIUM", "(CI config)", 0,
                f"Missing in CI: {label}", remed, "tooling"))
    if re.search(r"pull_request_target", all_ci) and re.search(r"checkout",
                                                               all_ci):
        rep.findings.append(_f("compound.cicd-pr-target",
            "CI/CD Security", "HIGH", "(CI config)", 0,
            "pull_request_target + checkout combination",
            "Never check out PR code under pull_request_target with secrets.",
            "tooling"))


REQUIRED_HEADERS = {
    "strict-transport-security": "HIGH",
    "content-security-policy": "MEDIUM",
    "x-frame-options": "MEDIUM",
    "x-content-type-options": "LOW",
    "referrer-policy": "LOW",
}


def check_live_headers(rep: Report, url: str) -> None:
    try:
        req = Request(url, method="HEAD",
                      headers={"User-Agent": f"security-audit/{VERSION}"})
        with urlopen(req, timeout=10) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
    except URLError as e:
        rep.findings.append(_f("live.connect", "Security Headers (live)",
                               "INFO", url, 0, f"Could not connect: {e}"))
        return
    for h, sev in REQUIRED_HEADERS.items():
        if h not in headers:
            rep.findings.append(_f(f"live.header-{h}", "Security Headers (live)",
                sev, url, 0, f"Missing header: {h}",
                "Configure the reverse proxy / middleware to send it."))
    cookies = headers.get("set-cookie", "")
    if cookies:
        for fl in ("Secure", "HttpOnly", "SameSite"):
            if fl.lower() not in cookies.lower():
                rep.findings.append(_f(f"live.cookie-{fl}",
                    "Secure Cookies (live)", "HIGH", url, 0,
                    f"Set-Cookie missing {fl} flag",
                    "Set cookies with Secure, HttpOnly and SameSite."))
    if url.startswith("http://"):
        rep.findings.append(_f("live.no-https", "HTTPS (live)", "CRITICAL",
            url, 0, "Site is not served over HTTPS",
            "Redirect 80 → 443 and enable HSTS."))


def _f(rule_id, check, sev, file, line, msg, remed="", role="production"):
    return Finding(rule_id, check, sev, file, line, msg, remed, role)


def _run_ok(cmd: list[str]) -> bool:
    try:
        subprocess.run(cmd, capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        prog="security-audit",
        description="Project security audit — multi-engine, baseline, "
                    "HTML/SARIF reports")
    ap.add_argument("--path", default=".", help="project root")
    ap.add_argument("--engine", default="auto",
                    choices=["auto", "regex", "gitleaks"],
                    help="scan engine: auto (regex + all available external "
                         "engines), regex only, or a single external engine")
    ap.add_argument("--since", metavar="REF",
                    help="scan only files changed since git ref (e.g. main)")
    ap.add_argument("--url", help="live site URL for header checks")
    ap.add_argument("--rules", type=Path, nargs="*", default=[],
                    help="extra YAML rule files")
    ap.add_argument("--config", type=Path, metavar="FILE",
                    help="path to .security-audit.toml (default: "
                         "<path>/.security-audit.toml)")
    ap.add_argument("--baseline", default=DEFAULT_BASELINE,
                    help=f"baseline file (default: {DEFAULT_BASELINE})")
    ap.add_argument("--update-baseline", action="store_true",
                    help="write current findings to the baseline, then exit")
    ap.add_argument("--only", metavar="ROLES",
                    help="with --update-baseline: only accept these roles, "
                         "comma-separated (e.g. test,tooling)")
    ap.add_argument("--baseline-reason", default="reviewed",
                    help="reason recorded for accepted findings")
    ap.add_argument("--accept-production-risk", action="store_true",
                    help="with --update-baseline: also accept production "
                         "CRITICAL/HIGH findings (requires conscious choice)")
    ap.add_argument("--json", dest="json_out", help="write JSON report")
    ap.add_argument("--sarif", dest="sarif_out", metavar="FILE",
                    help="write SARIF report (GitHub code scanning)")
    ap.add_argument("--html", dest="html_out", nargs="?", const="AUTO",
                    metavar="FILE",
                    help="also write an interactive HTML report "
                         "(optional FILE path)")
    ap.add_argument("--no-md", action="store_true",
                    help="skip the Markdown report")
    ap.add_argument("--report-dir", default=".",
                    help="directory for generated reports")
    ap.add_argument("--fail-on", default="HIGH",
                    choices=SEVERITIES + ["NEVER"],
                    help="exit non-zero at this severity or worse")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--open", action="store_true",
                    help="open the HTML (or Markdown) report after the scan "
                         "(macOS)")
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {VERSION}")
    args = ap.parse_args()

    st = Style(enabled=not args.no_color and sys.stdout.isatty())
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Error: {root} is not a directory", file=sys.stderr)
        return 2

    started = dt.datetime.now()
    t0 = time.monotonic()

    config = Config.load(args.config or root)

    rep = Report()
    engine_health: dict[str, str] = {}

    # --- regex engine (our YAML rule engine) --------------------------------
    if args.engine in ("auto", "regex"):
        rules = __import__("security_audit.engine",
                           fromlist=["load_rules"]).load_rules(args.rules)
        apply_rules(rep, root, rules, since_ref=args.since)
        engine_health["regex"] = "ran"
    else:
        engine_health["regex"] = "skipped: --engine gitleaks"

    # --- external engines ----------------------------------------------------
    for name, runner in ENGINES.items():
        if args.engine not in ("auto", name):
            engine_health[name] = "skipped: --engine selection"
            continue
        findings, status = runner(root)
        engine_health[name] = status
        if findings:
            rep.findings.extend(dedupe(rep.findings, findings))

    # --- compound checks (only make sense on a full scan) --------------------
    if not args.since:
        check_cookie_flags(rep, root)
        check_file_upload(rep, root)
        check_dependencies(rep, root)
        check_cicd(rep, root)
    if args.url:
        check_live_headers(rep, args.url)

    apply_config(rep, root, config)

    baseline = load_baseline(root, args.baseline)
    mark_baselined(rep, baseline)
    rep.stats = {
        "path": str(root),
        "files": sum(1 for p, _ in iter_files(root, args.since)
                     if p.suffix in CODE_EXT),
        "seconds": round(time.monotonic() - t0, 1),
        "started": started.strftime("%Y-%m-%d %H:%M:%S"),
        "since": args.since or "",
        "rules": len(rules) if args.engine in ("auto", "regex") else 0,
        "engines": engine_health,
        "config_file": str(args.config or "(default)"),
        "baseline_file": args.baseline if baseline else "",
    }

    if args.update_baseline:
        only_roles = ({r.strip() for r in args.only.split(",")}
                      if args.only else None)
        risky = [f for f in rep.active()
                 if f.role == "production"
                 and f.severity in ("CRITICAL", "HIGH")]
        if risky and not args.accept_production_risk \
                and (only_roles is None or "production" in only_roles):
            print(st.red(" Refusing to bulk-accept the following PRODUCTION "
                         "CRITICAL/HIGH findings:"))
            for f in risky:
                print(f"   - {f.check} @ {f.file}:{f.line or '-'} "
                      f"({f.rule_id})")
            print(st.yellow(" Fix them first, or re-run with "
                            "--accept-production-risk to consciously "
                            "accept them."))
            return 2
        path = save_baseline(root, rep, args.baseline, args.baseline_reason,
                             only_roles=only_roles)
        n = sum(1 for f in rep.findings if not f.baselined)
        scope = f" roles: {','.join(sorted(only_roles))}" if only_roles else ""
        print(f"Baseline updated: {path} "
              f"(+{n} newly accepted finding(s)){scope}")
        return 0

    print(render_console(rep, st, VERSION))
    if engine_health:
        print()
        print(st.bold(" Engine health"))
        for name, status in engine_health.items():
            icon = st.green("✓") if status == "ran" else st.yellow("-")
            print(f"   {icon} {name:<10} {status}")

    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = started.strftime("%Y%m%d-%H%M%S")
    written = []

    if not args.no_md:
        md_path = report_dir / f"security-audit-report-{stamp}.md"
        md_path.write_text(render_markdown(rep, VERSION), encoding="utf-8")
        written.append(("Markdown", md_path))
    if args.html_out:
        html_path = Path(args.html_out) if args.html_out != "AUTO" else \
            report_dir / f"security-audit-report-{stamp}.html"
        html_path.write_text(render_html(rep, VERSION), encoding="utf-8")
        written.append(("HTML", html_path))
    if args.json_out:
        p = Path(args.json_out)
        p.write_text(json.dumps(render_json(rep, VERSION), indent=2),
                     encoding="utf-8")
        written.append(("JSON", p))
    if args.sarif_out:
        p = Path(args.sarif_out)
        p.write_text(json.dumps(render_sarif(rep, VERSION), indent=2),
                     encoding="utf-8")
        written.append(("SARIF", p))

    print()
    print(st.dim(" " + "=" * 60))
    if written:
        print(st.bold(" Report(s) written to:"))
        for kind, path in written:
            print(f"   {kind:<9} {st.green(str(path.resolve()))}")
    else:
        print(st.dim(" Report writing disabled (--no-md)."))
    print(st.dim(" " + "=" * 60))

    if args.open and written:
        target = [p for k, p in written if k == "HTML"] or [written[0][1]]
        subprocess.run(["open", str(target[0].resolve())], check=False)

    if args.fail_on == "NEVER":
        return 0
    active_sevs = [f.severity for f in rep.active()]
    threshold = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(s) <= threshold for s in active_sevs) \
        else 0


if __name__ == "__main__":
    sys.exit(main())
