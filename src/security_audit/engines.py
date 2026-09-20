"""External engine integrations (v4 Orchestrator).

Each engine function returns (findings, status) where status is one of
\"ran\" | \"skipped: <reason>\". Findings are normalized into the shared
Finding model so renderers, baseline and scoring work unchanged.

Engines implemented:
  - gitleaks (secret detection — far better than our regex rules)
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from .engine import classify
from .model import Finding


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def available(cmd: list[str]) -> bool:
    try:
        _run(cmd)
        return True
    except FileNotFoundError:
        return False


# ---------------------------------------------------------------------------
# gitleaks
# ---------------------------------------------------------------------------

GITLEAKS_BIN = "gitleaks"


def run_gitleaks(root: Path) -> tuple[list[Finding], str]:
    """Run `gitleaks dir` on the target project and normalize findings.

    Exit codes: 0 = clean, 1 = leaks found, >1 = error.
    JSON report shape (8.x): list of findings with RuleID, Description,
    File, StartLine, Match, Secret, Fingerprint.
    """
    if not available([GITLEAKS_BIN, "version"]):
        return [], f"skipped: {GITLEAKS_BIN} not installed"

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = tmp.name

    try:
        proc = _run([
            GITLEAKS_BIN, "dir", "--no-banner",
            "--report-format", "json",
            "--report-path", report_path,
            str(root),
        ])
        if proc.returncode not in (0, 1):
            return [], (f"error: exit {proc.returncode} "
                        f"{proc.stderr.strip()[:120]}")

        try:
            raw = json.loads(Path(report_path).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return [], "error: could not parse gitleaks JSON report"

        findings: list[Finding] = []
        for g in raw:
            if not isinstance(g, dict):
                continue
            file = g.get("File", "")
            if not file:
                continue
            # gitleaks reports absolute paths under the scanned root
            rel = str(Path(file).relative_to(root)) \
                if file.startswith(str(root)) else file
            rule = g.get("RuleID", "unknown")
            findings.append(Finding(
                rule_id=f"gitleaks.{rule}",
                check="Secret Management",
                severity="CRITICAL",
                file=rel,
                line=int(g.get("StartLine", 0) or 0),
                message=f"gitleaks: {g.get('Description', rule)}",
                remediation="Rotate the leaked credential immediately, "
                            "move it to a secrets manager, and scrub git "
                            "history (gitleaks can also verify: "
                            "`gitleaks dir <path>`).",
                role=classify(Path(root) / rel),
                line_hash=str(g.get("Fingerprint", ""))[:12],
            ))
        return findings, "ran"
    finally:
        Path(report_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Registry — engines are looked up by name from the CLI
# ---------------------------------------------------------------------------

ENGINES = {
    "gitleaks": run_gitleaks,
}


def dedupe(existing: list[Finding], incoming: list[Finding]) -> list[Finding]:
    """Drop incoming findings that hit the same file+line as an existing
    finding from another engine (overlap between our regex rules and
    gitleaks is expected)."""
    seen = {(f.file, f.line) for f in existing}
    return [f for f in incoming if (f.file, f.line) not in seen]
