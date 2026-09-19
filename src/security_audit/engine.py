"""Scan engine: file discovery, role classification, YAML rule matching,
baseline handling, git-diff scoping. All checks are declarative rules."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .model import Finding, Report

SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__",
             "dist", "build", ".next", ".next-e2e", ".turbo", ".cache",
             "out", "coverage", ".playwright", "playwright-report",
             "test-results", ".vercel", ".output", ".mypy_cache"}
CODE_EXT = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".svelte", ".vue"}
TEST_MARKERS = ("tests/", "test/", "/test_", "/conftest", ".spec.",
                ".test.", "playwright.config", "e2e/")
TOOLING_MARKERS = (".claude/", ".github/", "scripts/", "alembic/versions/")


def classify(p: Path) -> str:
    s = p.as_posix()
    if any(m in s for m in TEST_MARKERS):
        return "test"
    if any(m in s for m in TOOLING_MARKERS):
        return "tooling"
    return "production"


def is_scannable(p: Path) -> bool:
    name = p.name
    if set(p.parts) & SKIP_DIRS:
        return False
    if ".min." in name or "node_modules_" in name or "compiled_" in name:
        return False
    if name.endswith("._.js"):
        return False
    try:
        if p.stat().st_size > 1_000_000:
            return False
    except OSError:
        return False
    return True


def changed_files_since(root: Path, ref: str) -> set[str]:
    """Files changed between ref and HEAD (git-required)."""
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "diff", "--name-only", ref, "HEAD"],
            capture_output=True, text=True, check=True)
        return set(out.stdout.splitlines())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return set()


def iter_files(root: Path, since_ref: str | None = None):
    changed = changed_files_since(root, since_ref) if since_ref else None
    for p in sorted(root.rglob("*")):
        if not (p.is_file() and is_scannable(p)):
            continue
        rel = str(p.relative_to(root))
        if changed is not None and rel not in changed:
            continue
        yield p, rel


def read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    id: str
    check: str
    severity: str
    pattern: str
    message: str
    remediation: str = ""
    inverse: bool = False            # fire when pattern is ABSENT project-wide
    exts: list[str] = field(default_factory=lambda: sorted(CODE_EXT))
    roles: list[str] = field(
        default_factory=lambda: ["production", "test", "tooling"])
    _rx: re.Pattern | None = field(default=None, repr=False)

    def compiled(self) -> re.Pattern:
        if self._rx is None:
            self._rx = re.compile(self.pattern,
                                  re.IGNORECASE | re.MULTILINE)
        return self._rx


def load_rules(extra_paths: list[Path] | None = None) -> list[Rule]:
    default = Path(__file__).parent / "default_rules.yml"
    rules: list[Rule] = []
    for src in [default, *(extra_paths or [])]:
        data = yaml.safe_load(src.read_text(encoding="utf-8")) or {}
        for r in data.get("rules", []):
            rules.append(Rule(**r))
    return rules


def apply_rules(report: Report, root: Path, rules: list[Rule],
                since_ref: str | None = None) -> None:
    found: set[str] = set()
    for p, rel in iter_files(root, since_ref):
        if p.suffix not in CODE_EXT:
            continue
        role = classify(p)
        lines = read(p).splitlines()
        for rule in rules:
            if p.suffix not in rule.exts or role not in rule.roles:
                continue
            rx = rule.compiled()
            for i, line in enumerate(lines, 1):
                if rx.search(line):
                    found.add(rule.id)
                    if not rule.inverse:
                        report.findings.append(Finding(
                            rule.id, rule.check, rule.severity, rel, i,
                            rule.message, rule.remediation, role))
    for rule in rules:
        if rule.inverse and rule.id not in found:
            report.findings.append(Finding(
                rule.id, rule.check, rule.severity, "(project-wide)", 0,
                f"Expected protection not found: {rule.message}",
                rule.remediation, "production"))


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

DEFAULT_BASELINE = ".security-audit-baseline.json"


def load_baseline(root: Path, name: str = DEFAULT_BASELINE) -> set[str]:
    path = root / name
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {e["fingerprint"] for e in data.get("accepted", [])}
    except (json.JSONDecodeError, KeyError):
        return set()


def save_baseline(root: Path, report: Report,
                  name: str = DEFAULT_BASELINE,
                  reason: str = "reviewed") -> Path:
    """Write the currently active findings as accepted baseline."""
    path = root / name
    existing = {}
    if path.exists():
        try:
            for e in json.loads(path.read_text())["accepted"]:
                existing[e["fingerprint"]] = e
        except (json.JSONDecodeError, KeyError):
            pass
    for f in report.findings:
        if not f.baselined:
            existing[f.fingerprint] = {
                "fingerprint": f.fingerprint, "rule": f.rule_id,
                "file": f.file, "severity": f.severity,
                "reason": reason}
    path.write_text(json.dumps({"accepted": list(existing.values())},
                               indent=2) + "\n", encoding="utf-8")
    return path


def mark_baselined(report: Report, baseline: set[str]) -> None:
    for f in report.findings:
        f.baselined = f.fingerprint in baseline
