"""Tests for external engine integrations (v4)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_audit.engines import dedupe  # noqa: E402
from security_audit.model import Finding  # noqa: E402


def _f(rule_id, file, line, msg="x"):
    return Finding(rule_id, "Secret Management", "CRITICAL", file, line, msg)


def test_dedupe_overlapping_lines():
    ours = [_f("secrets.generic", "app.py", 3)]
    gitleaks = [
        _f("gitleaks.aws-key", "app.py", 3),
        _f("gitleaks.aws-key", "app.py", 99),
        _f("gitleaks.aws-key", "other.py", 3),
    ]
    kept = dedupe(ours, gitleaks)
    assert len(kept) == 2
    assert all(f.rule_id == "gitleaks.aws-key" for f in kept)
    assert {(f.file, f.line) for f in kept} == {("app.py", 99), ("other.py", 3)}


def test_dedupe_empty_existing():
    incoming = [_f("gitleaks.aws-key", "app.py", 1)]
    assert dedupe([], incoming) == incoming


def test_finding_fingerprint_includes_occurrence():
    a = _f("r", "a.py", 1)
    b = _f("r", "a.py", 1)
    b.occurrence = 2
    assert a.fingerprint != b.fingerprint
