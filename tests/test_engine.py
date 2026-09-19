"""Smoke tests for v3.1 — run: uv run pytest tests/"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_audit.model import Finding, Report, hash_line  # noqa: E402
from security_audit.engine import (apply_rules, load_rules, load_baseline,  # noqa: E402
                                   mark_baselined, save_baseline)
from security_audit.renderers import render_html, render_json  # noqa: E402


def _make_project(tmp_path: Path, source: str) -> Path:
    f = tmp_path / "app.py"
    f.write_text(source)
    return tmp_path


def test_fingerprint_stable_under_refactor(tmp_path):
    line = 'password = "supersecret123"'
    root = _make_project(tmp_path, f"import os\n{line}\n")
    rules = load_rules()
    r1 = Report()
    apply_rules(r1, root, rules)
    f1 = [f for f in r1.findings if f.rule_id == "secrets.generic"][0]

    (tmp_path / "app.py").write_text(("\n" * 50) + f"import os\n{line}\n")
    r2 = Report()
    apply_rules(r2, root, rules)
    f2 = [f for f in r2.findings if f.rule_id == "secrets.generic"][0]

    assert f1.fingerprint == f2.fingerprint


def test_hash_line_normalizes_whitespace():
    assert hash_line("  x = 1  ") == hash_line("x = 1")


def test_baseline_roundtrip(tmp_path):
    root = _make_project(tmp_path, 'password = "supersecret123"\n')
    rules = load_rules()
    rep = Report()
    apply_rules(rep, root, rules)
    mark_baselined(rep, set())
    assert rep.active(), "expected active findings before baseline"

    path = save_baseline(root, rep, reason="test")
    baseline = load_baseline(root)

    rep2 = Report()
    apply_rules(rep2, root, rules)
    mark_baselined(rep2, baseline)
    assert not rep2.active(), "all findings should be baselined"
    assert json.loads(path.read_text())["accepted"]


def test_html_report_contains_data(tmp_path):
    root = _make_project(tmp_path, 'password = "supersecret123"\n')
    rep = Report()
    rep.stats = {"path": str(root), "started": "now", "files": 1, "seconds": 0}
    apply_rules(rep, root, load_rules())
    html = render_html(rep, "3.1.0")
    assert "secrets.generic" in html
    assert '"risk"' in html


def test_json_report_serializes(tmp_path):
    root = _make_project(tmp_path, 'password = "supersecret123"\n')
    rep = Report()
    rep.stats = {"path": str(root)}
    apply_rules(rep, root, load_rules())
    payload = render_json(rep, "3.1.0")
    assert json.dumps(payload)
    assert payload["findings"][0]["fingerprint"]
