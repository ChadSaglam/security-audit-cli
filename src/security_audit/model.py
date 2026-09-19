"""Data model: findings, report, risk scoring, baseline fingerprints."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# Role weights: test findings count 10x less, tooling 5x less.
ROLE_WEIGHT = {"production": 1.0, "test": 0.1, "tooling": 0.2}


@dataclass
class Finding:
    rule_id: str
    check: str
    severity: str
    file: str
    line: int
    message: str
    remediation: str = ""
    role: str = "production"          # production | test | tooling
    baselined: bool = False

    @property
    def fingerprint(self) -> str:
        """Stable identity for baseline matching (rule + normalized file)."""
        raw = f"{self.rule_id}:{self.file}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def active(self) -> list[Finding]:
        """Findings not accepted in the baseline."""
        return [f for f in self.findings if not f.baselined]

    def counts(self, active_only: bool = False) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in (self.active() if active_only else self.findings):
            c[f.severity] += 1
        return c

    def risk_score(self) -> int:
        """0 (nothing) → 100 (severe). Role-weighted, active findings only."""
        raw = sum(SEV_WEIGHT[f.severity] * ROLE_WEIGHT.get(f.role, 1.0)
                  for f in self.active())
        return min(100, round(raw))

    def risk_label(self) -> str:
        s = self.risk_score()
        for threshold, label in ((50, "SEVERE"), (25, "ELEVATED"),
                                 (10, "MODERATE"), (1, "LOW")):
            if s >= threshold:
                return label
        return "MINIMAL"
