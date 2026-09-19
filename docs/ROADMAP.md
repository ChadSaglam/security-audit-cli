# security-audit-cli — Roadmap

> Tracked via GitHub Issues. Each major version = one epic issue with a task checklist.
> Rule: a version ships only when every checkbox in its epic is ticked.

## Versions at a glance

| Version | Codename | Theme | Status |
|---|---|---|---|
| v3.1 | Stability | Fix the 3 known weaknesses | 🟡 in progress |
| v4 | Orchestrator | Wrap gitleaks + Semgrep, unified output | ⬜ planned |
| v5 | CI/CD deep | GitHub Action, GitLab template, PR bot | ⬜ planned |
| v6 | Extensibility | Plugin API, framework packs, rule registry | ⬜ planned |
| v7 | Observability | Dashboard history, trend charts | ⬜ planned |
| v8+ | AI Layer | Local LLM triage, NL queries, auto-fix | ⬜ post-v7 |

## v3.1 — Stability (current)

**Goal**: close the 3 known v3 weaknesses before scaling.

- [ ] Content-based fingerprint (`sha256(rule_id | file | line_content)`) — baseline survives refactoring
- [ ] +12 secret regex rules (Stripe, Slack, Google, Twilio, SendGrid, npm, PyPI, Docker, Discord, Telegram, Mailgun, Heroku)
- [ ] HTML report (`--html` flag, interactive filters, risk gauge)
- [ ] `.security-audit.toml` project config file (skip dirs, rule overrides, custom severities)

**Exit criteria**: `security-audit --html` opens an interactive page; baseline stays valid after 50-line refactor.

## v4 — Orchestrator

- [ ] gitleaks wrapper (`--engine gitleaks`) with normalized findings
- [ ] Semgrep (opengrep) wrapper with YAML rule bridge
- [ ] Unified dedupe: same file+line across engines merges into one finding
- [ ] Engine health report (which engines ran, which skipped)

**Exit criteria**: one command runs 3 engines; overlapping findings appear once.

## v5 — CI/CD deep

- [ ] GitHub Action published (`uses: ChadSaglam/security-audit-cli@v5`)
- [ ] GitLab CI template
- [ ] SARIF auto-upload in Action
- [ ] PR comment bot (summary + top findings)

**Exit criteria**: adding the Action to a repo gates PRs with zero extra config.

## v6 — Extensibility

- [ ] Plugin API (`security_audit.plugins` entry points)
- [ ] Framework packs: Next.js, FastAPI, SvelteKit
- [ ] Public rule registry (community YAML rules)

**Exit criteria**: a third-party repo can ship `pip install security-audit-pack-express`.

## v7 — Observability

- [ ] Scan history store (SQLite locally, JSONL in CI)
- [ ] Web dashboard: risk trend over time
- [ ] Compare two scans (`security-audit diff <report-a> <report-b>`)

**Exit criteria**: CI artifact + `security-audit dashboard` shows the risk curve.

## v8+ — AI Layer (post-v7)

- [ ] Local LLM triage (Ollama/MLX) — false-positive scoring per finding
- [ ] Natural-language query over findings
- [ ] Auto-fix suggestion patches

**Exit criteria**: `security-audit explain <fingerprint>` answers locally, offline.
