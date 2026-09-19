# security-audit-cli

A pluggable security audit CLI for web projects. YAML **rule engine**, 
**baseline** support, **git-diff** mode, role-aware risk scoring, and 
**Markdown / JSON / SARIF** reports.

> ⚠️ This is a **scanning tool**, not protection by itself. Regex-based static
> analysis produces false positives — verify every finding manually.
> A clean run does **not** mean the project is secure.

## Why v3

- **Declarative rules**: every check is a YAML rule in `default_rules.yml`;
  teams add their own via `--rules my-rules.yml`
- **Baseline**: `.security-audit-baseline.json` accepts known findings so
  `--fail-on HIGH` only fails CI on *new* issues
- **Incremental scans**: `--since main` scans only files changed in your PR
- **Role classification**: production / test / tooling separated and
  differently weighted in the risk score (test findings count ×0.1)
- **True integrations**: SARIF → GitHub Code Scanning; `--open` opens the
  report on macOS

## Install

```bash
pipx install security-audit-cli            # after PyPI release
# during development:
uv tool install '.[deps-audit]'
```

## Usage

```bash
security-audit                             # full scan of current dir
security-audit --since main                # only my PR's changes
security-audit --update-baseline           # accept current findings
security-audit --rules org-rules.yml       # extend with custom rules
security-audit --fail-on MEDIUM            # stricter gate
security-audit --sarif results.sarif       # GitHub Code Scanning
```

## Custom rules (extensibility)

```yaml
rules:
  - id: org.no-fetch-credentials
    check: Input Validation
    severity: HIGH
    pattern: "credentials:\\s*['\\\"]include"
    message: fetch() with include credentials
    remediation: Prefer same-origin only; reason why CORS + cookies.
```

`security-audit --rules org-rules.yml` merges these with the bundled set.

## CI (GitHub Actions)

```yaml
- uses: actions/checkout@v4
- run: pipx install security-audit-cli
- run: security-audit --path . --since origin/main --fail-on HIGH
```

Upload SARIF for inline PR annotations:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
  if: always()
- run: security-audit --sarif results.sarif  # before upload step
```

## Roadmap

- [ ] Publish to PyPI
- [ ] Baseline expire dates ("accept until 2026-12-31")
- [ ] HTML report
- [ ] Framework packs (Next.js, FastAPI, SvelteKit)
- [ ] Wrapper integrations (gitleaks, Trivy) with unified scoring
