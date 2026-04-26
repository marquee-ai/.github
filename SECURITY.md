# Security Policy

## Reporting a vulnerability

Please email **security@themarquee.ai** (or open a GitHub Security Advisory
draft on this repository). Do **not** open a public issue.

We aim to acknowledge within 24 hours and to ship a fix or mitigation within
the windows below.

## Severity policy — what blocks a merge vs what is advisory

This repository (and every other repo in `marquee-ai`) follows a single,
consistent rule:

> **PRs are blocked only on HIGH or CRITICAL severity findings.**
> Lower severities are visible in the Security tab and tracked, but do not
> gate merges. **Any leaked secret is treated as critical regardless of
> tool-assigned severity.**

## Layered enforcement

CodeQL, Dependabot and secret scanning each look at a *different* class of
problem. They are complementary, not overlapping. The gate is enforced in a
different layer for each — that is intentional:

| Class | Tool | Where high/critical-only is enforced |
|-------|------|--------------------------------------|
| Vulnerable source code (XSS, SQLi, path traversal, hardcoded creds in code, etc.) | **CodeQL** Default Setup | `codeql-severity-gate.yml` (PR-time, blocks merge) |
| New vulnerable dependency introduced by a PR | **`actions/dependency-review-action`** | `dependency-review.yml` (PR-time, `fail-on-severity: high`, blocks merge) |
| Pre-existing vulnerable deps on default branch | **Dependabot** | Auto-opened security update PRs (daily) |
| Leaked secrets in committed code | **Secret scanning push protection** | Blocks at push time — the commit never lands. Always treated as critical. |

Each tool covers its own class with its own native enforcement. There is no
combined "mega-gate" workflow because the default workflow `GITHUB_TOKEN`
cannot read the Dependabot or secret-scanning alert APIs (those require a
PAT). The four layers above already enforce the policy end-to-end without
needing one.

### Response time targets

| Severity | Patch / mitigation deadline |
|----------|------------------------------|
| Critical (incl. any leaked secret) | Same day (with edge-WAF mitigation if needed) |
| High     | Within 7 days |
| Moderate | Within 30 days |
| Low      | Best-effort |

## Tooling configuration

- `dependency-review.yml` — `fail-on-severity: high`. Blocks PRs that
  introduce new high/critical CVEs in deps.
- `codeql-severity-gate.yml` — translates CodeQL findings into a single
  severity-gated PR check. Backed by `code-scanning/alerts`.
- `dependabot.yml` — daily security updates; weekly Actions/Docker; major
  bumps held back.
- Push protection — enabled at org level, blocks secrets at push time.

## Manual one-time configuration (org admin)

Two settings that GitHub does not expose via REST and must be applied
in the UI:

1. **Code scanning protection rules** — Repo `Settings → Code security →
   Code scanning → Protection rules → Severity to require for protection`
   = **High and above**. (Defence in depth — the gate workflow already
   enforces this.)

2. **Dependabot auto-triage rule** — Repo `Settings → Code security →
   Dependabot → Custom auto-triage rules → New rule`:
   - Name: `auto-dismiss-low-moderate`
   - Severity: Low, Moderate
   - Action: Auto-dismiss

## Rollback

If a misclassified finding is blocking a critical fix, the security lead
(`@luiza-prog`) can:

1. Override the `codeql-severity-gate` workflow with the
   `codeql-severity-gate-override` label (defined in repo settings), **or**
2. Dismiss the alert with a documented reason (false positive / used in tests
   / inaccessible at runtime).

Both actions are auditable and reviewed in the next weekly security audit.
