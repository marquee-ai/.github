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

## Layered enforcement — why CodeQL alone is not the answer

CodeQL, Dependabot and secret scanning each look at a *different* class of
problem. They are complementary, not overlapping. The gate is enforced in a
different layer for each of them, and that's intentional:

| Class | Tool | Where high/critical-only is enforced | Lives in |
|-------|------|--------------------------------------|----------|
| Vulnerable source code (XSS, SQLi, path traversal, hardcoded creds in code, etc.) | **CodeQL** Default Setup | `codeql-severity-gate.yml` (PR-time, blocks merge) | this repo |
| Vulnerable third-party dependencies introduced by the PR | **`actions/dependency-review-action`** | `dependency-review.yml` (PR-time, `fail-on-severity: high`, blocks merge) | this repo |
| Pre-existing vulnerable deps not yet patched on default branch | **Dependabot alerts** | Auto-opened security update PRs (daily) + nightly drift audit | this repo + org |
| Leaked secrets in committed code | **Secret scanning push protection** | Blocks at push time — the commit never lands. Always critical. | GitHub-native |
| Repo-wide drift across all three signals | **Nightly cross-tool sweep** | `security-audit-nightly.yml` opens an issue if anything is high/critical | this repo |

### Why CodeQL doesn't try to gate Dependabot + secrets in the same workflow

The default workflow `GITHUB_TOKEN` cannot read the Dependabot alerts or
secret-scanning alerts REST endpoints (those endpoints require a
fine-grained PAT with the `Dependabot alerts: read` and
`Secret scanning alerts: read` permissions, which are not in the
`GITHUB_TOKEN` permission model). Pretending otherwise — wrapping calls in
try/catch and silently swallowing 403s — would create a false sense of
coverage. We chose explicit layering instead:

- **PR-time blocking** stays in CodeQL (gate workflow) and dependency-review.
- **Default-branch + repo-wide drift** is detected nightly by
  `security-audit-nightly.yml`, which authenticates with the org-admin
  `AUDIT_GH_TOKEN` PAT and opens a drift issue if anything high/critical is
  open — covering CodeQL, Dependabot **and** secret scanning in one place.
- **Secrets at push time** are caught by GitHub's native push protection —
  the commit physically does not enter the repo, so PR-time scanning is
  redundant.

Together these layers give the same end-to-end coverage a single mega-gate
would, but built on permissions that actually exist.

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
- `security-audit-nightly.yml` — runs daily 03:17 UTC; uses
  `AUDIT_GH_TOKEN`; opens a `security-drift` issue when anything
  high/critical is open across CodeQL + Dependabot + secret scanning.
  Auto-closes the issue on the next clean run.
- `dependabot.yml` — daily security updates; weekly Actions/Docker; major
  bumps held back.
- Push protection — enabled at org level, blocks secrets at push time.

## Manual one-time configuration (org admin)

Three settings that GitHub does not expose via REST and must be applied
in the UI / settings:

1. **`AUDIT_GH_TOKEN` repo secret** — fine-grained PAT scoped to all repos
   with read on `Dependabot alerts`, `Secret scanning alerts`, `Code
   scanning alerts`, `Issues: write`, `Metadata: read`. Required for
   `security-audit-nightly.yml`.

2. **Code scanning protection rules** — Repo `Settings → Code security →
   Code scanning → Protection rules → Severity to require for protection`
   = **High and above**. (Defence in depth — the gate workflow already
   enforces this.)

3. **Dependabot auto-triage rule** — Repo `Settings → Code security →
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
