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
> gate merges.

### Mapping

| Tooling | Block on | Advisory only |
|---------|----------|---------------|
| `actions/dependency-review-action` (new deps in PR) | High, Critical | Low, Moderate |
| CodeQL Default Setup (PR check) | High, Critical (via `codeql-severity-gate` workflow) | Low, Medium |
| Dependabot security alerts | Security update PRs auto-opened for all severities; **dashboard auto-dismisses Low/Moderate** | n/a |
| Secret scanning | Always blocks (push protection) | n/a |
| Branch protection required checks | `dependency-review`, `codeql-severity-gate` | n/a |

### Why this policy

1. Forces engineers to focus on findings that actually matter.
2. Removes the "wall of red" that causes alert fatigue and pre-approves
   cosmetic regex matches.
3. Aligns with the OWASP Top 10 risk-based prioritisation.
4. Lower severities still surface — we just don't block deploys on them.

### Response time targets

| Severity | Patch / mitigation deadline |
|----------|------------------------------|
| Critical | Same day (with edge-WAF mitigation if needed) |
| High     | Within 7 days |
| Moderate | Within 30 days |
| Low      | Best-effort |

## Tooling configuration

- `dependency-review.yml` — `fail-on-severity: high`
- `codeql-severity-gate.yml` — the workflow that translates CodeQL findings
  into a single severity-gated check. Backed by the
  `code-scanning/alerts` REST API.
- `dependabot.yml` — daily security updates; major bumps held back.

## Manual one-time configuration (org admin)

Two settings that GitHub does not expose via REST and must be applied in the UI:

1. **Code scanning protection rules** — Repo `Settings → Code security →
   Code scanning → Protection rules → Severity to require for protection`
   = **High and above**. (Optional — the `codeql-severity-gate` workflow
   already enforces this; the UI setting is defence in depth.)

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
