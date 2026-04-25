# Dependabot — org-wide configuration

This file replaces ad-hoc `dependabot.yml` definitions across the org.

## What it does

| Ecosystem | Frequency | Grouping | Major bumps |
|---|---|---|---|
| npm | Daily | Prod + dev grouped separately | Held back |
| GitHub Actions | Weekly | All actions in one PR | Held back |
| Docker | Weekly | All Dockerfiles in one PR | Held back |

## Why daily for npm

- **CVE response time matters.** Most published JS CVEs ship a patch within hours; we want a PR within 24h, not 7 days.
- **Grouping** keeps the noise sane — typical week is 1–3 PRs per repo.
- **Major bumps held back** ensures Dependabot never tries to upgrade us from Next 14 → Next 16 unattended.

## Reviewer

`luiza-prog` is auto-assigned. Re-route freely per PR.

## How to use across repos

This file lives in the org `.github` repo. GitHub auto-applies it to every repo in `marquee-ai` that has a `package.json` / `Dockerfile` / `.github/workflows/*.yml` and does **not** have its own `dependabot.yml`. Repos with their own config win locally.

## OWASP Top 10 alignment

- **A06** Vulnerable & Outdated Components — primary control.
- **A08** Software & Data Integrity — dependabot updates ship with regenerated lockfiles, and branch protection requires CI green before merge, preserving the integrity chain.

## Auditing

Weekly review: open `https://github.com/orgs/marquee-ai/security/advisories` to confirm no Critical advisories are sitting open longer than 24h. The Saturday `audit-org-security.py` script captures this in its report.
