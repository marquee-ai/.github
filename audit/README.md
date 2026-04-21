# Nightly Security Audit

Automated drift detection for the `marquee-ai` GitHub organization.

## What it does

Every day at 06:00 UTC, a GitHub Actions workflow runs `run_audit.py` which:

1. Collects the **current state** of the org via the GitHub REST API:
   - Org-level settings (2FA, default repo permission, Actions policy, workflow token default)
   - Installed GitHub Apps (slug, permissions, events)
   - Org rulesets
   - For **every repo**: visibility, webhooks, deploy keys, outside collaborators,
     security features (secret scanning, push protection, Dependabot updates),
     branch protection on the default branch, and open HIGH/CRITICAL alert counts.
2. Compares it to `baseline.json` (the previous run's snapshot).
3. If anything drifted (new app, new webhook, disabled security feature,
   repo flipped to public, alert spike, etc.) it:
   - Opens an issue in this repo with the full drift report
   - Posts to Slack if `SLACK_WEBHOOK` secret is configured
4. Commits the updated `baseline.json` back to the repo.

## What triggers an alert

| Change                                         | Alert |
| ---------------------------------------------- | ----- |
| New GitHub App installed                       | Yes   |
| App permissions changed                        | Yes   |
| New webhook on any repo                        | Yes   |
| New deploy key                                 | Yes   |
| New outside collaborator                       | Yes   |
| Repo visibility changed (private → public)     | Yes   |
| Secret scanning / push protection disabled     | Yes   |
| Branch protection removed or weakened          | Yes   |
| `enforce_admins` disabled                      | Yes   |
| Required status check removed                  | Yes   |
| Alert count spike (≥5 new in one day)          | Yes   |
| Org-level setting changed                      | Yes   |
| New / removed repo                             | Yes   |

## Setup (one-time)

The workflow needs two repo secrets in `marquee-ai/.github`:

1. **`AUDIT_GH_TOKEN`** — a fine-grained PAT (or classic PAT) owned by an org
   owner with at least:
   - `repo` (read)
   - `admin:org` → read
   - `security_events` (read)
   - `administration` → read
2. **`SLACK_WEBHOOK`** *(optional)* — incoming webhook URL for #security
   channel.

Run the workflow once manually (`Actions` → `Nightly Security Audit` → `Run
workflow`) to seed `baseline.json`. The first run never alerts.

## Files

- `run_audit.py` — the audit script
- `baseline.json` — last known good state (auto-updated)
- `last_report.md` — most recent drift report (auto-updated)
