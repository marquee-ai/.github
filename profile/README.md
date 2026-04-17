# marquee-ai

## Security Policy

All repositories in this organization enforce:

- **Dependency Review** — PRs that introduce HIGH or CRITICAL vulnerabilities are blocked from merging
- **License Compliance** — GPL-3.0 and AGPL-3.0 dependencies are denied
- **Secret Scanning** — Push protection enabled to prevent secrets from being committed
- **CodeQL** — Automated code scanning for security vulnerabilities

### For New Repositories

When creating a new repo, go to Actions > New Workflow and select the **Dependency Review** starter workflow. The org-level ruleset will enforce the check automatically.
