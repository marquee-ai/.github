## Summary

<!-- 1-3 bullets: what changed and why. -->



## Type of change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Security fix (closes a CVE / hardens a control)
- [ ] Migration / refactor
- [ ] Documentation only

## Security impact

> Every PR must answer this section. If "none", say "none and why".

- **Threat surface added/removed:**
- **Auth / authorization touched?** (yes/no — explain)
- **New dependencies?** (list each + why; flag any without active maintenance)
- **Secrets handled?** (yes/no — explain how they're sourced)
- **External network calls?** (list endpoints; SSRF guard in place?)

## OWASP Top 10 (2021) coverage

Tick every control this PR materially affects:

- [ ] A01 Broken Access Control
- [ ] A02 Cryptographic Failures
- [ ] A03 Injection
- [ ] A04 Insecure Design
- [ ] A05 Security Misconfiguration
- [ ] A06 Vulnerable & Outdated Components
- [ ] A07 Identification & Authentication Failures
- [ ] A08 Software & Data Integrity Failures
- [ ] A09 Security Logging & Monitoring Failures
- [ ] A10 Server-Side Request Forgery (SSRF)

## Test plan

<!-- Concrete commands or manual steps a reviewer can re-run. -->

- [ ] Local build green: `npm run build` (or equivalent)
- [ ] Type-check green: `npm run type-check`
- [ ] Lint green: `npm run lint`
- [ ] Unit tests green
- [ ] Manual smoke test (describe):

## Rollback plan

<!-- One sentence: what does "undo" look like? -->



## Screenshots / logs (if UI or runtime change)



## Reviewer checklist

- [ ] CODEOWNERS reviewer present
- [ ] CI green (or every red explicitly justified in PR body)
- [ ] No secrets, tokens, or PII committed
- [ ] Lockfile updates committed alongside `package.json` changes
- [ ] Migration: parallel-tree pattern preserved (don't delete the old path until cutover PR)
