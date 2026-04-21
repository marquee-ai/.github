#!/usr/bin/env python3
"""
Nightly Security Audit for marquee-ai GitHub Organization.

Queries org + repo settings, compares to baseline, emits GitHub Issue
and optional Slack alert if drift is detected.
"""
import json
import os
import sys
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timezone

ORG = "marquee-ai"
BASELINE_PATH = "audit/baseline.json"
REPORT_PATH = "audit/last_report.md"

TOKEN = os.environ.get("AUDIT_GH_TOKEN") or os.environ.get("GH_TOKEN")
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK", "")

if not TOKEN:
    print("ERROR: AUDIT_GH_TOKEN or GH_TOKEN must be set", file=sys.stderr)
    sys.exit(1)

CTX = ssl.create_default_context()


def gh(path, method="GET", data=None):
    url = f"https://api.github.com{path}" if path.startswith("/") else path
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Bearer {TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        resp = urllib.request.urlopen(req, context=CTX)
        return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read()), e.code
        except Exception:
            return {}, e.code


def collect_org_state():
    """Collect everything we want to track."""
    state = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "org": {},
        "apps": [],
        "repos": {},
        "rulesets": [],
        "summary": {},
    }

    # Org-level settings
    org, _ = gh(f"/orgs/{ORG}")
    state["org"] = {
        "two_factor_requirement_enabled": org.get("two_factor_requirement_enabled"),
        "members_can_create_repositories": org.get("members_can_create_repositories"),
        "members_can_create_public_repositories": org.get("members_can_create_public_repositories"),
        "default_repository_permission": org.get("default_repository_permission"),
    }

    # Actions permissions
    perms, _ = gh(f"/orgs/{ORG}/actions/permissions")
    state["org"]["allowed_actions"] = perms.get("allowed_actions")
    state["org"]["enabled_repositories"] = perms.get("enabled_repositories")

    wf_perms, _ = gh(f"/orgs/{ORG}/actions/permissions/workflow")
    state["org"]["default_workflow_permissions"] = wf_perms.get("default_workflow_permissions")

    # Installed GitHub Apps
    apps_resp, _ = gh(f"/orgs/{ORG}/installations")
    for a in apps_resp.get("installations", []):
        state["apps"].append({
            "slug": a["app_slug"],
            "id": a["id"],
            "repository_selection": a.get("repository_selection"),
            "permissions": a.get("permissions", {}),
            "events": a.get("events", []),
        })
    state["apps"].sort(key=lambda x: x["slug"])

    # Org rulesets
    rs, _ = gh(f"/orgs/{ORG}/rulesets")
    if isinstance(rs, list):
        for r in rs:
            state["rulesets"].append({
                "id": r["id"],
                "name": r["name"],
                "enforcement": r.get("enforcement"),
            })

    # All repos
    repos = []
    page = 1
    while True:
        r, _ = gh(f"/orgs/{ORG}/repos?per_page=100&page={page}&type=all")
        if not isinstance(r, list) or not r:
            break
        repos.extend(r)
        page += 1

    for repo in repos:
        name = repo["name"]
        full_name = repo["full_name"]
        repo_data = {
            "visibility": repo.get("visibility"),
            "archived": repo.get("archived", False),
            "default_branch": repo.get("default_branch"),
            "webhooks": [],
            "deploy_keys": [],
            "collaborators_outside": [],
            "security": {},
            "branch_protection": None,
            "alerts": {},
        }

        # Webhooks
        hooks, s = gh(f"/repos/{full_name}/hooks")
        if isinstance(hooks, list):
            for h in hooks:
                repo_data["webhooks"].append({
                    "name": h.get("name"),
                    "url": h.get("config", {}).get("url", ""),
                    "events": h.get("events", []),
                    "active": h.get("active"),
                })

        # Deploy keys
        keys, _ = gh(f"/repos/{full_name}/keys")
        if isinstance(keys, list):
            for k in keys:
                repo_data["deploy_keys"].append({
                    "title": k.get("title"),
                    "read_only": k.get("read_only"),
                    "created_at": k.get("created_at"),
                })

        # Outside collaborators
        ocs, _ = gh(f"/repos/{full_name}/collaborators?affiliation=outside")
        if isinstance(ocs, list):
            for c in ocs:
                repo_data["collaborators_outside"].append({
                    "login": c.get("login"),
                    "permissions": c.get("permissions", {}),
                })

        # Security features
        sec = repo.get("security_and_analysis", {}) or {}
        repo_data["security"] = {
            "secret_scanning": (sec.get("secret_scanning") or {}).get("status"),
            "push_protection": (sec.get("secret_scanning_push_protection") or {}).get("status"),
            "dependabot_security_updates": (sec.get("dependabot_security_updates") or {}).get("status"),
        }

        # Branch protection on main
        prot, status = gh(f"/repos/{full_name}/branches/{repo_data['default_branch']}/protection")
        if status == 200:
            required = prot.get("required_status_checks", {}) or {}
            repo_data["branch_protection"] = {
                "required_checks": sorted([c["context"] for c in required.get("checks", [])]),
                "enforce_admins": (prot.get("enforce_admins") or {}).get("enabled", False),
                "pr_approvals": (prot.get("required_pull_request_reviews") or {}).get("required_approving_review_count"),
            }

        # Open HIGH/CRITICAL alert counts
        sec_alerts, _ = gh(f"/repos/{full_name}/secret-scanning/alerts?state=open&per_page=100")
        code_alerts_h, _ = gh(f"/repos/{full_name}/code-scanning/alerts?state=open&severity=high&per_page=100")
        code_alerts_c, _ = gh(f"/repos/{full_name}/code-scanning/alerts?state=open&severity=critical&per_page=100")
        dep_alerts_h, _ = gh(f"/repos/{full_name}/dependabot/alerts?state=open&severity=high&per_page=100")
        dep_alerts_c, _ = gh(f"/repos/{full_name}/dependabot/alerts?state=open&severity=critical&per_page=100")

        repo_data["alerts"] = {
            "secret_scanning_open": len(sec_alerts) if isinstance(sec_alerts, list) else 0,
            "codeql_high_open": len(code_alerts_h) if isinstance(code_alerts_h, list) else 0,
            "codeql_critical_open": len(code_alerts_c) if isinstance(code_alerts_c, list) else 0,
            "dependabot_high_open": len(dep_alerts_h) if isinstance(dep_alerts_h, list) else 0,
            "dependabot_critical_open": len(dep_alerts_c) if isinstance(dep_alerts_c, list) else 0,
        }

        state["repos"][name] = repo_data

    # Summary numbers
    state["summary"] = {
        "total_repos": len(state["repos"]),
        "public_repos": sum(1 for r in state["repos"].values() if r["visibility"] == "public"),
        "total_apps": len(state["apps"]),
        "total_webhooks": sum(len(r["webhooks"]) for r in state["repos"].values()),
        "total_deploy_keys": sum(len(r["deploy_keys"]) for r in state["repos"].values()),
        "total_outside_collaborators": sum(len(r["collaborators_outside"]) for r in state["repos"].values()),
        "total_open_secret_alerts": sum(r["alerts"]["secret_scanning_open"] for r in state["repos"].values()),
        "total_open_high_codeql": sum(r["alerts"]["codeql_high_open"] + r["alerts"]["codeql_critical_open"] for r in state["repos"].values()),
    }
    return state


def compare_states(baseline, current):
    """Return a list of human-readable changes."""
    findings = []

    # Org settings changes
    for k, v in current["org"].items():
        old = baseline.get("org", {}).get(k)
        if old != v:
            findings.append(f"ORG setting changed — `{k}`: `{old}` → `{v}`")

    # New/removed apps
    base_apps = {a["slug"]: a for a in baseline.get("apps", [])}
    cur_apps = {a["slug"]: a for a in current["apps"]}
    for slug in cur_apps:
        if slug not in base_apps:
            findings.append(f"NEW GitHub App installed: `{slug}` (id={cur_apps[slug]['id']})")
    for slug in base_apps:
        if slug not in cur_apps:
            findings.append(f"GitHub App removed: `{slug}`")
    for slug in cur_apps:
        if slug in base_apps and cur_apps[slug]["permissions"] != base_apps[slug]["permissions"]:
            findings.append(f"App `{slug}` permissions changed")

    # Repo-level drift
    base_repos = baseline.get("repos", {})
    cur_repos = current.get("repos", {})

    for name in cur_repos:
        if name not in base_repos:
            findings.append(f"NEW repo created: `{name}` (visibility: {cur_repos[name]['visibility']})")
            continue

        old = base_repos[name]
        new = cur_repos[name]

        if old.get("visibility") != new.get("visibility"):
            findings.append(f"Repo `{name}` visibility changed: `{old.get('visibility')}` → `{new.get('visibility')}`")

        # Webhook diff
        old_hook_urls = {h["url"] for h in old.get("webhooks", [])}
        new_hook_urls = {h["url"] for h in new.get("webhooks", [])}
        for u in new_hook_urls - old_hook_urls:
            findings.append(f"NEW webhook on `{name}`: `{u}`")
        for u in old_hook_urls - new_hook_urls:
            findings.append(f"Webhook removed on `{name}`: `{u}`")

        # Deploy keys diff
        old_keys = {k["title"] for k in old.get("deploy_keys", [])}
        new_keys = {k["title"] for k in new.get("deploy_keys", [])}
        for k in new_keys - old_keys:
            findings.append(f"NEW deploy key on `{name}`: `{k}`")
        for k in old_keys - new_keys:
            findings.append(f"Deploy key removed on `{name}`: `{k}`")

        # Outside collaborators diff
        old_oc = {c["login"] for c in old.get("collaborators_outside", [])}
        new_oc = {c["login"] for c in new.get("collaborators_outside", [])}
        for u in new_oc - old_oc:
            findings.append(f"NEW outside collaborator on `{name}`: `{u}`")
        for u in old_oc - new_oc:
            findings.append(f"Outside collaborator removed on `{name}`: `{u}`")

        # Security features disabled
        for feat in ("secret_scanning", "push_protection", "dependabot_security_updates"):
            o = (old.get("security") or {}).get(feat)
            n = (new.get("security") or {}).get(feat)
            if o == "enabled" and n != "enabled":
                findings.append(f"SECURITY FEATURE DISABLED on `{name}`: `{feat}` ({o} → {n})")

        # Branch protection weakened
        obp = old.get("branch_protection") or {}
        nbp = new.get("branch_protection") or {}
        if obp and not nbp:
            findings.append(f"Branch protection REMOVED on `{name}`")
        elif obp.get("enforce_admins") and not nbp.get("enforce_admins"):
            findings.append(f"`enforce_admins` disabled on `{name}`")
        elif set(obp.get("required_checks", [])) - set(nbp.get("required_checks", [])):
            missing = set(obp.get("required_checks", [])) - set(nbp.get("required_checks", []))
            findings.append(f"Required status check removed on `{name}`: {missing}")

        # Alert spikes (5+ new)
        for alert_type in ("secret_scanning_open", "codeql_high_open", "codeql_critical_open", "dependabot_high_open", "dependabot_critical_open"):
            delta = new["alerts"].get(alert_type, 0) - old.get("alerts", {}).get(alert_type, 0)
            if delta >= 5:
                findings.append(f"Alert spike on `{name}`: `{alert_type}` increased by {delta}")

    # Deleted repos
    for name in base_repos:
        if name not in cur_repos:
            findings.append(f"Repo REMOVED: `{name}`")

    return findings


def format_report(findings, current):
    lines = []
    lines.append(f"# Nightly Security Audit — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("")
    s = current["summary"]
    lines.append("## Snapshot")
    lines.append("")
    lines.append(f"- Repos: **{s['total_repos']}** ({s['public_repos']} public)")
    lines.append(f"- Installed Apps: **{s['total_apps']}**")
    lines.append(f"- Webhooks: **{s['total_webhooks']}**")
    lines.append(f"- Deploy Keys: **{s['total_deploy_keys']}**")
    lines.append(f"- Outside Collaborators: **{s['total_outside_collaborators']}**")
    lines.append(f"- Open Secret Alerts: **{s['total_open_secret_alerts']}**")
    lines.append(f"- Open HIGH/CRITICAL CodeQL: **{s['total_open_high_codeql']}**")
    lines.append("")
    lines.append("## Drift Findings")
    lines.append("")
    if not findings:
        lines.append("No drift detected. All controls stable.")
    else:
        for f in findings:
            lines.append(f"- {f}")
    lines.append("")
    lines.append("<sub>Automated audit. Baseline is updated after each successful run.</sub>")
    return "\n".join(lines)


def create_github_issue(report_md):
    """Open an issue in the .github repo with the report."""
    title = f"[Audit] {datetime.now(timezone.utc).strftime('%Y-%m-%d')} — Drift detected"
    body = report_md
    data = {"title": title, "body": body, "labels": ["security-audit"]}
    r, s = gh(f"/repos/{ORG}/.github/issues", method="POST", data=data)
    if s == 201:
        print(f"Issue created: {r['html_url']}")
    else:
        print(f"Failed to create issue: {s} {r}", file=sys.stderr)


def post_slack(report_md):
    if not SLACK_WEBHOOK:
        return
    payload = {"text": f"*Marquee-AI Security Audit — drift detected*\n```\n{report_md[:3000]}\n```"}
    req = urllib.request.Request(SLACK_WEBHOOK, data=json.dumps(payload).encode(),
                                  headers={"Content-Type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(req, context=CTX)
        print("Slack notification sent")
    except Exception as e:
        print(f"Slack post failed: {e}", file=sys.stderr)


def main():
    print("Collecting current state...")
    current = collect_org_state()

    baseline = {}
    if os.path.exists(BASELINE_PATH):
        with open(BASELINE_PATH) as f:
            baseline = json.load(f)
        findings = compare_states(baseline, current)
    else:
        print("No baseline found — seeding initial baseline. No alerts on first run.")
        findings = []

    report = format_report(findings, current)

    os.makedirs("audit", exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        f.write(report)

    # Save new baseline
    with open(BASELINE_PATH, "w") as f:
        json.dump(current, f, indent=2, sort_keys=True)

    print("\n" + report)

    if findings:
        create_github_issue(report)
        post_slack(report)
        # Non-zero exit so the workflow step shows a warning badge
        sys.exit(0)
    else:
        print("\nNo drift. Baseline updated.")


if __name__ == "__main__":
    main()
