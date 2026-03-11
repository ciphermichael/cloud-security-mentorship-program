#!/usr/bin/env python3
"""
GitHub Security Monitoring Platform
Week 8 Project — Cloud Security Mentorship Programme
Monitors GitHub orgs for: secret exposure, dependency vulns, audit-log anomalies.
"""
import sys, os, re, json, argparse, logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict
import requests

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
BASE_URL     = "https://api.github.com"


# ─── CUSTOM SECRET PATTERNS ───────────────────────────────────────────────────
SECRET_PATTERNS = {
    "AWS_ACCESS_KEY":    re.compile(r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])"),
    "AWS_SECRET_KEY":    re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    "GITHUB_TOKEN":      re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"),
    "SLACK_TOKEN":       re.compile(r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}"),
    "STRIPE_KEY":        re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "TWILIO_TOKEN":      re.compile(r"SK[0-9a-fA-F]{32}"),
    "GOOGLE_API_KEY":    re.compile(r"AIza[0-9A-Za-z\\-_]{35}"),
    "SENDGRID_API_KEY":  re.compile(r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9_-]{43}"),
    "PRIVATE_KEY":       re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "DATABASE_URL":      re.compile(r"(?i)(postgres|mysql|mongodb)://[^\s\"']+"),
}

HEADERS = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}


def _gh(path: str, params: dict = None) -> dict | list:
    """Make a GitHub API call."""
    url = f"{BASE_URL}{path}"
    resp = requests.get(url, headers=HEADERS, params=params or {}, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _gh_paginate(path: str, params: dict = None) -> list:
    """Paginate through all pages of a GitHub API endpoint."""
    results, page = [], 1
    while True:
        p = {**(params or {}), "per_page": 100, "page": page}
        data = _gh(path, p)
        if not data:
            break
        results.extend(data if isinstance(data, list) else [data])
        if len(data) < 100:
            break
        page += 1
    return results


# ─── AUDIT LOG MONITORING ─────────────────────────────────────────────────────
HIGH_RISK_AUDIT_ACTIONS = {
    "org.create_actions_secret":   "CRITICAL",
    "org.remove_member":           "HIGH",
    "org.update_member":           "MEDIUM",
    "repo.create":                 "INFO",
    "protected_branch.policy_override": "HIGH",
    "org.disable_two_factor_requirement": "CRITICAL",
    "oauth_application.create":   "HIGH",
    "hook.create":                 "HIGH",
    "repo.archived":               "MEDIUM",
    "repo.destroy":                "CRITICAL",
    "team.add_repository":        "MEDIUM",
}


def audit_org_settings(org: str) -> List[Dict]:
    """Check GitHub org-level security settings."""
    findings = []
    try:
        org_data = _gh(f"/orgs/{org}")
        if not org_data.get("two_factor_requirement_enabled"):
            findings.append({
                "severity": "CRITICAL",
                "check_id": "GH-ORG-001",
                "resource": f"github.com/{org}",
                "description": "Org does NOT enforce 2FA — members can join without MFA",
                "remediation": "Settings → Security → Require 2FA for all members",
            })
        if not org_data.get("default_repository_permission") == "none":
            findings.append({
                "severity": "MEDIUM",
                "check_id": "GH-ORG-002",
                "resource": f"github.com/{org}",
                "description": f"Default repo permission is '{org_data.get('default_repository_permission')}' (should be 'none')",
                "remediation": "Set base permissions to 'None' and grant access explicitly per team.",
            })
        advanced_security = org_data.get("advanced_security_enabled_for_new_repositories", False)
        if not advanced_security:
            findings.append({
                "severity": "HIGH",
                "check_id": "GH-ORG-003",
                "resource": f"github.com/{org}",
                "description": "GitHub Advanced Security NOT enabled by default for new repos",
                "remediation": "Enable Advanced Security (Secret Scanning + Code Scanning) org-wide.",
            })
    except requests.HTTPError as e:
        logger.warning(f"Could not audit org {org}: {e}")
    return findings


def scan_repos(org: str) -> List[Dict]:
    """Scan all org repos for missing security settings."""
    findings = []
    try:
        repos = _gh_paginate(f"/orgs/{org}/repos", {"type": "all"})
        logger.info(f"Scanning {len(repos)} repositories in {org}")

        for repo in repos:
            name = repo["full_name"]
            archived = repo.get("archived", False)
            if archived:
                continue

            # Secret scanning
            if not repo.get("security_and_analysis", {}).get("secret_scanning", {}).get("status") == "enabled":
                findings.append({
                    "severity": "HIGH", "check_id": "GH-REPO-001",
                    "resource": f"github.com/{name}",
                    "description": "Secret Scanning is NOT enabled on this repository",
                    "remediation": "Settings → Code security → Enable Secret Scanning",
                })

            # Branch protection on default branch
            default_branch = repo.get("default_branch", "main")
            try:
                bp = _gh(f"/repos/{name}/branches/{default_branch}/protection")
                if not bp.get("required_pull_request_reviews"):
                    findings.append({
                        "severity": "MEDIUM", "check_id": "GH-REPO-002",
                        "resource": f"github.com/{name}/{default_branch}",
                        "description": "No required PR reviews on default branch",
                        "remediation": "Enable branch protection with at least 1 required reviewer.",
                    })
                if not bp.get("required_status_checks"):
                    findings.append({
                        "severity": "MEDIUM", "check_id": "GH-REPO-003",
                        "resource": f"github.com/{name}/{default_branch}",
                        "description": "No required status checks (CI/CD gates) on default branch",
                        "remediation": "Add required status checks so PRs can't merge without passing security scans.",
                    })
            except requests.HTTPError:
                findings.append({
                    "severity": "HIGH", "check_id": "GH-REPO-004",
                    "resource": f"github.com/{name}/{default_branch}",
                    "description": f"Default branch '{default_branch}' has NO branch protection rules",
                    "remediation": "Enable branch protection immediately to prevent force-pushes and unreviewed merges.",
                })

    except requests.HTTPError as e:
        logger.warning(f"Repo scan error: {e}")
    return findings


def scan_audit_log(org: str, hours: int = 24) -> List[Dict]:
    """Scan GitHub audit log for suspicious events."""
    findings = []
    since_ts = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp() * 1000)
    try:
        events = _gh_paginate(f"/orgs/{org}/audit-log",
                               {"include": "all", "phrase": f"created:>{since_ts}"})
        for ev in events:
            action = ev.get("action", "")
            if action in HIGH_RISK_AUDIT_ACTIONS:
                severity = HIGH_RISK_AUDIT_ACTIONS[action]
                actor = ev.get("actor", "unknown")
                findings.append({
                    "severity": severity, "check_id": f"GH-AUDIT-{action.replace('.','_').upper()}",
                    "resource": f"github.com/{org}",
                    "description": f"Audit event '{action}' performed by @{actor}",
                    "remediation": f"Review this action: {ev.get('@timestamp','')} — actor: @{actor}",
                    "raw_event": {k: v for k, v in ev.items() if k in ("action","actor","repo","created_at")},
                })
    except requests.HTTPError as e:
        logger.warning(f"Audit log error (requires org owner): {e}")
    return findings


def scan_workflow_permissions(org: str) -> List[Dict]:
    """Detect overly permissive GitHub Actions workflow settings."""
    findings = []
    try:
        perms = _gh(f"/orgs/{org}/actions/permissions")
        if perms.get("allowed_actions") == "all":
            findings.append({
                "severity": "HIGH", "check_id": "GH-ACTIONS-001",
                "resource": f"github.com/{org}/settings/actions",
                "description": "GitHub Actions allows ALL actions including from external forks",
                "remediation": "Restrict to 'selected' actions — allow only verified/own-org actions.",
            })
    except Exception as e:
        logger.debug(f"Actions permissions check: {e}")
    return findings


def main():
    parser = argparse.ArgumentParser(description="GitHub Security Monitoring Platform")
    parser.add_argument("--org",     required=True, help="GitHub organisation name")
    parser.add_argument("--hours",   type=int, default=24)
    parser.add_argument("--output",  choices=["console","json"], default="console")
    args = parser.parse_args()

    if not GITHUB_TOKEN:
        logger.error("Set GITHUB_TOKEN environment variable")
        sys.exit(1)

    logger.info(f"Scanning GitHub org: {args.org}")
    all_findings = []
    all_findings.extend(audit_org_settings(args.org))
    all_findings.extend(scan_repos(args.org))
    all_findings.extend(scan_audit_log(args.org, args.hours))
    all_findings.extend(scan_workflow_permissions(args.org))

    if args.output == "json":
        print(json.dumps(all_findings, indent=2))
        return

    sev_icons = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","INFO":"🔵"}
    print(f"\n🐙 GitHub Security Scan — {args.org}\n{'='*60}")
    print(f"Total findings: {len(all_findings)}\n")
    for f in sorted(all_findings, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(x["severity"],9)):
        icon = sev_icons.get(f["severity"],"•")
        print(f"{icon} [{f['severity']}] {f['check_id']}")
        print(f"   {f['resource']}")
        print(f"   Issue: {f['description']}")
        print(f"   Fix:   {f['remediation']}\n")

if __name__ == "__main__":
    main()
