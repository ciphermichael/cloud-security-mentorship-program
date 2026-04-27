# Week 07 — GitHub Supply Chain Security

**Phase 2: Identity Security | Project: 07-github-security-monitoring**

---

## Learning Objectives

By the end of this week you will be able to:

- Explain supply chain attack vectors and real-world examples (SolarWinds, XZ Utils, Log4Shell)
- Audit a GitHub organization's security posture using the GitHub API
- Enable and interpret GitHub Advanced Security: secret scanning, code scanning, dependency review
- Detect exposed secrets and compromised tokens using GitHub audit logs
- Monitor GitHub Actions workflow permissions for excessive access
- Write a Python org security auditor using PyGitHub

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | Supply chain attacks — taxonomy, SolarWinds deep-dive, SLSA framework | 2 hrs |
| Tue | GitHub security features — GHAS, Dependabot, secret scanning, code scanning | 2 hrs |
| Wed | GitHub API + audit log — events, webhook delivery, token scopes | 2 hrs |
| Thu | Build the org auditor — 2FA, branch protection, secret scanning, outside collaborators | 2 hrs |
| Fri | Add audit log streaming, detect token compromise patterns | 2 hrs |
| Sat | Full README, architecture diagram, push to GitHub | 3 hrs |
| Sun | Mentor review, mock interview on supply chain security | 1 hr |

---

## Topics Covered

### Supply Chain Attack Taxonomy

**Dependency confusion** — publish a malicious package with the same name as an internal private package. Package managers may prefer the public registry.

**Typosquatting** — `requets` instead of `requests`, `colourama` instead of `colorama`.

**Compromised maintainer account** — attacker takes over a legitimate package author and pushes malicious code.

**Malicious Actions** — a GitHub Action that exfiltrates `GITHUB_TOKEN` or repository secrets via environment variables.

**CI/CD pipeline injection** — if a pull request from a fork can modify `.github/workflows/`, the workflow may execute with write access to your repository.

**Real examples:**
- **SolarWinds (2020)** — Sunburst backdoor compiled into the Orion software build pipeline
- **XZ Utils (2024)** — Two-year social engineering campaign to insert a backdoor in the xz compression library
- **event-stream (2018)** — Malicious code injected into a popular npm package via a compromised maintainer

### GitHub Security Configuration Checklist

| Setting | Location | Risk if Missing |
|---------|----------|----------------|
| 2FA required for all members | Org → Settings → Security | Account takeover → code tampering |
| Branch protection on `main` | Repo → Settings → Branches | Direct pushes bypass reviews |
| Required PR reviews | Branch protection rule | Single person can merge malicious code |
| Secret scanning | Repo → Security → Code security | Credentials pushed to repo persist |
| Dependabot alerts | Repo → Security | Vulnerable dependencies undetected |
| Dependabot security updates | Repo → Security | No auto-patches for CVEs |
| Actions permissions → Read-only GITHUB_TOKEN | Repo → Settings → Actions | Workflow can write to repo/packages |
| Require signed commits | Branch protection | Anyone can impersonate commits |
| Outside collaborators review | Org → Settings | Ex-employees retain access |

### GitHub Actions Security Risks

```yaml
# DANGEROUS: Workflow triggered by pull_request_target with checkout of PR head
# This runs with write permissions in the context of the base repo
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # DANGEROUS
```

```yaml
# SAFE: Limit token permissions explicitly
on: [push]
jobs:
  build:
    permissions:
      contents: read      # minimal — cannot write
      id-token: write     # only if OIDC needed
    steps:
      - uses: actions/checkout@v4  # pins to commit SHA, not tag
```

---

## Instructor Mentoring Guidance

**Week 7 connects identity security to software delivery.** Most students haven't thought about the security of their own GitHub usage. Walk them through their own repos before they build the auditor — they'll likely find issues immediately.

**Common mistakes:**
- Using a personal access token with `repo:full` scope for the auditor — use a fine-grained token with only what's needed
- Not paginating API results — GitHub returns max 100 per page
- Missing that GitHub Advanced Security is only free for public repos on GitHub Free — they need GitHub Enterprise or a free trial for private repos

**Mentoring session agenda (60 min):**
1. (10 min) Show real-world example: scan GitHub for exposed AWS keys using `git log --all -p | grep -i "AKIA"`
2. (20 min) Code review of their org auditor — token handling, rate limiting, output format
3. (20 min) Mock interview: "Walk me through how you'd investigate a suspected GitHub token compromise"
4. (10 min) Preview Phase 3 — incident response

---

## Hands-on Lab

### Lab 1: Enable Secret Scanning and Test It

```bash
# Push a test secret to trigger GitHub secret scanning
# IMPORTANT: Use a revoked test credential — never push real secrets

# Create a test file with a fake AWS key pattern
cat > test-credentials.txt << 'EOF'
# These are intentionally fake/revoked test credentials
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF

git add test-credentials.txt
git commit -m "test: secret scanning trigger (fake credentials)"
git push

# Check GitHub → Security → Secret scanning alerts
# GitHub should detect the AWS key pattern within minutes
# Then remove the commit and revoke any real key that matches

# Clean up
git rm test-credentials.txt
git commit -m "chore: remove test file"
git push
```

### Lab 2: Audit Organization Security via API

```bash
# Install dependencies
pip install PyGithub requests

# Set your GitHub token (fine-grained, read:org scope)
export GITHUB_TOKEN="github_pat_..."
export GITHUB_ORG="your-org-name"
```

```python
# scripts/audit_org.py — quick standalone audit
from github import Github
import os

g = Github(os.environ['GITHUB_TOKEN'])
org = g.get_organization(os.environ['GITHUB_ORG'])

print(f"\n=== GitHub Org Security Audit: {org.login} ===\n")

# 2FA enforcement
print(f"2FA Required: {org.two_factor_requirement_enabled}")

# Member count
members = list(org.get_members())
print(f"Total members: {len(members)}")

# Outside collaborators
outside = list(org.get_outside_collaborators())
print(f"Outside collaborators: {len(outside)}")

# Repo-level checks
for repo in org.get_repos():
    if repo.private:
        protection = None
        try:
            protection = repo.get_branch('main').get_protection()
        except Exception:
            print(f"  [WARN] {repo.name}: main branch not protected")
```

---

## Weekly Assignment — GitHub Security Monitor

Build a comprehensive GitHub organization security monitor that:

1. **Org-level audit** — 2FA, SAML, verified domains, outside collaborators
2. **Repository scan** — branch protection, secret scanning, Dependabot, Actions permissions
3. **Audit log analysis** — detect suspicious events (token revocation, outside collaborator additions, bulk deletions)
4. **Secret exposure detection** — query GitHub secret scanning alerts API

```python
# src/monitor.py
import os
import json
from datetime import datetime, timezone
from pathlib import Path
from github import Github, GithubException
from dataclasses import dataclass, asdict

@dataclass
class SecurityFinding:
    severity: str
    category: str
    repository: str
    check: str
    description: str
    remediation: str

class GitHubSecurityMonitor:

    def __init__(self, token: str, org_name: str):
        self.g = Github(token, per_page=100)
        self.org = self.g.get_organization(org_name)
        self.findings: list[SecurityFinding] = []

    def _add(self, **kwargs):
        self.findings.append(SecurityFinding(**kwargs))

    # ── Org-Level Checks ──────────────────────────────────────────────────────

    def check_org_settings(self):
        print("[*] Checking org-level settings...")
        if not self.org.two_factor_requirement_enabled:
            self._add(
                severity='CRITICAL',
                category='Authentication',
                repository='<org>',
                check='2FA Enforcement',
                description='Organization does not require 2FA for all members.',
                remediation='Enable: Org → Settings → Security → Require 2FA'
            )

        outside = list(self.org.get_outside_collaborators())
        if outside:
            self._add(
                severity='MEDIUM',
                category='Access Control',
                repository='<org>',
                check='Outside Collaborators',
                description=f'{len(outside)} outside collaborators have repo access: '
                            f'{[u.login for u in outside[:5]]}',
                remediation='Review and remove collaborators who no longer need access.'
            )

    # ── Repository-Level Checks ───────────────────────────────────────────────

    def check_repos(self):
        print("[*] Checking repositories...")
        for repo in self.org.get_repos():
            self._check_branch_protection(repo)
            self._check_security_features(repo)
            self._check_actions_permissions(repo)

    def _check_branch_protection(self, repo):
        for branch_name in ('main', 'master'):
            try:
                branch = repo.get_branch(branch_name)
            except GithubException:
                continue
            try:
                protection = branch.get_protection()
                # Check required reviews
                review = protection.required_pull_request_reviews
                if review is None:
                    self._add(
                        severity='HIGH',
                        category='Code Review',
                        repository=repo.name,
                        check='PR Reviews Required',
                        description=f'Branch {branch_name} has no required PR reviews.',
                        remediation='Enable required reviewers in branch protection rules.'
                    )
                # Check status checks
                if not protection.required_status_checks:
                    self._add(
                        severity='MEDIUM',
                        category='CI/CD Security',
                        repository=repo.name,
                        check='Status Checks Required',
                        description=f'Branch {branch_name} requires no passing status checks.',
                        remediation='Require security scan CI jobs to pass before merge.'
                    )
            except GithubException:
                self._add(
                    severity='HIGH',
                    category='Branch Protection',
                    repository=repo.name,
                    check='Branch Protection Missing',
                    description=f'Branch {branch_name} has no protection rules.',
                    remediation='Create a branch protection rule with: require PRs, '
                                'require status checks, prevent force push.'
                )

    def _check_security_features(self, repo):
        try:
            alerts = list(repo.get_vulnerability_alert())
        except Exception:
            alerts = []
        # Check Dependabot alerts
        if repo.private:
            vuln_enabled = len(alerts) >= 0  # API call succeeded = feature enabled
        # Check secret scanning (available via API for GHAS)
        try:
            secret_alerts = list(repo.get_secret_scanning_alerts())
            if secret_alerts:
                self._add(
                    severity='CRITICAL',
                    category='Secret Exposure',
                    repository=repo.name,
                    check='Active Secret Scanning Alerts',
                    description=f'{len(secret_alerts)} unresolved secret scanning alerts.',
                    remediation='Revoke all exposed secrets immediately. '
                                'Rotate credentials and audit who had access.'
                )
        except Exception:
            pass

    def _check_actions_permissions(self, repo):
        try:
            perms = repo.get_workflow_run_default_permissions()
            if perms.get('default_workflow_permissions') == 'write':
                self._add(
                    severity='HIGH',
                    category='Actions Security',
                    repository=repo.name,
                    check='GITHUB_TOKEN Write Default',
                    description='Actions GITHUB_TOKEN defaults to write permissions.',
                    remediation='Change to read-only default: '
                                'Repo → Settings → Actions → General → '
                                '"Read repository contents and packages permissions"'
                )
        except Exception:
            pass

    # ── Audit Log Analysis ────────────────────────────────────────────────────

    def check_audit_log(self, days: int = 7):
        print(f"[*] Analyzing audit log (last {days} days)...")
        suspicious_actions = {
            'org.remove_member': ('HIGH', 'Member Removed from Org'),
            'org.add_outside_collaborator': ('HIGH', 'Outside Collaborator Added'),
            'repo.destroy': ('CRITICAL', 'Repository Deleted'),
            'protected_branch.update_allow_force_pushes_enforcement_level': (
                'HIGH', 'Branch Protection Weakened'),
            'secret_scanning_alert.dismiss': ('HIGH', 'Secret Alert Dismissed'),
        }
        try:
            for event in self.org.get_audit_log():
                action = event.get('action', '')
                if action in suspicious_actions:
                    severity, label = suspicious_actions[action]
                    self._add(
                        severity=severity,
                        category='Audit Log',
                        repository=event.get('repo', '<org>'),
                        check=label,
                        description=f'Audit event: {action} by {event.get("actor")} '
                                    f'at {event.get("created_at")}',
                        remediation='Review this action with the actor. '
                                    'Determine if authorized and document.'
                    )
        except Exception as e:
            print(f"  [WARN] Could not fetch audit log: {e}")

    # ── Report ────────────────────────────────────────────────────────────────

    def generate_report(self) -> dict:
        order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_f = sorted(self.findings, key=lambda f: order.get(f.severity, 9))
        counts = {}
        for f in sorted_f:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'org': self.org.login,
            'summary': {'total': len(sorted_f), 'by_severity': counts},
            'findings': [asdict(f) for f in sorted_f]
        }

    def run(self) -> dict:
        self.check_org_settings()
        self.check_repos()
        self.check_audit_log()
        return self.generate_report()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--org', required=True)
    parser.add_argument('--output', default='reports')
    args = parser.parse_args()

    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        raise SystemExit('Set GITHUB_TOKEN environment variable')

    monitor = GitHubSecurityMonitor(token, args.org)
    report = monitor.run()

    out = Path(args.output)
    out.mkdir(exist_ok=True)
    outfile = out / f"github-audit-{datetime.now().strftime('%Y-%m-%d')}.json"
    outfile.write_text(json.dumps(report, indent=2))
    print(f'\n[+] Report saved → {outfile}')
    print(f'    CRITICAL: {report["summary"]["by_severity"].get("CRITICAL", 0)}')
    print(f'    HIGH: {report["summary"]["by_severity"].get("HIGH", 0)}')
```

---

## Detection Queries

### GitHub Audit Log — Suspicious Events (Splunk SPL)

```
index=github_audit sourcetype=github:audit
| eval is_suspicious=case(
    action="org.remove_member", "true",
    action="repo.destroy", "true",
    action="protected_branch.update_allow_force_pushes_enforcement_level", "true",
    action="org.add_outside_collaborator", "true",
    1==1, "false"
)
| where is_suspicious="true"
| table _time, actor, action, repo, org
| sort -_time
```

### GitHub Token Compromise Indicators

```kql
// Azure Sentinel / GitHub audit log connector
// Detect GitHub token used from multiple IPs within 1 hour
GitHubAuditLog
| where TimeGenerated > ago(24h)
| where action != ""
| summarize
    IPCount = dcount(actor_ip),
    IPs = make_set(actor_ip),
    Actions = make_set(action)
  by actor, bin(TimeGenerated, 1h)
| where IPCount >= 3
| order by IPCount desc
```

---

## Interview Skills Gained

**Q: What is a supply chain attack? Give a real example.**
> A supply chain attack targets the software build, delivery, or dependency chain rather than the target directly. SolarWinds (2020): attackers compromised SolarWinds' build pipeline and inserted malicious code (Sunburst) into signed Orion software updates, which were then distributed to 18,000+ organizations including US government agencies.

**Q: How do you secure a GitHub Actions workflow?**
> (1) Pin action dependencies to full commit SHAs not tags — `uses: actions/checkout@a5ac7e51b` not `@v4`. (2) Set `permissions: contents: read` to restrict GITHUB_TOKEN. (3) Never use `pull_request_target` with checkout of the PR head. (4) Store secrets in GitHub Secrets, never in code. (5) Restrict which branches can trigger workflows.

**Q: How would you detect a compromised GitHub personal access token?**
> Look in the GitHub audit log for: (1) API calls from IPs not associated with the user, (2) access outside normal business hours, (3) actions the user never performs (repo deletion, org changes), (4) high volume of API calls (automated exfiltration). Also monitor GitHub secret scanning alerts for the token pattern if you know its prefix.

---

## Submission Checklist

- [ ] Python monitor runs: `python src/monitor.py --org your-org`
- [ ] Checks org 2FA, branch protection, outside collaborators, secret alerts, Actions permissions
- [ ] JSON report generated with severity levels
- [ ] Audit log analysis working (or documented why not — needs org owner)
- [ ] README includes threat model, checks performed, and remediation steps
- [ ] Screenshots: secret scanning alert in GitHub UI, branch protection settings
- [ ] `docs/supply-chain-threats.md` with taxonomy and real-world examples

---

## Links

→ Full project: [projects/07-github-security-monitoring/](../../projects/07-github-security-monitoring/)
→ Next: [Week 08 — Identity Review & Hardening Sprint](../week-08/README.md)
