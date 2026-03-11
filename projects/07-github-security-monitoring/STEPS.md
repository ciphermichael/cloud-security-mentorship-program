# Project 07 — GitHub Security Monitoring: Step-by-Step Guide

## Overview
Audit GitHub org security: 2FA, branch protection, secret scanning, Dependabot, and Actions workflow risks.

## Step 1 — Setup
```bash
pip install PyGithub rich requests python-dotenv
# Create .env with GITHUB_TOKEN=ghp_xxx and GITHUB_ORG=myorg
```

## Step 2 — Org & Repo Checker
```python
# src/org_checker.py
from github import Github
import os

def check_org(org_name: str, token: str) -> list:
    g = Github(token)
    org = g.get_organization(org_name)
    findings = []

    if not org.two_factor_requirement_enabled:
        findings.append({'severity':'CRITICAL','check':'2FA_NOT_ENFORCED',
            'detail':f'Org {org_name} does not enforce 2FA'})

    for member in org.get_members():
        if not member.two_factor_authentication:
            findings.append({'severity':'HIGH','check':'MEMBER_NO_2FA',
                'detail':f'@{member.login} has no 2FA'})

    outside = list(org.get_outside_collaborators())
    if outside:
        findings.append({'severity':'MEDIUM','check':'OUTSIDE_COLLABORATORS',
            'detail':f'{len(outside)} outside collaborators detected'})

    return findings

def check_repo(repo) -> list:
    findings = []
    try:
        bp = repo.get_branch(repo.default_branch).get_protection()
        if not bp.required_pull_request_reviews:
            findings.append({'severity':'HIGH','check':'NO_PR_REVIEW','repo':repo.full_name,
                'detail':'No required PR reviews on default branch'})
    except Exception:
        findings.append({'severity':'HIGH','check':'NO_BRANCH_PROTECTION','repo':repo.full_name,
            'detail':f'No branch protection on {repo.default_branch}'})
    return findings
```

## Step 3 — Workflow Scanner
```python
# src/workflow_scanner.py
import yaml, base64

RISKY_TRIGGERS = ['pull_request_target', 'workflow_run']

def scan_workflows(repo) -> list:
    findings = []
    try:
        for f in repo.get_contents('.github/workflows'):
            content = base64.b64decode(f.content).decode('utf-8', errors='ignore')
            workflow = yaml.safe_load(content) or {}
            on = workflow.get('on', {})
            triggers = list(on.keys()) if isinstance(on, dict) else [on]
            for t in triggers:
                if t in RISKY_TRIGGERS:
                    findings.append({'severity':'HIGH','check':'DANGEROUS_TRIGGER',
                        'repo':repo.full_name,'file':f.path,
                        'detail':f'Workflow uses {t} — risk of pwn-request attack'})
    except Exception:
        pass
    return findings
```

## Step 4 — Secret Scanning via API
```python
# src/secret_scanner.py
import requests, os

def get_secret_scanning_alerts(org: str, repo_name: str, token: str) -> list:
    headers = {'Authorization': f'token {token}', 'Accept': 'application/vnd.github+json'}
    url = f'https://api.github.com/repos/{org}/{repo_name}/secret-scanning/alerts'
    resp = requests.get(url, headers=headers)
    return resp.json() if resp.status_code == 200 else []
```

## Step 5 — Main Monitor
```python
# src/monitor.py
from github import Github
from .org_checker import check_org, check_repo
from .workflow_scanner import scan_workflows
from rich.console import Console
from rich.table import Table
import os, json

def main():
    token = os.environ['GITHUB_TOKEN']
    org_name = os.environ['GITHUB_ORG']
    console = Console()
    console.print(f'\n[bold blue]🔍 GitHub Security Monitor — {org_name}[/bold blue]\n')

    g = Github(token)
    findings = check_org(org_name, token)
    org = g.get_organization(org_name)
    for repo in org.get_repos():
        findings.extend(check_repo(repo))
        findings.extend(scan_workflows(repo))

    table = Table(title='GitHub Security Findings')
    table.add_column('Severity'); table.add_column('Check'); table.add_column('Detail')
    sev_order = ['CRITICAL','HIGH','MEDIUM','LOW']
    for f in sorted(findings, key=lambda x: sev_order.index(x.get('severity','LOW'))):
        colors = {'CRITICAL':'red','HIGH':'orange3','MEDIUM':'yellow','LOW':'green'}
        c = colors.get(f['severity'],'white')
        table.add_row(f'[{c}]{f["severity"]}[/{c}]', f['check'], f.get('detail',''))
    console.print(table)

    with open('reports/github-security.json','w') as fp:
        json.dump(findings, fp, indent=2)
    console.print(f'\n[green]✅ {len(findings)} findings saved[/green]')

if __name__ == '__main__':
    main()
```

## Step 6 — Run
```bash
export GITHUB_TOKEN=ghp_xxx
export GITHUB_ORG=myorg
python -m src.monitor
```
