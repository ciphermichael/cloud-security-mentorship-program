# 🐙 GitHub Security Monitoring

> **Week 8** | Phase 2: IAM & Identity Security

Monitors GitHub organisations for supply chain risks, secret exposure, branch protection gaps, and audit log anomalies.

## Setup
```bash
export GITHUB_TOKEN=ghp_your_personal_access_token
pip install -r requirements.txt

# Full org scan
python src/monitor.py --org your-org-name

# JSON output for SIEM ingestion
python src/monitor.py --org your-org --output json | jq .
```

## Required GitHub Token Scopes
- `repo` — branch protection, secret scanning status
- `admin:org` — org settings, audit log, member 2FA status
- `read:audit_log` — audit log events

## Security Checks
| Check ID | Severity | Description |
|----------|----------|-------------|
| GH-ORG-001 | 🔴 CRITICAL | 2FA not enforced organisation-wide |
| GH-ORG-002 | 🟡 MEDIUM | Default repo permissions too broad |
| GH-ORG-003 | 🟠 HIGH | Advanced Security not enabled by default |
| GH-REPO-001 | 🟠 HIGH | Secret scanning disabled on repo |
| GH-REPO-002 | 🟡 MEDIUM | No required PR reviews on default branch |
| GH-REPO-004 | 🟠 HIGH | No branch protection on default branch |
| GH-ACTIONS-001 | 🟠 HIGH | All Actions allowed (supply chain risk) |
| GH-AUDIT-* | varies | High-risk audit log events detected |
