# 🔑 IAM Security Analyser

> **Week 4** | Phase 1: Foundations

Audits AWS IAM for MFA gaps, stale credentials, admin over-privilege, and dormant accounts.

## Usage
```bash
pip install -r requirements.txt
python src/analyser.py --region us-east-1 --output html --output-file reports/iam.html
python src/analyser.py --output console
```

## Security Checks
| Check ID | Severity | Description |
|----------|----------|-------------|
| IAM-001 | 🔴 CRITICAL | Console user without MFA enrolled |
| IAM-002 | 🟠 HIGH | Access key older than 90 days |
| IAM-003 | 🟢 LOW | Inactive access key still present |
| IAM-004 | 🔴 CRITICAL | Root account has active access keys |
| IAM-005 | 🔴 CRITICAL | Root account has no MFA |
| IAM-006 | 🟠 HIGH | AdministratorAccess policy attached to user |
| IAM-007 | 🟠 HIGH | Wildcard (*) action in inline policy |
| IAM-008 | 🟡 MEDIUM | IAM user has never logged in |

## Key Concepts Demonstrated
- IAM credential report analysis
- Policy document parsing for over-privilege
- Boto3 pagination patterns
- Risk-based finding prioritisation
