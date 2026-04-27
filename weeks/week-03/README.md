# Week 03 — IAM Fundamentals & Security Analysis

**Phase 1: Foundations | Project: 03-iam-security-analyser**

---

## Learning Objectives

By the end of this week you will be able to:

- Explain AWS IAM structure: users, groups, roles, policies, and permission boundaries
- Identify over-privileged IAM policies using least-privilege analysis
- Detect stale IAM credentials (access keys older than 90 days, unused users)
- Check MFA compliance across all IAM users
- Query the IAM credential report programmatically
- Write a Python IAM security analyser using boto3

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | IAM fundamentals — users, groups, roles, policies, ARNs, trust policies | 2 hrs |
| Tue | Policy types — managed vs inline, SCPs, permission boundaries, conditions | 2 hrs |
| Wed | IAM credential report + Access Analyzer + Security Hub IAM findings | 2 hrs |
| Thu | Build the analyser — credential report parsing, stale key detection | 2 hrs |
| Fri | Add MFA compliance check + over-privilege detector (wildcard policies) | 2 hrs |
| Sat | Generate JSON report, write README, push to GitHub | 3 hrs |
| Sun | Review session with mentor, prep Week 4 reading | 1 hr |

---

## Topics Covered

### IAM Core Concepts

**Users** — human or service identities with long-term credentials. Best practice: use only for humans; use roles for everything else.

**Groups** — collections of users that inherit attached policies. Assign permissions to groups, never to individual users.

**Roles** — temporary identities assumed by users, services, or cross-account principals via STS. A role has:
- **Trust Policy** — who can assume it (`sts:AssumeRole`)
- **Permission Policy** — what it can do once assumed

**Policies** — JSON documents defining Allow/Deny on actions and resources:
- AWS Managed: maintained by AWS
- Customer Managed: you own and version them
- Inline: embedded directly in a user/role — avoid, harder to audit
- Service Control Policies (SCPs): org-level guardrails, cannot grant permissions only restrict

**Permission Boundaries** — cap the maximum permissions an identity can ever have regardless of attached policies. Use when delegating IAM creation rights to a team.

### Dangerous IAM Patterns to Detect

```json
// CRITICAL: Full admin access
{ "Effect": "Allow", "Action": "*", "Resource": "*" }

// HIGH: All IAM actions — privilege escalation vector
{ "Effect": "Allow", "Action": "iam:*", "Resource": "*" }

// HIGH: PassRole to any service — allows privilege escalation via EC2/Lambda
{ "Effect": "Allow", "Action": "iam:PassRole", "Resource": "*" }

// MEDIUM: Wildcard on sensitive actions
{ "Effect": "Allow", "Action": "s3:*", "Resource": "*" }
```

### IAM Credential Report Fields

The credential report CSV contains these security-relevant fields per user:

| Field | What to Check |
|-------|---------------|
| `mfa_active` | Must be `true` for all console users |
| `password_last_used` | Flag if >90 days or never used |
| `access_key_1_active` | Should be `false` if not actively used |
| `access_key_1_last_rotated` | Flag if >90 days old |
| `access_key_1_last_used_date` | Flag if never used but active |

---

## Instructor Mentoring Guidance

**Week 3 is a critical inflection point.** IAM is the #1 source of cloud breaches. Push students to read the Capital One breach report — a single over-privileged EC2 instance role exposed 100M records.

**Common student mistakes:**
- Using `--profile` without knowing which account they're hitting
- Confusing `iam:PassRole` with `sts:AssumeRole`
- Not handling pagination in boto3 (only seeing first 100 results)
- Committing credential report output with real user ARNs to GitHub

**Mentoring session agenda (60 min):**
1. (15 min) Live IAM Policy Simulator walkthrough — show policy evaluation order
2. (20 min) Code review — check pagination, error handling, no hardcoded credentials
3. (15 min) Mock interview: "Walk me through securing an AWS account from scratch"
4. (10 min) Preview Week 4 — explain why CloudTrail is the foundation of everything

**Office hours focus:** Help students understand that `Deny` always overrides `Allow` and how policy evaluation order works (SCP → permission boundary → identity policy → resource policy).

---

## Hands-on Lab

### Lab 1: IAM Policy Simulator

1. Open the AWS IAM Policy Simulator: `https://policysim.aws.amazon.com/`
2. Select a test user in your account
3. Test these actions and document what's allowed vs denied:
   - `s3:GetObject` on `arn:aws:s3:::*`
   - `iam:CreateUser`
   - `iam:PassRole`
   - `ec2:TerminateInstances`
4. Screenshot results and commit to `reports/policy-simulator-results.png`

### Lab 2: Generate and Parse the Credential Report

```bash
# Generate the credential report via CLI
aws iam generate-credential-report

# Wait a moment, then download it
aws iam get-credential-report \
  --query 'Content' \
  --output text | base64 --decode > credential-report.csv

# View it
column -t -s, credential-report.csv | head -20

# Find users without MFA (using grep)
grep ",false," credential-report.csv | grep -v "^<root_account>"
```

### Lab 3: Create a Least-Privilege Role

```bash
# Trust policy — allow EC2 to assume this role
cat > trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "ec2.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
EOF

# Permission policy — read-only on one S3 prefix
cat > perms.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::my-security-bucket",
      "arn:aws:s3:::my-security-bucket/reports/*"
    ]
  }]
}
EOF

aws iam create-role \
  --role-name SecurityAnalyserRole \
  --assume-role-policy-document file://trust.json

aws iam put-role-policy \
  --role-name SecurityAnalyserRole \
  --policy-name S3ReadReports \
  --policy-document file://perms.json

# Verify
aws iam get-role --role-name SecurityAnalyserRole
aws iam get-role-policy \
  --role-name SecurityAnalyserRole \
  --policy-name S3ReadReports
```

### Lab 4: Enable IAM Access Analyzer

```bash
# Create an Access Analyzer for your account
aws accessanalyzer create-analyzer \
  --analyzer-name account-analyzer \
  --type ACCOUNT

# List all active findings (resources accessible externally)
aws accessanalyzer list-findings \
  --analyzer-arn "$(aws accessanalyzer list-analyzers \
    --query 'analyzers[0].arn' --output text)" \
  --filter '{"status": {"eq": ["ACTIVE"]}}' \
  --query 'findings[*].{Resource:resource,Type:resourceType,Principal:principal}' \
  --output table
```

---

## Weekly Assignment — IAM Security Analyser

Build a Python script that performs a full IAM security audit and generates a JSON report.

### Requirements

The script must detect:

1. **Credential hygiene** — stale keys, unused keys, no MFA, root key existence
2. **Over-privilege** — wildcard policies, AdministratorAccess attached to users
3. **Stale identities** — users inactive for 90+ days
4. **Inline policies** — flag as non-standard/hard-to-audit

### Reference Implementation

```python
# src/analyser.py
import boto3
import csv
import json
import io
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Optional

STALE_DAYS = 90
ADMIN_POLICY_ARN = 'arn:aws:iam::aws:policy/AdministratorAccess'


@dataclass
class Finding:
    rule_id: str
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW
    resource_type: str  # USER | ROLE | POLICY | ROOT
    resource_name: str
    resource_arn: str
    description: str
    remediation: str
    mitre_tactic: str = ''


class IAMSecurityAnalyser:

    def __init__(self, region: str = 'us-east-1'):
        self.iam = boto3.client('iam', region_name=region)
        self.findings: list[Finding] = []
        self._now = datetime.now(timezone.utc)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _parse_aws_date(self, value: str) -> Optional[datetime]:
        if not value or value in ('N/A', 'not_supported', 'no_information'):
            return None
        return datetime.fromisoformat(value.replace('Z', '+00:00'))

    def _add(self, finding: Finding):
        self.findings.append(finding)

    def _age_days(self, dt: Optional[datetime]) -> Optional[int]:
        if dt is None:
            return None
        return (self._now - dt).days

    # ── Credential Report Checks ──────────────────────────────────────────────

    def _fetch_credential_report(self) -> list[dict]:
        self.iam.generate_credential_report()
        for _ in range(15):
            resp = self.iam.get_credential_report()
            if resp['State'] == 'COMPLETE':
                content = resp['Content'].decode('utf-8')
                return list(csv.DictReader(io.StringIO(content)))
            time.sleep(2)
        raise RuntimeError('Credential report timed out')

    def check_credential_report(self):
        rows = self._fetch_credential_report()
        for row in rows:
            name = row['user']
            arn = row['arn']

            if name == '<root_account>':
                if row['mfa_active'] == 'false':
                    self._add(Finding('IAM-001', 'CRITICAL', 'ROOT', 'root', arn,
                        'Root account has no MFA.',
                        'Enable virtual or hardware MFA on root immediately. '
                        'Never use root for daily operations.',
                        'TA0004 - Privilege Escalation'))
                for k in ('1', '2'):
                    if row.get(f'access_key_{k}_active') == 'true':
                        self._add(Finding('IAM-002', 'CRITICAL', 'ROOT', 'root', arn,
                            f'Root account has active access key {k}.',
                            'Delete all root access keys. Use IAM users/roles instead.',
                            'TA0006 - Credential Access'))
                continue

            # Console user without MFA
            if row['password_enabled'] == 'true' and row['mfa_active'] == 'false':
                self._add(Finding('IAM-003', 'HIGH', 'USER', name, arn,
                    f'Console user {name} has no MFA.',
                    'Require MFA via SCP or deny actions without '
                    '"aws:MultiFactorAuthPresent": "true" condition.',
                    'TA0006 - Credential Access'))

            # Inactive console user
            last_login = self._parse_aws_date(row.get('password_last_used', ''))
            age = self._age_days(last_login)
            if row['password_enabled'] == 'true' and age is not None and age > STALE_DAYS:
                self._add(Finding('IAM-004', 'MEDIUM', 'USER', name, arn,
                    f'User {name} has not logged in for {age} days.',
                    'Disable or delete inactive accounts. Review quarterly.',
                    'TA0003 - Persistence'))

            # Stale or never-used access keys
            for k in ('1', '2'):
                if row.get(f'access_key_{k}_active') != 'true':
                    continue
                rotated = self._parse_aws_date(row.get(f'access_key_{k}_last_rotated', ''))
                rot_age = self._age_days(rotated)
                if rot_age is not None and rot_age > STALE_DAYS:
                    self._add(Finding('IAM-005', 'HIGH', 'USER', name, arn,
                        f'Access key {k} for {name} is {rot_age} days old (>{STALE_DAYS} threshold).',
                        'Rotate access keys every 90 days. '
                        'Prefer IAM roles over long-term keys.',
                        'TA0006 - Credential Access'))

                last_used = self._parse_aws_date(row.get(f'access_key_{k}_last_used_date', ''))
                if last_used is None:
                    self._add(Finding('IAM-006', 'MEDIUM', 'USER', name, arn,
                        f'Access key {k} for {name} is active but has never been used.',
                        'Delete unused access keys immediately.',
                        'TA0003 - Persistence'))

    # ── Policy Checks ─────────────────────────────────────────────────────────

    def check_overprivileged_policies(self):
        paginator = self.iam.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            for pol in page['Policies']:
                ver = self.iam.get_policy_version(
                    PolicyArn=pol['Arn'],
                    VersionId=pol['DefaultVersionId']
                )['PolicyVersion']['Document']
                for stmt in ver.get('Statement', []):
                    if stmt.get('Effect') != 'Allow':
                        continue
                    actions = stmt.get('Action', [])
                    resources = stmt.get('Resource', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]
                    if '*' in actions and '*' in resources:
                        self._add(Finding('IAM-007', 'CRITICAL', 'POLICY',
                            pol['PolicyName'], pol['Arn'],
                            'Customer policy grants Action:* on Resource:* (full admin).',
                            'Replace with specific actions and scoped resource ARNs.',
                            'TA0004 - Privilege Escalation'))

    def check_admin_attached_to_users(self):
        paginator = self.iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                attached = self.iam.list_attached_user_policies(
                    UserName=user['UserName'])['AttachedPolicies']
                for pol in attached:
                    if pol['PolicyArn'] == ADMIN_POLICY_ARN:
                        self._add(Finding('IAM-008', 'CRITICAL', 'USER',
                            user['UserName'], user['Arn'],
                            f'AdministratorAccess attached directly to user {user["UserName"]}.',
                            'Assign AdministratorAccess only to roles, '
                            'never directly to users. Use groups.',
                            'TA0004 - Privilege Escalation'))

    def check_inline_policies(self):
        paginator = self.iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                inline = self.iam.list_user_policies(
                    UserName=user['UserName'])['PolicyNames']
                for pol_name in inline:
                    self._add(Finding('IAM-009', 'LOW', 'USER',
                        user['UserName'], user['Arn'],
                        f'User {user["UserName"]} has inline policy "{pol_name}". '
                        'Inline policies are hard to audit and reuse.',
                        'Convert to customer-managed policies for better governance.',
                        'TA0003 - Persistence'))

    # ── Report ────────────────────────────────────────────────────────────────

    def generate_report(self) -> dict:
        order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(self.findings, key=lambda f: order.get(f.severity, 9))
        counts = {}
        for f in sorted_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {
            'generated_at': self._now.isoformat(),
            'summary': {'total': len(sorted_findings), 'by_severity': counts},
            'findings': [asdict(f) for f in sorted_findings]
        }

    def run(self) -> dict:
        steps = [
            ('Credential report', self.check_credential_report),
            ('Over-privileged policies', self.check_overprivileged_policies),
            ('Admin attached to users', self.check_admin_attached_to_users),
            ('Inline policies', self.check_inline_policies),
        ]
        for label, fn in steps:
            print(f'[*] Checking {label}...')
            fn()

        report = self.generate_report()
        print(f'\n[+] IAM Audit Complete')
        print(f'    Total findings: {report["summary"]["total"]}')
        for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            c = report['summary']['by_severity'].get(sev, 0)
            if c:
                print(f'    {sev}: {c}')
        return report


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='IAM Security Analyser')
    parser.add_argument('--region', default='us-east-1')
    parser.add_argument('--output', default='reports')
    args = parser.parse_args()

    analyser = IAMSecurityAnalyser(region=args.region)
    report = analyser.run()

    out = Path(args.output)
    out.mkdir(exist_ok=True)
    outfile = out / f"iam-audit-{datetime.now().strftime('%Y-%m-%d')}.json"
    outfile.write_text(json.dumps(report, indent=2))
    print(f'[+] Report saved → {outfile}')
```

---

## Detection Queries

### CloudWatch Logs Insights

```
# Root account activity (any API call from root)
fields @timestamp, eventName, sourceIPAddress, userAgent
| filter userIdentity.type = "Root"
| sort @timestamp desc
| limit 50
```

```
# Console logins without MFA
fields @timestamp, userIdentity.userName, sourceIPAddress
| filter eventName = "ConsoleLogin"
  and responseElements.ConsoleLogin = "Success"
  and additionalEventData.MFAUsed = "No"
| sort @timestamp desc
```

```
# Failed AssumeRole attempts (credential stuffing / recon)
fields @timestamp, userIdentity.arn, requestParameters.roleArn, errorCode
| filter eventName = "AssumeRole" and errorCode = "AccessDenied"
| stats count() as failures by userIdentity.arn, requestParameters.roleArn
| sort failures desc
| limit 20
```

### Athena SQL (CloudTrail)

```sql
-- All new IAM users created in past 7 days
SELECT eventTime, userIdentity.arn AS actor,
    json_extract_scalar(requestParameters, '$.userName') AS new_user,
    sourceIPAddress
FROM cloudtrail_logs
WHERE eventName = 'CreateUser'
  AND eventTime > date_add('day', -7, now())
ORDER BY eventTime DESC;

-- Policy attachments (privilege grants) — high-value alert events
SELECT eventTime, userIdentity.arn AS actor,
    json_extract_scalar(requestParameters, '$.userName') AS target_user,
    json_extract_scalar(requestParameters, '$.policyArn') AS policy_arn
FROM cloudtrail_logs
WHERE eventName IN ('AttachUserPolicy','AttachRolePolicy','PutUserPolicy','PutRolePolicy')
  AND eventTime > date_add('day', -7, now())
ORDER BY eventTime DESC;

-- AdministratorAccess policy attached to anything
SELECT eventTime, userIdentity.arn, eventName,
    json_extract_scalar(requestParameters, '$.policyArn') AS attached_policy
FROM cloudtrail_logs
WHERE eventName IN ('AttachUserPolicy','AttachRolePolicy','AttachGroupPolicy')
  AND json_extract_scalar(requestParameters, '$.policyArn')
      LIKE '%AdministratorAccess%';
```

---

## Interview Skills Gained

**Q: Explain the difference between an IAM role and an IAM user.**
> A user has long-term credentials (password, access keys) tied to a person. A role has no credentials — it issues temporary STS tokens when assumed. Roles are preferred for services, automation, and cross-account access because temporary credentials reduce breach impact.

**Q: What is a permission boundary and when would you use it?**
> A permission boundary is a policy that caps the maximum permissions a user or role can ever have, regardless of what identity-based policies allow. Use it when delegating IAM management to a team — developers can create roles for their apps but cannot grant more permissions than they themselves have.

**Q: How would you detect a compromised IAM access key?**
> Look for: (1) API calls from unusual IP/geolocation, (2) calls outside business hours, (3) new IAM entities created by that identity, (4) access to resources it has never touched before, (5) GuardDuty finding `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`. All visible in CloudTrail.

**Q: What does least privilege mean in practice?**
> Start with zero permissions and add only what is documented as required. Use specific ARNs not wildcards. Use IAM Access Analyzer to surface over-permission. Review all policies quarterly. Prefer time-limited, session-scoped permissions.

---

## Submission Checklist

- [ ] Analyser runs: `python src/analyser.py --region us-east-1`
- [ ] Detects stale keys, no-MFA users, wildcard policies, admin-attached users
- [ ] JSON report saved with CRITICAL/HIGH/MEDIUM/LOW severity levels
- [ ] Sample report committed (ARNs scrubbed)
- [ ] README explains each check, how to run, and how to remediate
- [ ] CloudWatch Insights and Athena queries in `queries/`
- [ ] Screenshot of terminal output and JSON report in `docs/`
- [ ] Reflection: what surprised you about your account's IAM posture?

---

## Links

→ Full project: [projects/03-iam-security-analyser/](../../projects/03-iam-security-analyser/)
→ Next: [Week 04 — CloudTrail & Logging](../week-04/README.md)
