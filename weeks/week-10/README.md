# Week 10 — Cloud Compliance Frameworks: CIS, ISO 27001, SOC 2

**Phase 3: Threat Detection & Response | Project: 09-cloud-compliance-audit**

---

## Learning Objectives

By the end of this week you will be able to:

- Explain the CIS AWS Foundations Benchmark v2.0 and implement all Level 1 controls programmatically
- Map ISO 27001 Annex A controls to AWS security services
- Understand SOC 2 Trust Service Criteria and how cloud configurations evidence them
- Use AWS Config rules to continuously evaluate compliance posture
- Build a compliance audit tool that generates evidence packages and gap reports
- Explain the difference between a compliance control and a security control

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | CIS AWS Foundations Benchmark v2.0 — Level 1 vs Level 2, control families | 2 hrs |
| Tue | ISO 27001 Annex A — A.9 Access Control, A.12 Operations, A.16 Incident Management | 2 hrs |
| Wed | AWS Config — managed rules, custom rules, conformance packs | 2 hrs |
| Thu | Build compliance checker — CIS Level 1 checks 1.x through 3.x | 2 hrs |
| Fri | Build CIS checks 4.x through 5.x (Logging, Networking), generate report | 2 hrs |
| Sat | Evidence package generation, README, push to GitHub | 3 hrs |
| Sun | Mentor review — compliance reporting and audit evidence concepts | 1 hr |

---

## Topics Covered

### Compliance Framework Overview

| Framework | Used For | Key Areas |
|-----------|----------|-----------|
| CIS AWS Foundations Benchmark | AWS account hardening baseline | IAM, Logging, Monitoring, Networking |
| ISO 27001 | International information security standard | 114 controls across 14 domains |
| SOC 2 Type II | US audit standard for service organizations | Trust Service Criteria (CC, A, C, PI, P) |
| PCI DSS | Payment card industry | 12 requirements, cardholder data protection |
| HIPAA | US healthcare | PHI protection, audit controls |
| NIST CSF | Framework for critical infrastructure | Identify, Protect, Detect, Respond, Recover |

### CIS AWS Foundations Benchmark v2.0 — Control Families

**Section 1: Identity and Access Management (21 controls)**
- 1.1 Maintain current contact details
- 1.4 Ensure no root account access keys exist
- 1.5 Ensure MFA is enabled for root
- 1.9 Ensure IAM password policy requires minimum 14 characters
- 1.14 Ensure hardware MFA is enabled for root
- 1.16 Ensure IAM policies are attached to groups or roles, not users
- 1.17 Ensure a support role has been created for AWS Support
- 1.19 Ensure that all expired SSL/TLS certificates stored in IAM are removed
- 1.20 Ensure Access Analyzer is enabled for all regions
- 1.22 Ensure security questions are registered in the AWS account

**Section 2: Storage (7 controls)**
- 2.1.1 Ensure S3 Block Public Access is enabled at account level
- 2.1.2 Ensure MFA delete is enabled on S3 buckets with versioning
- 2.2.1 Ensure EBS volume encryption at rest is enabled
- 2.3.1 Ensure RDS DB instances are encrypted at rest
- 2.4.1 Ensure S3 buckets use SSE-KMS

**Section 3: Logging (8 controls)**
- 3.1 Ensure CloudTrail is enabled in all regions
- 3.2 Ensure CloudTrail log file validation is enabled
- 3.3 Ensure the S3 bucket CloudTrail logs to is not publicly accessible
- 3.4 Ensure CloudTrail trails are integrated with CloudWatch Logs
- 3.5 Ensure AWS Config is enabled in all regions
- 3.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs
- 3.8 Ensure rotation for customer created CMKs is enabled

**Section 4: Monitoring (15 controls)**
- 4.1 Ensure unauthorized API calls alarm exists
- 4.2 Ensure console login without MFA alarm exists
- 4.3 Ensure root account usage alarm exists
- 4.4 Ensure IAM policy changes alarm exists
- 4.5 Ensure CloudTrail changes alarm exists
- 4.13 Ensure VPC changes alarm exists
- 4.14 Ensure Dead Letter Queue is set for SNS topics

**Section 5: Networking (4 controls)**
- 5.1 Ensure no default VPC exists in any region
- 5.2 Ensure VPC Flow Logs are enabled
- 5.3 Ensure no security groups allow 0.0.0.0/0 to port 22
- 5.4 Ensure no security groups allow 0.0.0.0/0 to port 3389

---

## Instructor Mentoring Guidance

**Week 10 connects technical security to business language.** Compliance is how security requirements get funded and prioritized in most enterprises. Engineers who can speak compliance are far more effective at getting security work approved.

**Common mistakes:**
- Students think "compliance = security" — it doesn't. Compliance is a minimum bar; a fully CIS-compliant account can still have serious security gaps.
- Missing that AWS Config evaluates resources continuously, not just at assessment time
- Not understanding that evidence for SOC 2 requires historical proof — a screenshot from today doesn't prove a control was in place 6 months ago

**Mentoring session agenda (60 min):**
1. (10 min) Show the difference between security posture and compliance posture using a real-world example
2. (20 min) Walk through 5 CIS controls together — what they check, why they matter
3. (20 min) Code review of their compliance checker
4. (10 min) Mock interview: "A CISO asks you to get us SOC 2 ready in 90 days. What do you do first?"

---

## Hands-on Lab

### Lab 1: Enable AWS Config

```bash
# Create an S3 bucket for Config recordings
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
CONFIG_BUCKET="aws-config-${ACCOUNT_ID}-$(date +%s)"

aws s3 mb s3://$CONFIG_BUCKET

# Create Config delivery channel
cat > config-delivery.json << EOF
{
  "name": "default",
  "s3BucketName": "$CONFIG_BUCKET",
  "configSnapshotDeliveryProperties": {
    "deliveryFrequency": "Daily"
  }
}
EOF

# Create Config recorder
cat > config-recorder.json << EOF
{
  "name": "default",
  "roleARN": "arn:aws:iam::${ACCOUNT_ID}:role/aws-config-role",
  "recordingGroup": {
    "allSupported": true,
    "includeGlobalResourceTypes": true
  }
}
EOF

aws configservice put-configuration-recorder \
  --configuration-recorder file://config-recorder.json

aws configservice put-delivery-channel \
  --delivery-channel file://config-delivery.json

aws configservice start-configuration-recorder \
  --configuration-recorder-name default
```

### Lab 2: Deploy CIS Conformance Pack

```bash
# AWS provides a managed CIS conformance pack
aws configservice put-conformance-pack \
  --conformance-pack-name CIS-AWS-Foundations-Benchmark-Level-1 \
  --template-s3-uri s3://aws-configservice-us-east-1/cloudformation-templates-for-conformance-packs/\
operational-best-practices-for-cis-aws-foundations-benchmark-level-1.yaml \
  --delivery-s3-bucket $CONFIG_BUCKET

# Check compliance after ~5 minutes
aws configservice describe-conformance-pack-compliance \
  --conformance-pack-name CIS-AWS-Foundations-Benchmark-Level-1 \
  --query 'ConformancePackRuleComplianceList[?ComplianceType==`NON_COMPLIANT`]' \
  --output table
```

---

## Weekly Assignment — CIS Compliance Checker

Build a Python tool that checks all CIS AWS Foundations Benchmark Level 1 controls and generates a scored compliance report.

```python
# src/cis_checker.py
import boto3
import json
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Callable
from pathlib import Path


@dataclass
class ControlResult:
    control_id: str
    control_title: str
    section: str
    status: str           # PASS | FAIL | ERROR | MANUAL
    severity: str         # CRITICAL | HIGH | MEDIUM | LOW
    evidence: str         # What was found
    remediation: str
    cis_level: int = 1    # 1 or 2


class CISChecker:
    def __init__(self, region: str = 'us-east-1'):
        self.region = region
        self.iam = boto3.client('iam')
        self.ec2 = boto3.client('ec2', region_name=region)
        self.cloudtrail = boto3.client('cloudtrail', region_name=region)
        self.s3 = boto3.client('s3')
        self.config = boto3.client('config', region_name=region)
        self.results: list[ControlResult] = []

    def _add(self, **kwargs):
        self.results.append(ControlResult(**kwargs))

    # ── Section 1: IAM ────────────────────────────────────────────────────────

    def check_1_4_no_root_access_keys(self):
        resp = self.iam.get_account_summary()
        has_root_keys = resp['SummaryMap'].get('AccountAccessKeysPresent', 0) > 0
        self._add(
            control_id='1.4',
            control_title='Ensure no root account access keys exist',
            section='IAM',
            status='FAIL' if has_root_keys else 'PASS',
            severity='CRITICAL',
            evidence=f'Root access keys present: {has_root_keys}',
            remediation='Delete root access keys via IAM → Security Credentials → '
                        'Access keys section.'
        )

    def check_1_5_mfa_for_root(self):
        resp = self.iam.get_account_summary()
        mfa_active = resp['SummaryMap'].get('AccountMFAEnabled', 0) > 0
        self._add(
            control_id='1.5',
            control_title='Ensure MFA is enabled for the root user',
            section='IAM',
            status='PASS' if mfa_active else 'FAIL',
            severity='CRITICAL',
            evidence=f'Root MFA enabled: {mfa_active}',
            remediation='Enable MFA: IAM → Root account → Security credentials → '
                        'Assign MFA device.'
        )

    def check_1_9_password_policy(self):
        try:
            policy = self.iam.get_account_password_policy()['PasswordPolicy']
            issues = []
            if policy.get('MinimumPasswordLength', 0) < 14:
                issues.append(f'min length {policy.get("MinimumPasswordLength")} < 14')
            if not policy.get('RequireSymbols'):
                issues.append('symbols not required')
            if not policy.get('RequireNumbers'):
                issues.append('numbers not required')
            if not policy.get('RequireUppercaseCharacters'):
                issues.append('uppercase not required')
            if not policy.get('RequireLowercaseCharacters'):
                issues.append('lowercase not required')
            if not policy.get('PasswordReusePrevention', 0) >= 24:
                issues.append('reuse prevention < 24')
            if policy.get('MaxPasswordAge', 999) > 365:
                issues.append('max age > 365 days')
            status = 'FAIL' if issues else 'PASS'
            self._add(
                control_id='1.9',
                control_title='Ensure IAM password policy requires minimum 14 characters',
                section='IAM',
                status=status,
                severity='MEDIUM',
                evidence=f'Issues: {", ".join(issues)}' if issues else 'Password policy meets CIS requirements',
                remediation='Update via: aws iam update-account-password-policy '
                            '--minimum-password-length 14 --require-symbols '
                            '--require-numbers --require-uppercase-characters '
                            '--require-lowercase-characters --password-reuse-prevention 24'
            )
        except self.iam.exceptions.NoSuchEntityException:
            self._add(
                control_id='1.9',
                control_title='Ensure IAM password policy requires minimum 14 characters',
                section='IAM',
                status='FAIL',
                severity='MEDIUM',
                evidence='No password policy configured.',
                remediation='Create a password policy with all CIS Level 1 requirements.'
            )

    def check_1_16_no_policies_on_users(self):
        issues = []
        paginator = self.iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                attached = self.iam.list_attached_user_policies(
                    UserName=user['UserName'])['AttachedPolicies']
                if attached:
                    issues.append(f'{user["UserName"]}: {[p["PolicyName"] for p in attached]}')
        status = 'FAIL' if issues else 'PASS'
        self._add(
            control_id='1.16',
            control_title='Ensure IAM policies are attached only to groups or roles',
            section='IAM',
            status=status,
            severity='MEDIUM',
            evidence=f'Users with direct policies: {issues}' if issues else 'No users have direct policy attachments',
            remediation='Detach policies from users. Add users to groups and attach policies to groups.'
        )

    # ── Section 3: Logging ────────────────────────────────────────────────────

    def check_3_1_cloudtrail_enabled_all_regions(self):
        trails = self.cloudtrail.describe_trails(includeShadowTrails=False)['trailList']
        multi_region = [t for t in trails if t.get('IsMultiRegionTrail')]
        all_enabled = all(
            self.cloudtrail.get_trail_status(Name=t['Name'])['IsLogging']
            for t in multi_region
        ) if multi_region else False
        status = 'PASS' if multi_region and all_enabled else 'FAIL'
        self._add(
            control_id='3.1',
            control_title='Ensure CloudTrail is enabled in all regions',
            section='Logging',
            status=status,
            severity='HIGH',
            evidence=f'Multi-region trails: {[t["Name"] for t in multi_region]}, '
                     f'all logging: {all_enabled}',
            remediation='Create a multi-region trail with global service events enabled.'
        )

    def check_3_2_cloudtrail_log_validation(self):
        trails = self.cloudtrail.describe_trails(includeShadowTrails=False)['trailList']
        issues = [t['Name'] for t in trails if not t.get('LogFileValidationEnabled')]
        status = 'FAIL' if issues else 'PASS'
        self._add(
            control_id='3.2',
            control_title='Ensure CloudTrail log file validation is enabled',
            section='Logging',
            status=status,
            severity='HIGH',
            evidence=f'Trails without validation: {issues}' if issues else 'All trails have log validation enabled',
            remediation='Enable via: aws cloudtrail update-trail --name TRAIL_NAME '
                        '--enable-log-file-validation'
        )

    # ── Section 5: Networking ─────────────────────────────────────────────────

    def check_5_3_no_ssh_open_to_world(self):
        sgs = self.ec2.describe_security_groups()['SecurityGroups']
        issues = []
        for sg in sgs:
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', -1)
                to_port = rule.get('ToPort', -1)
                if from_port <= 22 <= to_port or from_port == -1:
                    for cidr in rule.get('IpRanges', []):
                        if cidr['CidrIp'] == '0.0.0.0/0':
                            issues.append(f'{sg["GroupId"]} ({sg.get("GroupName")})')
        status = 'FAIL' if issues else 'PASS'
        self._add(
            control_id='5.3',
            control_title='Ensure no security groups allow ingress from 0.0.0.0/0 to port 22',
            section='Networking',
            status=status,
            severity='CRITICAL',
            evidence=f'Vulnerable SGs: {issues}' if issues else 'No SGs expose SSH to the world',
            remediation='Restrict SSH to specific IP ranges or use AWS Systems Manager '
                        'Session Manager instead of SSH.'
        )

    def check_5_2_vpc_flow_logs(self):
        vpcs = self.ec2.describe_vpcs()['Vpcs']
        flow_logs = self.ec2.describe_flow_logs()['FlowLogs']
        covered_vpcs = {fl['ResourceId'] for fl in flow_logs if fl['FlowLogStatus'] == 'ACTIVE'}
        missing = [v['VpcId'] for v in vpcs if v['VpcId'] not in covered_vpcs]
        status = 'FAIL' if missing else 'PASS'
        self._add(
            control_id='5.2',
            control_title='Ensure VPC Flow Logs is enabled for every VPC',
            section='Networking',
            status=status,
            severity='MEDIUM',
            evidence=f'VPCs missing flow logs: {missing}' if missing else 'All VPCs have flow logs',
            remediation='Enable flow logs: aws ec2 create-flow-logs --resource-ids VPC_ID '
                        '--traffic-type ALL --log-destination-type cloud-watch-logs '
                        '--log-group-name /aws/vpc/flow-logs'
        )

    # ── Runner & Report ───────────────────────────────────────────────────────

    def run_all_checks(self):
        checks = [
            self.check_1_4_no_root_access_keys,
            self.check_1_5_mfa_for_root,
            self.check_1_9_password_policy,
            self.check_1_16_no_policies_on_users,
            self.check_3_1_cloudtrail_enabled_all_regions,
            self.check_3_2_cloudtrail_log_validation,
            self.check_5_2_vpc_flow_logs,
            self.check_5_3_no_ssh_open_to_world,
        ]
        for check in checks:
            try:
                print(f'[*] Running {check.__name__}...')
                check()
            except Exception as e:
                print(f'  [ERROR] {check.__name__}: {e}')

    def generate_report(self) -> dict:
        passed = [r for r in self.results if r.status == 'PASS']
        failed = [r for r in self.results if r.status == 'FAIL']
        score = round(len(passed) / max(len(self.results), 1) * 100, 1)
        return {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'framework': 'CIS AWS Foundations Benchmark v2.0 Level 1',
            'score': f'{score}%',
            'summary': {
                'total': len(self.results),
                'passed': len(passed),
                'failed': len(failed),
            },
            'failed_controls': [asdict(r) for r in failed],
            'all_results': [asdict(r) for r in self.results]
        }


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', default='us-east-1')
    parser.add_argument('--output', default='reports')
    args = parser.parse_args()

    checker = CISChecker(region=args.region)
    checker.run_all_checks()
    report = checker.generate_report()

    out = Path(args.output)
    out.mkdir(exist_ok=True)
    outfile = out / f"cis-compliance-{datetime.now().strftime('%Y-%m-%d')}.json"
    outfile.write_text(json.dumps(report, indent=2))

    print(f'\n[+] CIS Compliance Score: {report["score"]}')
    print(f'    Passed: {report["summary"]["passed"]} / {report["summary"]["total"]}')
    print(f'    Failed controls:')
    for r in report['failed_controls']:
        print(f'      [{r["severity"]}] {r["control_id"]}: {r["control_title"]}')
    print(f'\n[+] Report saved → {outfile}')
```

---

## Interview Skills Gained

**Q: What is the CIS Benchmark and how is it different from ISO 27001?**
> The CIS Benchmarks are prescriptive, technical configuration guidelines for specific technologies (AWS, Azure, Linux, etc.). ISO 27001 is a management system standard — it defines processes and governance requirements but not specific technical configurations. You use CIS to harden your AWS account; you use ISO 27001 to manage your overall information security program. Most enterprises use both.

**Q: What is the difference between compliance and security?**
> Compliance is meeting a defined set of controls established by a standard or regulation. Security is actually reducing risk. A system can be 100% compliant with a standard and still be insecure — because standards lag emerging threats, controls may be insufficient, or the standard doesn't cover your specific risk. Compliance is a floor, not a ceiling.

**Q: How would you approach getting an AWS account SOC 2 ready?**
> (1) Map SOC 2 Trust Service Criteria to existing AWS controls. (2) Identify gaps — what controls are missing? (3) Enable core services: CloudTrail, Config, GuardDuty, Security Hub. (4) Implement CIS Benchmark Level 1 as baseline. (5) Set up continuous compliance monitoring with Config conformance packs. (6) Document change management, incident response, and access review procedures. (7) Engage an auditor early — understand their evidence requirements.

---

## Submission Checklist

- [ ] Python checker implemented for all CIS Level 1 controls in sections 1, 3, and 5 (minimum 15 checks)
- [ ] JSON compliance report generated with pass/fail/score
- [ ] AWS Config conformance pack deployed (screenshot showing compliance results)
- [ ] Control-to-service mapping table in `docs/framework-mapping.md`
- [ ] Remediation commands documented for each failing control
- [ ] README explains scoring methodology and how to improve the score

---

## Links

→ Full project: [projects/09-cloud-compliance-audit/](../../projects/09-cloud-compliance-audit/)
→ Next: [Week 11 — Container Security & Docker Hardening](../week-11/README.md)
