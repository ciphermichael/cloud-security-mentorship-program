# Week 24 — Capstone: Presentation, Deployment & Program Graduation

**Phase 6: Final Week | Project: 15-capstone-cloud-secops-platform**

---

## Final Week Goals

By end of this week:
1. Platform deployed to production AWS (free tier)
2. 10-minute Loom demo video recorded
3. Final GitHub README — the best README you've ever written
4. 500-word blog post published on LinkedIn or Medium
5. 15-minute live presentation delivered to the cohort
6. Portfolio complete: 20 projects, all READMEs polished

---

## Daily Breakdown

| Day | Focus | Deliverable |
|-----|-------|-------------|
| Mon | Production deployment — Terraform apply, smoke test, final security check | Platform live at public URL |
| Tue | Final README and documentation sprint | README merged and complete |
| Wed | Demo video recording (10 min) — show every major feature | Loom video published |
| Thu | Blog post writing and publishing | LinkedIn/Medium post live |
| Fri | Presentation rehearsal x3, final portfolio check | Presentation ready |
| Sat | Live presentation to cohort (15 min + 10 min Q&A) | Graduation ceremony |
| Sun | Reflection, what's next, job applications sprint | Program complete |

---

## Production Deployment

### Final Deployment Checklist

Before deploying to production:

```bash
# 1. Final security scan of Terraform
checkov -d infrastructure/terraform/ \
  --framework terraform \
  --quiet \
  --compact

# 2. Final dependency scan
pip-audit -r requirements.txt
safety check -r requirements.txt

# 3. Final secrets scan
gitleaks detect --source . --verbose

# 4. Terraform plan review
cd infrastructure/terraform
terraform init
terraform plan -out=final-plan.tfplan

# Review the plan — verify:
# - All resources tagged correctly
# - No public S3 buckets
# - DynamoDB encryption enabled
# - Lambda roles are least-privilege
# - No resource deletions you didn't intend

# 5. Apply
terraform apply final-plan.tfplan

# 6. Smoke test
python scripts/smoke_test.py
```

```python
# scripts/smoke_test.py
"""Production smoke test — verify all platform components are healthy."""
import boto3
import json
import sys
from datetime import datetime, timezone

REGION = 'us-east-1'

def check_dynamodb():
    dynamodb = boto3.client('dynamodb', region_name=REGION)
    try:
        resp = dynamodb.describe_table(TableName='secops-findings')
        status = resp['Table']['TableStatus']
        assert status == 'ACTIVE', f'DynamoDB not ACTIVE: {status}'
        sse = resp['Table'].get('SSEDescription', {})
        assert sse.get('Status') == 'ENABLED', 'Encryption not enabled'
        print('  ✓ DynamoDB: ACTIVE, encrypted')
        return True
    except Exception as e:
        print(f'  ✗ DynamoDB: {e}')
        return False

def check_lambda():
    lambda_client = boto3.client('lambda', region_name=REGION)
    try:
        resp = lambda_client.get_function_configuration(
            FunctionName='secops-detection-engine'
        )
        state = resp.get('State', 'Unknown')
        assert state == 'Active', f'Lambda not Active: {state}'
        print(f'  ✓ Lambda: Active, runtime={resp.get("Runtime")}')
        return True
    except Exception as e:
        print(f'  ✗ Lambda: {e}')
        return False

def check_eventbridge():
    events = boto3.client('events', region_name=REGION)
    try:
        resp = events.describe_rule(Name='secops-iam-escalation')
        state = resp.get('State', 'Unknown')
        assert state == 'ENABLED', f'EventBridge rule not ENABLED: {state}'
        print(f'  ✓ EventBridge: ENABLED')
        return True
    except Exception as e:
        print(f'  ✗ EventBridge: {e}')
        return False

def check_detection_end_to_end():
    """Inject a test event and verify it creates a finding."""
    lambda_client = boto3.client('lambda', region_name=REGION)
    test_event = {
        'detail': {
            'eventName': 'CreateAccessKey',
            'eventTime': datetime.now(timezone.utc).isoformat(),
            'userIdentity': {
                'type': 'IAMUser',
                'arn': 'arn:aws:iam::000000000000:user/smoke-test',
                'userName': 'smoke-test'
            },
            'sourceIPAddress': '127.0.0.1'
        }
    }
    try:
        resp = lambda_client.invoke(
            FunctionName='secops-detection-engine',
            InvocationType='RequestResponse',
            Payload=json.dumps(test_event)
        )
        result = json.loads(resp['Payload'].read())
        assert result.get('count', 0) >= 1, 'No findings created from test event'
        print(f'  ✓ End-to-end detection: {result["count"]} finding(s) created')
        return True
    except Exception as e:
        print(f'  ✗ End-to-end detection: {e}')
        return False

if __name__ == '__main__':
    print('Running production smoke tests...\n')
    checks = [check_dynamodb, check_lambda, check_eventbridge, check_detection_end_to_end]
    results = [check() for check in checks]
    print(f'\n{"✓ All checks passed" if all(results) else "✗ Some checks failed"} '
          f'({sum(results)}/{len(results)})')
    sys.exit(0 if all(results) else 1)
```

---

## Final README Template

The capstone README must be the best README in your portfolio. Use this template:

```markdown
# Cloud Security Operations Platform

> A production-grade security operations platform that ingests cloud logs,
> detects threats in real time, auto-responds to incidents, and visualizes
> security posture across AWS and Azure.

[![CI](https://github.com/YOUR_USERNAME/cloud-secops-platform/actions/workflows/ci.yml/badge.svg)](...)
[![Coverage](https://img.shields.io/badge/coverage-78%25-green)](...)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## What This Platform Does

[Architecture diagram here — PNG exported from draw.io]

The platform consists of 8 integrated components:

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Log Ingestion | Lambda + EventBridge | Real-time CloudTrail event processing |
| Detection Engine | Python + 20 rules | MITRE-mapped threat detection |
| Data Lake | S3 + Glue + Athena | Historical log storage and query |
| SOAR Orchestrator | Step Functions | Automated incident containment |
| CTI Enrichment | AlienVault OTX | Threat actor context on every finding |
| UEBA Engine | Python + pandas | Insider threat behavioural analytics |
| Compliance Checker | AWS Config + Python | CIS Benchmark continuous assessment |
| Dashboard | Streamlit | Live security posture visualization |

---

## Live Demo

[Link to deployed Streamlit dashboard]
[Link to Loom demo video]

---

## Security Concepts Demonstrated

- IAM Privilege Escalation Detection (MITRE T1098, T1098.001, T1098.003)
- CloudTrail Threat Hunting with Athena SQL
- Automated SOAR response with AWS Step Functions
- UEBA Anomaly Detection (3-sigma baseline deviation)
- CTI Enrichment with AlienVault OTX and AbuseIPDB
- CIS AWS Foundations Benchmark Compliance Scoring
- DevSecOps: 7-stage security pipeline with SARIF reporting
- Zero Trust IAM: per-session authorization, MFA conditions

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/YOUR_USERNAME/cloud-secops-platform
cd cloud-secops-platform
pip install -r requirements.txt

# Configure AWS credentials
export AWS_PROFILE=security-sandbox
export AWS_REGION=us-east-1

# Deploy infrastructure (requires Terraform)
cd infrastructure/terraform
terraform init && terraform apply

# Run smoke test
python scripts/smoke_test.py

# Start dashboard
streamlit run src/dashboard/app.py
```

---

## Detection Rules

The platform includes 20 detection rules across 8 MITRE ATT&CK tactics:

| Rule | Severity | MITRE | Tactic |
|------|----------|-------|--------|
| Root Account API Call | CRITICAL | T1078 | Initial Access |
| CloudTrail Deleted | CRITICAL | T1562.008 | Defense Evasion |
| IAM Privilege Escalation | CRITICAL/HIGH | T1098.003 | Priv. Escalation |
| New IAM User Created | HIGH | T1136.003 | Persistence |
| Mass S3 Download | HIGH | T1530 | Collection |
| ... | | | |

---

## Architecture Decision Records

See [docs/adr/](docs/adr/) for key architectural decisions and their rationale.

---

## Tests

```bash
pytest tests/ -v --cov=src --cov-report=term
# 78% coverage, 47 tests
```

---

## License

MIT — See [LICENSE](LICENSE)
```

---

## Demo Video Script (10 minutes)

Structure your Loom recording:

```
0:00 - 0:30  Introduction: "I built a Cloud Security Operations Platform 
             over 6 months. Let me show you what it does."

0:30 - 2:00  Architecture walkthrough: show the diagram, explain each component
             in plain English. "This is the detection engine — it watches 
             CloudTrail in real time..."

2:00 - 4:00  Live demo Part 1: trigger an IAM escalation event, watch the 
             Lambda fire, show the finding appear in the dashboard in real time.

4:00 - 5:30  Live demo Part 2: show SOAR in action — GuardDuty finding triggers
             Step Functions, instance gets isolated, Slack alert fires.

5:30 - 7:00  Dashboard walkthrough: risk score, severity breakdown chart, 
             finding detail, CSV export, CTI enrichment on a finding.

7:00 - 8:30  Code walkthrough: show the detection engine code, one unit test,
             the Terraform config for the Lambda role.

8:30 - 9:30  Interview talking points: "The hardest part was X... The most
             interesting thing I learned was Y... I'd extend it by doing Z."

9:30 - 10:00 Call to action: GitHub link, LinkedIn, available for interviews.
```

---

## Presentation Structure (15 minutes + 10 min Q&A)

```
Slide 1 (1 min): Title + Your Name
"I built a complete Cloud Security Operations Platform over 6 months.
Today I'll walk you through what I built, what I learned, and what's next."

Slide 2 (2 min): The Problem
"Security teams in cloud environments face three challenges: 
[visibility, response speed, scale]. I built a platform that addresses all three."

Slide 3 (3 min): Architecture
[Show your architecture diagram]
"The platform ingests from CloudTrail, GuardDuty, Security Hub, and Azure Sentinel..."

Slide 4 (3 min): Live Demo
[Switch to browser — live platform]
"Let me show you a real finding from earlier today..."

Slide 5 (2 min): Technical Highlights
"The detection engine runs 20 rules mapped to MITRE ATT&CK.
The SOAR pipeline can isolate a compromised EC2 instance in under 5 minutes.
The platform self-audits using the same tools I built earlier in the program."

Slide 6 (2 min): What I Learned + What's Next
"The hardest part was [X]. The most valuable insight was [Y].
Next I want to add [Z feature] and get the [AWS Security Specialty / CompTIA CySA+]."

Slide 7 (1 min): Thank You + Questions
GitHub: github.com/yourhandle
LinkedIn: linkedin.com/in/yourhandle
Available for interviews: immediately / [date]
```

---

## Program Graduation Checklist

### Portfolio (20 Projects)

- [ ] 01 Network Security Auditor — README with architecture and demo
- [ ] 02 Storage Security Scanner — README with architecture and demo
- [ ] 03 IAM Security Analyser — README with architecture and demo
- [ ] 04 IAM Privilege Escalation Detector — README with architecture and demo
- [ ] 05 CloudTrail Threat Hunting Lab — README with queries and demo
- [ ] 06 Azure Sentinel Detection Engineering — 20 KQL rules documented
- [ ] 07 GitHub Security Monitoring — README with architecture and demo
- [ ] 08 Automated Incident Response — SOAR diagram and demo
- [ ] 09 Cloud Compliance Audit Tool — CIS scoring and report
- [ ] 10 Container Security Framework — Falco rules and scan results
- [ ] 11 Kubernetes Threat Detection — RBAC, OPA, Falco setup
- [ ] 12 DevSecOps Pipeline — 7-stage workflow, SARIF screenshots
- [ ] 13 Multi-Cloud Dashboard — deployed Streamlit link
- [ ] 14 Insider Threat Detection — UEBA report and risk scores
- [ ] 15 Capstone Cloud SecOps Platform — full README, live URL, Loom video
- [ ] 16-20 Additional projects — each with README and demo

### Skills Demonstrated

- [ ] AWS security services (IAM, CloudTrail, GuardDuty, Security Hub, Config, Step Functions)
- [ ] Azure security (Sentinel, Defender for Cloud, KQL, Entra ID)
- [ ] Detection engineering (20+ rules in KQL, SPL, Athena SQL, CloudWatch Insights)
- [ ] SOAR and incident response automation
- [ ] Container and Kubernetes security
- [ ] DevSecOps CI/CD security pipelines
- [ ] Cloud compliance (CIS, ISO 27001, SOC 2)
- [ ] Threat intelligence integration
- [ ] UEBA and behavioural analytics
- [ ] Zero Trust architecture design
- [ ] Cloud forensics investigation
- [ ] Professional documentation and reporting

### What's Next

After program completion, recommended next steps:

**Certifications:**
- AWS Security Specialty (most respected for AWS cloud security)
- CompTIA CySA+ (vendor-neutral, good baseline)
- Microsoft SC-200 (Azure Security Operations Analyst)
- CCSP (ISC)² Cloud Security Professional

**Communities:**
- Cloud Security Forum (reddit.com/r/cloudsecurity)
- SANS Internet Storm Center (isc.sans.edu)
- MITRE ATT&CK Community (groups.google.com/g/attack-community)
- Cloud Security Alliance (cloudsecurityalliance.org)

**CTF and Challenges:**
- CloudGoat (vulnerable-by-design AWS environment by Rhino Security Labs)
- FLAWS.cloud (free AWS security challenges)
- Kubernetes Goat (vulnerable K8s environment)
- HackTheBox (cloud-focused challenges)

**Continued Learning:**
- AWS Security Blog (aws.amazon.com/security/security-bulletins)
- Cloudvulndb.org (cloud vulnerability database)
- CISA cybersecurity advisories

---

## Final Words from Your Mentor

You started this program with basic Linux, networking, and scripting knowledge. Over 24 weeks you've:

- Built 20 security tools from scratch
- Written 50+ detection queries across 4 query languages
- Engineered automated incident response pipelines
- Hardened containers, Kubernetes clusters, and cloud accounts
- Designed a complete security operations platform

The cloud security field needs engineers who can build, not just configure. You are now one of them.

The GitHub portfolio you've built demonstrates more practical ability than most certifications. Use it. Show it. Be proud of it.

Good luck — you've earned it.

---

## Links

→ Full project: [projects/15-capstone-cloud-secops-platform/](../../projects/15-capstone-cloud-secops-platform/)
→ Full program overview: [README.md](../../README.md)
