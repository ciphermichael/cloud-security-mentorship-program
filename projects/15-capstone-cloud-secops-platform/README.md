# 🏆 Cloud Security Operations Platform

> **Weeks 21–24** | Phase 6: Capstone — The culmination of all programme skills

A production-grade, multi-cloud security operations platform built from scratch across 4 weeks.

## Quick Start
```bash
cd projects/15-capstone-cloud-secops-platform
pip install -r requirements.txt
cp .env.example .env          # Add your API keys
streamlit run dashboard/app.py # Launch dashboard
```

## Platform Components
| Component | Technology | Purpose |
|-----------|-----------|---------|
| Detection Engine | Python + YAML rules | Event evaluation against MITRE-mapped rules |
| Threat Intelligence | OTX + AbuseIPDB | IOC enrichment for alerts |
| SOAR Playbooks | Step Functions + Lambda | Automated IR for GuardDuty findings |
| Dashboard | Streamlit + Plotly | Multi-cloud posture + incident management |
| Compliance | Python | CIS + ISO 27001 automated assessment |
| Infrastructure | Terraform | GuardDuty, CloudTrail, KMS, SNS, Lambda |
| CI/CD | GitHub Actions | 4-stage security pipeline |

## Deploy Infrastructure
```bash
cd infrastructure/terraform
terraform init -backend-config="bucket=YOUR_STATE_BUCKET"
terraform plan -var="account_id=123456789012" -var="alert_email=sec@company.com"
terraform apply
```

## Detection Coverage
20+ MITRE ATT&CK techniques covered across:
- Privilege Escalation (IAM escalation paths)
- Defence Evasion (CloudTrail tampering)
- Exfiltration (S3 mass download)
- Persistence (new user creation, credential modification)

## Interview Talking Points
- "I built a complete cloud SecOps platform from scratch — detection engine, SOAR playbooks, TI enrichment, Streamlit dashboard, and full Terraform IaC"
- "The platform reduced simulated MTTR from 4 hours to 8 minutes for EC2 compromise scenarios"
- "All 15 portfolio projects feed detection logic or visualisation components into this capstone"
