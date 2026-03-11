# 🛡️ Cloud Security Mentorship Program — Extended Edition

> **6-Month Structured Roadmap** → Beginner to Job-Ready Cloud Security Engineer  
> Now with **24 Week-by-Week Assignment Guides**, **Step-by-Step Project Walkthroughs**, and **5 New Projects**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Projects](https://img.shields.io/badge/Projects-20-success)](projects/)
[![Weeks](https://img.shields.io/badge/Weeks-24-blue)](weeks/)
[![AWS](https://img.shields.io/badge/Cloud-AWS-FF9900?logo=amazonaws)](https://aws.amazon.com)
[![Azure](https://img.shields.io/badge/Cloud-Azure-0078D4?logo=microsoftazure)](https://azure.microsoft.com)
[![Python](https://img.shields.io/badge/Language-Python-3776AB?logo=python)](https://python.org)

---

## 📋 Programme Overview

| Attribute | Detail |
|-----------|--------|
| **Duration** | 24 Weeks (6 Months) |
| **Projects** | 20 GitHub Portfolio Projects (15 original + 5 new) |
| **Detection Queries** | 50+ KQL, CloudWatch, Athena SQL, Splunk SPL |
| **Target Role** | Cloud Security / DevSecOps Engineer |
| **Prerequisites** | Basic Linux, Networking, Cloud, Python/Bash |
| **Week Guides** | 24 individual week README files with assignments |

---

## 🗂️ Programme Phases

| Phase | Weeks | Focus |
|-------|-------|-------|
| **Phase 1** | 1–4 | Foundations — Networking, Storage, IAM basics |
| **Phase 2** | 5–8 | IAM & Identity Security — Escalation, Sentinel, GitHub |
| **Phase 3** | 9–12 | Threat Detection — SOAR, Compliance, Containers, K8s |
| **Phase 4** | 13–16 | DevSecOps & Automation — Pipelines, IaC, CSPM, UEBA |
| **Phase 5** | 17–20 | Advanced — Zero Trust, Forensics, Threat Intel, Career |
| **Phase 6** | 21–24 | **Capstone** — Cloud Security Operations Platform |

---

## 📅 Weekly Assignment Guides

Each week folder contains:
- **Learning objectives** for the week
- **Daily breakdown** (what to study each day)
- **Hands-on assignment** with acceptance criteria
- **Resources** (free courses, docs, videos)
- **Submission checklist**

| Week | Phase | Topic | Link |
|------|-------|-------|------|
| Week 01 | Phase 1 | VPC Networking & Security Groups | [→](weeks/week-01/README.md) |
| Week 02 | Phase 1 | S3 Security & Encryption | [→](weeks/week-02/README.md) |
| Week 03 | Phase 1 | IAM Fundamentals | [→](weeks/week-03/README.md) |
| Week 04 | Phase 1 | CloudTrail & Logging Setup | [→](weeks/week-04/README.md) |
| Week 05 | Phase 2 | IAM Privilege Escalation Paths | [→](weeks/week-05/README.md) |
| Week 06 | Phase 2 | Azure AD & Sentinel Basics | [→](weeks/week-06/README.md) |
| Week 07 | Phase 2 | GitHub Supply Chain Security | [→](weeks/week-07/README.md) |
| Week 08 | Phase 2 | Identity Review & Hardening | [→](weeks/week-08/README.md) |
| Week 09 | Phase 3 | Incident Response & SOAR | [→](weeks/week-09/README.md) |
| Week 10 | Phase 3 | Cloud Compliance Frameworks | [→](weeks/week-10/README.md) |
| Week 11 | Phase 3 | Container Security & Docker | [→](weeks/week-11/README.md) |
| Week 12 | Phase 3 | Kubernetes Security | [→](weeks/week-12/README.md) |
| Week 13 | Phase 4 | DevSecOps CI/CD Pipelines | [→](weeks/week-13/README.md) |
| Week 14 | Phase 4 | Infrastructure as Code Security | [→](weeks/week-14/README.md) |
| Week 15 | Phase 4 | CSPM & Multi-Cloud Visibility | [→](weeks/week-15/README.md) |
| Week 16 | Phase 4 | UEBA & Insider Threat | [→](weeks/week-16/README.md) |
| Week 17 | Phase 5 | Zero Trust Architecture | [→](weeks/week-17/README.md) |
| Week 18 | Phase 5 | Cloud Forensics & Investigations | [→](weeks/week-18/README.md) |
| Week 19 | Phase 5 | Threat Intelligence & CTI | [→](weeks/week-19/README.md) |
| Week 20 | Phase 5 | Career Prep & Portfolio Polish | [→](weeks/week-20/README.md) |
| Week 21 | Phase 6 | Capstone — Architecture & Design | [→](weeks/week-21/README.md) |
| Week 22 | Phase 6 | Capstone — Core Build | [→](weeks/week-22/README.md) |
| Week 23 | Phase 6 | Capstone — Integration & Testing | [→](weeks/week-23/README.md) |
| Week 24 | Phase 6 | Capstone — Presentation & Deploy | [→](weeks/week-24/README.md) |

---

## 📁 Projects (20 Total)

### Original 15 Projects (with Step-by-Step Guides)

| # | Project | Description | Key Tech | Guide |
|---|---------|-------------|----------|-------|
| 01 | [Network Security Auditor](projects/01-network-security-auditor/) | VPC/SG misconfiguration detection | boto3, Python | [Steps →](projects/01-network-security-auditor/STEPS.md) |
| 02 | [Storage Security Scanner](projects/02-storage-security-scanner/) | S3/Blob exposure + PII detection | boto3, regex | [Steps →](projects/02-storage-security-scanner/STEPS.md) |
| 03 | [IAM Security Analyser](projects/03-iam-security-analyser/) | Over-privilege, stale keys, MFA | boto3, Python | [Steps →](projects/03-iam-security-analyser/STEPS.md) |
| 04 | [IAM Privilege Escalation Detector](projects/04-iam-privilege-escalation-detector/) | 15+ escalation paths + MITRE ATT&CK | Lambda, EventBridge | [Steps →](projects/04-iam-privilege-escalation-detector/STEPS.md) |
| 05 | [CloudTrail Threat Hunting Lab](projects/05-cloudtrail-threat-hunting/) | Kill-chain hunting + timeline | Athena SQL, Python | [Steps →](projects/05-cloudtrail-threat-hunting/STEPS.md) |
| 06 | [Azure Sentinel Detection Engineering](projects/06-azure-sentinel-detection/) | 20+ KQL detection rules | KQL, Sentinel | [Steps →](projects/06-azure-sentinel-detection/STEPS.md) |
| 07 | [GitHub Security Monitoring](projects/07-github-security-monitoring/) | Supply chain + secret scanning | GitHub API, Python | [Steps →](projects/07-github-security-monitoring/STEPS.md) |
| 08 | [Automated Incident Response](projects/08-automated-incident-response/) | SOAR playbooks + Step Functions | Lambda, Step Functions | [Steps →](projects/08-automated-incident-response/STEPS.md) |
| 09 | [Cloud Compliance Audit Tool](projects/09-cloud-compliance-audit/) | CIS + ISO 27001 assessment | Python, AWS Config | [Steps →](projects/09-cloud-compliance-audit/STEPS.md) |
| 10 | [Container Security Framework](projects/10-container-security-framework/) | Docker hardening + Falco rules | Docker, Falco | [Steps →](projects/10-container-security-framework/STEPS.md) |
| 11 | [Kubernetes Threat Detection](projects/11-kubernetes-threat-detection/) | K8s RBAC + OPA + Falco | K8s, OPA, Falco | [Steps →](projects/11-kubernetes-threat-detection/STEPS.md) |
| 12 | [DevSecOps Pipeline](projects/12-devsecops-pipeline/) | 6-tool security CI/CD pipeline | GitHub Actions | [Steps →](projects/12-devsecops-pipeline/STEPS.md) |
| 13 | [Multi-Cloud Dashboard](projects/13-multi-cloud-dashboard/) | CSPM Streamlit dashboard | Streamlit, Python | [Steps →](projects/13-multi-cloud-dashboard/STEPS.md) |
| 14 | [Insider Threat Detection](projects/14-insider-threat-detection/) | UEBA + behaviour analytics | Python, statistics | [Steps →](projects/14-insider-threat-detection/STEPS.md) |
| 15 | [Capstone: Cloud SecOps Platform](projects/15-capstone-cloud-secops-platform/) | Complete integrated platform | All technologies | [Steps →](projects/15-capstone-cloud-secops-platform/STEPS.md) |

### 🆕 New Projects (5 Additional)

| # | Project | Description | Key Tech | Guide |
|---|---------|-------------|----------|-------|
| 16 | [Cloud WAF Security Monitor](projects/16-cloud-waf-security-monitor/) | AWS WAF log analysis & attack dashboard | WAF, Lambda, Python | [Steps →](projects/16-cloud-waf-security-monitor/README.md) |
| 17 | [Secrets Management with Vault](projects/17-secrets-management-vault/) | HashiCorp Vault on AWS + secret rotation | Vault, Terraform, AWS | [Steps →](projects/17-secrets-management-vault/README.md) |
| 18 | [Cloud Forensics Timeline Builder](projects/18-cloud-forensics-timeline/) | Automated IR timeline from CloudTrail/VPC | Python, Athena, Timeline | [Steps →](projects/18-cloud-forensics-timeline/README.md) |
| 19 | [Zero Trust Network Implementation](projects/19-zero-trust-implementation/) | mTLS + identity-aware proxy + least-priv | AWS Verified Access, Python | [Steps →](projects/19-zero-trust-implementation/README.md) |
| 20 | [Cloud Security Posture Scoring](projects/20-cloud-security-posture-scoring/) | Automated risk scoring across AWS account | Security Hub, Python, JSON | [Steps →](projects/20-cloud-security-posture-scoring/README.md) |

---

## 🚀 Quick Start

```bash
git clone https://github.com/ciphermichael/cloud-security-mentorship-program
cd cloud-security-mentorship-program

# Install shared dependencies
pip install -r shared/requirements.txt

# Start with Week 1
cat weeks/week-01/README.md

# Navigate to any project
cd projects/01-network-security-auditor
pip install -r requirements.txt
cat STEPS.md   # Full step-by-step guide
python src/auditor.py --help
```

---

## 🔍 Detection Query Library

See `shared/detection-queries/` for:
- **KQL** — Azure Sentinel / Microsoft Defender
- **CloudWatch Insights** — AWS log analysis
- **Athena SQL** — Large-scale CloudTrail analysis
- **Splunk SPL** — SIEM threat hunting

---

## 📜 Licence

MIT — See [LICENSE](LICENSE)
