# 🛡️ Cloud Security Mentorship Program

> **6-Month Structured Roadmap** → Beginner to Job-Ready Cloud Security Engineer

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Projects](https://img.shields.io/badge/Projects-15-success)](projects/)
[![AWS](https://img.shields.io/badge/Cloud-AWS-FF9900?logo=amazonaws)](https://aws.amazon.com)
[![Azure](https://img.shields.io/badge/Cloud-Azure-0078D4?logo=microsoftazure)](https://azure.microsoft.com)
[![Python](https://img.shields.io/badge/Language-Python-3776AB?logo=python)](https://python.org)

## 📋 Programme Overview

| Attribute | Detail |
|-----------|--------|
| **Duration** | 24 Weeks (6 Months) |
| **Projects** | 15 GitHub Portfolio Projects |
| **Detection Queries** | 50+ KQL, CloudWatch, Athena SQL, Splunk SPL |
| **Target Role** | Cloud Security / DevSecOps Engineer |
| **Prerequisites** | Basic Linux, Networking, Cloud, Python/Bash |

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

## 📁 Projects

| # | Project | Description | Key Tech |
|---|---------|-------------|----------|
| 01 | [Network Security Auditor](projects/01-network-security-auditor/) | VPC/SG misconfiguration detection | boto3, Python |
| 02 | [Storage Security Scanner](projects/02-storage-security-scanner/) | S3/Blob exposure + PII detection | boto3, regex |
| 03 | [IAM Security Analyser](projects/03-iam-security-analyser/) | Over-privilege, stale keys, MFA | boto3, Python |
| 04 | [IAM Privilege Escalation Detector](projects/04-iam-privilege-escalation-detector/) | 15+ escalation paths + MITRE ATT&CK | Lambda, EventBridge |
| 05 | [CloudTrail Threat Hunting Lab](projects/05-cloudtrail-threat-hunting/) | Kill-chain hunting + timeline | Athena SQL, Python |
| 06 | [Azure Sentinel Detection Engineering](projects/06-azure-sentinel-detection/) | 20+ KQL detection rules | KQL, Sentinel |
| 07 | [GitHub Security Monitoring](projects/07-github-security-monitoring/) | Supply chain + secret scanning | GitHub API, Python |
| 08 | [Automated Incident Response](projects/08-automated-incident-response/) | SOAR playbooks + Step Functions | Lambda, Step Functions |
| 09 | [Cloud Compliance Audit Tool](projects/09-cloud-compliance-audit/) | CIS + ISO 27001 assessment | Python, AWS Config |
| 10 | [Container Security Framework](projects/10-container-security-framework/) | Docker hardening + Falco rules | Docker, Falco |
| 11 | [Kubernetes Threat Detection](projects/11-kubernetes-threat-detection/) | K8s RBAC + OPA + Falco | K8s, OPA, Falco |
| 12 | [DevSecOps Pipeline](projects/12-devsecops-pipeline/) | 6-tool security CI/CD pipeline | GitHub Actions |
| 13 | [Multi-Cloud Dashboard](projects/13-multi-cloud-dashboard/) | CSPM Streamlit dashboard | Streamlit, Python |
| 14 | [Insider Threat Detection](projects/14-insider-threat-detection/) | UEBA + behaviour analytics | Python, statistics |
| 15 | [Capstone: Cloud SecOps Platform](projects/15-capstone-cloud-secops-platform/) | Complete integrated platform | All technologies |

---

## 🔍 Detection Query Library

See [`shared/detection-queries/`](shared/detection-queries/) for:
- **KQL** — Azure Sentinel / Microsoft Defender
- **CloudWatch Insights** — AWS log analysis
- **Athena SQL** — Large-scale CloudTrail analysis
- **Splunk SPL** — SIEM threat hunting

---

## 🚀 Getting Started

```bash
git clone https://github.com/YOUR_USERNAME/cloud-security-mentorship-program
cd cloud-security-mentorship-program

# Install shared dependencies
pip install -r shared/requirements.txt

# Navigate to any project
cd projects/01-network-security-auditor
pip install -r requirements.txt
python src/auditor.py --help
```

## 📜 Licence
MIT — See [LICENSE](LICENSE)
