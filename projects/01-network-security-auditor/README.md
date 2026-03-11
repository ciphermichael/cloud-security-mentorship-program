# 🔐 AWS Network Security Auditor

> **Week 2 Project** | Phase 1: Foundations

[![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)](https://python.org)
[![AWS](https://img.shields.io/badge/Cloud-AWS-FF9900?logo=amazonaws)](https://aws.amazon.com)

## 🚨 Problem Statement

Cloud teams routinely deploy Security Groups with `0.0.0.0/0` ingress rules for convenience — exposing SSH, RDP, and databases directly to the internet. This tool automatically detects these misconfigurations before attackers do.

## 🏗️ Architecture

```
AWS Account
    └── All Regions
            ├── EC2 Security Groups  ──► SG Checks (SG-001 to SG-006)
            ├── VPCs                 ──► Flow Log Coverage (FL-001, FL-002)
            ├── EC2 Instances        ──► Public Exposure (PE-001, PE-002)
            └── Network ACLs         ──► NACL Rules (NACL-001)
                        │
                        ▼
                Report Generator
                ├── HTML Report
                ├── Markdown Report
                └── JSON Output
```

## ✅ Security Concepts Demonstrated

- VPC security group least-privilege analysis
- Network ACL stateless rule auditing
- VPC Flow Log coverage verification
- Public IP exposure enumeration
- Risk-based finding severity scoring (CRITICAL → LOW)

## 🛠️ Tech Stack

![Python](https://img.shields.io/badge/-Python-3776AB?logo=python&logoColor=white)
![boto3](https://img.shields.io/badge/-boto3-FF9900?logo=amazonaws&logoColor=white)

## 🚀 Quick Start

```bash
cd projects/01-network-security-auditor
pip install -r requirements.txt

# Console output (default)
python src/auditor.py --region us-east-1

# Generate HTML report
python src/auditor.py --region us-east-1 --output html --output-file reports/audit.html

# Scan all regions
python src/auditor.py --all-regions --output markdown

# Use named AWS profile
python src/auditor.py --profile my-profile --region eu-west-1
```

## 📊 Security Checks

| Check ID | Severity | Description |
|----------|----------|-------------|
| SG-001 | 🔴 CRITICAL | All traffic open to 0.0.0.0/0 |
| SG-002 | 🔴 CRITICAL | SSH/RDP/DB port open to internet |
| SG-003 | 🟠 HIGH | High-risk ports (FTP/Telnet) open |
| SG-004 | 🟠 HIGH | All ports (0-65535) open |
| SG-005 | 🟡 MEDIUM | Unrestricted egress |
| SG-006 | 🟡 MEDIUM | Default SG has rules |
| FL-001 | 🟠 HIGH | VPC has no flow logs |
| FL-002 | 🟢 LOW | Flow logs to S3 only (no real-time) |
| PE-001 | 🟡 MEDIUM | EC2 instance has public IP |
| NACL-001 | 🟡 MEDIUM | NACL allows all inbound traffic |

## 📸 Screenshots
> Add screenshots of: terminal output, HTML report, AWS Console

## 🔗 Interview Talking Points
- "I built an automated SG auditor using boto3 that scans across all AWS regions and generates risk-prioritised HTML reports"
- "The tool detects the most common cloud misconfiguration — 0.0.0.0/0 on port 22 — that causes major breaches"
