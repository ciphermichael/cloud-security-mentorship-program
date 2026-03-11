# 🔍 CloudTrail Threat Hunting Lab

> **Week 6 Project** | Phase 2: IAM & Identity Security

[![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)](https://python.org)
[![AWS](https://img.shields.io/badge/CloudTrail-Threat_Hunt-FF9900?logo=amazonaws)](https://aws.amazon.com)

## 🚨 Problem Statement
Security teams need systematic methodology to investigate cloud compromises. This project builds a complete CloudTrail threat hunting framework covering all 5 kill-chain phases mapped to MITRE ATT&CK for Cloud.

## 🏗️ Architecture
```
CloudTrail Logs (S3 / CloudWatch)
    │
    ├── Phase 1: Reconnaissance Hunt  ──► ListBuckets, DescribeInstances
    ├── Phase 2: Escalation Hunt      ──► CreatePolicyVersion, AttachUserPolicy
    ├── Phase 3: Exfiltration Hunt    ──► GetObject, GetSecretValue
    ├── Phase 4: Persistence Hunt     ──► CreateUser, CreateFunction
    └── Phase 5: Evasion Hunt         ──► StopLogging, DeleteTrail
               │
               ▼
    Timeline Reconstruction → Attack Report
```

## 🚀 Usage
```bash
pip install -r requirements.txt

# Hunt all activity in last 24 hours
python src/threat_hunter.py --region us-east-1

# Hunt specific actor
python src/threat_hunter.py --actor arn:aws:iam::123456789012:user/bob --hours 72

# JSON output for SIEM
python src/threat_hunter.py --output json > hunt_results.json
```

## ✅ Kill-Chain Phases Detected
| Phase | Events Monitored | MITRE Tactic |
|-------|-----------------|--------------|
| 🔭 Reconnaissance | ListBuckets, DescribeInstances, GetCallerIdentity | Discovery |
| 🔺 Privilege Escalation | CreatePolicyVersion, AttachUserPolicy | Priv Esc |
| 📤 Exfiltration | GetObject, GetSecretValue | Exfiltration |
| 🕸️ Persistence | CreateUser, CreateAccessKey, CreateFunction | Persistence |
| 🫥 Defence Evasion | StopLogging, DeleteTrail | Defence Evasion |

## 📁 Included Queries
- `queries/athena/` — 10 Athena SQL hunting queries
- `queries/cloudwatch/` — CloudWatch Insights detection queries
- `playbooks/threat_hunting_playbook.md` — Step-by-step methodology

## 💼 Interview Talking Points
- "I built a kill-chain threat hunter that correlates CloudTrail events across 5 MITRE ATT&CK phases to reconstruct attacker timelines"
- "The tool detected a simulated account compromise within 3 minutes of running"
