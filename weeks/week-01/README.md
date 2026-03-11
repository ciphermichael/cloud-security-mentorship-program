# 📅 Week 1 — VPC Networking & Security Groups

**Phase 1: Foundations | Project: 01-network-security-auditor**

---

## 🎯 Learning Objectives

By the end of this week you will be able to:
- Describe how AWS VPCs, subnets, route tables, and internet gateways work
- Identify dangerous Security Group misconfigurations (0.0.0.0/0 ingress on sensitive ports)
- Write boto3 Python code to query VPC and SG resources
- Produce a structured JSON report of findings

---

## 📅 Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | AWS VPC fundamentals — subnets, route tables, NACLs, IGW | 2 hrs |
| Tue | Security Groups deep-dive — stateful vs stateless, CIDR rules | 2 hrs |
| Wed | boto3 setup — AWS CLI config, IAM permissions, first API call | 2 hrs |
| Thu | Build the SG scanner — list all SGs, flag 0.0.0.0/0 ingress | 2 hrs |
| Fri | Add VPC flow log gap detection + generate JSON report | 2 hrs |
| Sat | Polish, test against a real AWS account (free tier), push to GitHub | 3 hrs |
| Sun | Review, read feedback, prep Week 2 reading | 1 hr |

---

## 📚 Study Resources

- [AWS VPC Documentation](https://docs.aws.amazon.com/vpc/latest/userguide/)
- [boto3 EC2 Reference](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html)
- [Cloud Security Alliance: VPC Security Best Practices](https://cloudsecurityalliance.org)
- Free: [AWS Skill Builder — Cloud Practitioner Essentials](https://explore.skillbuilder.aws)
- Video: Search "AWS VPC explained" on YouTube (freeCodeCamp or TechWorld with Nana)

---

## 📝 Weekly Assignment

### Task: VPC & Security Group Audit Script

Build a Python script that:

1. **Lists all VPCs** in your AWS account with their CIDR ranges
2. **Scans all Security Groups** for inbound rules that allow:
   - `0.0.0.0/0` on port 22 (SSH)
   - `0.0.0.0/0` on port 3389 (RDP)
   - `0.0.0.0/0` on port 3306 (MySQL)
   - `0.0.0.0/0` on **any** port (`-1`)
3. **Checks for VPCs missing flow logs**
4. **Outputs a JSON report** with severity levels: `CRITICAL`, `HIGH`, `MEDIUM`
5. **Prints a summary table** to stdout

### Acceptance Criteria

- [ ] Script runs with `python auditor.py --region us-east-1`
- [ ] JSON report saved to `reports/YYYY-MM-DD-audit.json`
- [ ] At least 3 severity levels implemented
- [ ] README explains how to run and interpret findings
- [ ] Code pushed to GitHub with meaningful commit messages

### Starter Skeleton

```python
import boto3
import json
from datetime import datetime

def get_security_groups(region: str) -> list:
    ec2 = boto3.client('ec2', region_name=region)
    response = ec2.describe_security_groups()
    return response['SecurityGroups']

def check_open_ingress(sg: dict) -> list:
    findings = []
    dangerous_ports = {22: 'SSH', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL'}
    for rule in sg.get('IpPermissions', []):
        for cidr in rule.get('IpRanges', []):
            if cidr['CidrIp'] == '0.0.0.0/0':
                port = rule.get('FromPort', -1)
                findings.append({
                    'sg_id': sg['GroupId'],
                    'sg_name': sg.get('GroupName'),
                    'port': port,
                    'service': dangerous_ports.get(port, 'Unknown'),
                    'severity': 'CRITICAL' if port in dangerous_ports else 'HIGH'
                })
    return findings

if __name__ == '__main__':
    # TODO: add argparse, loop regions, save JSON
    pass
```

---

## ✅ Submission Checklist

- [ ] GitHub repo link shared with mentor
- [ ] Script tested against AWS free-tier account
- [ ] JSON report example committed to `reports/` folder
- [ ] Reflection paragraph: what was hardest? what would you add next?

---

## 🔗 Links to Project

→ Full project: [`projects/01-network-security-auditor/`](../../projects/01-network-security-auditor/)  
→ Step-by-step guide: [`projects/01-network-security-auditor/STEPS.md`](../../projects/01-network-security-auditor/STEPS.md)
