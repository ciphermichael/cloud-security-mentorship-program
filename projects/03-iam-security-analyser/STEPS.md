# 🔍 Project 03 — IAM Security Analyser: Step-by-Step Guide

> **Skill Level:** Beginner-Intermediate | **Week:** 3

## Overview
Scans AWS IAM for over-privileged policies, stale access keys, missing MFA, and inactive users.

## Step 1 — Setup
```bash
mkdir iam-security-analyser && cd iam-security-analyser
python -m venv venv && source venv/bin/activate
pip install boto3 rich pandas
mkdir -p src reports tests
```

## Step 2 — Credential Report Analyser
```python
# src/credential_checker.py
import boto3, csv, io, time
from datetime import datetime, timezone

def get_credential_report() -> list:
    iam = boto3.client("iam")
    iam.generate_credential_report()
    time.sleep(2)
    report = iam.get_credential_report()["Content"].decode("utf-8")
    return list(csv.DictReader(io.StringIO(report)))

def check_mfa_disabled(users: list) -> list:
    return [
        {"user": u["user"], "severity": "CRITICAL", "issue": "MFA_DISABLED",
         "detail": f"User {u['user']} has no MFA device enabled"}
        for u in users if u.get("mfa_active") == "false" and u["user"] != "<root_account>"
    ]

def check_stale_keys(users: list, max_days: int = 90) -> list:
    findings = []
    now = datetime.now(timezone.utc)
    for u in users:
        for key_num in ["1", "2"]:
            active = u.get(f"access_key_{key_num}_active")
            last_used = u.get(f"access_key_{key_num}_last_used_date")
            if active == "true" and last_used and last_used != "N/A":
                last_used_dt = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                days = (now - last_used_dt).days
                if days > max_days:
                    findings.append({
                        "user": u["user"], "severity": "HIGH", "issue": "STALE_ACCESS_KEY",
                        "detail": f"Access key {key_num} last used {days} days ago"
                    })
    return findings
```

## Step 3 — Policy Wildcard Scanner
```python
# src/policy_checker.py
import boto3, json

def check_wildcard_policies() -> list:
    iam = boto3.client("iam")
    findings = []
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            version = iam.get_policy_version(
                PolicyArn=policy["Arn"],
                VersionId=policy["DefaultVersionId"]
            )["PolicyVersion"]["Document"]
            for stmt in version.get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    actions = stmt.get("Action", [])
                    resources = stmt.get("Resource", [])
                    a_list = actions if isinstance(actions, list) else [actions]
                    r_list = resources if isinstance(resources, list) else [resources]
                    if "*" in a_list and "*" in r_list:
                        findings.append({
                            "policy": policy["PolicyName"],
                            "arn": policy["Arn"],
                            "severity": "CRITICAL",
                            "issue": "WILDCARD_POLICY",
                            "detail": "Policy grants Action:* on Resource:* — full admin access"
                        })
    return findings
```

## Step 4 — Main Runner
```python
# src/analyser.py
from .credential_checker import get_credential_report, check_mfa_disabled, check_stale_keys
from .policy_checker import check_wildcard_policies
import json
from datetime import datetime
from pathlib import Path

def main():
    Path("reports").mkdir(exist_ok=True)
    print("[*] Generating IAM credential report...")
    users = get_credential_report()
    
    findings = []
    findings.extend(check_mfa_disabled(users))
    findings.extend(check_stale_keys(users))
    findings.extend(check_wildcard_policies())
    
    report = {"timestamp": datetime.utcnow().isoformat(), "findings": findings,
              "summary": {sev: sum(1 for f in findings if f.get("severity") == sev)
                          for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]}}
    
    with open("reports/iam-audit.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"[+] {len(findings)} total findings")
    for f in findings[:10]:
        key = "user" if "user" in f else "policy"
        print(f"  [{f['severity']}] {f.get(key,'?')}: {f['issue']}")

if __name__ == "__main__":
    main()
```

## Step 5 — Run
```bash
python -m src.analyser
cat reports/iam-audit.json | python -m json.tool | head -50
```

## Step 6 — Enhancements
1. Add unused role detection (no AssumeRole calls in 60 days)
2. Check for root account access keys
3. Add IAM Access Analyzer integration
4. Export to Excel with colour coding
5. Deploy as a weekly Lambda + email report
