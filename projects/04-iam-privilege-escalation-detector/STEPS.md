# 🔍 Project 04 — IAM Privilege Escalation Detector: Step-by-Step Guide

> **Skill Level:** Intermediate | **Week:** 5

## Overview
Detects 15+ AWS IAM privilege escalation paths in real-time using EventBridge and Lambda.

## The 15 Escalation Paths

| # | Path | Dangerous API | Severity |
|---|------|--------------|----------|
| 1 | CreateNewPolicyVersion | iam:CreatePolicyVersion | CRITICAL |
| 2 | SetDefaultPolicyVersion | iam:SetDefaultPolicyVersion | CRITICAL |
| 3 | CreateAccessKey | iam:CreateAccessKey | CRITICAL |
| 4 | CreateLoginProfile | iam:CreateLoginProfile | CRITICAL |
| 5 | UpdateLoginProfile | iam:UpdateLoginProfile | HIGH |
| 6 | AttachUserPolicy | iam:AttachUserPolicy | CRITICAL |
| 7 | AttachGroupPolicy | iam:AttachGroupPolicy | HIGH |
| 8 | AttachRolePolicy | iam:AttachRolePolicy | HIGH |
| 9 | PutUserPolicy | iam:PutUserPolicy | CRITICAL |
| 10 | PutGroupPolicy | iam:PutGroupPolicy | HIGH |
| 11 | PutRolePolicy | iam:PutRolePolicy | HIGH |
| 12 | AddUserToGroup | iam:AddUserToGroup | HIGH |
| 13 | UpdateAssumeRolePolicy | iam:UpdateAssumeRolePolicy | CRITICAL |
| 14 | PassRole+Lambda | iam:PassRole + lambda:CreateFunction | CRITICAL |
| 15 | PassRole+EC2 | iam:PassRole + ec2:RunInstances | HIGH |

## Step 1 — Create the EventBridge Rule
```bash
aws events put-rule \
  --name "IAMPrivEscDetection" \
  --event-pattern '{
    "source": ["aws.iam"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": [
        "CreatePolicyVersion","SetDefaultPolicyVersion","CreateAccessKey",
        "CreateLoginProfile","UpdateLoginProfile","AttachUserPolicy",
        "AttachGroupPolicy","AttachRolePolicy","PutUserPolicy","PutGroupPolicy",
        "PutRolePolicy","AddUserToGroup","UpdateAssumeRolePolicy"
      ]
    }
  }' \
  --state ENABLED
```

## Step 2 — Lambda Detection Function
```python
# src/detector.py
import json, boto3, os
from datetime import datetime

SNS_ARN = os.environ.get("SNS_ALERT_ARN")

ESCALATION_MAP = {
    "CreatePolicyVersion":    ("POLICY_VERSION_ESCALATION", "CRITICAL"),
    "SetDefaultPolicyVersion":("DEFAULT_POLICY_VERSION", "CRITICAL"),
    "CreateAccessKey":        ("NEW_ACCESS_KEY", "HIGH"),
    "CreateLoginProfile":     ("CREATE_CONSOLE_LOGIN", "CRITICAL"),
    "UpdateLoginProfile":     ("UPDATE_CONSOLE_LOGIN", "HIGH"),
    "AttachUserPolicy":       ("ATTACH_USER_POLICY", "CRITICAL"),
    "AttachGroupPolicy":      ("ATTACH_GROUP_POLICY", "HIGH"),
    "AttachRolePolicy":       ("ATTACH_ROLE_POLICY", "HIGH"),
    "PutUserPolicy":          ("INLINE_USER_POLICY", "CRITICAL"),
    "PutGroupPolicy":         ("INLINE_GROUP_POLICY", "HIGH"),
    "PutRolePolicy":          ("INLINE_ROLE_POLICY", "HIGH"),
    "AddUserToGroup":         ("USER_ADDED_TO_GROUP", "MEDIUM"),
    "UpdateAssumeRolePolicy": ("TRUST_POLICY_MODIFIED", "CRITICAL"),
}

def lambda_handler(event, context):
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "")

    if event_name not in ESCALATION_MAP:
        return

    path_name, severity = ESCALATION_MAP[event_name]
    user = detail.get("userIdentity", {}).get("arn", "Unknown")

    alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "escalation_path": path_name,
        "severity": severity,
        "actor": user,
        "event": event_name,
        "region": detail.get("awsRegion"),
        "source_ip": detail.get("sourceIPAddress"),
        "mitre_tactic": "TA0004 — Privilege Escalation",
        "mitre_technique": "T1098 — Account Manipulation",
    }

    print(json.dumps(alert))

    if SNS_ARN:
        boto3.client("sns").publish(
            TopicArn=SNS_ARN,
            Subject=f"[{severity}] IAM Privilege Escalation Detected: {path_name}",
            Message=json.dumps(alert, indent=2)
        )

    return alert
```

## Step 3 — Unit Tests
```python
# tests/test_detector.py
from src.detector import lambda_handler

def test_attach_user_policy_detection():
    event = {"detail": {
        "eventName": "AttachUserPolicy",
        "userIdentity": {"arn": "arn:aws:iam::123456789:user/alice"},
        "awsRegion": "us-east-1",
        "sourceIPAddress": "1.2.3.4"
    }}
    result = lambda_handler(event, None)
    assert result["severity"] == "CRITICAL"
    assert result["escalation_path"] == "ATTACH_USER_POLICY"

def test_unknown_event_returns_none():
    event = {"detail": {"eventName": "ListUsers"}}
    result = lambda_handler(event, None)
    assert result is None
```

## Step 4 — Deploy
```bash
# Package and deploy Lambda
zip -r function.zip src/ -x "src/__pycache__/*"
aws lambda create-function \
  --function-name IAMPrivEscDetector \
  --runtime python3.11 \
  --role arn:aws:iam::ACCOUNT:role/LambdaSecurityRole \
  --handler src.detector.lambda_handler \
  --zip-file fileb://function.zip \
  --environment "Variables={SNS_ALERT_ARN=arn:aws:sns:us-east-1:ACCOUNT:SecurityAlerts}"

# Wire EventBridge to Lambda
aws events put-targets \
  --rule IAMPrivEscDetection \
  --targets "Id=DetectorLambda,Arn=$(aws lambda get-function --function-name IAMPrivEscDetector --query Configuration.FunctionArn --output text)"
```

## Step 5 — Test End-to-End
```bash
# Simulate an escalation event
aws lambda invoke \
  --function-name IAMPrivEscDetector \
  --payload '{"detail":{"eventName":"AttachUserPolicy","userIdentity":{"arn":"arn:aws:iam::123:user/test"},"awsRegion":"us-east-1","sourceIPAddress":"1.2.3.4"}}' \
  response.json
cat response.json
```
