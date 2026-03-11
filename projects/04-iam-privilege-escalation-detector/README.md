# ⚡ IAM Privilege Escalation Detector

> **Week 5** | Phase 2: IAM & Identity Security | MITRE ATT&CK T1078.004

Detects 8 IAM privilege escalation paths in CloudTrail with real-time Lambda alerting via EventBridge.

## Usage
```bash
# Hunt CloudTrail for last 24 hours
python src/detection_engine.py --region us-east-1 --hours 24

# Print MITRE ATT&CK coverage matrix
python src/detection_engine.py --coverage-matrix

# Deploy Lambda for real-time detection
zip lambda.zip src/lambda/alert_handler.py
aws lambda create-function --function-name csop-escalation-detector \
  --zip-file fileb://lambda.zip --handler alert_handler.lambda_handler \
  --runtime python3.11 --role arn:aws:iam::ACCOUNT:role/lambda-role
```

## Escalation Paths Detected
| Path ID | Technique | Severity | Required Permission |
|---------|-----------|----------|-------------------|
| EP-001 | CreatePolicyVersion | 🔴 CRITICAL | iam:CreatePolicyVersion |
| EP-002 | PassRole + Lambda | 🟠 HIGH | iam:PassRole + lambda:* |
| EP-003 | AttachUserPolicy | 🔴 CRITICAL | iam:AttachUserPolicy |
| EP-004 | CreateAccessKey cross-user | 🟠 HIGH | iam:CreateAccessKey |
| EP-005 | UpdateLoginProfile | 🟠 HIGH | iam:UpdateLoginProfile |
| EP-006 | SetDefaultPolicyVersion | 🔴 CRITICAL | iam:SetDefaultPolicyVersion |
| EP-007 | PutUserPolicy | 🟠 HIGH | iam:PutUserPolicy |
| EP-008 | AddUserToGroup | 🟠 HIGH | iam:AddUserToGroup |
