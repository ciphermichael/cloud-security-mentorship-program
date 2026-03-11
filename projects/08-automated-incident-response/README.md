# 🚨 Automated Incident Response

> **Week 9** | Phase 3: Threat Detection & SIEM

SOAR playbooks + AWS Step Functions for automated EC2 compromise response. Reduces MTTR from hours to minutes.

## Playbooks Included
| Playbook | Trigger | Actions |
|----------|---------|---------|
| EC2 Compromise | GuardDuty HIGH/CRITICAL | Quarantine → Snapshot → Metadata → Notify |
| IAM Compromise | Escalation detector | Disable key → Revoke sessions → Alert |

## Deploy the Lambda
```bash
# Package
zip -j ir_handler.zip src/playbooks/ec2_compromise.py

# Create function
aws lambda create-function \
  --function-name csop-ir-ec2 \
  --zip-file fileb://ir_handler.zip \
  --handler ec2_compromise.lambda_handler \
  --runtime python3.11 \
  --role arn:aws:iam::ACCOUNT_ID:role/ir-lambda-role \
  --environment Variables="{SNS_TOPIC_ARN=arn:...,FORENSIC_S3_BUCKET=csop-forensic}"

# Wire to GuardDuty via EventBridge
aws events put-rule --name guardduty-high \
  --event-pattern '{"source":["aws.guardduty"],"detail":{"severity":[{"numeric":[">=",7]}]}}'
```

## Response Time Targets
| Action | Target |
|--------|--------|
| Detection → Quarantine | < 2 minutes |
| EBS snapshots created | < 5 minutes |
| Security team notified | < 3 minutes |
