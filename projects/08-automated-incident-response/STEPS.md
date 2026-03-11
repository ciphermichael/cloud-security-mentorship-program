# Project 08 — Automated Incident Response (SOAR): Step-by-Step Guide

> **Skill Level:** Intermediate | **Week:** 9

## Overview
Build SOAR playbooks using AWS Step Functions + Lambda for fully automated IR.

## Playbook Flow: Compromised EC2
```
GuardDuty Finding (severity ≥ 7)
  → EventBridge Rule
  → Step Functions State Machine
      1. Isolate EC2 (swap to empty Security Group)
      2. Snapshot EBS volumes (forensic preservation)
      3. Notify Slack
      4. Create JIRA ticket
      5. Tag resource as COMPROMISED
```

## Step 1 — Create Forensic Isolation SG
```bash
SG_ID=$(aws ec2 create-security-group \
  --group-name forensic-isolation \
  --description "Zero-trust forensic isolation" \
  --vpc-id vpc-YOUR_VPC \
  --query GroupId --output text)
echo "Forensic SG: $SG_ID"
# Do NOT add any inbound or outbound rules — leave completely empty
```

## Step 2 — Lambda: EC2 Isolation
```python
# src/lambdas/isolate_ec2.py
import boto3, os
from datetime import datetime

FORENSIC_SG = os.environ['FORENSIC_SG_ID']

def handler(event, context):
    ec2 = boto3.client('ec2')
    instance_id = event['instance_id']

    resp = ec2.describe_instances(InstanceIds=[instance_id])
    prev_sgs = [sg['GroupId']
        for r in resp['Reservations']
        for i in r['Instances']
        for sg in i['SecurityGroups']]

    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[FORENSIC_SG])
    ec2.create_tags(Resources=[instance_id], Tags=[
        {'Key': 'SecurityStatus', 'Value': 'COMPROMISED'},
        {'Key': 'IsolatedAt', 'Value': datetime.utcnow().isoformat()},
        {'Key': 'PreviousSGs', 'Value': ','.join(prev_sgs)},
    ])
    return {'instance_id': instance_id, 'previous_sgs': prev_sgs, 'status': 'ISOLATED'}
```

## Step 3 — Lambda: EBS Snapshot
```python
# src/lambdas/snapshot_ebs.py
import boto3
from datetime import datetime

def handler(event, context):
    ec2 = boto3.client('ec2')
    instance_id = event['instance_id']
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    volumes = [m['Ebs']['VolumeId']
        for r in resp['Reservations']
        for i in r['Instances']
        for m in i.get('BlockDeviceMappings', []) if 'Ebs' in m]

    snapshots = []
    for vol in volumes:
        snap = ec2.create_snapshot(
            VolumeId=vol,
            Description=f'FORENSIC-{instance_id}-{datetime.utcnow().strftime("%Y%m%d-%H%M")}',
            TagSpecifications=[{'ResourceType': 'snapshot', 'Tags': [
                {'Key': 'Purpose', 'Value': 'ForensicCapture'},
                {'Key': 'InstanceId', 'Value': instance_id}
            ]}]
        )
        snapshots.append(snap['SnapshotId'])
    return {**event, 'snapshots': snapshots}
```

## Step 4 — Lambda: Slack Notifier
```python
# src/lambdas/notify_slack.py
import json, urllib.request, os

SLACK_WEBHOOK = os.environ['SLACK_WEBHOOK_URL']

def handler(event, context):
    msg = {
        'text': ':rotating_light: *Security Incident — EC2 Compromised*',
        'attachments': [{'color': '#FF0000', 'fields': [
            {'title': 'Instance', 'value': event.get('instance_id', 'N/A'), 'short': True},
            {'title': 'Status', 'value': event.get('status', 'N/A'), 'short': True},
            {'title': 'Snapshots', 'value': str(event.get('snapshots', [])), 'short': False},
        ]}]
    }
    req = urllib.request.Request(SLACK_WEBHOOK, json.dumps(msg).encode(),
                                  {'Content-Type': 'application/json'})
    urllib.request.urlopen(req)
    return {**event, 'slack_notified': True}
```

## Step 5 — Step Functions State Machine (ASL)
```json
{
  "Comment": "Compromised EC2 IR Playbook",
  "StartAt": "IsolateInstance",
  "States": {
    "IsolateInstance": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:REGION:ACCT:function:isolate-ec2",
      "Next": "SnapshotVolumes",
      "Retry": [{"ErrorEquals": ["States.ALL"], "MaxAttempts": 2}]
    },
    "SnapshotVolumes": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:REGION:ACCT:function:snapshot-ebs",
      "Next": "NotifySlack"
    },
    "NotifySlack": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:REGION:ACCT:function:notify-slack",
      "End": true
    }
  }
}
```

## Step 6 — EventBridge Rule (GuardDuty Trigger)
```bash
aws events put-rule --name GuardDutyHighSeverity \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {"severity": [{"numeric": [">=", 7]}]}
  }' --state ENABLED

aws events put-targets --rule GuardDutyHighSeverity \
  --targets '[{
    "Id": "IRPlaybook",
    "Arn": "arn:aws:states:REGION:ACCT:stateMachine:CompromisedEC2Playbook",
    "RoleArn": "arn:aws:iam::ACCT:role/EventBridgeStepFunctionsRole"
  }]'
```

## Step 7 — Test End-to-End
```bash
aws stepfunctions start-execution \
  --state-machine-arn arn:aws:states:REGION:ACCT:stateMachine:CompromisedEC2Playbook \
  --input '{"instance_id": "i-0abc123def456789", "severity": 8}'

# Watch execution in AWS Console > Step Functions
```

## Step 8 — Additional Playbooks to Build
1. **Compromised IAM Key** — deactivate key, find API calls, notify
2. **Public S3 Bucket Detected** — enable block public access automatically  
3. **Abnormal Data Exfiltration** — quarantine IAM user, revoke sessions
4. **Ransomware Detected on EC2** — isolate + snapshot + alert CISO
