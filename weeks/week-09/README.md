# Week 09 — Automated Incident Response & SOAR

**Phase 3: Threat Detection & Response | Project: 08-automated-incident-response**

---

## Learning Objectives

By the end of this week you will be able to:

- Design SOAR playbooks for the 5 most common cloud security incidents
- Implement an AWS Step Functions state machine for orchestrated incident response
- Use Lambda functions to perform automated containment actions
- Integrate Slack/SNS/PagerDuty alerts into a response workflow
- Define MTTD (Mean Time to Detect) and MTTR (Mean Time to Respond) as measurable security metrics
- Build a playbook that isolates a compromised EC2 instance in under 5 minutes

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | SOAR concepts — playbooks, runbooks, triage tiers, MTTD/MTTR | 2 hrs |
| Tue | AWS Step Functions fundamentals — states, transitions, error handling, Express workflows | 2 hrs |
| Wed | Build containment Lambda functions: isolate EC2, revoke IAM credentials, snapshot EBS | 2 hrs |
| Thu | Wire the Step Functions state machine, connect GuardDuty → EventBridge → SOAR | 2 hrs |
| Fri | Build 2 more playbooks: S3 data exfiltration, compromised IAM key | 2 hrs |
| Sat | Full architecture diagram, deployment via CloudFormation/SAM, push to GitHub | 3 hrs |
| Sun | Mentor review — simulate an incident and run the playbook live | 1 hr |

---

## Topics Covered

### SOAR Fundamentals

**SOAR** = Security Orchestration, Automation, and Response.

**Playbook** — documented sequence of steps to respond to a specific threat scenario. Defines who does what, when, with what tools.

**Runbook** — technical how-to document. Execution instructions for one step in a playbook. Example: "How to isolate an EC2 instance."

**Triage Tiers:**
- **Tier 1** — Automated: alert → automated check → auto-close or escalate (no human needed)
- **Tier 2** — Assisted: human reviews alert with automated context enrichment
- **Tier 3** — Manual: complex investigation requiring senior analyst

**Key metrics:**
- **MTTD** — Mean Time to Detect: from incident start to alert firing
- **MTTR** — Mean Time to Respond: from alert firing to containment complete
- Industry benchmarks: MTTD <15 min, MTTR <60 min for high-severity cloud incidents

### AWS GuardDuty → EventBridge → SOAR Pipeline

```
GuardDuty Finding
  ↓ (EventBridge rule on finding severity)
EventBridge Rule
  ↓ (target: Step Functions Express Workflow)
SOAR Orchestrator (Step Functions)
  ├─ Enrich: Lambda → get more context from CloudTrail, VPC
  ├─ Triage: Lambda → decide severity, check whitelist
  ├─ Contain: Lambda → isolate resource (if auto-approved)
  ├─ Notify: SNS → Slack channel, PagerDuty
  └─ Ticket: Lambda → create Jira/ServiceNow ticket
```

### 5 Cloud Incident Playbooks

| Incident | GuardDuty Finding Type | Auto-Contain? | MTTR Target |
|----------|----------------------|---------------|-------------|
| Compromised EC2 | `UnauthorizedAccess:EC2/MaliciousIPCaller` | Yes | <5 min |
| Compromised IAM Key | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` | Yes (disable key) | <3 min |
| S3 Data Exfiltration | `Exfiltration:S3/MaliciousIPCaller` | Yes (block bucket public) | <5 min |
| Crypto Mining | `CryptoCurrency:EC2/BitcoinTool.B` | Yes (terminate instance) | <10 min |
| Recon from Compromised Account | `Recon:IAMUser/NetworkPermissions` | No (requires human) | <30 min |

---

## Instructor Mentoring Guidance

**Week 9 teaches students to think operationally.** Detection is not enough — you must contain and remediate. The most common failure mode is engineers who build great detection but have no idea how to respond.

**Key coaching points:**
- Emphasize that automated containment must be reversible where possible. Isolating an instance is safe; terminating it may destroy forensic evidence.
- Step Functions can be deployed with AWS SAM or CloudFormation — teach the infrastructure-as-code approach from day one.
- The simulation exercise at the end of the week (mentor simulates a GuardDuty finding, student runs the playbook) is critical — theory without practice doesn't stick.

**Mentoring session agenda (60 min):**
1. (10 min) Student demo: run the compromised EC2 playbook against a test instance
2. (20 min) Scenario: "GuardDuty fires `Backdoor:EC2/C&CActivity` — walk me through your next 30 minutes"
3. (20 min) Code review of Step Functions definition and Lambda functions
4. (10 min) Preview Week 10 — compliance frameworks and how SOAR supports compliance

---

## Hands-on Lab

### Lab 1: EC2 Isolation Lambda

```python
# lambda/isolate_ec2.py
import boto3
import json
from datetime import datetime, timezone

ec2 = boto3.client('ec2')
iam = boto3.client('iam')


def create_isolation_security_group(vpc_id: str, instance_id: str) -> str:
    """Create a deny-all security group for isolation."""
    sg_name = f'ISOLATED-{instance_id}-{int(datetime.now().timestamp())}'
    sg = ec2.create_security_group(
        GroupName=sg_name,
        Description=f'Isolation SG for incident response - {instance_id}',
        VpcId=vpc_id
    )
    sg_id = sg['GroupId']
    # Revoke default egress (all traffic)
    ec2.revoke_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[{
            'IpProtocol': '-1',
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }]
    )
    # Tag for forensic tracking
    ec2.create_tags(Resources=[sg_id], Tags=[
        {'Key': 'Purpose', 'Value': 'IncidentResponse'},
        {'Key': 'IsolatedAt', 'Value': datetime.now(timezone.utc).isoformat()},
        {'Key': 'TargetInstance', 'Value': instance_id}
    ])
    return sg_id


def lambda_handler(event: dict, context) -> dict:
    instance_id = event['instance_id']
    finding_id = event.get('finding_id', 'unknown')

    # Get current instance details
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    instance = resp['Reservations'][0]['Instances'][0]
    vpc_id = instance['VpcId']
    original_sgs = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]

    # Create isolation SG
    isolation_sg = create_isolation_security_group(vpc_id, instance_id)

    # Replace all security groups with isolation SG
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[isolation_sg]
    )

    # Tag instance as isolated
    ec2.create_tags(Resources=[instance_id], Tags=[
        {'Key': 'SecurityStatus', 'Value': 'ISOLATED'},
        {'Key': 'IsolatedAt', 'Value': datetime.now(timezone.utc).isoformat()},
        {'Key': 'OriginalSGs', 'Value': ','.join(original_sgs)},
        {'Key': 'FindingId', 'Value': finding_id}
    ])

    return {
        'status': 'isolated',
        'instance_id': instance_id,
        'isolation_sg': isolation_sg,
        'original_sgs': original_sgs,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
```

### Lab 2: EBS Forensic Snapshot

```python
# lambda/snapshot_evidence.py
import boto3
from datetime import datetime, timezone

ec2 = boto3.client('ec2')


def lambda_handler(event: dict, context) -> dict:
    instance_id = event['instance_id']
    finding_id = event.get('finding_id', 'unknown')

    # Get all volumes attached to instance
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    instance = resp['Reservations'][0]['Instances'][0]
    volumes = [
        bdm['Ebs']['VolumeId']
        for bdm in instance.get('BlockDeviceMappings', [])
        if 'Ebs' in bdm
    ]

    snapshots = []
    for vol_id in volumes:
        snap = ec2.create_snapshot(
            VolumeId=vol_id,
            Description=f'FORENSIC - {instance_id} - Finding {finding_id}',
            TagSpecifications=[{
                'ResourceType': 'snapshot',
                'Tags': [
                    {'Key': 'Purpose', 'Value': 'ForensicEvidence'},
                    {'Key': 'InstanceId', 'Value': instance_id},
                    {'Key': 'FindingId', 'Value': finding_id},
                    {'Key': 'CapturedAt', 'Value': datetime.now(timezone.utc).isoformat()},
                    {'Key': 'ChainOfCustody', 'Value': 'AutomatedIR'}
                ]
            }]
        )
        snapshots.append({'volume_id': vol_id, 'snapshot_id': snap['SnapshotId']})

    return {
        'status': 'snapshots_created',
        'instance_id': instance_id,
        'snapshots': snapshots,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
```

### Lab 3: Step Functions State Machine

```json
{
  "Comment": "Cloud Incident Response Orchestrator",
  "StartAt": "Enrich",
  "States": {
    "Enrich": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:REGION:ACCOUNT:function:enrich-incident",
      "ResultPath": "$.enrichment",
      "Next": "Triage",
      "Retry": [{
        "ErrorEquals": ["Lambda.ServiceException"],
        "IntervalSeconds": 2,
        "MaxAttempts": 3
      }],
      "Catch": [{
        "ErrorEquals": ["States.ALL"],
        "Next": "NotifyFailure",
        "ResultPath": "$.error"
      }]
    },
    "Triage": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:REGION:ACCOUNT:function:triage-incident",
      "ResultPath": "$.triage",
      "Next": "AutoContainDecision"
    },
    "AutoContainDecision": {
      "Type": "Choice",
      "Choices": [
        {
          "And": [
            {"Variable": "$.triage.severity", "StringEquals": "HIGH"},
            {"Variable": "$.triage.auto_contain_approved", "BooleanEquals": true}
          ],
          "Next": "AutoContain"
        }
      ],
      "Default": "NotifyHuman"
    },
    "AutoContain": {
      "Type": "Parallel",
      "Branches": [
        {
          "StartAt": "IsolateEC2",
          "States": {
            "IsolateEC2": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:REGION:ACCOUNT:function:isolate-ec2",
              "End": true
            }
          }
        },
        {
          "StartAt": "SnapshotEvidence",
          "States": {
            "SnapshotEvidence": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:REGION:ACCOUNT:function:snapshot-evidence",
              "End": true
            }
          }
        }
      ],
      "ResultPath": "$.containment",
      "Next": "NotifyContainment"
    },
    "NotifyContainment": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sns:publish",
      "Parameters": {
        "TopicArn": "arn:aws:sns:REGION:ACCOUNT:security-alerts",
        "Message.$": "States.JsonToString($.containment)",
        "Subject": "AUTO-CONTAINED: Cloud Security Incident"
      },
      "Next": "CreateTicket"
    },
    "NotifyHuman": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sns:publish",
      "Parameters": {
        "TopicArn": "arn:aws:sns:REGION:ACCOUNT:security-alerts",
        "Message": "HUMAN REVIEW REQUIRED: Cloud Security Incident",
        "Subject": "ACTION REQUIRED: Security Incident"
      },
      "Next": "CreateTicket"
    },
    "CreateTicket": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:REGION:ACCOUNT:function:create-jira-ticket",
      "Next": "Done"
    },
    "NotifyFailure": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sns:publish",
      "Parameters": {
        "TopicArn": "arn:aws:sns:REGION:ACCOUNT:security-alerts",
        "Message": "SOAR FAILURE - manual response required",
        "Subject": "SOAR ORCHESTRATION FAILED"
      },
      "Next": "Done"
    },
    "Done": {
      "Type": "Succeed"
    }
  }
}
```

---

## Detection Queries

### CloudWatch Insights — GuardDuty Findings

```
# High-severity GuardDuty findings in last 24h
fields @timestamp, type, severity, resource.instanceDetails.instanceId
| filter severity >= 7.0
| sort @timestamp desc
| limit 50
```

### Athena SQL — Incident Timeline Reconstruction

```sql
-- Full activity timeline for a compromised instance
-- Replace 'i-1234567890abcdef0' with the actual instance ID
SELECT
    eventTime,
    eventName,
    eventSource,
    userIdentity.arn,
    sourceIPAddress,
    errorCode
FROM cloudtrail_logs
WHERE (
    -- Direct actions on the instance
    json_extract_scalar(requestParameters, '$.instanceId') = 'i-1234567890abcdef0'
    -- Or actions by the instance's role
    OR userIdentity.sessionContext.sessionIssuer.type = 'Role'
)
  AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventTime ASC;
```

---

## Interview Skills Gained

**Q: Walk me through responding to a compromised EC2 instance.**
> (1) Alert fires — GuardDuty finding or CloudTrail anomaly. (2) Preserve evidence: take EBS snapshot before any changes. (3) Isolate: replace security groups with deny-all isolation SG. Do NOT terminate — that destroys evidence. (4) Collect memory artifacts if possible via Systems Manager. (5) Investigate: review instance metadata service calls, outbound connections from VPC flow logs, any credentials obtained from IMDS. (6) Identify root cause: how did attacker gain initial access? (7) Eradicate: once root cause identified, patch/remediate. (8) Recover: build clean replacement. (9) Document: write incident report.

**Q: What is the difference between a playbook and a runbook?**
> A playbook is the strategic document — it defines what to do for a specific scenario, who is responsible, escalation paths, and success criteria. A runbook is a tactical how-to document — step-by-step commands for one specific task within a playbook. Think of the playbook as the chapter outline and the runbook as the detailed instructions for one paragraph.

**Q: How do you decide what to automate in incident response vs require human approval?**
> Automate actions that are: (1) fast and decisive — stopping an attack requires speed, (2) reversible — isolation is reversible, deletion is not, (3) well-understood — high confidence in the detection. Require human approval for: (1) destructive actions, (2) ambiguous signals, (3) actions affecting high-value production systems, (4) anything involving customer data. Always automate evidence collection — that is always safe and time-critical.

---

## Submission Checklist

- [ ] Compromised EC2 playbook implemented end-to-end (EventBridge → Step Functions → Lambda)
- [ ] 3 Lambda functions working: isolate, snapshot, notify
- [ ] 2 additional playbooks documented (compromised IAM key, S3 exfiltration)
- [ ] Step Functions state machine deployed and tested with a mock event
- [ ] MTTD and MTTR targets documented for each playbook
- [ ] Architecture diagram showing full pipeline
- [ ] Demo: simulate GuardDuty finding → watch automation run (video or screenshots)

---

## Links

→ Full project: [projects/08-automated-incident-response/](../../projects/08-automated-incident-response/)
→ Next: [Week 10 — Cloud Compliance Frameworks](../week-10/README.md)
