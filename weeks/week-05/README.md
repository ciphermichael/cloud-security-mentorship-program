# Week 05 — IAM Privilege Escalation — 15 Attack Paths

**Phase 2: Identity Security | Project: 04-iam-privilege-escalation-detector**

---

## Learning Objectives

By the end of this week you will be able to:

- Name and explain 15+ AWS IAM privilege escalation attack paths
- Map each path to MITRE ATT&CK (T1098 — Account Manipulation, TA0004 — Privilege Escalation)
- Write Python detection functions for each escalation path using CloudTrail events
- Deploy an EventBridge rule + Lambda to alert on escalation attempts in real time
- Explain why `iam:PassRole` is one of the most dangerous individual permissions in AWS

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | Study all 15 escalation paths — understand the attack, not just the name | 2 hrs |
| Tue | Lab: simulate 3 safe escalation paths in a test account, observe CloudTrail | 2 hrs |
| Wed | Build the Python detector — EventBridge trigger → Lambda analyzer | 2 hrs |
| Thu | Write unit tests for each detection function (mock CloudTrail events) | 2 hrs |
| Fri | Add SNS alerting, test end-to-end, document MITRE mapping | 2 hrs |
| Sat | Full README with architecture diagram, push to GitHub | 3 hrs |
| Sun | Mentor review session — discuss escalation path interview questions | 1 hr |

---

## Topics Covered

### The 15 IAM Privilege Escalation Paths

Rhino Security Labs documented these paths. Every cloud security engineer must know them cold.

#### Group A — Creating/Modifying Policy Documents

**Path 1: `iam:CreatePolicyVersion`**
> If you can create a new version of an existing policy and set it as default, you can grant yourself any permission.
> CloudTrail event: `CreatePolicyVersion` where `setAsDefault=true`

**Path 2: `iam:SetDefaultPolicyVersion`**
> If a policy has a stored version with admin access and you can flip it to default.
> CloudTrail event: `SetDefaultPolicyVersion`

#### Group B — Modifying Role Trust Policies

**Path 3: `iam:UpdateAssumeRolePolicy`**
> Modify the trust policy of a high-privilege role to allow your identity to assume it.
> CloudTrail event: `UpdateAssumeRolePolicy` where principal includes actor's ARN

**Path 4: `iam:PassRole` + service abuse**
> Pass a high-privilege role to EC2/Lambda/Glue/etc. — the service then acts as that role.
> CloudTrail events: `PassRole` + `RunInstances` or `CreateFunction` or `CreateJob`

#### Group C — Attaching Policies

**Path 5: `iam:AttachUserPolicy`**
> Attach a powerful policy (like AdministratorAccess) directly to a user you control.

**Path 6: `iam:AttachRolePolicy`**
> Attach a powerful policy to a role you can assume.

**Path 7: `iam:AttachGroupPolicy`**
> Attach a powerful policy to a group you belong to.

**Path 8: `iam:PutUserPolicy` (inline policy)**
> Create an inline policy on a user with full admin permissions.

**Path 9: `iam:PutRolePolicy` (inline policy)**
> Create an inline policy on a role with full admin permissions.

#### Group D — User/Group Manipulation

**Path 10: `iam:AddUserToGroup`**
> Add yourself to a powerful group (e.g., Admins).

**Path 11: `iam:CreateAccessKey` on another user**
> Create access keys for an existing admin user and use those keys.

**Path 12: `iam:CreateLoginProfile`**
> Create a console password for a user that had no console access, then log in as them.

**Path 13: `iam:UpdateLoginProfile`**
> Change the console password of an existing user you don't control.

#### Group E — Service-Specific Escalation

**Path 14: `iam:PassRole` → AWS Glue**
> Create a Glue job with an admin role, execute arbitrary code that makes privileged API calls.

**Path 15: `iam:PassRole` → AWS Lambda**
> Create a Lambda function with an admin execution role, invoke it to do privileged actions.

**Bonus Path: `sts:AssumeRole` on a misconfigured trust policy**
> If a role's trust policy has `"Principal": "*"` or trusts the entire account, any identity can assume it.

---

## Instructor Mentoring Guidance

**This week produces the most satisfying "aha" moment of Phase 2.** When students realize that `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion` = instant admin escalation, they start thinking like attackers. That mindset shift is the goal.

**Common mistakes:**
- Students run escalation paths against their own production account — always use a disposable sandbox account
- Missing that `iam:PassRole` requires BOTH PassRole permission AND a create action (EC2, Lambda, etc.)
- Not writing unit tests with mocked CloudTrail events — tests break when live AWS environment changes

**Mentoring session agenda (60 min):**
1. (10 min) Quick quiz: name 5 escalation paths without notes
2. (20 min) Walk through the Lambda-based detector code together — discuss false positive rate
3. (20 min) Mock interview: "An adversary has obtained an access key. The key has only `iam:CreatePolicyVersion`. Walk me through their attack chain."
4. (10 min) Preview Week 6 — Azure AD and why Entra ID escalation is just as dangerous

**Office hours:** Help students debug Lambda execution roles and EventBridge pattern syntax. The JSON pattern matching for EventBridge rules has subtle differences from CloudTrail event structure.

---

## Hands-on Lab

### Lab 1: Observe Path 1 in a Sandbox

```bash
# In your TEST ACCOUNT ONLY — create a low-privilege policy
cat > low-priv-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:ListBuckets"],
    "Resource": "*"
  }]
}
EOF

POLICY_ARN=$(aws iam create-policy \
  --policy-name TestEscalationPolicy \
  --policy-document file://low-priv-policy.json \
  --query 'Policy.Arn' --output text)

# Create a "new version" with admin access — this is Path 1
cat > admin-version.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
EOF

aws iam create-policy-version \
  --policy-arn "$POLICY_ARN" \
  --policy-document file://admin-version.json \
  --set-as-default

# Observe this in CloudTrail — the event will show:
# eventName: CreatePolicyVersion
# requestParameters.setAsDefault: true

# CLEANUP — always clean up after escalation labs
aws iam delete-policy-version \
  --policy-arn "$POLICY_ARN" \
  --version-id v2
aws iam delete-policy --policy-arn "$POLICY_ARN"
```

### Lab 2: EventBridge Detection Rule

```bash
# Deploy the EventBridge rule that captures escalation events
cat > escalation-pattern.json << 'EOF'
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": [
      "CreatePolicyVersion",
      "SetDefaultPolicyVersion",
      "UpdateAssumeRolePolicy",
      "AttachUserPolicy",
      "AttachRolePolicy",
      "AttachGroupPolicy",
      "PutUserPolicy",
      "PutRolePolicy",
      "AddUserToGroup",
      "CreateAccessKey",
      "CreateLoginProfile",
      "UpdateLoginProfile"
    ]
  }
}
EOF

# Create the rule
aws events put-rule \
  --name IAMPrivilegeEscalation \
  --event-pattern file://escalation-pattern.json \
  --state ENABLED \
  --description "Detect IAM privilege escalation attempts"
```

---

## Weekly Assignment — IAM Privilege Escalation Detector

Build a Python Lambda function that receives EventBridge events and analyzes them for escalation patterns.

```python
# src/detector.py
import json
import boto3
import os
from datetime import datetime, timezone

# Map each eventName to its escalation path and severity
ESCALATION_PATHS = {
    'CreatePolicyVersion': {
        'path_id': 1,
        'name': 'Create Policy Version',
        'severity': 'CRITICAL',
        'mitre': 'T1098.003',
        'description': 'New policy version may grant elevated permissions',
        'condition': lambda detail: detail.get('requestParameters', {})
                                         .get('setAsDefault') == 'true'
    },
    'SetDefaultPolicyVersion': {
        'path_id': 2,
        'name': 'Set Default Policy Version',
        'severity': 'HIGH',
        'mitre': 'T1098.003',
        'description': 'Switching to a stored policy version — may contain admin perms',
        'condition': lambda detail: True
    },
    'UpdateAssumeRolePolicy': {
        'path_id': 3,
        'name': 'Update Role Trust Policy',
        'severity': 'CRITICAL',
        'mitre': 'T1098.003',
        'description': 'Role trust policy changed — could allow lateral movement',
        'condition': lambda detail: True
    },
    'AttachUserPolicy': {
        'path_id': 5,
        'name': 'Attach Policy to User',
        'severity': 'HIGH',
        'mitre': 'T1098',
        'description': 'Policy attached directly to user',
        'condition': lambda detail: True
    },
    'AttachRolePolicy': {
        'path_id': 6,
        'name': 'Attach Policy to Role',
        'severity': 'HIGH',
        'mitre': 'T1098',
        'description': 'Policy attached to role — check if it grants admin',
        'condition': lambda detail: True
    },
    'AttachGroupPolicy': {
        'path_id': 7,
        'name': 'Attach Policy to Group',
        'severity': 'HIGH',
        'mitre': 'T1098',
        'description': 'Policy attached to group',
        'condition': lambda detail: True
    },
    'PutUserPolicy': {
        'path_id': 8,
        'name': 'Inline Policy on User',
        'severity': 'HIGH',
        'mitre': 'T1098',
        'description': 'Inline policy added — often used to hide permissions',
        'condition': lambda detail: True
    },
    'PutRolePolicy': {
        'path_id': 9,
        'name': 'Inline Policy on Role',
        'severity': 'HIGH',
        'mitre': 'T1098',
        'description': 'Inline policy added to role',
        'condition': lambda detail: True
    },
    'AddUserToGroup': {
        'path_id': 10,
        'name': 'User Added to Group',
        'severity': 'MEDIUM',
        'mitre': 'T1098',
        'description': 'User added to group — potential privilege inheritance',
        'condition': lambda detail: True
    },
    'CreateAccessKey': {
        'path_id': 11,
        'name': 'Access Key Created',
        'severity': 'HIGH',
        'mitre': 'T1098.001',
        'description': 'New access key — could be for a different user (persistence)',
        'condition': lambda detail: True
    },
    'CreateLoginProfile': {
        'path_id': 12,
        'name': 'Console Password Created',
        'severity': 'HIGH',
        'mitre': 'T1098',
        'description': 'Console access granted to a user that had none',
        'condition': lambda detail: True
    },
    'UpdateLoginProfile': {
        'path_id': 13,
        'name': 'Console Password Changed',
        'severity': 'CRITICAL',
        'mitre': 'T1098',
        'description': 'Console password changed — potential account takeover',
        'condition': lambda detail: True
    },
}

sns_client = boto3.client('sns')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')


def analyze_event(event: dict) -> dict | None:
    """Analyze a CloudTrail event for privilege escalation."""
    detail = event.get('detail', {})
    event_name = detail.get('eventName', '')
    path = ESCALATION_PATHS.get(event_name)

    if not path:
        return None

    # Check optional condition (e.g., CreatePolicyVersion must set as default)
    if not path['condition'](detail):
        return None

    actor = detail.get('userIdentity', {})
    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'path_id': path['path_id'],
        'path_name': path['name'],
        'severity': path['severity'],
        'mitre_technique': path['mitre'],
        'description': path['description'],
        'event_name': event_name,
        'actor_arn': actor.get('arn', 'unknown'),
        'actor_type': actor.get('type', 'unknown'),
        'source_ip': detail.get('sourceIPAddress', 'unknown'),
        'aws_region': detail.get('awsRegion', 'unknown'),
        'event_time': detail.get('eventTime', 'unknown'),
        'request_params': detail.get('requestParameters', {}),
    }


def lambda_handler(event: dict, context) -> dict:
    findings = []
    # EventBridge can deliver one event at a time, but we handle batch too
    events = event if isinstance(event, list) else [event]

    for raw_event in events:
        finding = analyze_event(raw_event)
        if finding:
            findings.append(finding)
            print(f"[ALERT] {finding['severity']} - {finding['path_name']} "
                  f"by {finding['actor_arn']} from {finding['source_ip']}")

            if SNS_TOPIC_ARN and finding['severity'] in ('CRITICAL', 'HIGH'):
                sns_client.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject=f"[{finding['severity']}] IAM Escalation: {finding['path_name']}",
                    Message=json.dumps(finding, indent=2)
                )

    return {'findings': findings, 'count': len(findings)}
```

### Unit Tests

```python
# tests/test_detector.py
import json
import pytest
from src.detector import analyze_event, ESCALATION_PATHS


def make_event(event_name: str, extra_params: dict = None) -> dict:
    """Build a minimal EventBridge / CloudTrail event for testing."""
    return {
        'detail': {
            'eventName': event_name,
            'userIdentity': {
                'type': 'IAMUser',
                'arn': 'arn:aws:iam::123456789012:user/attacker',
                'userName': 'attacker'
            },
            'sourceIPAddress': '1.2.3.4',
            'awsRegion': 'us-east-1',
            'eventTime': '2024-01-15T10:00:00Z',
            'requestParameters': extra_params or {}
        }
    }


class TestEscalationPaths:

    def test_path_1_create_policy_version_with_default(self):
        event = make_event('CreatePolicyVersion', {'setAsDefault': 'true'})
        finding = analyze_event(event)
        assert finding is not None
        assert finding['severity'] == 'CRITICAL'
        assert finding['path_id'] == 1

    def test_path_1_create_policy_version_without_default(self):
        # Not setting as default is lower risk — should still alert but condition fails
        event = make_event('CreatePolicyVersion', {'setAsDefault': 'false'})
        finding = analyze_event(event)
        assert finding is None  # condition requires setAsDefault=true

    def test_path_3_update_assume_role_policy(self):
        event = make_event('UpdateAssumeRolePolicy',
                          {'roleName': 'AdminRole', 'policyDocument': '{}'})
        finding = analyze_event(event)
        assert finding is not None
        assert finding['severity'] == 'CRITICAL'
        assert finding['mitre_technique'] == 'T1098.003'

    def test_path_11_create_access_key_another_user(self):
        event = make_event('CreateAccessKey', {'userName': 'admin-user'})
        finding = analyze_event(event)
        assert finding is not None
        assert finding['severity'] == 'HIGH'

    def test_path_13_update_login_profile(self):
        event = make_event('UpdateLoginProfile', {'userName': 'admin-user'})
        finding = analyze_event(event)
        assert finding is not None
        assert finding['severity'] == 'CRITICAL'

    def test_unknown_event_returns_none(self):
        event = make_event('DescribeInstances')
        finding = analyze_event(event)
        assert finding is None

    def test_all_paths_are_mapped(self):
        # Ensure every path ID is unique
        path_ids = [v['path_id'] for v in ESCALATION_PATHS.values()]
        assert len(path_ids) == len(set(path_ids)), "Duplicate path IDs found"

    @pytest.mark.parametrize("event_name", list(ESCALATION_PATHS.keys()))
    def test_all_paths_produce_findings(self, event_name):
        event = make_event(event_name, {'setAsDefault': 'true'})
        finding = analyze_event(event)
        # All paths should produce a finding (some may depend on condition)
        # At minimum, the path must be defined
        assert event_name in ESCALATION_PATHS
```

Run tests: `pytest tests/ -v --tb=short`

---

## Detection Queries

### Athena SQL — Escalation Path Hunting

```sql
-- All privilege escalation events in the last 7 days
SELECT
    eventTime,
    eventName,
    userIdentity.arn AS actor,
    userIdentity.type,
    sourceIPAddress,
    awsRegion,
    json_extract_scalar(requestParameters, '$.roleName') AS target_role,
    json_extract_scalar(requestParameters, '$.userName') AS target_user,
    json_extract_scalar(requestParameters, '$.policyArn') AS policy_arn
FROM cloudtrail_logs
WHERE eventName IN (
    'CreatePolicyVersion', 'SetDefaultPolicyVersion',
    'UpdateAssumeRolePolicy', 'AttachUserPolicy',
    'AttachRolePolicy', 'AttachGroupPolicy',
    'PutUserPolicy', 'PutRolePolicy',
    'AddUserToGroup', 'CreateAccessKey',
    'CreateLoginProfile', 'UpdateLoginProfile'
)
  AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventTime DESC;

-- Escalation chain: CreatePolicyVersion immediately followed by SetDefaultPolicyVersion
WITH escalation_events AS (
    SELECT
        userIdentity.arn AS actor,
        eventName,
        from_iso8601_timestamp(eventTime) AS ts
    FROM cloudtrail_logs
    WHERE eventName IN ('CreatePolicyVersion', 'SetDefaultPolicyVersion')
)
SELECT a.actor, a.ts AS create_ts, b.ts AS set_default_ts,
    date_diff('second', a.ts, b.ts) AS seconds_between
FROM escalation_events a
JOIN escalation_events b
    ON a.actor = b.actor
    AND a.eventName = 'CreatePolicyVersion'
    AND b.eventName = 'SetDefaultPolicyVersion'
    AND date_diff('minute', a.ts, b.ts) BETWEEN 0 AND 10
ORDER BY seconds_between ASC;
```

---

## Interview Skills Gained

**Q: Name 5 AWS IAM privilege escalation paths.**
> 1. `CreatePolicyVersion` + `SetDefaultPolicyVersion` — create an admin version of an existing policy
> 2. `UpdateAssumeRolePolicy` — edit a high-privilege role's trust policy to allow your identity
> 3. `iam:PassRole` + `RunInstances` — pass an admin role to an EC2 instance you control
> 4. `CreateAccessKey` on another user — create keys for an existing admin user
> 5. `UpdateLoginProfile` — change an admin user's console password

**Q: Why is `iam:PassRole` one of the most dangerous IAM permissions?**
> PassRole allows you to assign an IAM role to an AWS service (EC2, Lambda, Glue, etc.). If you can pass an admin role to a service and then interact with that service, you effectively act as the admin role — even without a direct AssumeRole on it. It's an indirect privilege escalation vector that bypasses role trust policy restrictions.

**Q: How would you detect privilege escalation in AWS?**
> Monitor CloudTrail for the 15 known escalation event names using an EventBridge rule. Alert in real time via Lambda → SNS. Also run daily Athena queries looking for these events clustered in time or from unusual identities. Correlate with GuardDuty findings like `Policy:IAMUser/RootCredentialUsage`.

---

## Submission Checklist

- [ ] 15 escalation paths documented in `docs/escalation-paths.md` with MITRE mappings
- [ ] Python Lambda detector handles all 15 paths
- [ ] Unit tests pass for all paths: `pytest tests/ -v`
- [ ] EventBridge rule deployed to sandbox account
- [ ] SNS alert fires when escalation is detected (screenshot)
- [ ] Architecture diagram showing EventBridge → Lambda → SNS flow
- [ ] MITRE ATT&CK table in README with technique IDs

---

## Links

→ Full project: [projects/04-iam-privilege-escalation-detector/](../../projects/04-iam-privilege-escalation-detector/)
→ Next: [Week 06 — Azure Sentinel & KQL Detection Engineering](../week-06/README.md)
