# Week 22 — Capstone: Core Platform Build (Sprint 1)

**Phase 6: Capstone | Project: 15-capstone-cloud-secops-platform**

---

## Sprint 1 Goal

By end of this week: data ingestion pipeline operational, at least 8 detection rules firing against real data, finding storage in DynamoDB, and a live Streamlit dashboard showing real findings.

---

## Daily Breakdown

| Day | Focus | Deliverable |
|-----|-------|-------------|
| Mon | Data ingestion pipeline — CloudTrail S3 → Glue catalog → Athena | Athena table queryable |
| Tue | Finding schema + DynamoDB storage + Finding service class | `src/findings.py` complete |
| Wed | Detection engine — 8 rules against CloudTrail events | Detection Lambda deployable |
| Thu | Streamlit dashboard skeleton — connects to DynamoDB, shows live findings | Dashboard running locally |
| Fri | Integration test: end-to-end (CloudTrail event → finding → dashboard) | E2E test passing |
| Sat | Sprint 1 review, bug fixes, code review session with mentor | Sprint 1 merged to main |
| Sun | Mentor daily standup + preview Sprint 2 | Sprint 2 plan confirmed |

---

## Core Implementation

### Finding Service

```python
# src/findings.py
import boto3
import uuid
import json
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from typing import Optional

FINDINGS_TABLE = 'secops-findings'


@dataclass
class Finding:
    source: str           # cloudtrail | guardduty | securityhub | azure_sentinel | github
    severity: str         # CRITICAL | HIGH | MEDIUM | LOW
    title: str
    description: str
    event_time: str
    mitre_technique: str = ''
    mitre_tactic: str = ''
    actor_arn: str = ''
    source_ip: str = ''
    resource_id: str = ''
    resource_type: str = ''
    soar_status: str = 'pending'
    cti_enrichment: dict = field(default_factory=dict)
    raw_event: dict = field(default_factory=dict)

    # Generated fields
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class FindingService:

    def __init__(self, region: str = 'us-east-1', table_name: str = FINDINGS_TABLE):
        self.dynamodb = boto3.resource('dynamodb', region_name=region)
        self.table = self.dynamodb.Table(table_name)

    def save(self, finding: Finding) -> str:
        item = asdict(finding)
        # DynamoDB doesn't support nested dicts in some conditions — serialize complex fields
        item['raw_event'] = json.dumps(item.get('raw_event', {}))
        item['cti_enrichment'] = json.dumps(item.get('cti_enrichment', {}))
        self.table.put_item(Item=item)
        return finding.id

    def get_recent(self, hours: int = 24, severity_filter: list = None) -> list[dict]:
        """Get findings from the last N hours, optionally filtered by severity."""
        cutoff = datetime.now(timezone.utc).isoformat()
        # Simple scan — in production use GSI on event_time
        response = self.table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('created_at').gt(
                (datetime.now(timezone.utc).replace(hour=0, minute=0, second=0)).isoformat()
            )
        )
        findings = response.get('Items', [])
        if severity_filter:
            findings = [f for f in findings if f.get('severity') in severity_filter]
        # Deserialize JSON fields
        for f in findings:
            f['raw_event'] = json.loads(f.get('raw_event', '{}'))
            f['cti_enrichment'] = json.loads(f.get('cti_enrichment', '{}'))
        return sorted(findings, key=lambda x: x.get('event_time', ''), reverse=True)

    def update_soar_status(self, finding_id: str, status: str):
        self.table.update_item(
            Key={'id': finding_id},
            UpdateExpression='SET soar_status = :s, updated_at = :u',
            ExpressionAttributeValues={
                ':s': status,
                ':u': datetime.now(timezone.utc).isoformat()
            }
        )
```

### Detection Engine

```python
# src/detection/engine.py
import json
import boto3
from datetime import datetime, timezone
from src.findings import Finding, FindingService

MITRE_MAPPING = {
    'CreatePolicyVersion': ('T1098.003', 'Account Manipulation', 'Privilege Escalation'),
    'UpdateAssumeRolePolicy': ('T1098.003', 'Account Manipulation', 'Privilege Escalation'),
    'AttachUserPolicy': ('T1098', 'Account Manipulation', 'Privilege Escalation'),
    'AttachRolePolicy': ('T1098', 'Account Manipulation', 'Privilege Escalation'),
    'CreateAccessKey': ('T1098.001', 'Additional Cloud Credentials', 'Persistence'),
    'CreateLoginProfile': ('T1136.003', 'Cloud Account Create', 'Persistence'),
    'UpdateLoginProfile': ('T1098', 'Account Manipulation', 'Privilege Escalation'),
    'DeleteTrail': ('T1562.008', 'Disable Cloud Logs', 'Defense Evasion'),
    'StopLogging': ('T1562.008', 'Disable Cloud Logs', 'Defense Evasion'),
    'GetObject': ('T1530', 'Data from Cloud Storage', 'Collection'),
    'CreateUser': ('T1136.003', 'Cloud Account Create', 'Persistence'),
    'ConsoleLogin': ('T1078', 'Valid Accounts', 'Initial Access'),
}

ESCALATION_EVENTS = {
    'CreatePolicyVersion', 'SetDefaultPolicyVersion', 'UpdateAssumeRolePolicy',
    'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy',
    'PutUserPolicy', 'PutRolePolicy', 'AddUserToGroup',
    'CreateAccessKey', 'CreateLoginProfile', 'UpdateLoginProfile',
}

HIGH_VALUE_EVENTS = {
    'DeleteTrail': ('CRITICAL', 'CloudTrail trail deleted — audit logging removed'),
    'StopLogging': ('CRITICAL', 'CloudTrail logging stopped — blind spot created'),
    'CreateUser': ('HIGH', 'New IAM user created — potential persistence'),
    'CreateLoginProfile': ('HIGH', 'Console access added to IAM user — potential escalation'),
}


class DetectionEngine:

    def __init__(self, region: str = 'us-east-1'):
        self.finding_service = FindingService(region=region)
        self.region = region

    def analyze(self, event: dict) -> list[Finding]:
        """Analyze a CloudTrail event and return any findings."""
        findings = []
        detail = event.get('detail', event)  # Handle EventBridge envelope
        event_name = detail.get('eventName', '')
        user_identity = detail.get('userIdentity', {})
        actor_arn = user_identity.get('arn', user_identity.get('userName', 'unknown'))
        source_ip = detail.get('sourceIPAddress', '')
        event_time = detail.get('eventTime', datetime.now(timezone.utc).isoformat())

        mitre = MITRE_MAPPING.get(event_name, ('', '', ''))

        # Rule 1: IAM privilege escalation
        if event_name in ESCALATION_EVENTS:
            findings.append(Finding(
                source='cloudtrail',
                severity='HIGH' if event_name != 'UpdateAssumeRolePolicy' else 'CRITICAL',
                title=f'IAM Privilege Escalation Attempt: {event_name}',
                description=f'Actor {actor_arn} performed {event_name} — potential privilege escalation',
                event_time=event_time,
                mitre_technique=mitre[0],
                mitre_tactic=mitre[2],
                actor_arn=actor_arn,
                source_ip=source_ip,
                raw_event=detail
            ))

        # Rule 2: High-value events
        if event_name in HIGH_VALUE_EVENTS:
            sev, desc = HIGH_VALUE_EVENTS[event_name]
            findings.append(Finding(
                source='cloudtrail',
                severity=sev,
                title=f'Security-Relevant Event: {event_name}',
                description=f'{desc} — actor: {actor_arn}',
                event_time=event_time,
                mitre_technique=mitre[0],
                mitre_tactic=mitre[2],
                actor_arn=actor_arn,
                source_ip=source_ip,
                raw_event=detail
            ))

        # Rule 3: Root account usage
        if user_identity.get('type') == 'Root':
            findings.append(Finding(
                source='cloudtrail',
                severity='CRITICAL',
                title='Root Account API Call Detected',
                description=f'Root account used for {event_name} — should never be used operationally',
                event_time=event_time,
                mitre_technique='T1078.004',
                mitre_tactic='Initial Access',
                actor_arn=actor_arn,
                source_ip=source_ip,
                raw_event=detail
            ))

        return findings

    def process_event(self, event: dict) -> list[str]:
        """Process event and save any findings. Returns finding IDs."""
        findings = self.analyze(event)
        ids = []
        for finding in findings:
            finding_id = self.finding_service.save(finding)
            ids.append(finding_id)
            print(f'[FINDING] {finding.severity} — {finding.title}')
        return ids


def lambda_handler(event: dict, context) -> dict:
    engine = DetectionEngine()
    ids = engine.process_event(event)
    return {'finding_ids': ids, 'count': len(ids)}
```

### Streamlit Dashboard

```python
# src/dashboard/app.py
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timezone
from src.findings import FindingService

st.set_page_config(
    page_title="Cloud SecOps Platform",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Cloud Security Operations Platform")
st.caption(f"Live | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")

# Sidebar controls
with st.sidebar:
    st.header("Controls")
    severity_filter = st.multiselect(
        "Severity Filter",
        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        default=['CRITICAL', 'HIGH']
    )
    hours_back = st.slider("Lookback (hours)", 1, 168, 24)
    auto_refresh = st.checkbox("Auto-refresh (30s)", value=False)

    if st.button("🔄 Refresh Now"):
        st.rerun()

# Load data
try:
    svc = FindingService()
    findings = svc.get_recent(hours=hours_back, severity_filter=severity_filter or None)
    df = pd.DataFrame(findings)
except Exception as e:
    st.error(f"Could not connect to findings database: {e}")
    # Use mock data for demo
    df = pd.DataFrame([
        {'severity': 'CRITICAL', 'title': 'Root account usage', 'source': 'cloudtrail',
         'actor_arn': 'arn:aws:iam::123456789012:root', 'source_ip': '1.2.3.4',
         'event_time': datetime.now(timezone.utc).isoformat(), 'soar_status': 'pending'},
        {'severity': 'HIGH', 'title': 'IAM escalation: AttachRolePolicy', 'source': 'cloudtrail',
         'actor_arn': 'arn:aws:iam::123456789012:user/dev-user', 'source_ip': '10.0.1.5',
         'event_time': datetime.now(timezone.utc).isoformat(), 'soar_status': 'auto_contained'},
    ])
    findings = df.to_dict('records')

# Metrics row
sev_colors = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
cols = st.columns(5)
for i, (sev, emoji) in enumerate(sev_colors.items()):
    count = len(df[df['severity'] == sev]) if not df.empty else 0
    cols[i].metric(f"{emoji} {sev}", count)
cols[4].metric("Total", len(df))

st.divider()

if not df.empty:
    col_l, col_r = st.columns(2)

    with col_l:
        st.subheader("Findings by Severity")
        counts = df['severity'].value_counts().reset_index()
        counts.columns = ['Severity', 'Count']
        fig = px.bar(counts, x='Severity', y='Count',
                     color='Severity',
                     color_discrete_map={
                         'CRITICAL': '#d32f2f', 'HIGH': '#f57c00',
                         'MEDIUM': '#fbc02d', 'LOW': '#388e3c'
                     })
        fig.update_layout(showlegend=False, height=300)
        st.plotly_chart(fig, use_container_width=True)

    with col_r:
        st.subheader("Findings by Source")
        if 'source' in df.columns:
            source_counts = df['source'].value_counts().reset_index()
            source_counts.columns = ['Source', 'Count']
            fig2 = px.pie(source_counts, values='Count', names='Source', hole=0.4)
            fig2.update_layout(height=300)
            st.plotly_chart(fig2, use_container_width=True)

    st.subheader("Active Findings — Requires Action")
    display_cols = [c for c in ['severity', 'title', 'actor_arn', 'source_ip',
                                 'event_time', 'soar_status', 'source']
                    if c in df.columns]
    if display_cols:
        st.dataframe(
            df[display_cols].sort_values(
                'severity',
                key=lambda s: s.map({'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3})
            ),
            use_container_width=True,
            height=400
        )
        st.download_button(
            "📥 Export CSV",
            data=df.to_csv(index=False),
            file_name=f"findings-{datetime.now().strftime('%Y-%m-%d-%H%M')}.csv",
            mime='text/csv'
        )
else:
    st.success("No active findings matching your filter. Security posture is good.")

# Auto-refresh
if auto_refresh:
    import time
    time.sleep(30)
    st.rerun()
```

### Terraform Infrastructure

```hcl
# infrastructure/terraform/main.tf

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

locals {
  prefix = "secops"
  tags = {
    Project     = "CloudSecOpsPlatform"
    Environment = "dev"
    Owner       = "security-team"
    ManagedBy   = "terraform"
  }
}

# DynamoDB findings table
resource "aws_dynamodb_table" "findings" {
  name           = "${local.prefix}-findings"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"
  stream_enabled = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute { name = "id"; type = "S" }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.main.arn
  }

  point_in_time_recovery { enabled = true }

  tags = local.tags
}

# KMS key for encryption
resource "aws_kms_key" "main" {
  description             = "SecOps platform encryption key"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  tags                    = local.tags
}

resource "aws_kms_alias" "main" {
  name          = "alias/${local.prefix}-key"
  target_key_id = aws_kms_key.main.key_id
}

# Lambda execution role — least privilege
resource "aws_iam_role" "detection_lambda" {
  name = "${local.prefix}-detection-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.tags
}

resource "aws_iam_role_policy" "detection_lambda" {
  name = "detection-permissions"
  role = aws_iam_role.detection_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBFindings"
        Effect = "Allow"
        Action = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:GetItem"]
        Resource = aws_dynamodb_table.findings.arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:log-group:/aws/lambda/${local.prefix}-*"
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.main.arn
      }
    ]
  })
}

# Detection Lambda
resource "aws_lambda_function" "detection_engine" {
  function_name = "${local.prefix}-detection-engine"
  role          = aws_iam_role.detection_lambda.arn
  handler       = "src.detection.engine.lambda_handler"
  runtime       = "python3.12"
  timeout       = 30
  memory_size   = 256

  filename         = "lambda.zip"
  source_code_hash = filebase64sha256("lambda.zip")

  environment {
    variables = {
      FINDINGS_TABLE = aws_dynamodb_table.findings.name
      REGION         = var.region
    }
  }

  tracing_config { mode = "Active" }  # X-Ray tracing
  tags = local.tags
}

# EventBridge rule for IAM escalation detection
resource "aws_cloudwatch_event_rule" "iam_escalation" {
  name        = "${local.prefix}-iam-escalation"
  description = "Detect IAM privilege escalation events"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        "CreatePolicyVersion", "SetDefaultPolicyVersion",
        "UpdateAssumeRolePolicy", "AttachUserPolicy", "AttachRolePolicy",
        "PutUserPolicy", "PutRolePolicy", "CreateAccessKey",
        "CreateLoginProfile", "UpdateLoginProfile", "CreateUser"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "detection_lambda" {
  rule      = aws_cloudwatch_event_rule.iam_escalation.name
  target_id = "DetectionLambda"
  arn       = aws_lambda_function.detection_engine.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detection_engine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_escalation.arn
}
```

---

## Sprint 1 Integration Test

```python
# tests/integration/test_e2e_detection.py
"""
End-to-end test: inject a mock CloudTrail event, verify finding is stored.
Run against a real AWS account with the DynamoDB table created.
"""
import json
import boto3
import time
import pytest
from src.detection.engine import DetectionEngine, lambda_handler
from src.findings import FindingService


@pytest.fixture
def mock_iam_escalation_event():
    return {
        "detail": {
            "eventName": "AttachRolePolicy",
            "eventTime": "2024-01-15T03:00:00Z",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/test-user",
                "userName": "test-user"
            },
            "sourceIPAddress": "198.51.100.42",
            "awsRegion": "us-east-1",
            "requestParameters": {
                "roleName": "AdminRole",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            }
        }
    }


@pytest.fixture
def mock_root_usage_event():
    return {
        "detail": {
            "eventName": "ConsoleLogin",
            "eventTime": "2024-01-15T03:00:00Z",
            "userIdentity": {
                "type": "Root",
                "arn": "arn:aws:iam::123456789012:root",
            },
            "sourceIPAddress": "203.0.113.1",
            "awsRegion": "us-east-1",
        }
    }


class TestDetectionEngine:

    def test_iam_escalation_produces_finding(self, mock_iam_escalation_event):
        engine = DetectionEngine()
        findings = engine.analyze(mock_iam_escalation_event)
        assert len(findings) >= 1
        f = findings[0]
        assert f.severity in ('HIGH', 'CRITICAL')
        assert 'AttachRolePolicy' in f.title
        assert f.mitre_technique != ''

    def test_root_usage_produces_critical_finding(self, mock_root_usage_event):
        engine = DetectionEngine()
        findings = engine.analyze(mock_root_usage_event)
        assert any(f.severity == 'CRITICAL' for f in findings)

    def test_benign_event_produces_no_findings(self):
        engine = DetectionEngine()
        event = {"detail": {
            "eventName": "DescribeInstances",
            "eventTime": "2024-01-15T09:00:00Z",
            "userIdentity": {"type": "IAMUser", "userName": "dev-user"},
            "sourceIPAddress": "10.0.1.5"
        }}
        findings = engine.analyze(event)
        assert len(findings) == 0

    @pytest.mark.integration
    def test_finding_stored_in_dynamodb(self, mock_iam_escalation_event):
        """Integration test — requires real DynamoDB table."""
        result = lambda_handler(mock_iam_escalation_event, None)
        assert result['count'] >= 1
        assert len(result['finding_ids']) >= 1

        svc = FindingService()
        time.sleep(1)  # Brief wait for consistency
        recent = svc.get_recent(hours=1)
        finding_ids = {f['id'] for f in recent}
        assert any(fid in finding_ids for fid in result['finding_ids'])
```

---

## Sprint 1 Acceptance Criteria

- [ ] Athena table created and queryable with at least one test query
- [ ] DynamoDB findings table created via Terraform
- [ ] Detection Lambda deployed and reachable via EventBridge
- [ ] 8 detection rules implemented and unit tested
- [ ] Dashboard runs locally showing live DynamoDB data
- [ ] End-to-end integration test passing (inject mock event → verify finding stored → verify dashboard shows it)
- [ ] All code on `main` with passing CI pipeline

---

## Links

→ Next: [Week 23 — Capstone Integration & Testing](../week-23/README.md)
