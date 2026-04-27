# Week 23 — Capstone: Integration, Testing & Security Hardening (Sprint 2)

**Phase 6: Capstone | Project: 15-capstone-cloud-secops-platform**

---

## Sprint 2 Goal

By end of this week: all platform components integrated end-to-end (AWS + Azure + GitHub feeds), test suite passing with >70% coverage, platform hardened against its own security controls, load tested at 10,000 events/min.

---

## Daily Breakdown

| Day | Focus | Deliverable |
|-----|-------|-------------|
| Mon | SOAR integration — wire GuardDuty → Step Functions with existing playbooks | SOAR pipeline e2e working |
| Tue | CTI enrichment integration — enrich all new findings automatically | CTI running as async task |
| Wed | Azure Sentinel feed integration — ingest KQL rule alerts via API | Azure connector working |
| Thu | Test suite — unit + integration, target >70% coverage | `pytest --cov` report |
| Fri | Load test (Locust) + platform self-audit (run your own tools against the platform) | Load report + security findings fixed |
| Sat | Fix all CRITICAL/HIGH findings from self-audit, final integration test | All gates passing |
| Sun | Sprint 2 review with mentor | Sprint 3 confirmed |

---

## Integration Tests

### Full Integration Test Suite

```python
# tests/integration/test_full_platform.py
"""
Full platform integration test.
Requires: AWS credentials, DynamoDB table, Lambda deployed.
Run with: pytest tests/integration/ -v --tb=short -m integration
"""
import json
import time
import boto3
import pytest
from datetime import datetime, timezone
from src.findings import FindingService, Finding
from src.detection.engine import DetectionEngine
from src.soar.orchestrator import SOAROrchestrator


ACCOUNT_ID = boto3.client('sts').get_caller_identity()['Account']
REGION = 'us-east-1'


class TestDataIngestion:

    def test_cloudtrail_athena_query(self):
        """Verify Athena can query CloudTrail logs."""
        athena = boto3.client('athena', region_name=REGION)
        resp = athena.start_query_execution(
            QueryString='SELECT COUNT(*) FROM cloudtrail_logs LIMIT 1',
            QueryExecutionContext={'Database': 'secops_database'},
            ResultConfiguration={'OutputLocation': 's3://secops-athena-results/'}
        )
        qid = resp['QueryExecutionId']
        for _ in range(30):
            status = athena.get_query_execution(QueryExecutionId=qid)
            state = status['QueryExecution']['Status']['State']
            if state in ('SUCCEEDED', 'FAILED', 'CANCELLED'):
                break
            time.sleep(2)
        assert state == 'SUCCEEDED', f'Athena query failed: {state}'


class TestDetectionIntegration:

    @pytest.mark.parametrize("event_name,expected_severity", [
        ('DeleteTrail', 'CRITICAL'),
        ('AttachRolePolicy', 'HIGH'),
        ('CreateAccessKey', 'HIGH'),
        ('CreateUser', 'HIGH'),
    ])
    def test_detection_rules_correct_severity(self, event_name, expected_severity):
        engine = DetectionEngine(region=REGION)
        event = {'detail': {
            'eventName': event_name,
            'eventTime': datetime.now(timezone.utc).isoformat(),
            'userIdentity': {'type': 'IAMUser', 'arn': 'arn:aws:iam::123:user/test',
                             'userName': 'test'},
            'sourceIPAddress': '10.0.0.1'
        }}
        findings = engine.analyze(event)
        assert len(findings) >= 1
        assert any(f.severity == expected_severity for f in findings), \
            f'{event_name} expected {expected_severity}, got {[f.severity for f in findings]}'


class TestFindingStorage:

    def test_save_and_retrieve_finding(self):
        svc = FindingService(region=REGION)
        finding = Finding(
            source='cloudtrail',
            severity='HIGH',
            title='Integration Test Finding',
            description='Test finding for integration test suite',
            event_time=datetime.now(timezone.utc).isoformat(),
            actor_arn='arn:aws:iam::123456789012:user/test-user'
        )
        finding_id = svc.save(finding)
        assert finding_id

        time.sleep(1)
        recent = svc.get_recent(hours=1)
        saved = next((f for f in recent if f['id'] == finding_id), None)
        assert saved is not None
        assert saved['severity'] == 'HIGH'
        assert saved['title'] == 'Integration Test Finding'

        # Cleanup
        svc.table.delete_item(Key={'id': finding_id})


class TestDashboardDataFlow:

    def test_dashboard_can_query_findings(self):
        """Verify dashboard data layer works."""
        svc = FindingService(region=REGION)
        findings = svc.get_recent(hours=24)
        assert isinstance(findings, list)


class TestPlatformSecurity:
    """Self-audit: run security checks against the platform's own resources."""

    def test_dynamodb_encryption_enabled(self):
        """Platform self-check: DynamoDB table must be encrypted."""
        dynamodb = boto3.client('dynamodb', region_name=REGION)
        resp = dynamodb.describe_table(TableName='secops-findings')
        sse = resp['Table'].get('SSEDescription', {})
        assert sse.get('Status') == 'ENABLED', \
            'DynamoDB table is not encrypted — failed platform self-audit'

    def test_lambda_tracing_enabled(self):
        """Platform self-check: Lambda must have X-Ray tracing."""
        lambda_client = boto3.client('lambda', region_name=REGION)
        resp = lambda_client.get_function_configuration(
            FunctionName='secops-detection-engine'
        )
        assert resp.get('TracingConfig', {}).get('Mode') == 'Active', \
            'Lambda X-Ray tracing not enabled'

    def test_no_public_s3_buckets(self):
        """Platform self-check: no platform S3 buckets should be public."""
        s3 = boto3.client('s3', region_name=REGION)
        for bucket in s3.list_buckets()['Buckets']:
            name = bucket['Name']
            if not name.startswith('secops'):
                continue
            try:
                public_block = s3.get_public_access_block(Bucket=name)
                config = public_block['PublicAccessBlockConfiguration']
                assert all([
                    config['BlockPublicAcls'],
                    config['BlockPublicPolicy'],
                    config['IgnorePublicAcls'],
                    config['RestrictPublicBuckets']
                ]), f'Bucket {name} has public access enabled — platform security failure'
            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                pytest.fail(f'Bucket {name} has no public access block configured')
```

### Load Testing with Locust

```python
# tests/load/locustfile.py
"""
Load test the detection engine at 10,000 events/min.
Run with: locust -f tests/load/locustfile.py --headless -u 100 -r 10 -t 60s
"""
from locust import HttpUser, task, between
import json
import random
from datetime import datetime, timezone

ESCALATION_EVENTS = [
    'AttachRolePolicy', 'CreateAccessKey', 'UpdateLoginProfile',
    'CreateUser', 'AttachUserPolicy', 'PutRolePolicy'
]
BENIGN_EVENTS = [
    'DescribeInstances', 'ListBuckets', 'GetUser',
    'DescribeSecurityGroups', 'ListRoles'
]


class DetectionEngineUser(HttpUser):
    """Simulate CloudTrail events being delivered to the detection Lambda."""
    wait_time = between(0.01, 0.1)  # 10-100ms between events

    @task(3)
    def benign_event(self):
        self.client.post('/invoke', json={
            'event_name': random.choice(BENIGN_EVENTS),
            'user': f'user-{random.randint(1, 100)}',
            'source_ip': f'10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'
        })

    @task(1)
    def escalation_event(self):
        self.client.post('/invoke', json={
            'event_name': random.choice(ESCALATION_EVENTS),
            'user': f'attacker-{random.randint(1, 5)}',
            'source_ip': f'{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.1'
        })
```

```bash
# Run load test
pip install locust
locust -f tests/load/locustfile.py \
  --headless \
  -u 200 \       # 200 concurrent users
  -r 20 \        # spawn 20/second
  -t 120s \      # run for 2 minutes
  --html reports/load-test-report.html

# Target: p95 latency < 500ms at 10,000 events/min
```

---

## Platform Security Self-Audit

Run your own tools against the platform:

```bash
# 1. IAM audit — check Lambda execution roles
python projects/03-iam-security-analyser/src/analyser.py \
  --region us-east-1 \
  --output reports/platform-iam-audit.json

# 2. S3 security check
python projects/02-storage-security-scanner/src/scanner.py \
  --prefix secops \
  --output reports/platform-s3-audit.json

# 3. Network security audit
python projects/01-network-security-auditor/src/auditor.py \
  --region us-east-1 \
  --output reports/platform-network-audit.json

# 4. Checkov against Terraform
checkov -d infrastructure/terraform/ \
  --output json \
  --output-file-path reports/platform-iac-audit/

# Fix all CRITICAL and HIGH findings before Week 24
```

---

## Coverage Report

```bash
# Run full test suite with coverage
pip install pytest pytest-cov pytest-asyncio

pytest tests/unit/ \
  -v \
  --cov=src \
  --cov-report=html:reports/coverage/ \
  --cov-report=term-missing \
  --cov-fail-under=70  # Fail if coverage drops below 70%

# Open coverage report
open reports/coverage/index.html
```

---

## Sprint 2 Acceptance Criteria

- [ ] GuardDuty → Step Functions SOAR pipeline working end-to-end (demo video)
- [ ] CTI enrichment running automatically on all new findings
- [ ] Azure Sentinel feed (or mock) integrated and producing findings
- [ ] `pytest tests/unit/ tests/integration/ --cov=src` shows >70% coverage
- [ ] Load test at 10,000 events/min with p95 < 500ms
- [ ] Platform self-audit CRITICAL/HIGH findings all fixed
- [ ] `pytest tests/integration/test_platform_security.py` all passing

---

## Links

→ Next: [Week 24 — Capstone Presentation & Deploy](../week-24/README.md)
