# Project 15 — Capstone: Cloud SecOps Platform: Step-by-Step Guide

> **Skill Level:** Advanced | **Weeks:** 21–24

## Overview
Build a complete, integrated Cloud Security Operations Platform combining all 14 previous projects into a unified, deployable system.

## Platform Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Cloud SecOps Platform                      │
├──────────────┬──────────────────────┬───────────────────────┤
│   INGESTION  │     DETECTION        │     RESPONSE          │
│              │                      │                        │
│  AWS Logs    │  IAM Escalation      │  SOAR Playbooks       │
│  GuardDuty   │  UEBA Engine         │  Slack Alerts         │
│  CloudTrail  │  Compliance Checks   │  Auto-Remediation     │
│  Sentinel    │  Container Scan      │  JIRA Tickets         │
│  GitHub      │  Threat Intel        │  Incident Timeline    │
├──────────────┴──────────────────────┴───────────────────────┤
│              VISUALISATION (Streamlit Dashboard)             │
│   Risk Score | Findings | Trends | Compliance | Hunt Lab    │
└─────────────────────────────────────────────────────────────┘
```

## Week 21 — Architecture & Planning

### Step 1 — Repository Structure
```bash
capstone-cloud-secops/
├── ingestion/
│   ├── aws_ingestion.py       # CloudTrail, GuardDuty, Security Hub
│   ├── azure_ingestion.py     # Azure Sentinel, Defender
│   └── github_ingestion.py    # GitHub audit logs
├── detection/
│   ├── iam_detector.py        # Privilege escalation
│   ├── ueba_engine.py         # Behavioural analytics
│   ├── compliance_engine.py   # CIS checks
│   └── threat_intel.py        # CTI enrichment
├── response/
│   ├── playbooks.py           # SOAR orchestration
│   ├── notifier.py            # Slack/PagerDuty
│   └── remediator.py          # Auto-fix actions
├── storage/
│   ├── s3_lake.py             # S3 data lake writer
│   └── dynamodb.py            # State tracking
├── api/
│   └── app.py                 # FastAPI REST API
├── dashboard/
│   └── main.py                # Streamlit dashboard
├── infra/
│   ├── main.tf                # Terraform IaC
│   └── lambda/                # Lambda functions
├── tests/
└── docker-compose.yml
```

## Week 22 — Core Build

### Step 2 — Event Bus (Central Coordinator)
```python
# core/event_bus.py
import asyncio
from dataclasses import dataclass
from typing import Callable, Dict, List
from enum import Enum

class EventType(Enum):
    FINDING_CREATED = "finding.created"
    ALERT_TRIGGERED = "alert.triggered"
    REMEDIATION_NEEDED = "remediation.needed"
    BASELINE_UPDATED = "baseline.updated"

@dataclass
class SecurityEvent:
    event_type: EventType
    source: str
    severity: str
    data: dict
    timestamp: str = None

    def __post_init__(self):
        if not self.timestamp:
            from datetime import datetime
            self.timestamp = datetime.utcnow().isoformat()

class EventBus:
    def __init__(self):
        self._handlers: Dict[EventType, List[Callable]] = {}

    def subscribe(self, event_type: EventType, handler: Callable):
        self._handlers.setdefault(event_type, []).append(handler)

    async def publish(self, event: SecurityEvent):
        handlers = self._handlers.get(event.event_type, [])
        await asyncio.gather(*[
            asyncio.create_task(asyncio.coroutine(h)(event))
            if asyncio.iscoroutinefunction(h) else asyncio.sleep(0)
            for h in handlers
        ])
        for h in handlers:
            if not asyncio.iscoroutinefunction(h):
                h(event)

# Global event bus instance
bus = EventBus()
```

### Step 3 — Finding Model
```python
# core/models.py
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List

@dataclass
class Finding:
    id: str
    title: str
    severity: str           # CRITICAL, HIGH, MEDIUM, LOW, INFO
    source: str             # aws, azure, github, ueba, compliance
    resource_id: str
    resource_type: str
    description: str
    remediation: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    cti_enrichment: Optional[dict] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    status: str = 'OPEN'    # OPEN, IN_PROGRESS, RESOLVED, SUPPRESSED

    @property
    def risk_score(self) -> int:
        return {'CRITICAL':100,'HIGH':75,'MEDIUM':40,'LOW':10,'INFO':5}.get(self.severity, 0)
```

### Step 4 — Platform Orchestrator
```python
# platform/orchestrator.py
import asyncio
import logging
from core.event_bus import bus, EventType, SecurityEvent
from ingestion.aws_ingestion import AWSIngestion
from detection.iam_detector import IAMDetector
from detection.ueba_engine import UEBAEngine
from response.playbooks import PlaybookEngine
from storage.s3_lake import S3DataLake

log = logging.getLogger(__name__)

class CloudSecOpsPlatform:
    def __init__(self, config: dict):
        self.config = config
        self.aws = AWSIngestion(config.get('aws', {}))
        self.iam_detector = IAMDetector()
        self.ueba = UEBAEngine()
        self.playbooks = PlaybookEngine(config.get('playbooks', {}))
        self.lake = S3DataLake(config.get('s3_bucket', ''))
        self._setup_subscriptions()

    def _setup_subscriptions(self):
        bus.subscribe(EventType.FINDING_CREATED, self._handle_finding)
        bus.subscribe(EventType.ALERT_TRIGGERED, self._handle_alert)

    def _handle_finding(self, event: SecurityEvent):
        finding = event.data
        log.info(f'Finding: [{finding["severity"]}] {finding["title"]}')
        if finding['severity'] in ('CRITICAL', 'HIGH'):
            bus.publish(SecurityEvent(
                event_type=EventType.ALERT_TRIGGERED,
                source='orchestrator',
                severity=finding['severity'],
                data=finding
            ))

    def _handle_alert(self, event: SecurityEvent):
        self.playbooks.execute(event.data)

    def run_full_scan(self):
        log.info('[*] Starting full platform scan...')
        findings = []
        findings.extend(self.aws.get_guardduty_findings())
        findings.extend(self.aws.get_security_hub_findings())
        findings.extend(self.iam_detector.detect())
        ueba_alerts = self.ueba.analyse_recent()
        findings.extend([a.to_finding() for a in ueba_alerts])

        for f in findings:
            bus.publish(SecurityEvent(
                event_type=EventType.FINDING_CREATED,
                source=f.get('source','unknown'),
                severity=f.get('severity','MEDIUM'),
                data=f
            ))
        self.lake.store_findings(findings)
        log.info(f'[+] Scan complete: {len(findings)} findings')
        return findings
```

## Week 23 — Integration & Testing

### Step 5 — FastAPI Backend
```python
# api/app.py
from fastapi import FastAPI, HTTPException
from platform.orchestrator import CloudSecOpsPlatform
import yaml

app = FastAPI(title='Cloud SecOps Platform API', version='1.0')
config = yaml.safe_load(open('config.yaml'))
platform = CloudSecOpsPlatform(config)

@app.get('/health')
def health():
    return {'status': 'healthy'}

@app.get('/api/findings')
def get_findings(severity: str = None, source: str = None, limit: int = 100):
    findings = platform.lake.query_findings(severity=severity, source=source, limit=limit)
    return {'findings': findings, 'count': len(findings)}

@app.post('/api/scan')
def trigger_scan():
    findings = platform.run_full_scan()
    return {'status': 'completed', 'findings_count': len(findings)}

@app.get('/api/risk-score')
def get_risk_score():
    from src.risk_scorer import calculate_risk_score
    findings = platform.lake.query_findings(limit=1000)
    return calculate_risk_score(findings)
```

### Step 6 — Docker Compose (Local Dev)
```yaml
# docker-compose.yml
version: '3.9'
services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - AWS_PROFILE=default
      - SLACK_WEBHOOK=${SLACK_WEBHOOK}
    volumes:
      - ~/.aws:/root/.aws:ro
    command: uvicorn api.app:app --host 0.0.0.0 --port 8000 --reload

  dashboard:
    build: .
    ports:
      - "8501:8501"
    depends_on:
      - api
    command: streamlit run dashboard/main.py --server.port 8501
```

## Week 24 — Deploy & Demo

### Step 7 — Terraform Infrastructure
```hcl
# infra/main.tf
provider "aws" { region = var.region }

resource "aws_lambda_function" "scanner" {
  filename         = "lambda.zip"
  function_name    = "cloud-secops-scanner"
  role             = aws_iam_role.scanner_role.arn
  handler          = "platform.orchestrator.lambda_handler"
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = 512
  environment {
    variables = {
      SLACK_WEBHOOK = var.slack_webhook
      S3_BUCKET     = aws_s3_bucket.findings_lake.bucket
    }
  }
}

resource "aws_cloudwatch_event_rule" "daily_scan" {
  name                = "DailySecurityScan"
  schedule_expression = "cron(0 6 * * ? *)"
}

resource "aws_cloudwatch_event_target" "scan_target" {
  rule = aws_cloudwatch_event_rule.daily_scan.name
  arn  = aws_lambda_function.scanner.arn
}

resource "aws_s3_bucket" "findings_lake" {
  bucket = "${var.account_name}-security-findings-lake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lake_enc" {
  bucket = aws_s3_bucket.findings_lake.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}
```

### Step 8 — Deploy
```bash
# Package Lambda
pip install -r requirements.txt -t lambda_layer/
zip -r lambda.zip . -x "*.git*" "tests/*" "*.pyc"

# Terraform
cd infra
terraform init
terraform plan -out=tfplan
terraform apply tfplan

# Run local demo
docker-compose up
# Dashboard: http://localhost:8501
# API docs:  http://localhost:8000/docs
```
