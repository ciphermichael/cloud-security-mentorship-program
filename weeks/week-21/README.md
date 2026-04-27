# Week 21 — Capstone: Architecture Design & Planning

**Phase 6: Capstone — Cloud Security Operations Platform | Project: 15-capstone-cloud-secops-platform**

---

## Learning Objectives

By the end of this week you will be able to:

- Design a complete Cloud Security Operations Platform architecture
- Apply STRIDE threat modelling to your own platform
- Produce API contracts, data flow diagrams, and AWS cost estimates
- Plan a 3-week development sprint with clearly scoped tasks
- Set up the project repository, infrastructure, and CI/CD for the capstone

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | Architecture design — define all components, data flows, integrations | 3 hrs |
| Tue | STRIDE threat model the platform itself | 2 hrs |
| Wed | API contracts, data schema, AWS cost estimate | 2 hrs |
| Thu | Set up repository, CI/CD pipeline, Terraform skeleton | 2 hrs |
| Fri | Sprint planning — break Week 22 and 23 into daily tasks | 2 hrs |
| Sat | Architecture document finalized, repo scaffolded, push to GitHub | 3 hrs |
| Sun | Architecture review with mentor | 1 hr |

---

## Capstone Platform Overview

The capstone is a **Cloud Security Operations Platform** — a production-grade security tooling platform that integrates everything built in the previous 20 weeks into a cohesive, deployable system.

### What the Platform Does

```
┌──────────────────────────────────────────────────────────────────────┐
│              CLOUD SECURITY OPERATIONS PLATFORM                      │
│                                                                      │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────┐ │
│  │  Data Sources  │  │   Detection    │  │      Dashboard          │ │
│  │                │  │   Engine       │  │                         │ │
│  │ • CloudTrail   │→ │ • 20 rules     │→ │ • Risk score            │ │
│  │ • GuardDuty    │  │ • IAM escalation│  │ • Live findings         │ │
│  │ • Security Hub │  │ • Threat hunt  │  │ • Trend charts          │ │
│  │ • Azure Sentinel│  │ • UEBA engine  │  │ • Entity drill-down     │ │
│  │ • GitHub audit │  │                │  │ • Export CSV/PDF        │ │
│  └────────────────┘  └────────────────┘  └────────────────────────┘ │
│           ↓                  ↓                        ↑              │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────┐ │
│  │  Data Lake     │  │  SOAR Engine   │  │    CTI Enrichment       │ │
│  │                │  │                │  │                         │ │
│  │ • S3 (raw)     │  │ • Step Func.   │  │ • OTX lookup            │ │
│  │ • Glue catalog │  │ • Auto-isolate │  │ • AbuseIPDB             │ │
│  │ • Athena SQL   │  │ • Auto-snapshot│  │ • Threat actor mapping  │ │
│  │ • 90-day WORM  │  │ • Slack/SNS    │  │ • MITRE ATT&CK mapping  │ │
│  └────────────────┘  └────────────────┘  └────────────────────────┘ │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Compliance Engine — CIS + SOC 2 scoring + evidence export    │ │
│  └────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

### Platform Components

| Component | Technology | Week Built In |
|-----------|-----------|---------------|
| CloudTrail ingestion pipeline | Lambda + S3 + Glue | Week 4 |
| IAM escalation detector | EventBridge + Lambda | Week 5 |
| KQL detection rules (Azure) | Sentinel analytics | Week 6 |
| CTI enrichment engine | Python + OTX/AbuseIPDB | Week 19 |
| SOAR orchestrator | Step Functions + Lambda | Week 9 |
| UEBA engine | Python + pandas | Week 16 |
| Compliance checker | Python + AWS Config | Week 10 |
| Security dashboard | Streamlit | Week 15 |

---

## Architecture Document (Week 21 Deliverable)

Create `docs/architecture.md`:

### System Architecture Diagram

Draw this using draw.io (free) or Excalidraw (free). Export as PNG and SVG and commit both.

The diagram must show:
1. Data source layer (CloudTrail, GuardDuty, Security Hub, GitHub)
2. Ingestion layer (EventBridge rules, Lambda triggers, Kinesis if high volume)
3. Storage layer (S3 data lake with partitioning, Glue catalog, Athena)
4. Processing layer (Detection Lambda, SOAR Step Functions, UEBA engine, CTI enrichment)
5. Presentation layer (Streamlit dashboard, SNS/Slack notifications)
6. Supporting infrastructure (KMS encryption, VPC, IAM roles, CloudTrail)

### Data Flow Document

```
Event Flow 1: CloudTrail → Detection (real-time)
=====================================
AWS API Call
  → CloudTrail (15 min delay)
  → EventBridge rule (matches escalation events)
  → Lambda: IAMEscalationDetector
    → Lookup: is this a known-safe action? (DynamoDB whitelist)
    → Enrich: CTI lookup on source IP
    → Score: calculate severity
  → If HIGH/CRITICAL:
    → SNS → Slack alert with enrichment context
    → Step Functions: SOAR playbook
    → DynamoDB: store finding
  → Streamlit: dashboard polls DynamoDB for live updates

Event Flow 2: GuardDuty → SOAR (automated response)
=====================================
GuardDuty Finding (severity >= 7.0)
  → EventBridge (GuardDuty findings rule)
  → Step Functions: cloud-ir-orchestrator
    Step 1: Enrich (Lambda → CTI + CloudTrail context)
    Step 2: Triage (Lambda → whitelist check, severity assessment)
    Step 3: Decision (Choice state → auto-contain or human review)
    Step 4a: Auto-contain (Parallel → isolate EC2 + snapshot EBS)
    Step 4b: Notify (SNS → Slack + PagerDuty)
    Step 5: Ticket (Lambda → Jira/GitHub Issue)
```

### API Contracts

```yaml
# Platform internal APIs (Lambda function contracts)

# Finding Schema
Finding:
  id: string (UUID)
  source: enum [cloudtrail, guardduty, securityhub, azure_sentinel, github]
  event_time: ISO8601
  severity: enum [CRITICAL, HIGH, MEDIUM, LOW]
  title: string
  description: string
  mitre_technique: string  # T1098, T1530, etc.
  mitre_tactic: string
  actor_arn: string
  source_ip: string
  resource_id: string
  resource_type: string
  cti_enrichment:
    is_malicious: bool
    confidence: int (0-100)
    threat_names: list[string]
    ttps: list[string]
  soar_status: enum [pending, auto_contained, human_review, resolved]
  created_at: ISO8601
  updated_at: ISO8601

# Risk Score Schema
RiskScore:
  account_id: string
  region: string
  calculated_at: ISO8601
  overall_score: float (0-100)
  scores_by_category:
    iam: float
    network: float
    logging: float
    data: float
    compute: float
  finding_counts:
    CRITICAL: int
    HIGH: int
    MEDIUM: int
    LOW: int
```

### STRIDE Threat Model for the Platform

Apply STRIDE to the platform itself:

| Threat | Component | Risk | Mitigation |
|--------|-----------|------|------------|
| **Spoofing** | Dashboard authentication | HIGH | Require OAuth/SSO, no password auth |
| **Tampering** | Findings stored in DynamoDB | HIGH | DynamoDB streams + audit trail |
| **Repudiation** | SOAR automated actions | HIGH | Every action logged with identity |
| **Information Disclosure** | Dashboard shows security findings | CRITICAL | Private VPC, auth required, no public endpoint |
| **Denial of Service** | Lambda functions processing logs | MEDIUM | Reserved concurrency, SQS deadletter |
| **Elevation of Privilege** | Lambda execution role | CRITICAL | Least-privilege role, no `iam:*` |

### AWS Cost Estimate

```
Monthly cost estimate for the platform (AWS free tier + minimal resources):

Component              Free Tier     Minimal Paid
--------------------------------------------------
Lambda (5M invocations)  Free          $1/month
DynamoDB (25 GB)         Free          ~$3/month
S3 (50 GB)               First 5 GB   ~$2/month
Athena (per query)        -            $1-5/month
Step Functions            4K free      ~$2/month
EventBridge               1M free      Free
GuardDuty (30-day trial)  Free trial   ~$10/month
Security Hub (30-day)     Free trial   ~$2/month
CloudWatch Logs           5 GB free    ~$3/month
Streamlit Cloud           Free tier    Free

TOTAL (minimal):                      ~$24/month
TOTAL (free tier only):               $0 (first 30 days)
```

### Sprint Plan (Weeks 22-24)

```markdown
## Sprint 1 — Week 22: Core Build
Day 1: Data ingestion pipeline (CloudTrail S3 → Glue catalog → Athena table)
Day 2: Detection Lambda with 5 rules (IAM escalation, open SGs, root usage)
Day 3: Finding schema + DynamoDB storage
Day 4: Streamlit dashboard skeleton (connecting to DynamoDB)
Day 5: Integration test: end-to-end event → finding → dashboard
Day 6: Sprint 1 review and bug fixes

## Sprint 2 — Week 23: Integration & Testing
Day 1: SOAR integration (GuardDuty → Step Functions)
Day 2: CTI enrichment integration
Day 3: UEBA engine integration (batch job, not real-time)
Day 4: Compliance checker integration
Day 5: Test suite (unit + integration, >70% coverage)
Day 6: Load test with Locust (10,000 events/min target)

## Sprint 3 — Week 24: Polish & Deploy
Day 1: Security hardening (platform self-audit with tools from Week 3)
Day 2: Documentation (README, runbook, deployment guide)
Day 3: Demo video recording
Day 4: Blog post writing
Day 5: Production deployment
Day 6: Live presentation to cohort
```

---

## Repository Setup

```bash
# Initialize the capstone repository
git init cloud-secops-platform
cd cloud-secops-platform

# Create directory structure
mkdir -p {src/{ingestion,detection,soar,ueba,compliance,enrichment,dashboard},
           infrastructure/{terraform,cloudformation},
           tests/{unit,integration},
           docs,
           queries/{athena,cloudwatch,kql,splunk},
           scripts,
           reports}

# Create main files
touch README.md requirements.txt .env.example .gitignore
touch src/__init__.py
touch infrastructure/terraform/main.tf
touch infrastructure/terraform/variables.tf
touch infrastructure/terraform/outputs.tf

# .gitignore
cat > .gitignore << 'EOF'
.env
*.pyc
__pycache__/
.aws/
reports/*.json
*.tfvars
.terraform/
*.tfstate
*.tfstate.backup
.cti-cache/
evidence/
EOF

# Initial commit
git add .
git commit -m "chore: initialize capstone project structure"
```

---

## Submission Checklist

- [ ] Architecture document committed to `docs/architecture.md`
- [ ] System diagram (PNG + SVG) committed to `docs/`
- [ ] STRIDE threat model table for the platform
- [ ] API contracts and data schemas defined
- [ ] AWS cost estimate documented
- [ ] Sprint plan for Weeks 22-24 with daily tasks
- [ ] Repository structure scaffolded and CI/CD configured
- [ ] Mentor reviewed and approved architecture design

---

## Links

→ Full project: [projects/15-capstone-cloud-secops-platform/](../../projects/15-capstone-cloud-secops-platform/)
→ Next: [Week 22 — Capstone Core Build](../week-22/README.md)
