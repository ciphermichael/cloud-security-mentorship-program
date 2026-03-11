# 👤 Insider Threat Detection System

> **Week 16** | Phase 4: DevSecOps & Automation | MITRE TA0009, TA0010

UEBA engine that builds per-user behaviour baselines from 30 days of CloudTrail and detects anomalies using z-score statistical analysis.

## Run
```bash
pip install -r requirements.txt

# Demo mode — generates synthetic users and anomaly
python src/ueba/detection_engine.py

# Production mode
export AWS_PROFILE=readonly-auditor
python src/ueba/detection_engine.py
```

## Risk Indicators
| Indicator | Weight | Detection Logic |
|-----------|--------|----------------|
| volume_anomaly | 20 | Daily API calls > 3σ above baseline |
| after_hours_access | 25 | Activity outside 07:00–20:00 Mon–Fri |
| new_resource_access | 30 | >5 resources never accessed before |
| bulk_s3_download | 35 | >100 GetObject calls in analysis window |
| sensitive_service | 20 | >10 accesses to IAM/Secrets/KMS |
| weekend_admin_action | 35 | IAM admin actions on Sat/Sun |

## Alert Severity Thresholds
| Score Range | Severity | Action |
|-------------|----------|--------|
| ≥ 80 | 🔴 CRITICAL | Suspend account, notify CISO |
| 60–79 | 🟠 HIGH | Investigate, check HR records |
| 40–59 | 🟡 MEDIUM | Monitor closely, log for 7 days |

> ⚠️ Privacy Notice: All monitoring must comply with organisation policy and employment law.
