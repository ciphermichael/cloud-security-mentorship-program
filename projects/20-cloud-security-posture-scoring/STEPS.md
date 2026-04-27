# Project 20 — Cloud Security Posture Scoring: Step-by-Step Guide

> **Skill Level:** Intermediate | **Time:** ~8 hours | **Week:** 15

---

## Overview

Build a weighted security posture scoring engine that aggregates findings from AWS Security Hub across 6 categories (IAM, Network, Data, Logging, Compliance, Runtime) into a single risk score from 0 (minimal risk) to 100 (critical).

**Scoring model:**
```
Overall Score (0-100) = Weighted average of:
  IAM Score         ×0.25  — MFA, stale keys, overprivilege
  Network Score     ×0.20  — Open SGs, NACLs, VPC exposure
  Data Score        ×0.20  — S3 encryption, RDS encryption, public buckets
  Logging Score     ×0.15  — CloudTrail, GuardDuty, Config coverage
  Compliance Score  ×0.10  — CIS Benchmark, Config rules
  Runtime Score     ×0.10  — GuardDuty findings, active incidents
```

---

## Prerequisites

```bash
pip install boto3 streamlit pandas plotly pytest moto
```

AWS permissions:
- `securityhub:GetFindings`, `securityhub:ListStandards`
- `guardduty:ListFindings`, `guardduty:GetFindings`
- `sts:GetCallerIdentity`

---

## Step 1 — Enable AWS Security Hub

```bash
# Enable Security Hub and subscribe to CIS Benchmark
aws securityhub enable-security-hub \
  --enable-default-standards

# Wait 5-10 minutes for initial findings to populate
aws securityhub get-findings \
  --filters '{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
  --query 'Findings[0:3].{Severity:Severity.Label,Title:Title}' \
  --output table
```

---

## Step 2 — Run the Scorer

```bash
cd projects/20-cloud-security-posture-scoring

pip install -r requirements.txt

python -m src.scorer --region us-east-1 --output reports

# Expected output:
# ==================================================
# Cloud Security Posture Score: 34.2/100
# Risk Level: MEDIUM
# Total Findings: 47
#
# Category Breakdown:
#   iam         :  45.0/100  (12 findings, 2 CRITICAL)
#   network     :  38.0/100  (8 findings, 1 CRITICAL)
#   data        :  28.0/100  (9 findings, 0 CRITICAL)
#   logging     :  18.0/100  (4 findings, 0 CRITICAL)
#   compliance  :  42.0/100  (10 findings, 1 CRITICAL)
#   runtime     :  20.0/100  (4 findings, 0 CRITICAL)
#
# Report saved → reports/posture-score-2024-01-15.json
```

---

## Step 3 — Run Tests

```bash
pytest tests/test_scorer.py -v

# 18 tests covering:
# - Category scoring with CRITICAL/HIGH/MEDIUM/LOW mixes
# - Weights sum to 1.0
# - Risk level classification (CRITICAL/HIGH/MEDIUM/LOW/MINIMAL)
# - Finding categorisation by product name
# - Score capped at 100
```

---

## Step 4 — Build the Streamlit Dashboard

```python
# src/dashboard.py
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import boto3, json
from src.scorer import PostureScorer

st.set_page_config(page_title='Security Posture Score', page_icon='🛡️', layout='wide')
st.title('🛡️ Cloud Security Posture Score')

if st.sidebar.button('🔄 Refresh Score'):
    scorer = PostureScorer()
    report = scorer.run()

    # Gauge chart for overall score
    fig = go.Figure(go.Indicator(
        mode='gauge+number',
        value=report.overall_score,
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': 'darkred' if report.overall_score >= 70
                    else 'orange' if report.overall_score >= 40 else 'green'},
            'steps': [
                {'range': [0, 30], 'color': '#c8e6c9'},
                {'range': [30, 60], 'color': '#fff9c4'},
                {'range': [60, 100], 'color': '#ffcdd2'},
            ],
            'threshold': {'line': {'color': 'red', 'width': 4}, 'value': 70}
        },
        title={'text': f'Risk Level: {report.risk_level}'}
    ))
    st.plotly_chart(fig, use_container_width=True)

    # Category breakdown
    cats = list(report.category_scores.keys())
    scores = [report.category_scores[c].score for c in cats]
    fig2 = px.bar(x=cats, y=scores, color=scores,
                  color_continuous_scale='RdYlGn_r',
                  range_color=[0, 100],
                  labels={'x': 'Category', 'y': 'Risk Score'},
                  title='Risk Score by Category')
    st.plotly_chart(fig2, use_container_width=True)
```

```bash
streamlit run src/dashboard.py
```

---

## Step 5 — Extend with Historical Trending

```python
# Track scores over time for trend analysis
import json
from pathlib import Path
from datetime import datetime, timezone

def save_historical_score(report, history_file: str = 'reports/score-history.json'):
    path = Path(history_file)
    history = json.loads(path.read_text()) if path.exists() else []
    history.append({
        'date': datetime.now(timezone.utc).date().isoformat(),
        'overall_score': report.overall_score,
        'risk_level': report.risk_level,
        'total_findings': report.total_findings,
        'category_scores': {
            cat: cs.score for cat, cs in report.category_scores.items()
        }
    })
    path.write_text(json.dumps(history, indent=2))
```

---

## Step 6 — GitHub Portfolio Checklist

- [ ] `src/scorer.py` — full scoring engine with 6 categories and weights
- [ ] `tests/test_scorer.py` — 18 unit tests, all passing
- [ ] `src/dashboard.py` — gauge chart + category bar chart (screenshot required)
- [ ] `reports/sample-posture-score.json` — example output committed
- [ ] `STEPS.md` — this guide
- [ ] README with scoring methodology explanation and example score
- [ ] Screenshot of the Streamlit dashboard with gauge chart

---

## Common Issues

| Issue | Fix |
|-------|-----|
| `InvalidAccessException: Security Hub not enabled` | Run `aws securityhub enable-security-hub` first |
| 0 findings on a fresh account | Wait 10-15 minutes after enabling Security Hub for initial scan |
| Score is 0 with no findings | Empty account — use `--demo` flag to load sample data |
| `ThrottlingException` | Add `time.sleep(0.2)` between paginator calls |
