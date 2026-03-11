# 🆕 Project 20 — Cloud Security Posture Scoring

> **New Project** | Skill Level: Intermediate | Phase 4–5

## Overview
Build an automated risk scoring engine that aggregates findings from AWS Security Hub, GuardDuty, Config, Trusted Advisor and outputs a weighted security score with drill-down reports.

## Scoring Model
```
Overall Score (0-100) = Weighted average of:
  ├── IAM Score         (25% weight) — MFA, keys, privilege
  ├── Network Score     (20% weight) — SGs, NACLs, exposure  
  ├── Data Score        (20% weight) — S3, RDS, encryption
  ├── Logging Score     (15% weight) — CloudTrail, GuardDuty
  ├── Compliance Score  (10% weight) — CIS, Config rules
  └── Incident Score    (10% weight) — Active GuardDuty findings
```

## Step 1 — Security Hub Findings Collector
```python
# src/collectors/security_hub.py
import boto3
from datetime import datetime, timedelta

def get_findings(region: str = 'us-east-1', days: int = 7) -> list:
    sh = boto3.client('securityhub', region_name=region)
    findings = []
    paginator = sh.get_paginator('get_findings')
    for page in paginator.paginate(
        Filters={
            'WorkflowStatus': [
                {'Value': 'NEW', 'Comparison': 'EQUALS'},
                {'Value': 'NOTIFIED', 'Comparison': 'EQUALS'},
            ],
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
        }
    ):
        for f in page['Findings']:
            findings.append({
                'id': f['Id'],
                'title': f['Title'],
                'severity': f.get('Severity', {}).get('Label', 'UNKNOWN'),
                'severity_score': f.get('Severity', {}).get('Normalized', 0),
                'resource_type': f.get('Resources', [{}])[0].get('Type', 'N/A'),
                'control_id': f.get('Compliance', {}).get('SecurityControlId', ''),
                'category': _categorise(f),
                'status': f.get('Compliance', {}).get('Status', 'N/A'),
            })
    return findings

def _categorise(finding: dict) -> str:
    title = finding.get('Title', '').lower()
    ctrl  = finding.get('Compliance', {}).get('SecurityControlId', '')
    if any(k in title for k in ['iam', 'mfa', 'password', 'access key', 'root']):
        return 'IAM'
    if any(k in title for k in ['vpc', 'security group', 'nacl', 'subnet']):
        return 'NETWORK'
    if any(k in title for k in ['s3', 'rds', 'encrypt', 'kms', 'ebs']):
        return 'DATA'
    if any(k in title for k in ['cloudtrail', 'guardduty', 'config', 'logging']):
        return 'LOGGING'
    return 'COMPLIANCE'
```

## Step 2 — GuardDuty Threat Collector
```python
# src/collectors/guardduty.py
import boto3

def get_active_findings(region: str = 'us-east-1') -> list:
    gd = boto3.client('guardduty', region_name=region)
    detectors = gd.list_detectors()['DetectorIds']
    if not detectors:
        return []
    detector_id = detectors[0]
    finding_ids = gd.list_findings(
        DetectorId=detector_id,
        FindingCriteria={'Criterion': {'service.archived': {'Eq': ['false']}}}
    )['FindingIds']
    if not finding_ids:
        return []
    findings = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids[:50])['Findings']
    return [{
        'id': f['Id'],
        'title': f['Title'],
        'severity': f['Severity'],
        'type': f['Type'],
        'category': 'INCIDENT',
        'resource_type': f.get('Resource', {}).get('ResourceType', 'N/A'),
        'account': f.get('AccountId'),
    } for f in findings]
```

## Step 3 — Scoring Engine
```python
# src/scorer.py
from typing import List, Dict
import math

SEVERITY_PENALTY = {
    'CRITICAL': 30,
    'HIGH': 15,
    'MEDIUM': 7,
    'LOW': 2,
    'INFORMATIONAL': 0,
}

CATEGORY_WEIGHTS = {
    'IAM':        0.25,
    'NETWORK':    0.20,
    'DATA':       0.20,
    'LOGGING':    0.15,
    'COMPLIANCE': 0.10,
    'INCIDENT':   0.10,
}

def calculate_category_score(findings: List[dict], category: str) -> float:
    """Score a single category from 0 (worst) to 100 (best)."""
    cat_findings = [f for f in findings if f.get('category') == category]
    if not cat_findings:
        return 100.0  # No findings = perfect score

    total_penalty = sum(
        SEVERITY_PENALTY.get(f.get('severity', 'LOW'), 0)
        for f in cat_findings
    )
    # Use logarithmic decay so score doesn't hit 0 on minor issues
    score = max(0.0, 100 - (total_penalty * (1 - math.exp(-len(cat_findings) / 20))))
    return round(score, 1)

def calculate_overall_score(findings: List[dict]) -> Dict:
    category_scores = {
        cat: calculate_category_score(findings, cat)
        for cat in CATEGORY_WEIGHTS
    }

    overall = sum(
        score * weight
        for cat, weight in CATEGORY_WEIGHTS.items()
        for score in [category_scores.get(cat, 100)]
    )
    overall = round(overall, 1)

    grade = 'A' if overall >= 90 else \
            'B' if overall >= 75 else \
            'C' if overall >= 60 else \
            'D' if overall >= 40 else 'F'

    severity_breakdown = {}
    for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL']:
        severity_breakdown[sev] = sum(1 for f in findings if f.get('severity','').upper() == sev)

    return {
        'overall_score': overall,
        'grade': grade,
        'category_scores': category_scores,
        'severity_breakdown': severity_breakdown,
        'total_findings': len(findings),
        'risk_level': 'CRITICAL' if overall < 40 else 'HIGH' if overall < 60 else
                      'MEDIUM' if overall < 75 else 'LOW' if overall < 90 else 'MINIMAL',
    }

def get_top_risks(findings: List[dict], n: int = 10) -> List[dict]:
    """Return top N findings ranked by impact."""
    severity_rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    return sorted(findings,
                  key=lambda x: severity_rank.get(x.get('severity','LOW'), 9))[:n]
```

## Step 4 — Trend Tracker (DynamoDB)
```python
# src/trend_tracker.py
import boto3
from datetime import datetime
import json

TABLE_NAME = 'SecurityScoreHistory'

def save_score(score_data: dict, account_id: str = None):
    if not account_id:
        account_id = boto3.client('sts').get_caller_identity()['Account']
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(TABLE_NAME)
    table.put_item(Item={
        'AccountId':  account_id,
        'Timestamp':  datetime.utcnow().isoformat(),
        'Score':      str(score_data['overall_score']),
        'Grade':      score_data['grade'],
        'Breakdown':  json.dumps(score_data['category_scores']),
    })
    print(f'[+] Score {score_data["overall_score"]} saved to DynamoDB')

def get_score_history(account_id: str, days: int = 30) -> list:
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(TABLE_NAME)
    from datetime import timedelta
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    resp = table.query(
        KeyConditionExpression='AccountId = :aid AND #ts >= :cutoff',
        ExpressionAttributeNames={'#ts': 'Timestamp'},
        ExpressionAttributeValues={':aid': account_id, ':cutoff': cutoff},
    )
    return sorted(resp.get('Items', []), key=lambda x: x['Timestamp'])
```

## Step 5 — Streamlit Score Dashboard
```python
# dashboard.py
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import boto3, json
from src.collectors.security_hub import get_findings
from src.collectors.guardduty import get_active_findings
from src.scorer import calculate_overall_score, get_top_risks

st.set_page_config(page_title='Security Posture Score', layout='wide', page_icon='📊')
st.title('📊 Cloud Security Posture Score')

@st.cache_data(ttl=300)
def load_data():
    findings = get_findings() + get_active_findings()
    score = calculate_overall_score(findings)
    return findings, score

with st.spinner('Calculating security posture...'):
    findings, score = load_data()

# ---- Score Gauge ----
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    fig = go.Figure(go.Indicator(
        mode='gauge+number+delta',
        value=score['overall_score'],
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"Security Score — Grade {score['grade']}", 'font': {'size': 24}},
        delta={'reference': 75},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': 'darkblue'},
            'steps': [
                {'range': [0, 40],  'color': '#dc3545'},
                {'range': [40, 60], 'color': '#fd7e14'},
                {'range': [60, 75], 'color': '#ffc107'},
                {'range': [75, 90], 'color': '#28a745'},
                {'range': [90, 100],'color': '#20c997'},
            ],
            'threshold': {'line': {'color': 'red', 'width': 4}, 'value': 60}
        }
    ))
    fig.update_layout(height=300)
    st.plotly_chart(fig, use_container_width=True)

# ---- Category Scores ----
st.subheader('📋 Score by Category')
cat_df = pd.DataFrame([
    {'Category': k, 'Score': v, 'Weight': f"{int(w*100)}%"}
    for k, v in score['category_scores'].items()
    for w in [{'IAM':0.25,'NETWORK':0.20,'DATA':0.20,'LOGGING':0.15,'COMPLIANCE':0.10,'INCIDENT':0.10}.get(k, 0)]
])
fig2 = px.bar(cat_df, x='Category', y='Score', color='Score',
               color_continuous_scale=['red','orange','yellow','green'],
               range_color=[0, 100], title='Category Security Scores')
fig2.add_hline(y=75, line_dash='dash', line_color='grey', annotation_text='Target: 75')
st.plotly_chart(fig2, use_container_width=True)

# ---- Top Risks ----
st.subheader('🔴 Top 10 Risks to Address')
top_risks = get_top_risks(findings, 10)
risk_df = pd.DataFrame(top_risks)[['severity','title','category','resource_type']]
severity_colors = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢'}
risk_df['sev_icon'] = risk_df['severity'].map(severity_colors)
st.dataframe(risk_df[['sev_icon','severity','title','category']], use_container_width=True)

# ---- Findings Summary ----
st.subheader('📈 Finding Distribution')
sev_df = pd.DataFrame([
    {'Severity': k, 'Count': v}
    for k, v in score['severity_breakdown'].items() if v > 0
])
if not sev_df.empty:
    fig3 = px.pie(sev_df, values='Count', names='Severity',
                  color='Severity',
                  color_discrete_map={'CRITICAL':'#dc3545','HIGH':'#fd7e14',
                                      'MEDIUM':'#ffc107','LOW':'#28a745'})
    st.plotly_chart(fig3, use_container_width=True)
```

## Step 6 — Scheduled Lambda (Daily Score)
```python
# src/lambda_scorer.py
import boto3, json
from .collectors.security_hub import get_findings
from .collectors.guardduty import get_active_findings
from .scorer import calculate_overall_score
from .trend_tracker import save_score

def lambda_handler(event, context):
    findings = get_findings() + get_active_findings()
    score = calculate_overall_score(findings)
    save_score(score)

    # Post to Slack if score drops below threshold
    if score['overall_score'] < 60:
        import urllib.request, os
        webhook = os.environ.get('SLACK_WEBHOOK')
        if webhook:
            msg = {'text': f':warning: Security Score Alert: *{score["overall_score"]}/100* (Grade {score["grade"]}) — {score["total_findings"]} open findings'}
            urllib.request.urlopen(
                urllib.request.Request(webhook, json.dumps(msg).encode(),
                                       {'Content-Type': 'application/json'})
            )

    return {'score': score['overall_score'], 'grade': score['grade'],
            'findings': score['total_findings']}
```

## Step 7 — Run
```bash
pip install boto3 streamlit plotly pandas

# Enable Security Hub and GuardDuty in your AWS account first
aws securityhub enable-security-hub
aws guardduty create-detector --enable

# Run dashboard
streamlit run dashboard.py

# Or run scorer CLI
python -c "
from src.collectors.security_hub import get_findings
from src.scorer import calculate_overall_score
findings = get_findings()
score = calculate_overall_score(findings)
print(f'Score: {score[\"overall_score\"]}/100 | Grade: {score[\"grade\"]} | Findings: {score[\"total_findings\"]}')
"
```
