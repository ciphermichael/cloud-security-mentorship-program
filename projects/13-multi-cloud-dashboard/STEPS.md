# Project 13 — Multi-Cloud Security Dashboard: Step-by-Step Guide

> **Skill Level:** Intermediate | **Week:** 15

## Overview
Streamlit CSPM dashboard aggregating findings from AWS Security Hub and Azure Defender for Cloud.

## Step 1 — Setup
```bash
pip install streamlit boto3 azure-mgmt-security azure-identity pandas plotly requests
```

## Step 2 — AWS Security Hub Collector
```python
# src/aws_collector.py
import boto3
from datetime import datetime, timedelta

def get_securityhub_findings(region: str = 'us-east-1', days: int = 7) -> list:
    sh = boto3.client('securityhub', region_name=region)
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    findings = []
    paginator = sh.get_paginator('get_findings')
    filters = {
        'UpdatedAt': [{'DateRange': {'Value': days, 'Unit': 'DAYS'}}],
        'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'},
                           {'Value': 'NOTIFIED', 'Comparison': 'EQUALS'}]
    }
    for page in paginator.paginate(Filters=filters):
        for f in page['Findings']:
            findings.append({
                'cloud': 'AWS',
                'id': f.get('Id', '')[:50],
                'title': f.get('Title', 'Unknown')[:100],
                'severity': f.get('Severity', {}).get('Label', 'UNKNOWN'),
                'resource': f.get('Resources', [{}])[0].get('Id', 'N/A')[:80],
                'created_at': f.get('CreatedAt', ''),
                'updated_at': f.get('UpdatedAt', ''),
                'compliance_status': f.get('Compliance', {}).get('Status', 'N/A'),
                'aws_account': f.get('AwsAccountId', ''),
            })
    return findings
```

## Step 3 — Azure Defender Collector
```python
# src/azure_collector.py
from azure.identity import DefaultAzureCredential
from azure.mgmt.security import SecurityCenter
import os

def get_azure_findings(subscription_id: str = None) -> list:
    sub_id = subscription_id or os.environ.get('AZURE_SUBSCRIPTION_ID')
    client = SecurityCenter(DefaultAzureCredential(), sub_id)
    
    findings = []
    for alert in client.alerts.list():
        findings.append({
            'cloud': 'Azure',
            'id': alert.name,
            'title': alert.alert_display_name or 'Unknown',
            'severity': (alert.severity or 'Unknown').upper(),
            'resource': alert.compromised_entity or 'N/A',
            'created_at': str(alert.time_generated_utc) if alert.time_generated_utc else '',
            'updated_at': str(alert.time_generated_utc) if alert.time_generated_utc else '',
            'status': alert.status or 'Unknown',
            'subscription': sub_id,
        })
    return findings
```

## Step 4 — Risk Scorer
```python
# src/risk_scorer.py
from typing import List

SEVERITY_SCORES = {'CRITICAL': 100, 'HIGH': 75, 'MEDIUM': 40, 'LOW': 10, 'INFORMATIONAL': 5}

def calculate_risk_score(findings: List[dict]) -> dict:
    if not findings:
        return {'overall_score': 100, 'grade': 'A', 'total_findings': 0}
    
    raw_score = sum(SEVERITY_SCORES.get(f.get('severity','').upper(), 0) for f in findings)
    normalized = max(0, 100 - min(raw_score / 10, 100))
    
    grade = 'A' if normalized >= 90 else 'B' if normalized >= 75 else 'C' if normalized >= 60 else 'D' if normalized >= 40 else 'F'
    
    return {
        'overall_score': round(normalized, 1),
        'grade': grade,
        'total_findings': len(findings),
        'by_severity': {sev: sum(1 for f in findings if f.get('severity','').upper() == sev)
                        for sev in ['CRITICAL','HIGH','MEDIUM','LOW']},
        'by_cloud': {cloud: sum(1 for f in findings if f.get('cloud') == cloud)
                     for cloud in ['AWS','Azure']},
    }
```

## Step 5 — Streamlit Dashboard
```python
# dashboard.py
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from src.aws_collector import get_securityhub_findings
from src.azure_collector import get_azure_findings
from src.risk_scorer import calculate_risk_score

st.set_page_config(page_title='Cloud Security Dashboard', page_icon='🛡️', layout='wide')

# ---- Sidebar ----
st.sidebar.title('⚙️ Settings')
days = st.sidebar.slider('Days of findings', 1, 30, 7)
show_aws = st.sidebar.checkbox('AWS Security Hub', value=True)
show_azure = st.sidebar.checkbox('Azure Defender', value=True)

# ---- Load Data ----
@st.cache_data(ttl=300)  # Cache for 5 minutes
def load_findings(days, include_aws, include_azure):
    findings = []
    if include_aws:
        try:
            findings.extend(get_securityhub_findings(days=days))
        except Exception as e:
            st.warning(f'AWS: {e}')
    if include_azure:
        try:
            findings.extend(get_azure_findings())
        except Exception as e:
            st.warning(f'Azure: {e}')
    return findings

with st.spinner('Loading findings...'):
    findings = load_findings(days, show_aws, show_azure)

score_data = calculate_risk_score(findings)
df = pd.DataFrame(findings) if findings else pd.DataFrame()

# ---- Header ----
st.title('🛡️ Multi-Cloud Security Dashboard')
st.caption(f'Showing {len(findings)} findings from last {days} days')

# ---- Score Cards ----
col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    color = 'normal' if score_data['overall_score'] >= 70 else 'inverse'
    st.metric('Security Score', f"{score_data['overall_score']}/100", delta=f"Grade {score_data['grade']}")
with col2:
    st.metric('🔴 Critical', score_data['by_severity'].get('CRITICAL', 0))
with col3:
    st.metric('🟠 High', score_data['by_severity'].get('HIGH', 0))
with col4:
    st.metric('🟡 Medium', score_data['by_severity'].get('MEDIUM', 0))
with col5:
    st.metric('Total Findings', score_data['total_findings'])

st.divider()

if not df.empty:
    # ---- Charts ----
    col1, col2 = st.columns(2)
    with col1:
        sev_counts = df['severity'].value_counts().reset_index()
        fig = px.pie(sev_counts, values='count', names='severity',
                     title='Findings by Severity',
                     color='severity',
                     color_discrete_map={'CRITICAL':'#dc3545','HIGH':'#fd7e14',
                                         'MEDIUM':'#ffc107','LOW':'#28a745'})
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        if 'cloud' in df.columns:
            cloud_counts = df['cloud'].value_counts().reset_index()
            fig2 = px.bar(cloud_counts, x='cloud', y='count',
                          title='Findings by Cloud Provider',
                          color='cloud',
                          color_discrete_map={'AWS':'#FF9900','Azure':'#0078D4'})
            st.plotly_chart(fig2, use_container_width=True)

    # ---- Findings Table ----
    st.subheader('📋 All Findings')
    severity_filter = st.multiselect('Filter by severity',
        options=['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL'],
        default=['CRITICAL','HIGH'])
    
    filtered_df = df[df['severity'].isin(severity_filter)] if severity_filter else df
    
    # Colour-code severity
    def style_severity(val):
        colors = {'CRITICAL':'background-color:#dc3545;color:white',
                  'HIGH':'background-color:#fd7e14;color:white',
                  'MEDIUM':'background-color:#ffc107',
                  'LOW':'background-color:#d4edda'}
        return colors.get(val, '')
    
    display_cols = [c for c in ['cloud','severity','title','resource','created_at'] if c in filtered_df.columns]
    st.dataframe(filtered_df[display_cols].style.map(style_severity, subset=['severity']),
                 use_container_width=True, height=400)
else:
    st.info('No findings loaded. Check your AWS/Azure credentials.')
```

## Step 6 — Run
```bash
streamlit run dashboard.py
# Opens at http://localhost:8501
```

## Step 7 — Deploy to Streamlit Cloud
```bash
# Add to requirements.txt and push to GitHub
# Go to share.streamlit.io and connect your repo
# Set secrets: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AZURE_*
```
