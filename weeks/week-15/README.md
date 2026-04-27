# Week 15 — CSPM & Multi-Cloud Security Posture Dashboard

**Phase 4: DevSecOps & Automation | Project: 13-multi-cloud-dashboard**

---

## Learning Objectives

By the end of this week you will be able to:

- Explain Cloud Security Posture Management (CSPM) and its role in cloud security programs
- Pull security findings from AWS Security Hub and Azure Defender for Cloud via API
- Build a real-time Streamlit security dashboard with risk scoring and trend analysis
- Implement a risk scoring algorithm that weights severity, asset value, and exploitability
- Visualize security posture with charts, heat maps, and drill-down tables
- Understand the difference between CSPM, CWPP, and CNAPP

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | CSPM fundamentals — Security Hub, Defender for Cloud, CSPM market overview | 2 hrs |
| Tue | AWS Security Hub API — pull findings, understand schema, enable standards | 2 hrs |
| Wed | Azure Defender for Cloud API — connect, pull recommendations, map to findings | 2 hrs |
| Thu | Build Streamlit dashboard — overview page, severity breakdown, top findings | 2 hrs |
| Fri | Add trend chart (7-day history), risk score algorithm, drill-down table | 2 hrs |
| Sat | Polish dashboard, deploy to a shareable URL, push to GitHub | 3 hrs |
| Sun | Mentor review — present dashboard as if to a CISO | 1 hr |

---

## Topics Covered

### CSPM vs CWPP vs CNAPP

| Acronym | Full Name | What It Covers |
|---------|-----------|----------------|
| CSPM | Cloud Security Posture Management | Configuration and compliance of cloud services |
| CWPP | Cloud Workload Protection Platform | Runtime protection of workloads (VMs, containers) |
| CNAPP | Cloud-Native Application Protection Platform | Full stack: CSPM + CWPP + DevSecOps scanning |

**Examples:** 
- CSPM: AWS Security Hub, Azure Defender for Cloud, Orca Security, Prisma Cloud
- CWPP: Crowdstrike Falcon, SentinelOne, Aqua Security, Sysdig
- CNAPP: Wiz, Lacework, Orca (combines both)

### AWS Security Hub Schema

```json
{
  "SchemaVersion": "2018-10-08",
  "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/abc123",
  "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty",
  "GeneratorId": "arn:aws:guardduty:us-east-1:123456789012:detector/def456",
  "AwsAccountId": "123456789012",
  "Types": ["TTPs/Initial Access/UnauthorizedAccess"],
  "CreatedAt": "2024-01-15T10:30:00Z",
  "UpdatedAt": "2024-01-15T10:30:00Z",
  "Severity": {
    "Label": "HIGH",
    "Normalized": 70
  },
  "Title": "EC2 instance has an open SSH port to the internet",
  "Description": "Security Group sg-0123456789 has port 22 open to 0.0.0.0/0",
  "Resources": [{
    "Type": "AwsEc2SecurityGroup",
    "Id": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789",
    "Partition": "aws",
    "Region": "us-east-1"
  }],
  "Compliance": {
    "Status": "FAILED",
    "RelatedRequirements": ["CIS AWS 5.3"]
  },
  "WorkflowState": "NEW",
  "RecordState": "ACTIVE"
}
```

### Risk Scoring Algorithm

```python
def calculate_risk_score(findings: list[dict]) -> float:
    """
    Risk score 0-100 based on:
    - 60% weight: severity distribution
    - 20% weight: finding age (older unresolved = higher risk)
    - 20% weight: asset criticality (production > dev)
    """
    if not findings:
        return 0.0

    severity_weights = {'CRITICAL': 100, 'HIGH': 70, 'MEDIUM': 40, 'LOW': 10}
    total_weighted = sum(
        severity_weights.get(f.get('Severity', {}).get('Label', 'LOW'), 10)
        for f in findings
    )
    max_possible = len(findings) * 100

    severity_score = (total_weighted / max_possible) * 60 if max_possible else 0
    # Add age and criticality penalties (simplified)
    age_penalty = min(20, len([f for f in findings
                                if f.get('WorkflowState') == 'NEW']) / len(findings) * 20)
    return round(severity_score + age_penalty, 1)
```

---

## Instructor Mentoring Guidance

**Week 15 produces the most visually impressive portfolio artifact in the program.** A Streamlit dashboard with real cloud security data is genuinely impressive to hiring managers.

**Key coaching points:**
- Students should deploy the dashboard publicly using Streamlit Cloud (free tier) so they can share the link in interviews
- Risk scoring is subjective — there's no single "right" formula. Push students to explain and defend their algorithm
- Caching API calls is essential — AWS Security Hub is slow, don't call it on every dashboard refresh

**Mentoring session agenda (60 min):**
1. (5 min) Student shares the Streamlit Cloud URL — click through it together
2. (20 min) Present dashboard as if to CISO: "Here's our multi-cloud security posture..."
3. (25 min) Code review — API error handling, caching, secrets management
4. (10 min) Mock interview: "Walk me through your risk scoring methodology"

---

## Hands-on Lab

### Lab 1: Enable AWS Security Hub

```bash
# Enable Security Hub
aws securityhub enable-security-hub \
  --enable-default-standards

# Subscribe to CIS AWS Foundations Benchmark
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
    StandardsArn=arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0

# Wait for findings to populate (5-10 minutes), then query
aws securityhub get-findings \
  --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}' \
  --query 'Findings[*].{Title:Title,Severity:Severity.Label,Resource:Resources[0].Id}' \
  --output table
```

### Lab 2: Streamlit Dashboard

```python
# src/dashboard.py
import streamlit as st
import boto3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timezone, timedelta
import json
from functools import lru_cache

st.set_page_config(
    page_title="Cloud Security Posture Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# ── Data Layer ────────────────────────────────────────────────────────────────

@st.cache_data(ttl=300)  # Cache for 5 minutes
def fetch_security_hub_findings(region: str = 'us-east-1') -> list[dict]:
    """Fetch active HIGH and CRITICAL findings from Security Hub."""
    client = boto3.client('securityhub', region_name=region)
    findings = []
    paginator = client.get_paginator('get_findings')
    pages = paginator.paginate(
        Filters={
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
            'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}],
        },
        SortCriteria=[{'Field': 'SeverityNormalized', 'SortOrder': 'desc'}]
    )
    for page in pages:
        findings.extend(page['Findings'])
    return findings


def parse_finding(f: dict) -> dict:
    return {
        'id': f.get('Id', '')[-40:],
        'title': f.get('Title', ''),
        'severity': f.get('Severity', {}).get('Label', 'UNKNOWN'),
        'severity_score': f.get('Severity', {}).get('Normalized', 0),
        'product': f.get('ProductName', f.get('GeneratorId', '')),
        'resource_type': (f.get('Resources', [{}])[0].get('Type', '')),
        'resource_id': (f.get('Resources', [{}])[0].get('Id', '')),
        'region': f.get('Region', ''),
        'created': f.get('CreatedAt', ''),
        'standard': (f.get('Compliance', {}).get('RelatedRequirements', [''])[0]),
        'status': f.get('WorkflowState', 'NEW'),
    }


def calculate_risk_score(df: pd.DataFrame) -> float:
    if df.empty:
        return 0.0
    weights = {'CRITICAL': 100, 'HIGH': 70, 'MEDIUM': 40, 'LOW': 10}
    df = df.copy()
    df['weight'] = df['severity'].map(weights).fillna(10)
    total = df['weight'].sum()
    max_possible = len(df) * 100
    return round((total / max_possible) * 100, 1) if max_possible else 0.0


# ── Dashboard Layout ──────────────────────────────────────────────────────────

st.title("🛡️ Cloud Security Posture Dashboard")
st.caption(f"Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")

# Sidebar
with st.sidebar:
    st.header("Settings")
    region = st.selectbox("AWS Region", ["us-east-1", "us-west-2", "eu-west-1"])
    refresh = st.button("🔄 Refresh Data")

# Load data
with st.spinner("Fetching findings from Security Hub..."):
    try:
        raw = fetch_security_hub_findings(region)
        df = pd.DataFrame([parse_finding(f) for f in raw])
    except Exception as e:
        st.error(f"Failed to fetch findings: {e}")
        st.info("Running with mock data for demo purposes")
        # Generate realistic mock data for demo
        df = pd.DataFrame([
            {'title': 'S3 bucket publicly accessible', 'severity': 'CRITICAL', 'severity_score': 90,
             'resource_type': 'AwsS3Bucket', 'region': region, 'product': 'Security Hub'},
            {'title': 'Root account usage detected', 'severity': 'HIGH', 'severity_score': 70,
             'resource_type': 'AwsIamUser', 'region': region, 'product': 'GuardDuty'},
            {'title': 'MFA not enabled for IAM user', 'severity': 'MEDIUM', 'severity_score': 40,
             'resource_type': 'AwsIamUser', 'region': region, 'product': 'Security Hub'},
            {'title': 'Security group port 22 open to world', 'severity': 'HIGH', 'severity_score': 70,
             'resource_type': 'AwsEc2SecurityGroup', 'region': region, 'product': 'Security Hub'},
        ])
        raw = []

# ── Top Metrics ───────────────────────────────────────────────────────────────

risk_score = calculate_risk_score(df)

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    color = "🔴" if risk_score >= 70 else "🟡" if risk_score >= 40 else "🟢"
    st.metric("Risk Score", f"{color} {risk_score}/100")

with col2:
    critical_count = len(df[df['severity'] == 'CRITICAL']) if not df.empty else 0
    st.metric("CRITICAL", critical_count, delta=None)

with col3:
    high_count = len(df[df['severity'] == 'HIGH']) if not df.empty else 0
    st.metric("HIGH", high_count)

with col4:
    medium_count = len(df[df['severity'] == 'MEDIUM']) if not df.empty else 0
    st.metric("MEDIUM", medium_count)

with col5:
    st.metric("Total Findings", len(df))

st.divider()

# ── Charts ────────────────────────────────────────────────────────────────────

col_left, col_right = st.columns(2)

with col_left:
    st.subheader("Findings by Severity")
    if not df.empty:
        sev_counts = df['severity'].value_counts().reset_index()
        sev_counts.columns = ['Severity', 'Count']
        colors = {'CRITICAL': '#d32f2f', 'HIGH': '#f57c00',
                  'MEDIUM': '#fbc02d', 'LOW': '#388e3c', 'UNKNOWN': '#757575'}
        fig = px.bar(sev_counts, x='Severity', y='Count',
                     color='Severity',
                     color_discrete_map=colors,
                     text='Count')
        fig.update_traces(textposition='outside')
        fig.update_layout(showlegend=False, height=350)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No findings to display")

with col_right:
    st.subheader("Findings by Resource Type")
    if not df.empty and 'resource_type' in df.columns:
        type_counts = df['resource_type'].value_counts().head(8).reset_index()
        type_counts.columns = ['Resource Type', 'Count']
        fig2 = px.pie(type_counts, values='Count', names='Resource Type',
                      hole=0.4)
        fig2.update_layout(height=350)
        st.plotly_chart(fig2, use_container_width=True)

# ── Findings Table ────────────────────────────────────────────────────────────

st.subheader("Top Findings — Requires Action")

severity_filter = st.multiselect(
    "Filter by severity",
    options=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
    default=['CRITICAL', 'HIGH']
)

if not df.empty:
    filtered = df[df['severity'].isin(severity_filter)] if severity_filter else df
    display_cols = [c for c in ['severity', 'title', 'resource_type', 'region', 'product']
                    if c in filtered.columns]
    st.dataframe(
        filtered[display_cols].sort_values('severity',
            key=lambda s: s.map({'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3})),
        use_container_width=True,
        height=400
    )
    st.download_button(
        "📥 Export CSV",
        data=filtered.to_csv(index=False),
        file_name=f"security-findings-{datetime.now().strftime('%Y-%m-%d')}.csv",
        mime="text/csv"
    )
else:
    st.success("No active findings — great posture!")
```

```bash
# Run the dashboard
pip install streamlit plotly boto3 pandas
streamlit run src/dashboard.py

# Deploy to Streamlit Cloud (free)
# 1. Push to GitHub
# 2. Go to share.streamlit.io
# 3. Connect your repo → select src/dashboard.py → Deploy
```

---

## Interview Skills Gained

**Q: What is CSPM and why do enterprises need it?**
> Cloud Security Posture Management continuously monitors cloud resources for misconfigurations and compliance violations against frameworks like CIS, PCI-DSS, and SOC 2. Enterprises need it because cloud environments change constantly — developers provision new resources daily, and a misconfiguration can appear at any time. CSPM provides continuous visibility rather than point-in-time audits.

**Q: What is the difference between a finding severity and a business risk?**
> A finding severity (CRITICAL/HIGH/MEDIUM/LOW) is a technical assessment of the vulnerability's exploitability and impact. Business risk combines severity with context: a CRITICAL finding in a dev sandbox is less urgent than a MEDIUM finding in a production database storing healthcare data. Risk prioritization must consider asset value, data sensitivity, and compensating controls.

**Q: How do you present security posture to an executive audience?**
> Lead with business impact, not technical details. "Our risk score improved from 73 to 45 this quarter, reducing our exposure to data breach by closing 12 critical gaps." Use trend data — executives want to see if things are getting better or worse. Quantify where possible: number of critical findings closed, MTTR improvement, compliance percentage. Save technical details for an appendix.

---

## Submission Checklist

- [ ] Dashboard runs locally: `streamlit run src/dashboard.py`
- [ ] Dashboard deployed and accessible via public Streamlit Cloud URL (include in README)
- [ ] Risk score implemented with documented algorithm
- [ ] Severity breakdown chart, resource type chart, findings table all working
- [ ] CSV export working
- [ ] Dashboard demonstrates AWS Security Hub findings (real or realistic mock data)
- [ ] README includes dashboard screenshot and the Streamlit Cloud link

---

## Links

→ Full project: [projects/13-multi-cloud-dashboard/](../../projects/13-multi-cloud-dashboard/)
→ Next: [Week 16 — UEBA & Insider Threat Detection](../week-16/README.md)
