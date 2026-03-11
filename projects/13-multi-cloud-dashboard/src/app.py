"""
Multi-Cloud Security Dashboard
Week 15 Project — Cloud Security Mentorship Programme

A Streamlit-based CSPM dashboard aggregating findings from:
- AWS Security Hub
- Prowler JSON output
- Azure Defender for Cloud API (placeholder)

Run: streamlit run app.py
"""
import json
import subprocess
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# ─── PAGE CONFIG ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Cloud Security Operations Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── STYLING ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  .main-header {
      background: linear-gradient(135deg, #0d2137 0%, #1b4f8a 100%);
      color: white; padding: 20px 28px; border-radius: 10px;
      margin-bottom: 24px;
  }
  .metric-card {
      background: white; padding: 16px 20px; border-radius: 8px;
      border-left: 4px solid #1b4f8a;
      box-shadow: 0 1px 4px rgba(0,0,0,.08);
  }
  .finding-critical { border-left-color: #dc2626; }
  .finding-high     { border-left-color: #ea580c; }
  .finding-medium   { border-left-color: #d97706; }
  .finding-low      { border-left-color: #16a34a; }
</style>
""", unsafe_allow_html=True)


# ─── DATA LOADING ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=300)  # Cache for 5 minutes
def load_aws_security_hub_findings() -> List[Dict]:
    """Load findings from AWS Security Hub via boto3."""
    try:
        import boto3
        client = boto3.client("securityhub")
        findings = []
        paginator = client.get_paginator("get_findings")
        filters = {
            "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"},
                               {"Value": "NOTIFIED", "Comparison": "EQUALS"}],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        }
        for page in paginator.paginate(Filters=filters, MaxResults=100):
            findings.extend(page.get("Findings", []))

        return [_normalise_hub_finding(f) for f in findings]
    except Exception as e:
        st.sidebar.warning(f"AWS Security Hub: {e}")
        return []


@st.cache_data(ttl=600)
def load_prowler_findings(prowler_output_path: str = "data/prowler_output.json") -> List[Dict]:
    """Load findings from Prowler JSON output file."""
    path = Path(prowler_output_path)
    if not path.exists():
        return _generate_demo_findings()  # Return demo data if no real output

    try:
        with open(path) as fh:
            data = json.load(fh)
        return [_normalise_prowler_finding(f) for f in data]
    except Exception as e:
        st.sidebar.warning(f"Prowler file error: {e}")
        return _generate_demo_findings()


def _normalise_hub_finding(f: Dict) -> Dict:
    """Normalise AWS Security Hub finding to unified schema."""
    return {
        "id": f.get("Id", ""),
        "source": "AWS Security Hub",
        "cloud": "AWS",
        "title": f.get("Title", ""),
        "description": f.get("Description", ""),
        "severity": f.get("Severity", {}).get("Label", "INFORMATIONAL"),
        "severity_score": {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2,
                           "LOW": 1, "INFORMATIONAL": 0}.get(
            f.get("Severity", {}).get("Label", "INFORMATIONAL"), 0),
        "resource": f.get("Resources", [{}])[0].get("Id", "unknown"),
        "resource_type": f.get("Resources", [{}])[0].get("Type", "unknown"),
        "region": f.get("Region", "unknown"),
        "service": f.get("ProductFields", {}).get("aws/securityhub/FindingId", "").split("/")[0],
        "compliance": [c.get("Status", "") for c in f.get("Compliance", {}).get("AssociatedStandards", [])],
        "remediation": f.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
        "first_seen": f.get("FirstObservedAt", ""),
        "last_seen": f.get("LastObservedAt", ""),
    }


def _normalise_prowler_finding(f: Dict) -> Dict:
    """Normalise Prowler JSON finding to unified schema."""
    severity_map = {"critical": "CRITICAL", "high": "HIGH",
                    "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
    severity = severity_map.get(f.get("Severity", "info").lower(), "INFO")
    return {
        "id": f.get("CheckID", ""),
        "source": "Prowler",
        "cloud": f.get("Cloud", "AWS"),
        "title": f.get("CheckTitle", ""),
        "description": f.get("Description", ""),
        "severity": severity,
        "severity_score": {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            .get(severity, 0),
        "resource": f.get("ResourceArn", "unknown"),
        "resource_type": f.get("ResourceType", "unknown"),
        "region": f.get("Region", "unknown"),
        "service": f.get("ServiceName", ""),
        "compliance": f.get("Compliance", {}).get("ISO27001", []),
        "remediation": f.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
        "first_seen": f.get("Timestamp", ""),
        "last_seen": f.get("Timestamp", ""),
    }


def _generate_demo_findings() -> List[Dict]:
    """Generate realistic demo findings for demonstration."""
    import random
    random.seed(42)

    demo_checks = [
        ("CRITICAL", "S3-PUBLIC-001", "S3 bucket publicly accessible", "AWS", "s3", "s3://prod-data-lake"),
        ("CRITICAL", "IAM-MFA-001", "Root account no MFA", "AWS", "iam", "arn:aws:iam::123456789012:root"),
        ("HIGH", "EC2-SG-001", "SSH open to 0.0.0.0/0", "AWS", "ec2", "sg-0abc123def456"),
        ("HIGH", "IAM-KEY-001", "Access key >90 days old", "AWS", "iam", "AKIA...XYZ (user: deploy-bot)"),
        ("HIGH", "BLOB-001", "Azure Blob container public", "Azure", "storage", "az://mycontainer"),
        ("HIGH", "AKS-PRIV-001", "AKS privileged pod allowed", "Azure", "aks", "ns/production"),
        ("MEDIUM", "SG-EGRESS-001", "Unrestricted outbound SG", "AWS", "ec2", "sg-0xyz789"),
        ("MEDIUM", "S3-NOLOG-001", "S3 bucket no access logging", "AWS", "s3", "s3://app-assets"),
        ("MEDIUM", "KMS-001", "EBS not encrypted with CMK", "AWS", "ec2", "vol-0abc12345"),
        ("MEDIUM", "RDS-001", "RDS no deletion protection", "AWS", "rds", "db-production"),
        ("MEDIUM", "NSG-001", "Azure NSG allows all inbound", "Azure", "network", "nsg-webservers"),
        ("LOW", "TAG-001", "Resource missing required tags", "AWS", "ec2", "i-0abc123def"),
        ("LOW", "FL-001", "VPC Flow Logs disabled", "AWS", "vpc", "vpc-0123abc"),
        ("LOW", "BLOB-VER-001", "Blob versioning disabled", "Azure", "storage", "az://backups"),
        ("INFO", "CT-001", "CloudTrail not multi-region", "AWS", "cloudtrail", "trail-us-east-1"),
    ]

    findings = []
    for severity, check_id, title, cloud, service, resource in demo_checks:
        findings.append({
            "id": check_id,
            "source": "Prowler" if cloud == "AWS" else "Azure Defender",
            "cloud": cloud,
            "title": title,
            "description": f"Automated detection: {title}",
            "severity": severity,
            "severity_score": {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                .get(severity, 0),
            "resource": resource,
            "resource_type": service,
            "region": random.choice(["us-east-1", "eu-west-1", "us-west-2", "eastus"]),
            "service": service,
            "compliance": [],
            "remediation": "See detailed remediation in security documentation.",
            "first_seen": (datetime.now() - timedelta(days=random.randint(1, 30))).isoformat(),
            "last_seen": datetime.now().isoformat(),
        })
    return findings


# ─── RISK SCORING ─────────────────────────────────────────────────────────────

def calculate_posture_score(findings: List[Dict]) -> float:
    """Calculate security posture score 0-100 (higher = better)."""
    if not findings:
        return 100.0
    weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    max_score = 100
    deductions = sum(weights.get(f["severity"], 0) for f in findings)
    score = max(0, max_score - deductions)
    return round(score, 1)


# ─── DASHBOARD PAGES ──────────────────────────────────────────────────────────

def page_overview(findings: List[Dict]):
    """Main security posture overview page."""
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ Cloud Security Operations Dashboard</h1>
        <p style="margin:0;opacity:.8">Multi-Cloud Security Posture Management — Real-time Risk Overview</p>
    </div>
    """, unsafe_allow_html=True)

    if not findings:
        st.info("No findings loaded. Configure your cloud connectors in the sidebar.")
        return

    df = pd.DataFrame(findings)
    posture_score = calculate_posture_score(findings)

    # KPI Row
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    with col1:
        score_color = "#16a34a" if posture_score >= 70 else "#d97706" if posture_score >= 50 else "#dc2626"
        st.metric("Security Score", f"{posture_score}/100",
                  delta=None, help="Lower findings = higher score")
    with col2:
        st.metric("🔴 Critical", df[df.severity == "CRITICAL"].shape[0])
    with col3:
        st.metric("🟠 High", df[df.severity == "HIGH"].shape[0])
    with col4:
        st.metric("🟡 Medium", df[df.severity == "MEDIUM"].shape[0])
    with col5:
        st.metric("🟢 Low", df[df.severity == "LOW"].shape[0])
    with col6:
        st.metric("📦 Total Resources", df["resource"].nunique())

    st.divider()

    # Charts row
    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("Findings by Severity")
        sev_counts = df["severity"].value_counts()
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sev_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c",
                      "MEDIUM": "#d97706", "LOW": "#16a34a", "INFO": "#2563eb"}
        ordered = {s: sev_counts.get(s, 0) for s in sev_order if sev_counts.get(s, 0) > 0}
        fig = px.bar(
            x=list(ordered.keys()), y=list(ordered.values()),
            color=list(ordered.keys()),
            color_discrete_map=sev_colors,
            labels={"x": "Severity", "y": "Count"},
            height=300,
        )
        fig.update_layout(showlegend=False, plot_bgcolor="white",
                          paper_bgcolor="white", margin=dict(t=20))
        st.plotly_chart(fig, use_container_width=True)

    with col_right:
        st.subheader("Findings by Cloud Provider")
        cloud_counts = df["cloud"].value_counts()
        fig2 = px.pie(
            values=cloud_counts.values,
            names=cloud_counts.index,
            color_discrete_sequence=["#FF9900", "#0078D4", "#34A853"],
            height=300,
        )
        fig2.update_layout(margin=dict(t=20))
        st.plotly_chart(fig2, use_container_width=True)

    # Top findings table
    st.subheader("🔴 Critical & High Findings — Immediate Action Required")
    critical_high = df[df["severity"].isin(["CRITICAL", "HIGH"])].sort_values(
        "severity_score", ascending=False
    )

    if not critical_high.empty:
        st.dataframe(
            critical_high[["severity", "cloud", "service", "title", "resource", "region"]].rename(
                columns={"severity": "Severity", "cloud": "Cloud", "service": "Service",
                         "title": "Finding", "resource": "Resource", "region": "Region"}
            ),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("✅ No Critical or High severity findings!")


def page_findings(findings: List[Dict]):
    """Full findings list with filtering."""
    st.header("📋 All Security Findings")

    if not findings:
        st.info("No findings available.")
        return

    df = pd.DataFrame(findings)

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        sev_filter = st.multiselect("Severity", options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                                     default=["CRITICAL", "HIGH", "MEDIUM"])
    with col2:
        cloud_filter = st.multiselect("Cloud", options=df["cloud"].unique().tolist(),
                                       default=df["cloud"].unique().tolist())
    with col3:
        service_filter = st.multiselect("Service", options=df["service"].unique().tolist(),
                                         default=df["service"].unique().tolist())

    filtered = df[
        df["severity"].isin(sev_filter) &
        df["cloud"].isin(cloud_filter) &
        df["service"].isin(service_filter)
    ]

    st.caption(f"Showing {len(filtered)} of {len(df)} findings")

    st.dataframe(
        filtered[["severity", "cloud", "service", "title", "resource",
                  "region", "remediation"]].rename(
            columns={"severity": "Severity", "cloud": "Cloud", "service": "Service",
                     "title": "Finding", "resource": "Resource",
                     "region": "Region", "remediation": "Remediation"}
        ),
        use_container_width=True,
        hide_index=True,
    )


def page_compliance(findings: List[Dict]):
    """Compliance posture by service and framework."""
    st.header("📊 Compliance Posture")

    if not findings:
        st.info("No findings available.")
        return

    df = pd.DataFrame(findings)

    # Risk by service heatmap
    st.subheader("Risk by Cloud Service")
    service_sev = df.groupby(["service", "severity"]).size().unstack(fill_value=0)
    st.dataframe(service_sev, use_container_width=True)

    # Risk score gauge per cloud
    st.subheader("Posture Score by Cloud Provider")
    clouds = df["cloud"].unique()
    cols = st.columns(len(clouds))
    for i, cloud in enumerate(clouds):
        cloud_findings = df[df["cloud"] == cloud].to_dict("records")
        score = calculate_posture_score(cloud_findings)
        with cols[i]:
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                title={"text": cloud},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "#1b4f8a"},
                    "steps": [
                        {"range": [0, 50], "color": "#fee2e2"},
                        {"range": [50, 75], "color": "#fef3c7"},
                        {"range": [75, 100], "color": "#d1fae5"},
                    ],
                },
            ))
            fig.update_layout(height=250, margin=dict(t=40, b=0, l=20, r=20))
            st.plotly_chart(fig, use_container_width=True)


# ─── MAIN APP ─────────────────────────────────────────────────────────────────

def main():
    # Sidebar
    with st.sidebar:
        st.image("https://img.shields.io/badge/🛡️-CloudSecOps-0d2137", use_column_width=True)
        st.title("Configuration")

        data_source = st.radio("Data Source", ["Demo Data", "AWS Security Hub", "Prowler File"])
        st.divider()

        if data_source == "Prowler File":
            prowler_path = st.text_input("Prowler JSON Path", "data/prowler_output.json")
        st.divider()

        if st.button("🔄 Refresh Data", type="primary"):
            st.cache_data.clear()
            st.rerun()

        st.caption(f"Last refresh: {datetime.now().strftime('%H:%M:%S')}")

    # Load data
    with st.spinner("Loading security findings..."):
        if data_source == "Demo Data":
            findings = _generate_demo_findings()
            st.sidebar.success(f"✅ Demo: {len(findings)} findings loaded")
        elif data_source == "AWS Security Hub":
            findings = load_aws_security_hub_findings()
            st.sidebar.success(f"✅ Security Hub: {len(findings)} findings")
        else:
            findings = load_prowler_findings(prowler_path)
            st.sidebar.success(f"✅ Prowler: {len(findings)} findings")

    # Navigation
    page = st.tabs(["🏠 Overview", "📋 All Findings", "📊 Compliance"])

    with page[0]:
        page_overview(findings)
    with page[1]:
        page_findings(findings)
    with page[2]:
        page_compliance(findings)


if __name__ == "__main__":
    main()
