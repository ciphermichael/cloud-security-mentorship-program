"""
AWS WAF Security Monitor — Streamlit Dashboard.

Run:
    export WAF_LOG_BUCKET=aws-waf-logs-my-account
    streamlit run src/dashboard.py
"""
import os
from datetime import datetime, timezone
from collections import Counter

import boto3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from .log_parser import parse_recent_from_s3, WAFEvent

st.set_page_config(
    page_title='AWS WAF Security Monitor',
    page_icon='🛡️',
    layout='wide',
)

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header('Configuration')
    bucket = st.text_input(
        'WAF Log Bucket',
        value=os.environ.get('WAF_LOG_BUCKET', 'aws-waf-logs-my-account')
    )
    max_files = st.slider('Max log files to load', 1, 50, 10)
    refresh = st.button('🔄 Refresh Data')
    st.divider()
    st.caption(f'Updated: {datetime.now(timezone.utc).strftime("%H:%M UTC")}')

# ── Data Loading ──────────────────────────────────────────────────────────────

st.title('🛡️ AWS WAF Real-Time Attack Monitor')

@st.cache_data(ttl=60)
def load_waf_events(bucket: str, max_files: int) -> list[dict]:
    events = parse_recent_from_s3(bucket, max_files=max_files)
    return [
        {
            'timestamp': e.timestamp,
            'action': e.action,
            'client_ip': e.client_ip,
            'country': e.country,
            'method': e.method,
            'uri': e.uri[:80],
            'user_agent': e.user_agent[:60],
            'attack_type': e.attack_type or 'NONE',
            'attack_severity': e.attack_severity or '',
            'blocked': e.blocked,
            'rules_matched': ', '.join(e.rules_matched[:3]),
        }
        for e in events
    ]

try:
    raw = load_waf_events(bucket, max_files)
    df = pd.DataFrame(raw)
    if df.empty:
        st.warning('No WAF events found. Check bucket name and permissions.')
        st.stop()
except Exception as exc:
    st.error(f'Could not load WAF data: {exc}')
    st.info('Displaying demo data. Set WAF_LOG_BUCKET and ensure AWS credentials.')
    # Demo data for portfolio presentation
    df = pd.DataFrame([
        {'action': 'BLOCK', 'client_ip': '198.51.100.1', 'country': 'RU',
         'method': 'GET', 'uri': "/login?id=1' UNION SELECT--",
         'attack_type': 'SQL_INJECTION', 'attack_severity': 'CRITICAL', 'blocked': True,
         'timestamp': '2024-01-15T03:00:00Z', 'user_agent': 'sqlmap/1.7', 'rules_matched': 'SQLi-001'},
        {'action': 'BLOCK', 'client_ip': '203.0.113.42', 'country': 'CN',
         'method': 'POST', 'uri': '/search?q=<script>alert(1)</script>',
         'attack_type': 'XSS', 'attack_severity': 'HIGH', 'blocked': True,
         'timestamp': '2024-01-15T03:01:00Z', 'user_agent': 'Mozilla/5.0', 'rules_matched': 'XSS-001'},
        {'action': 'ALLOW', 'client_ip': '10.0.0.1', 'country': 'US',
         'method': 'GET', 'uri': '/api/products',
         'attack_type': 'NONE', 'attack_severity': '', 'blocked': False,
         'timestamp': '2024-01-15T03:02:00Z', 'user_agent': 'Mozilla/5.0', 'rules_matched': ''},
    ] * 10)

# ── Metrics Row ───────────────────────────────────────────────────────────────

total = len(df)
blocked = df['blocked'].sum()
block_rate = round(blocked / max(total, 1) * 100, 1)
critical = len(df[df['attack_severity'] == 'CRITICAL'])
unique_ips = df['client_ip'].nunique()

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric('Total Requests', f'{total:,}')
col2.metric('Blocked', f'{blocked:,}', delta=f'{block_rate}% rate')
col3.metric('CRITICAL Attacks', critical,
            delta_color='inverse' if critical > 0 else 'normal')
col4.metric('Unique Source IPs', unique_ips)
col5.metric('Countries', df['country'].nunique())

st.divider()

# ── Charts Row ────────────────────────────────────────────────────────────────

col_l, col_m, col_r = st.columns(3)

with col_l:
    st.subheader('Attack Types')
    attacks = df[df['attack_type'] != 'NONE']['attack_type'].value_counts()
    if not attacks.empty:
        fig = px.bar(
            attacks.reset_index(), x='attack_type', y='count',
            color='attack_type',
            color_discrete_map={
                'SQL_INJECTION': '#d32f2f', 'XSS': '#f57c00',
                'PATH_TRAVERSAL': '#fbc02d', 'COMMAND_INJECTION': '#880e4f',
                'SCANNER': '#1565c0', 'LOG4SHELL': '#4a0080',
            },
            labels={'attack_type': 'Attack', 'count': 'Count'},
        )
        fig.update_layout(showlegend=False, height=300, margin=dict(t=10))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success('No attacks detected in current window.')

with col_m:
    st.subheader('Requests by Country')
    country_counts = df['country'].value_counts().head(8)
    fig2 = px.pie(
        country_counts.reset_index(),
        values='count', names='country', hole=0.4
    )
    fig2.update_layout(height=300, margin=dict(t=10))
    st.plotly_chart(fig2, use_container_width=True)

with col_r:
    st.subheader('Allow vs Block')
    action_counts = df['action'].value_counts().reset_index()
    fig3 = px.pie(
        action_counts, values='count', names='action', hole=0.4,
        color='action',
        color_discrete_map={'BLOCK': '#d32f2f', 'ALLOW': '#388e3c', 'COUNT': '#f57c00'}
    )
    fig3.update_layout(height=300, margin=dict(t=10))
    st.plotly_chart(fig3, use_container_width=True)

# ── Top Attacker IPs ──────────────────────────────────────────────────────────

st.subheader('Top Attacker IPs')
blocked_df = df[df['blocked']]
if not blocked_df.empty:
    top_ips = (
        blocked_df.groupby('client_ip')
        .agg(
            requests=('client_ip', 'count'),
            countries=('country', lambda x: ', '.join(x.unique()[:3])),
            attacks=('attack_type', lambda x: ', '.join(x[x != 'NONE'].unique()[:3])),
        )
        .sort_values('requests', ascending=False)
        .head(10)
        .reset_index()
    )
    st.dataframe(top_ips, use_container_width=True, height=250)

# ── Raw Events Table ──────────────────────────────────────────────────────────

st.subheader('Recent Events')

sev_filter = st.multiselect(
    'Filter by severity',
    ['CRITICAL', 'HIGH', 'MEDIUM', ''],
    default=['CRITICAL', 'HIGH']
)

display = df[df['attack_severity'].isin(sev_filter)] if sev_filter else df
display_cols = ['timestamp', 'action', 'client_ip', 'country',
                'method', 'uri', 'attack_type', 'attack_severity']
st.dataframe(
    display[display_cols].sort_values('timestamp', ascending=False).head(100),
    use_container_width=True, height=400
)

st.download_button(
    '📥 Export CSV',
    data=display.to_csv(index=False),
    file_name=f'waf-events-{datetime.now().strftime("%Y-%m-%d")}.csv',
    mime='text/csv'
)
