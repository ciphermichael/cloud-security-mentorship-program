"""
Streamlit dashboard for Cloud Security Posture Score.

Run:
    streamlit run src/dashboard.py
"""
import json
from pathlib import Path
from datetime import datetime, timezone

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px

from src.scorer import PostureScorer

st.set_page_config(
    page_title='Security Posture Score',
    page_icon='🛡️',
    layout='wide',
)

st.title('Cloud Security Posture Score')
st.caption('Aggregates AWS Security Hub findings into a 0–100 risk score across 6 categories.')

# ── Sidebar controls ───────────────────────────────────────────────────────────

with st.sidebar:
    st.header('Settings')
    region = st.selectbox('AWS Region', ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'])
    refresh = st.button('Refresh Score')
    st.markdown('---')
    st.markdown('**Score legend**')
    st.markdown('- 0–29: MINIMAL risk\n- 30–49: LOW risk\n- 50–69: MEDIUM risk\n- 70–84: HIGH risk\n- 85–100: CRITICAL risk')

# ── Session state ──────────────────────────────────────────────────────────────

if 'report' not in st.session_state:
    st.session_state.report = None

if refresh or st.session_state.report is None:
    with st.spinner('Collecting Security Hub findings…'):
        try:
            scorer = PostureScorer(region=region)
            st.session_state.report = scorer.run()
        except Exception as exc:
            st.error(f'Failed to collect findings: {exc}')
            st.stop()

report = st.session_state.report

# ── Overall score gauge ────────────────────────────────────────────────────────

score = report.overall_score
risk = report.risk_level

bar_color = (
    '#d32f2f' if score >= 85 else
    '#f57c00' if score >= 70 else
    '#fbc02d' if score >= 50 else
    '#388e3c' if score >= 30 else
    '#1b5e20'
)

gauge = go.Figure(go.Indicator(
    mode='gauge+number+delta',
    value=score,
    number={'suffix': '/100', 'font': {'size': 48}},
    gauge={
        'axis': {'range': [0, 100], 'tickwidth': 1},
        'bar': {'color': bar_color, 'thickness': 0.3},
        'steps': [
            {'range': [0, 30],  'color': '#c8e6c9'},
            {'range': [30, 50], 'color': '#fff9c4'},
            {'range': [50, 70], 'color': '#ffe0b2'},
            {'range': [70, 85], 'color': '#ffcdd2'},
            {'range': [85, 100], 'color': '#b71c1c'},
        ],
        'threshold': {
            'line': {'color': 'red', 'width': 4},
            'thickness': 0.75,
            'value': 70,
        },
    },
    title={'text': f'Risk Level: <b>{risk}</b>', 'font': {'size': 20}},
))
gauge.update_layout(height=350, margin=dict(t=60, b=20, l=20, r=20))

col1, col2 = st.columns([2, 1])
with col1:
    st.plotly_chart(gauge, use_container_width=True)

with col2:
    st.metric('Total Findings', report.total_findings)
    st.metric('Overall Score', f'{score:.1f}/100')
    st.metric('Risk Level', risk)
    checked_at = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    st.caption(f'Last refreshed: {checked_at}')

# ── Category breakdown bar chart ───────────────────────────────────────────────

cats = list(report.category_scores.keys())
scores = [report.category_scores[c].score for c in cats]
counts = [report.category_scores[c].finding_count for c in cats]
criticals = [report.category_scores[c].critical_count for c in cats]

bar_fig = px.bar(
    x=cats,
    y=scores,
    color=scores,
    color_continuous_scale='RdYlGn_r',
    range_color=[0, 100],
    text=[f'{s:.0f}' for s in scores],
    labels={'x': 'Category', 'y': 'Risk Score (0-100)', 'color': 'Score'},
    title='Risk Score by Category',
)
bar_fig.update_traces(textposition='outside')
bar_fig.update_layout(
    yaxis_range=[0, 110],
    coloraxis_showscale=False,
    margin=dict(t=60, b=20),
)
st.plotly_chart(bar_fig, use_container_width=True)

# ── Category detail table ──────────────────────────────────────────────────────

st.subheader('Category Details')
rows = []
for cat in cats:
    cs = report.category_scores[cat]
    rows.append({
        'Category': cat.upper(),
        'Risk Score': f'{cs.score:.1f}',
        'Findings': cs.finding_count,
        'Critical': cs.critical_count,
        'High': cs.high_count,
    })

st.dataframe(rows, use_container_width=True, hide_index=True)

# ── Historical trend (if score-history.json exists) ────────────────────────────

history_path = Path('reports/score-history.json')
if history_path.exists():
    try:
        history = json.loads(history_path.read_text())
        if len(history) > 1:
            dates = [h['date'] for h in history]
            overall = [h['overall_score'] for h in history]
            trend_fig = px.line(
                x=dates, y=overall,
                markers=True,
                labels={'x': 'Date', 'y': 'Risk Score'},
                title='Score Trend Over Time',
            )
            trend_fig.update_layout(yaxis_range=[0, 100])
            st.plotly_chart(trend_fig, use_container_width=True)
    except (json.JSONDecodeError, KeyError):
        pass
