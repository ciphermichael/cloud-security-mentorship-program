# 🆕 Project 16 — Cloud WAF Security Monitor

> **New Project** | Skill Level: Intermediate | Phase 5

## Overview
Monitor AWS WAF logs in real-time to detect SQLi, XSS, path traversal, and brute-force attacks. Includes a live Streamlit attack dashboard.

## Step 1 — Enable WAF Logging
```bash
aws s3 mb s3://aws-waf-logs-YOUR-ACCOUNT
aws wafv2 put-logging-configuration \
  --logging-configuration '{
    "ResourceArn": "arn:aws:wafv2:us-east-1:ACCT:regional/webacl/MyWebACL/xxx",
    "LogDestinationConfigs": ["arn:aws:s3:::aws-waf-logs-YOUR-ACCOUNT"]
  }'
```

## Step 2 — WAF Log Parser
```python
# src/log_ingester.py
import boto3, gzip, json

def parse_waf_log_file(bucket: str, key: str) -> list:
    s3 = boto3.client('s3')
    content = s3.get_object(Bucket=bucket, Key=key)['Body'].read()
    if key.endswith('.gz'):
        content = gzip.decompress(content)
    events = []
    for line in content.decode('utf-8').strip().split('\n'):
        if not line: continue
        try:
            e = json.loads(line)
            events.append({
                'timestamp': e.get('timestamp'),
                'action': e.get('action'),
                'client_ip': e.get('httpRequest', {}).get('clientIp'),
                'country': e.get('httpRequest', {}).get('country'),
                'uri': e.get('httpRequest', {}).get('uri'),
                'method': e.get('httpRequest', {}).get('httpMethod'),
                'rules_matched': [r.get('ruleId') for r in e.get('nonTerminatingMatchingRules', [])],
            })
        except json.JSONDecodeError:
            continue
    return events
```

## Step 3 — Attack Classifier
```python
# src/attack_classifier.py
import re
from typing import Optional

ATTACK_PATTERNS = {
    'SQL_INJECTION': [r'(?i)(union\s+select|drop\s+table|1=1|or\s+1\s*=\s*1)'],
    'XSS':           [r'(?i)(<script|javascript:|onerror\s*=|document\.cookie)'],
    'PATH_TRAVERSAL':[r'(\.\.\/|%2e%2e%2f|\/etc\/passwd)'],
    'SCANNER':       [r'(?i)(sqlmap|nikto|nuclei|ffuf|gobuster)'],
}

def classify_attack(event: dict) -> Optional[str]:
    uri = event.get('uri', '')
    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, uri):
                return attack_type
    return 'UNKNOWN' if event.get('action') == 'BLOCK' else None

def enrich_events(events: list) -> list:
    return [{**e, 'attack_type': classify_attack(e), 'blocked': e.get('action') == 'BLOCK'}
            for e in events]
```

## Step 4 — Real-Time Lambda Alert
```python
# src/alerter.py
import boto3, json, os, urllib.request
from collections import Counter

SLACK_WEBHOOK = os.environ.get('SLACK_WEBHOOK')
THRESHOLD = int(os.environ.get('BLOCK_THRESHOLD', '50'))

def lambda_handler(event, context):
    """Triggered by S3 event when new WAF log arrives."""
    from .log_ingester import parse_waf_log_file
    from .attack_classifier import enrich_events
    bucket = event['Records'][0]['s3']['bucket']['name']
    key    = event['Records'][0]['s3']['object']['key']
    raw    = parse_waf_log_file(bucket, key)
    enriched = enrich_events(raw)
    blocked  = [e for e in enriched if e['blocked']]
    if len(blocked) >= THRESHOLD:
        top_ips     = Counter(e['client_ip'] for e in blocked).most_common(3)
        top_attacks = Counter(e['attack_type'] for e in blocked).most_common(3)
        msg = {
            'text': f':shield: *WAF Alert — {len(blocked)} requests blocked*',
            'attachments': [{'color':'#FF0000','fields':[
                {'title':'Top IPs',     'value': str(top_ips),     'short': True},
                {'title':'Attack Types','value': str(top_attacks), 'short': True},
            ]}]
        }
        req = urllib.request.Request(SLACK_WEBHOOK, json.dumps(msg).encode(),
                                     {'Content-Type':'application/json'})
        urllib.request.urlopen(req)
    return {'processed': len(raw), 'blocked': len(blocked)}
```

## Step 5 — Streamlit Attack Dashboard
```python
# dashboard.py
import streamlit as st, pandas as pd, plotly.express as px, boto3, json
from src.log_ingester import parse_waf_log_file
from src.attack_classifier import enrich_events

st.set_page_config(page_title='WAF Security Monitor', layout='wide')
st.title('🛡️ AWS WAF Real-Time Attack Monitor')

bucket = st.sidebar.text_input('WAF Log Bucket', 'aws-waf-logs-my-account')
if st.sidebar.button('🔄 Refresh'):
    s3 = boto3.client('s3')
    keys = [o['Key'] for o in s3.list_objects_v2(Bucket=bucket, MaxKeys=10).get('Contents', [])]
    events = []
    for key in keys:
        events.extend(parse_waf_log_file(bucket, key))
    df = pd.DataFrame(enrich_events(events))
    if not df.empty:
        col1, col2, col3 = st.columns(3)
        col1.metric('Total Requests', len(df))
        col2.metric('Blocked', df['blocked'].sum())
        col3.metric('Block Rate', f"{df['blocked'].mean()*100:.1f}%")
        fig = px.bar(df.groupby('attack_type').size().reset_index(name='count'),
                     x='attack_type', y='count', title='Attacks by Type', color='attack_type')
        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(df[['timestamp','client_ip','country','method','uri','attack_type','blocked']],
                     use_container_width=True)
```

## Step 6 — Custom WAF Rules (Terraform)
```hcl
# waf_rules/custom_rules.tf
resource "aws_wafv2_rule_group" "custom_rules" {
  name     = "CustomSecurityRules"
  scope    = "REGIONAL"
  capacity = 100

  rule {
    name     = "BlockScanners"
    priority = 1
    action   { block {} }
    statement {
      byte_match_statement {
        field_to_match  { single_header { name = "user-agent" } }
        positional_constraint = "CONTAINS"
        search_string   = "sqlmap"
        text_transformation { priority = 0; type = "LOWERCASE" }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BlockScanners"
      sampled_requests_enabled   = true
    }
  }
}
```

## Step 7 — Run
```bash
pip install boto3 streamlit pandas plotly
streamlit run dashboard.py
```
