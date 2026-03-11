# 🆕 Project 18 — Cloud Forensics Timeline Builder

> **New Project** | Skill Level: Advanced | Phase 5

## Overview
Automate forensic evidence collection from CloudTrail and VPC Flow Logs, correlate events into a kill-chain timeline, and generate an analyst-ready incident report.

## What You'll Build
```
cloud-forensics-timeline/
├── src/
│   ├── evidence_collector.py   # CloudTrail + VPC flow log ingestion
│   ├── correlator.py           # Multi-source event correlation
│   ├── timeline_builder.py     # Chronological attack timeline
│   ├── mitre_mapper.py         # Map events to ATT&CK techniques
│   └── report_generator.py     # HTML + PDF incident report
├── data/                       # Sample incident data
├── reports/
└── tests/
```

## Step 1 — Evidence Collector
```python
# src/evidence_collector.py
import boto3, json
from datetime import datetime, timedelta
from pathlib import Path

class EvidenceCollector:
    def __init__(self, incident_id: str, region: str = 'us-east-1'):
        self.incident_id = incident_id
        self.region = region
        self.evidence_dir = Path(f'evidence/{incident_id}')
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def collect_cloudtrail_events(self, start_time: datetime, end_time: datetime,
                                   entities: list = None) -> list:
        """Collect CloudTrail events for a time window, optionally filtered by entity."""
        ct = boto3.client('cloudtrail', region_name=self.region)
        events = []
        kwargs = {
            'StartTime': start_time,
            'EndTime': end_time,
            'MaxResults': 50,
        }
        while True:
            resp = ct.lookup_events(**kwargs)
            for raw_event in resp.get('Events', []):
                event = {
                    'source': 'cloudtrail',
                    'timestamp': raw_event['EventTime'].isoformat(),
                    'event_name': raw_event.get('EventName'),
                    'username': raw_event.get('Username'),
                    'resource_name': raw_event.get('ResourceName', ''),
                    'source_ip': raw_event.get('CloudTrailEvent', '{}'),
                    'raw': raw_event.get('CloudTrailEvent', '{}'),
                }
                # Filter by entity if provided
                if entities:
                    raw_str = str(raw_event)
                    if any(e in raw_str for e in entities):
                        events.append(event)
                else:
                    events.append(event)
            next_token = resp.get('NextToken')
            if not next_token: break
            kwargs['NextToken'] = next_token

        self._save_evidence('cloudtrail_events.json', events)
        print(f'[+] Collected {len(events)} CloudTrail events')
        return events

    def collect_vpc_flow_logs(self, log_group: str, start_time: datetime,
                               end_time: datetime, filter_ip: str = None) -> list:
        """Query VPC flow logs from CloudWatch Logs."""
        cw = boto3.client('logs', region_name=self.region)
        query = f"fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, protocol, action, bytes"
        if filter_ip:
            query += f" | filter srcAddr = '{filter_ip}' or dstAddr = '{filter_ip}'"
        query += " | sort @timestamp asc | limit 1000"

        resp = cw.start_query(
            logGroupName=log_group,
            startTime=int(start_time.timestamp()),
            endTime=int(end_time.timestamp()),
            queryString=query,
        )
        query_id = resp['queryId']

        import time
        for _ in range(30):
            status = cw.get_query_results(queryId=query_id)
            if status['status'] in ('Complete', 'Failed', 'Cancelled'):
                break
            time.sleep(2)

        results = []
        for row in status.get('results', []):
            record = {field['field']: field['value'] for field in row}
            record['source'] = 'vpc_flow_logs'
            results.append(record)

        self._save_evidence('vpc_flow_logs.json', results)
        print(f'[+] Collected {len(results)} VPC flow log records')
        return results

    def _save_evidence(self, filename: str, data: list):
        path = self.evidence_dir / filename
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        print(f'[+] Evidence saved: {path}')
```

## Step 2 — Event Correlator
```python
# src/correlator.py
from datetime import datetime
from typing import List
import json

class EventCorrelator:
    """Correlate events from multiple sources into a unified timeline."""

    def normalise(self, events: list, source_type: str) -> list:
        """Normalise events from different sources to a common schema."""
        normalised = []
        for event in events:
            if source_type == 'cloudtrail':
                try:
                    raw = json.loads(event.get('raw', '{}'))
                    normalised.append({
                        'timestamp': event.get('timestamp'),
                        'source': 'CloudTrail',
                        'actor': raw.get('userIdentity', {}).get('arn', event.get('username', 'Unknown')),
                        'action': event.get('event_name'),
                        'target': raw.get('requestParameters', {}) or event.get('resource_name', 'N/A'),
                        'source_ip': raw.get('sourceIPAddress', 'N/A'),
                        'region': raw.get('awsRegion', 'N/A'),
                        'outcome': 'FAIL' if raw.get('errorCode') else 'SUCCESS',
                        'raw': raw,
                    })
                except Exception:
                    pass

            elif source_type == 'vpc_flow':
                normalised.append({
                    'timestamp': event.get('@timestamp'),
                    'source': 'VPC Flow Logs',
                    'actor': event.get('srcAddr', 'N/A'),
                    'action': f"NETWORK_{event.get('action','?')}",
                    'target': f"{event.get('dstAddr')}:{event.get('dstPort')}",
                    'source_ip': event.get('srcAddr'),
                    'protocol': event.get('protocol'),
                    'bytes': event.get('bytes', 0),
                    'outcome': event.get('action', 'UNKNOWN'),
                    'raw': event,
                })
        return normalised

    def correlate_by_entity(self, all_events: list, entity: str) -> list:
        """Return all events involving a specific entity (IP, ARN, user)."""
        return [e for e in all_events
                if entity in str(e.get('actor','')) or
                   entity in str(e.get('source_ip','')) or
                   entity in str(e.get('target',''))]

    def build_unified_timeline(self, *event_lists) -> list:
        """Merge and sort all event sources chronologically."""
        combined = []
        for events in event_lists:
            combined.extend(events)
        return sorted(combined, key=lambda x: x.get('timestamp',''))
```

## Step 3 — MITRE ATT&CK Mapper
```python
# src/mitre_mapper.py
EVENT_TO_MITRE = {
    # Initial Access
    'ConsoleLogin':                    ('TA0001', 'T1078', 'Initial Access', 'Valid Accounts'),
    'AssumeRoleWithWebIdentity':       ('TA0001', 'T1078.004', 'Initial Access', 'Valid Accounts: Cloud Accounts'),
    # Persistence
    'CreateAccessKey':                 ('TA0003', 'T1098.001', 'Persistence', 'Account Manipulation: Add Cloud Credentials'),
    'CreateUser':                      ('TA0003', 'T1136', 'Persistence', 'Create Account'),
    'CreateLoginProfile':              ('TA0003', 'T1098', 'Persistence', 'Account Manipulation'),
    # Privilege Escalation
    'AttachUserPolicy':                ('TA0004', 'T1098', 'Privilege Escalation', 'Account Manipulation'),
    'PutUserPolicy':                   ('TA0004', 'T1098', 'Privilege Escalation', 'Account Manipulation'),
    'UpdateAssumeRolePolicy':          ('TA0004', 'T1548', 'Privilege Escalation', 'Abuse Elevation Control'),
    # Discovery
    'ListBuckets':                     ('TA0007', 'T1619', 'Discovery', 'Cloud Storage Object Discovery'),
    'DescribeInstances':               ('TA0007', 'T1580', 'Discovery', 'Cloud Infrastructure Discovery'),
    'ListUsers':                       ('TA0007', 'T1087.004', 'Discovery', 'Account Discovery: Cloud Account'),
    # Collection / Exfiltration
    'GetObject':                       ('TA0009', 'T1530', 'Collection', 'Data from Cloud Storage'),
    # Defence Evasion
    'DeleteTrail':                     ('TA0005', 'T1562.008', 'Defence Evasion', 'Disable Cloud Logs'),
    'StopLogging':                     ('TA0005', 'T1562.008', 'Defence Evasion', 'Disable Cloud Logs'),
    'DeleteFlowLogs':                  ('TA0005', 'T1562.008', 'Defence Evasion', 'Disable Cloud Logs'),
    # Impact
    'TerminateInstances':              ('TA0040', 'T1489', 'Impact', 'Service Stop'),
    'DeleteBucket':                    ('TA0040', 'T1485', 'Impact', 'Data Destruction'),
}

def map_to_mitre(event: dict) -> dict:
    action = event.get('action', '')
    mapping = EVENT_TO_MITRE.get(action)
    if mapping:
        return {
            **event,
            'mitre_tactic_id':     mapping[0],
            'mitre_technique_id':  mapping[1],
            'mitre_tactic':        mapping[2],
            'mitre_technique':     mapping[3],
        }
    return event

def annotate_timeline(timeline: list) -> list:
    return [map_to_mitre(event) for event in timeline]
```

## Step 4 — Incident Report Generator
```python
# src/report_generator.py
from jinja2 import Template
from datetime import datetime
import json

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <title>Incident Report — {{ incident_id }}</title>
  <style>
    body { font-family: Arial; margin: 30px; }
    .header { background: #1a1a2e; color: white; padding: 20px; border-radius: 8px; }
    .timeline-item { border-left: 3px solid #007bff; padding: 10px 20px; margin: 10px 0; }
    .critical { border-color: #dc3545; background: #fff5f5; }
    .badge { padding: 2px 8px; border-radius: 4px; font-size: 12px; color: white; }
    .ta { background: #6f42c1; } .technique { background: #0d6efd; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th { background: #343a40; color: white; padding: 10px; }
    td { padding: 8px; border-bottom: 1px solid #dee2e6; font-size: 13px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🔍 Cloud Incident Investigation Report</h1>
    <p>Incident: {{ incident_id }} | Generated: {{ generated_at }} | Total Events: {{ total_events }}</p>
  </div>

  <h2>Executive Summary</h2>
  <p>{{ executive_summary }}</p>

  <h2>Attack Timeline</h2>
  {% for event in timeline[:50] %}
  <div class="timeline-item {% if event.get('mitre_tactic_id') %}critical{% endif %}">
    <strong>{{ event.timestamp }}</strong> |
    <code>{{ event.action }}</code> by <em>{{ event.actor }}</em>
    from {{ event.source_ip }}
    {% if event.get('mitre_tactic') %}
    <br><span class="badge ta">{{ event.mitre_tactic_id }}</span>
    <span class="badge technique">{{ event.mitre_technique }}</span>
    {% endif %}
  </div>
  {% endfor %}

  <h2>MITRE ATT&CK Techniques Observed</h2>
  <table>
    <tr><th>Tactic</th><th>Technique</th><th>Event Count</th></tr>
    {% for t in mitre_summary %}
    <tr><td>{{ t.tactic }}</td><td>{{ t.technique }}</td><td>{{ t.count }}</td></tr>
    {% endfor %}
  </table>
</body>
</html>
"""

def generate_html_report(incident_id: str, timeline: list, output: str = None) -> str:
    from collections import Counter
    mitre_events = [e for e in timeline if e.get('mitre_tactic')]
    mitre_counts = Counter((e['mitre_tactic'], e['mitre_technique']) for e in mitre_events)
    mitre_summary = [{'tactic': k[0], 'technique': k[1], 'count': v}
                     for k, v in mitre_counts.most_common()]

    html = Template(REPORT_TEMPLATE).render(
        incident_id=incident_id,
        generated_at=datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'),
        total_events=len(timeline),
        executive_summary=f"Investigation identified {len(mitre_events)} events mapped to {len(mitre_summary)} MITRE ATT&CK techniques.",
        timeline=timeline,
        mitre_summary=mitre_summary,
    )

    output = output or f'reports/{incident_id}-forensic-report.html'
    with open(output, 'w') as f:
        f.write(html)
    print(f'[+] Report generated: {output}')
    return output
```

## Step 5 — Main Forensics Runner
```python
# src/main.py
import argparse
from datetime import datetime, timedelta
from .evidence_collector import EvidenceCollector
from .correlator import EventCorrelator
from .mitre_mapper import annotate_timeline
from .report_generator import generate_html_report

def investigate(incident_id: str, suspect_ip: str = None,
                hours_back: int = 24, region: str = 'us-east-1'):
    print(f'\n[*] Starting forensic investigation: {incident_id}')
    end_time   = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours_back)

    # Step 1 — Collect Evidence
    collector = EvidenceCollector(incident_id, region)
    ct_events = collector.collect_cloudtrail_events(start_time, end_time,
                                                     entities=[suspect_ip] if suspect_ip else None)

    # Step 2 — Normalise & Correlate
    corr = EventCorrelator()
    norm_ct = corr.normalise(ct_events, 'cloudtrail')
    timeline = corr.build_unified_timeline(norm_ct)

    # Step 3 — Filter by suspect entity
    if suspect_ip:
        timeline = corr.correlate_by_entity(timeline, suspect_ip)

    # Step 4 — Annotate with MITRE ATT&CK
    timeline = annotate_timeline(timeline)

    # Step 5 — Generate Report
    generate_html_report(incident_id, timeline)

    print(f'\n[+] Investigation complete: {len(timeline)} events analysed')
    return timeline

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--incident-id', required=True)
    parser.add_argument('--suspect-ip')
    parser.add_argument('--hours-back', type=int, default=24)
    parser.add_argument('--region', default='us-east-1')
    args = parser.parse_args()
    investigate(args.incident_id, args.suspect_ip, args.hours_back, args.region)
```

## Step 6 — Run
```bash
pip install boto3 jinja2 fpdf2

# Investigate a real incident
python -m src.main --incident-id INC-2024-001 --suspect-ip 185.220.101.45 --hours-back 48

# Open report
open reports/INC-2024-001-forensic-report.html
```
