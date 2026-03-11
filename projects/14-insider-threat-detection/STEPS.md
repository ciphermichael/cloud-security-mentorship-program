# Project 14 — Insider Threat Detection (UEBA): Step-by-Step Guide

> **Skill Level:** Advanced | **Week:** 16

## Overview
Build a User Entity Behaviour Analytics (UEBA) engine that detects insider threats using statistical baseline analysis of CloudTrail logs.

## Step 1 — Generate Sample CloudTrail Data
```python
# scripts/generate_sample_data.py
import json, random
from datetime import datetime, timedelta

USERS = [f'user{i:02d}' for i in range(1, 51)]
BUSINESS_HOURS = range(8, 18)
REGIONS = ['us-east-1', 'us-west-2', 'eu-west-1']
EVENTS = ['GetObject', 'PutObject', 'DeleteObject', 'ConsoleLogin',
          'DescribeInstances', 'CreateAccessKey', 'ListBuckets']

def generate_events(days: int = 30, events_per_day: int = 200) -> list:
    events = []
    base = datetime.utcnow() - timedelta(days=days)
    for day in range(days):
        for _ in range(events_per_day):
            user = random.choice(USERS)
            hour = random.gauss(13, 3)  # Peak at 1pm, spread 3hr
            hour = max(0, min(23, int(hour)))
            event = {
                'eventTime': (base + timedelta(days=day, hours=hour)).isoformat(),
                'userIdentity': {'userName': user, 'type': 'IAMUser'},
                'eventName': random.choice(EVENTS),
                'sourceIPAddress': f'10.0.{random.randint(0,10)}.{random.randint(1,254)}',
                'awsRegion': random.choice(REGIONS[:2]),  # Normally only 2 regions
            }
            events.append(event)
    
    # Inject anomalies for 3 users
    malicious_user = USERS[5]
    for _ in range(50):
        events.append({
            'eventTime': (datetime.utcnow() - timedelta(hours=2)).isoformat(),
            'userIdentity': {'userName': malicious_user, 'type': 'IAMUser'},
            'eventName': 'GetObject',
            'sourceIPAddress': '185.220.101.45',  # Tor exit node
            'awsRegion': 'eu-west-1',  # Unusual region
        })
    return events

if __name__ == '__main__':
    events = generate_events()
    with open('data/sample_cloudtrail.json', 'w') as f:
        json.dump(events, f, indent=2)
    print(f'Generated {len(events)} events')
```

## Step 2 — Baseline Builder
```python
# src/baseline.py
import json
import numpy as np
from collections import defaultdict
from datetime import datetime

class UserBaseline:
    def __init__(self):
        self.users = {}
    
    def build(self, events: list, training_days: int = 21):
        """Build per-user behavioural baselines from historical data."""
        cutoff = datetime.utcnow().timestamp() - (training_days * 86400)
        
        user_data = defaultdict(lambda: {
            'hours': [], 'api_calls': [], 'regions': defaultdict(int),
            'ips': set(), 'event_types': defaultdict(int)
        })
        
        for event in events:
            try:
                event_time = datetime.fromisoformat(event['eventTime'].replace('Z','+00:00'))
            except Exception:
                continue
            
            if event_time.timestamp() < cutoff:
                continue  # Skip data newer than training window
            
            user = event.get('userIdentity', {}).get('userName', 'Unknown')
            user_data[user]['hours'].append(event_time.hour)
            user_data[user]['regions'][event.get('awsRegion','unknown')] += 1
            user_data[user]['ips'].add(event.get('sourceIPAddress',''))
            user_data[user]['event_types'][event.get('eventName','Unknown')] += 1
        
        for user, data in user_data.items():
            hours = data['hours']
            self.users[user] = {
                'avg_hour': np.mean(hours) if hours else 13.0,
                'std_hour': np.std(hours) if len(hours) > 1 else 2.0,
                'known_regions': list(data['regions'].keys()),
                'known_ips': list(data['ips']),
                'top_events': dict(sorted(data['event_types'].items(), key=lambda x: -x[1])[:5]),
                'daily_event_count': len(hours) / max(training_days, 1),
            }
        
        print(f'[+] Built baselines for {len(self.users)} users')
    
    def get(self, username: str) -> dict:
        return self.users.get(username, {})
    
    def save(self, path: str = 'data/baselines.json'):
        import json
        with open(path, 'w') as f:
            json.dump(self.users, f, indent=2)
```

## Step 3 — Anomaly Detector
```python
# src/detector.py
from dataclasses import dataclass
from typing import List
from datetime import datetime
import numpy as np

@dataclass
class UEBAAlert:
    user: str
    risk_score: float
    anomalies: List[str]
    event: dict
    severity: str

    @property
    def mitre_technique(self) -> str:
        if 'After-hours' in self.anomalies[0]: return 'T1078 — Valid Accounts'
        if 'Unknown IP' in self.anomalies[0]: return 'T1133 — External Remote Services'
        if 'Volume' in self.anomalies[0]: return 'T1530 — Data from Cloud Storage'
        return 'T1078 — Valid Accounts'

class AnomalyDetector:
    SIGMA_THRESHOLD = 2.0  # Flag if >2σ from baseline
    
    def __init__(self, baselines: dict):
        self.baselines = baselines
    
    def analyse_event(self, event: dict) -> UEBAAlert | None:
        user = event.get('userIdentity', {}).get('userName', 'Unknown')
        baseline = self.baselines.get(user)
        if not baseline:
            return None
        
        anomalies = []
        risk_score = 0.0
        
        # Check 1: After-hours activity
        try:
            event_hour = datetime.fromisoformat(event['eventTime'].replace('Z','+00:00')).hour
            avg_h = baseline.get('avg_hour', 13)
            std_h = baseline.get('std_hour', 2)
            if std_h > 0:
                z_score = abs(event_hour - avg_h) / std_h
                if z_score > self.SIGMA_THRESHOLD:
                    anomalies.append(f'After-hours access (hour={event_hour}, baseline={avg_h:.1f}±{std_h:.1f}, z={z_score:.1f}σ)')
                    risk_score += min(z_score * 10, 40)
        except Exception:
            pass
        
        # Check 2: Unknown region
        region = event.get('awsRegion', '')
        known_regions = baseline.get('known_regions', [])
        if region and known_regions and region not in known_regions:
            anomalies.append(f'Unknown region: {region} (known: {known_regions})')
            risk_score += 25
        
        # Check 3: Unknown IP
        ip = event.get('sourceIPAddress', '')
        known_ips = baseline.get('known_ips', [])
        if ip and known_ips and ip not in known_ips:
            anomalies.append(f'Unknown IP: {ip}')
            risk_score += 15
        
        if not anomalies:
            return None
        
        severity = 'CRITICAL' if risk_score >= 60 else 'HIGH' if risk_score >= 35 else 'MEDIUM'
        return UEBAAlert(user=user, risk_score=risk_score, anomalies=anomalies,
                         event=event, severity=severity)

def analyse_batch(events: list, baselines: dict) -> List[UEBAAlert]:
    detector = AnomalyDetector(baselines)
    alerts = []
    for event in events:
        alert = detector.analyse_event(event)
        if alert:
            alerts.append(alert)
    return sorted(alerts, key=lambda x: -x.risk_score)
```

## Step 4 — Risk Score Report
```python
# src/report.py
from .detector import UEBAAlert
from typing import List
import json

def generate_report(alerts: List[UEBAAlert], output: str = 'reports/ueba-report.json'):
    report = {
        'total_alerts': len(alerts),
        'users_flagged': len(set(a.user for a in alerts)),
        'high_risk_users': [
            {'user': a.user, 'risk_score': a.risk_score, 'severity': a.severity,
             'anomalies': a.anomalies, 'mitre': a.mitre_technique}
            for a in alerts[:20]
        ]
    }
    with open(output, 'w') as f:
        json.dump(report, f, indent=2)
    print(f'[+] {len(alerts)} alerts for {report["users_flagged"]} users — saved to {output}')
    for a in alerts[:5]:
        print(f'  [{a.severity}] {a.user} — Score: {a.risk_score:.1f} — {a.anomalies[0]}')
```

## Step 5 — Run the Full Pipeline
```bash
# Generate sample data
python scripts/generate_sample_data.py

# Build baselines + detect
python -c "
import json
from src.baseline import UserBaseline
from src.detector import analyse_batch
from src.report import generate_report

events = json.load(open('data/sample_cloudtrail.json'))
bl = UserBaseline()
bl.build(events)
alerts = analyse_batch(events[-1000:], bl.users)
generate_report(alerts)
"
```
