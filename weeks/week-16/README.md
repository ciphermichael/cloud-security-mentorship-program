# Week 16 — UEBA: Insider Threat Detection & Behaviour Analytics

**Phase 4: DevSecOps & Automation | Project: 14-insider-threat-detection**

---

## Learning Objectives

By the end of this week you will be able to:

- Explain User and Entity Behaviour Analytics (UEBA) and how it differs from rule-based detection
- Implement statistical baselines for normal user behaviour from CloudTrail logs
- Detect behavioural anomalies: off-hours access, API volume spikes, new geolocation, data hoarding
- Build an entity risk scoring engine with configurable weights
- Generate a user risk heatmap dashboard
- Write Splunk SPL and KQL UEBA queries for insider threat hunting

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | UEBA fundamentals — insider threat taxonomy, behavioural baselines, ML vs statistical detection | 2 hrs |
| Tue | Generate synthetic CloudTrail log dataset (50 users, 30 days) | 2 hrs |
| Wed | Build baseline engine — normal hours, usual API calls, typical regions per user | 2 hrs |
| Thu | Implement anomaly detectors — 3σ volume spike, new hour, new geo, data hoarding | 2 hrs |
| Fri | Build risk scoring engine and entity risk heatmap | 2 hrs |
| Sat | Dashboard + report generation, push to GitHub | 3 hrs |
| Sun | Mentor review — UEBA detection scenarios and interview prep | 1 hr |

---

## Topics Covered

### Insider Threat Taxonomy

**Malicious insider** — intentionally steals data or sabotages systems. Usually motivated by money, revenge, or coercion.

**Negligent insider** — accidentally causes a breach (clicks phishing link, misconfigures storage).

**Compromised insider** — external attacker has taken over a legitimate account.

**Key UEBA detection scenarios:**
1. **Data hoarding** — user downloads 10x their normal data volume before resignation date
2. **Privilege abuse** — uses legitimate access at unusual times or on unusual data
3. **Account sharing** — user account logs in from 2 locations simultaneously
4. **Reconnaissance** — suddenly accesses many more resources than their baseline
5. **Exfiltration prep** — creates new S3 buckets, enables cross-account access

### Statistical Anomaly Detection

**3-sigma rule:** If a user's API call count today is more than 3 standard deviations above their 30-day mean, flag it. This catches ~0.27% of observations under normal distribution.

```python
import numpy as np

def is_anomalous(today_value: float, baseline: list[float],
                 sigma_threshold: float = 3.0) -> tuple[bool, float]:
    """
    Returns (is_anomalous, z_score)
    z_score > threshold means anomalous
    """
    if len(baseline) < 7:  # Need at least 7 days of data
        return False, 0.0
    mean = np.mean(baseline)
    std = np.std(baseline)
    if std == 0:
        return today_value > mean * 2, 0.0
    z_score = (today_value - mean) / std
    return abs(z_score) > sigma_threshold, z_score
```

### Behavioural Baseline Features

For each user, compute baselines over a rolling 30-day window:

| Feature | Baseline Metric | Anomaly Signal |
|---------|----------------|----------------|
| API call volume | Mean + std per day | Volume > mean + 3σ |
| Active hours | Mode hour range (e.g., 9am-6pm) | Access at 2am |
| Source IPs | Set of seen IPs | New IP not in set |
| Geolocation | Countries/cities seen | New country |
| Services accessed | Set of AWS services | New service (e.g., never used Glacier before) |
| S3 buckets accessed | Set of bucket names | New bucket |
| Data downloaded | Mean GB per day | Download > mean + 3σ |

---

## Instructor Mentoring Guidance

**Week 16 introduces probabilistic thinking.** Rule-based detection is binary — an event is suspicious or not. UEBA is probabilistic — an event is more or less suspicious given context.

**Key coaching points:**
- Statistical detection has false positives. Teach students to tune thresholds based on the cost of false alerts vs missed incidents.
- Entity risk scores must be explainable — a CISO will ask "why is this user scored as high risk?" and the answer must be specific.
- The insider threat scenario is sensitive — emphasize that these tools must be used within legal and HR boundaries with proper disclosure.

**Mentoring session agenda (60 min):**
1. (10 min) Present a realistic insider threat scenario: "Jane in finance has been accessing S3 buckets she never touched before, and her API call volume tripled over the past week. She submitted her resignation yesterday. What do you do?"
2. (20 min) Code review of the anomaly detection engine
3. (20 min) Mock interview: "A user's risk score jumped from 15 to 85 overnight. Walk me through your investigation process."
4. (10 min) Preview Phase 5 — Zero Trust, Forensics, Threat Intelligence

---

## Hands-on Lab

### Lab 1: Synthetic Log Generator

```python
# scripts/generate_synthetic_logs.py
"""Generate 30 days of realistic CloudTrail-like logs for 50 users."""
import json
import random
import numpy as np
from datetime import datetime, timezone, timedelta
from pathlib import Path

USERS = [f'user-{i:03d}' for i in range(1, 51)]
SERVICES = ['s3', 'ec2', 'iam', 'rds', 'lambda', 'cloudtrail', 'kms', 'sts']
REGIONS = ['us-east-1', 'us-west-2', 'eu-west-1']
ACTIONS_BY_SERVICE = {
    's3': ['GetObject', 'PutObject', 'ListBuckets', 'DeleteObject', 'CreateBucket'],
    'ec2': ['DescribeInstances', 'RunInstances', 'StopInstances', 'DescribeSecurityGroups'],
    'iam': ['GetUser', 'ListUsers', 'GetPolicy', 'CreateAccessKey'],
    'rds': ['DescribeDBInstances', 'CreateDBSnapshot'],
    'lambda': ['ListFunctions', 'InvokeFunction', 'GetFunction'],
    'cloudtrail': ['DescribeTrails', 'LookupEvents'],
    'kms': ['Decrypt', 'Encrypt', 'DescribeKey'],
    'sts': ['GetCallerIdentity', 'AssumeRole'],
}

# Define "normal" profile for each user
USER_PROFILES = {}
for user in USERS:
    USER_PROFILES[user] = {
        'usual_services': random.sample(SERVICES, k=random.randint(2, 4)),
        'work_start': random.randint(7, 10),
        'work_end': random.randint(17, 20),
        'daily_api_mean': random.randint(20, 200),
        'daily_api_std': random.randint(5, 30),
        'usual_region': random.choice(REGIONS),
        'usual_ips': [f'10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'
                       for _ in range(random.randint(1, 3))],
    }

def generate_events(user: str, date: datetime, is_anomalous: bool = False) -> list[dict]:
    profile = USER_PROFILES[user]
    events = []

    if is_anomalous:
        # Anomalous: high volume, unusual hours, new service
        count = profile['daily_api_mean'] * random.randint(5, 15)
        hours = list(range(0, 6))  # Middle of night
        services = SERVICES  # Access all services
    else:
        count = max(1, int(np.random.normal(profile['daily_api_mean'],
                                             profile['daily_api_std'])))
        hours = list(range(profile['work_start'], profile['work_end']))
        services = profile['usual_services']

    for _ in range(count):
        hour = random.choice(hours)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        ts = date.replace(hour=hour, minute=minute, second=second)
        service = random.choice(services)
        action = random.choice(ACTIONS_BY_SERVICE.get(service, ['DescribeX']))
        ip = (f'{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'
              if is_anomalous and random.random() < 0.3 else random.choice(profile['usual_ips']))
        events.append({
            'eventTime': ts.isoformat(),
            'eventSource': f'{service}.amazonaws.com',
            'eventName': action,
            'userIdentity': {
                'type': 'IAMUser',
                'userName': user,
                'arn': f'arn:aws:iam::123456789012:user/{user}'
            },
            'sourceIPAddress': ip,
            'awsRegion': (random.choice(REGIONS) if is_anomalous and random.random() < 0.2
                          else profile['usual_region']),
        })
    return events


def generate_dataset(output_dir: str = 'data/synthetic_logs'):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    all_events = []
    now = datetime.now(timezone.utc)

    # Mark 3 users as "anomalous" in the last 3 days
    anomalous_users = random.sample(USERS, k=3)

    for day_offset in range(30, 0, -1):
        date = now - timedelta(days=day_offset)
        date = date.replace(tzinfo=timezone.utc)
        is_recent = day_offset <= 3

        for user in USERS:
            is_anom = (user in anomalous_users and is_recent)
            events = generate_events(user, date, is_anomalous=is_anom)
            all_events.extend(events)

    outfile = out / 'cloudtrail_synthetic.json'
    outfile.write_text(json.dumps(all_events, indent=2, default=str))
    print(f'Generated {len(all_events)} events → {outfile}')
    print(f'Anomalous users (last 3 days): {anomalous_users}')
    return anomalous_users

if __name__ == '__main__':
    generate_dataset()
```

### Lab 2: UEBA Engine

```python
# src/ueba_engine.py
import json
import numpy as np
import pandas as pd
from pathlib import Path
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from collections import defaultdict

SIGMA_THRESHOLD = 3.0
BASELINE_DAYS = 21     # Train on first 21 days
DETECTION_DAYS = 7     # Detect anomalies in last 7 days


@dataclass
class Anomaly:
    user: str
    detection_date: str
    anomaly_type: str
    severity: str       # HIGH | MEDIUM | LOW
    details: str
    z_score: float = 0.0
    risk_delta: int = 0


@dataclass
class UserProfile:
    username: str
    daily_api_counts: list[float] = field(default_factory=list)
    usual_hours: set = field(default_factory=set)
    seen_ips: set = field(default_factory=set)
    seen_regions: set = field(default_factory=set)
    seen_services: set = field(default_factory=set)
    baseline_s3_downloads: list[float] = field(default_factory=list)


class UEBAEngine:

    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.profiles: dict[str, UserProfile] = {}
        self.anomalies: list[Anomaly] = []
        self.risk_scores: dict[str, int] = {}

    def load_and_parse(self):
        events = json.loads(self.log_path.read_text())
        df = pd.DataFrame(events)
        df['eventTime'] = pd.to_datetime(df['eventTime'])
        df['userName'] = df['userIdentity'].apply(lambda x: x.get('userName', ''))
        df['hour'] = df['eventTime'].dt.hour
        df['date'] = df['eventTime'].dt.date
        return df

    def build_baselines(self, df: pd.DataFrame):
        cutoff = df['eventTime'].max() - timedelta(days=DETECTION_DAYS)
        baseline_df = df[df['eventTime'] <= cutoff]

        for user, group in baseline_df.groupby('userName'):
            profile = UserProfile(username=user)
            # Daily API counts
            daily = group.groupby('date').size()
            profile.daily_api_counts = daily.tolist()
            # Usual working hours (hours that appear in >10% of sessions)
            hour_counts = group['hour'].value_counts(normalize=True)
            profile.usual_hours = set(hour_counts[hour_counts > 0.1].index)
            # Seen IPs and regions
            profile.seen_ips = set(group['sourceIPAddress'].unique())
            profile.seen_regions = set(group['awsRegion'].unique())
            # Seen services
            profile.seen_services = set(group['eventSource'].str.split('.').str[0].unique())
            # S3 download counts
            s3_daily = group[group['eventName'] == 'GetObject'].groupby('date').size()
            profile.baseline_s3_downloads = s3_daily.tolist()
            self.profiles[user] = profile

    def detect_anomalies(self, df: pd.DataFrame):
        cutoff = df['eventTime'].max() - timedelta(days=DETECTION_DAYS)
        detection_df = df[df['eventTime'] > cutoff]

        for user, group in detection_df.groupby('userName'):
            profile = self.profiles.get(user)
            if not profile:
                continue

            for date, day_events in group.groupby('date'):
                date_str = str(date)

                # 1. API volume spike
                today_count = len(day_events)
                is_anom, z = self._is_sigma_anomaly(
                    today_count, profile.daily_api_counts)
                if is_anom:
                    self.anomalies.append(Anomaly(
                        user=user, detection_date=date_str,
                        anomaly_type='API_VOLUME_SPIKE',
                        severity='HIGH',
                        details=f'API calls: {today_count} (z-score: {z:.2f}, '
                                f'baseline mean: {np.mean(profile.daily_api_counts):.0f})',
                        z_score=z, risk_delta=30
                    ))

                # 2. Off-hours access
                used_hours = set(day_events['hour'].unique())
                unusual_hours = used_hours - profile.usual_hours
                if unusual_hours and len(day_events) > 5:
                    self.anomalies.append(Anomaly(
                        user=user, detection_date=date_str,
                        anomaly_type='OFF_HOURS_ACCESS',
                        severity='MEDIUM',
                        details=f'Activity at unusual hours: {sorted(unusual_hours)}',
                        risk_delta=15
                    ))

                # 3. New IP address
                today_ips = set(day_events['sourceIPAddress'].unique())
                new_ips = today_ips - profile.seen_ips
                if new_ips:
                    self.anomalies.append(Anomaly(
                        user=user, detection_date=date_str,
                        anomaly_type='NEW_SOURCE_IP',
                        severity='MEDIUM',
                        details=f'New IP(s) not seen in baseline: {new_ips}',
                        risk_delta=20
                    ))

                # 4. New region
                today_regions = set(day_events['awsRegion'].unique())
                new_regions = today_regions - profile.seen_regions
                if new_regions:
                    self.anomalies.append(Anomaly(
                        user=user, detection_date=date_str,
                        anomaly_type='NEW_REGION',
                        severity='MEDIUM',
                        details=f'API calls from new region(s): {new_regions}',
                        risk_delta=25
                    ))

                # 5. New service accessed (lateral discovery)
                today_services = set(day_events['eventSource'].str.split('.').str[0].unique())
                new_services = today_services - profile.seen_services
                if len(new_services) >= 3:  # Accessing 3+ new services in one day
                    self.anomalies.append(Anomaly(
                        user=user, detection_date=date_str,
                        anomaly_type='BROAD_SERVICE_ACCESS',
                        severity='HIGH',
                        details=f'Accessed {len(new_services)} new services: {new_services}',
                        risk_delta=25
                    ))

    def calculate_risk_scores(self):
        for anomaly in self.anomalies:
            self.risk_scores[anomaly.user] = min(
                100,
                self.risk_scores.get(anomaly.user, 0) + anomaly.risk_delta
            )

    def _is_sigma_anomaly(self, value: float,
                          baseline: list[float]) -> tuple[bool, float]:
        if len(baseline) < 5:
            return False, 0.0
        mean = np.mean(baseline)
        std = np.std(baseline)
        if std < 1:
            return value > mean * 3, 0.0
        z = (value - mean) / std
        return z > SIGMA_THRESHOLD, round(z, 2)

    def run(self) -> dict:
        print('[*] Loading logs...')
        df = self.load_and_parse()
        print(f'    {len(df)} events, {df["userName"].nunique()} users')

        print('[*] Building baselines...')
        self.build_baselines(df)

        print('[*] Detecting anomalies...')
        self.detect_anomalies(df)

        self.calculate_risk_scores()

        # Sort by risk score
        top_risky = sorted(self.risk_scores.items(),
                           key=lambda x: x[1], reverse=True)[:10]

        print(f'\n[+] Results: {len(self.anomalies)} anomalies across '
              f'{len(set(a.user for a in self.anomalies))} users')
        print('\nTop risky users:')
        for user, score in top_risky:
            print(f'    {user}: {score}/100')

        return {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'total_anomalies': len(self.anomalies),
            'anomalies_by_type': {
                atype: len([a for a in self.anomalies if a.anomaly_type == atype])
                for atype in set(a.anomaly_type for a in self.anomalies)
            },
            'risk_scores': dict(top_risky),
            'anomalies': [asdict(a) for a in self.anomalies]
        }
```

---

## Detection Queries

### Splunk SPL — UEBA Insider Threat

```
| tstats count as api_calls
    values(Authentication.src_ip) as src_ips
    dc(Authentication.src_ip) as unique_ips
  from datamodel=Authentication
  where Authentication.action=success
  by Authentication.user _time span=1d
| stats
    avg(api_calls) as avg_calls
    stdev(api_calls) as std_calls
    latest(api_calls) as today_calls
  by Authentication.user
| eval z_score = (today_calls - avg_calls) / if(std_calls > 0, std_calls, 1)
| where z_score > 3
| table Authentication.user, today_calls, avg_calls, z_score
| sort -z_score
```

### KQL — Azure Sentinel UEBA Queries

```kql
// Users with abnormal sign-in volume
let baseline = SigninLogs
| where TimeGenerated between (ago(30d) .. ago(7d))
| summarize
    avg_logins = avg(count()),
    stdev_logins = stdev(count())
  by UserPrincipalName, bin(TimeGenerated, 1d);

let recent = SigninLogs
| where TimeGenerated > ago(7d)
| summarize recent_logins = count()
  by UserPrincipalName, bin(TimeGenerated, 1d);

recent
| join kind=inner baseline on UserPrincipalName
| extend z_score = (recent_logins - avg_logins) / max_of(stdev_logins, 1.0)
| where z_score > 3
| project UserPrincipalName, recent_logins, avg_logins, z_score
| order by z_score desc
```

```kql
// Data hoarding: mass S3/SharePoint downloads before resignation
let at_risk_users = HR_TerminationData  // Custom watchlist
| where TerminationDate between (now() .. now() + 30d)
| project UserPrincipalName;

CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType == "FileDownloaded"
| where AccountObjectId in (at_risk_users)
| summarize DownloadCount = count(), FileSizeGB = sum(FileSize) / 1e9
  by AccountDisplayName, bin(TimeGenerated, 1d)
| where DownloadCount > 100 or FileSizeGB > 5
| order by DownloadCount desc
```

---

## Interview Skills Gained

**Q: What is UEBA and how does it differ from rule-based detection?**
> UEBA (User and Entity Behaviour Analytics) builds statistical baselines of normal behaviour for each user and entity, then alerts on deviations. Rule-based detection fires when a specific known-bad event occurs (e.g., login from a specific country). UEBA catches unknown threats that have no pre-defined rule — like a user suddenly downloading 100x their normal data volume. The tradeoff: UEBA produces more false positives and requires tuning.

**Q: How do you determine the right sigma threshold for anomaly detection?**
> Start with 3σ which theoretically catches the top 0.27% of observations. Run it against 30 days of historical data and count the false positives. If it generates too many alerts (alert fatigue), raise to 3.5σ or 4σ. If you're missing real incidents, lower to 2.5σ. Track the false positive rate and tune monthly. Also consider using different thresholds for different anomaly types — volume spikes can tolerate higher sensitivity than new region access.

**Q: What are the legal considerations for UEBA and insider threat programs?**
> Employees must be informed that their work systems are monitored (usually via acceptable use policies). UEBA must comply with employment law — in some jurisdictions, continuous monitoring requires employee consent or union agreement. Data minimization is important — only collect what's needed for security, not surveillance. All UEBA investigations must be conducted in collaboration with HR and Legal. The goal is security, not monitoring for performance management.

---

## Submission Checklist

- [ ] Synthetic log generator creates realistic 30-day dataset for 50 users
- [ ] Baseline engine computes per-user profiles for all 5 features
- [ ] Anomaly detector flags all 5 anomaly types
- [ ] Risk scoring engine produces a score 0-100 for each user
- [ ] Output JSON report with top 10 risky users and their anomaly details
- [ ] Splunk SPL and KQL queries in `queries/` folder
- [ ] README explains the statistical methodology and tuning approach
- [ ] Ethical considerations section in README

---

## Links

→ Full project: [projects/14-insider-threat-detection/](../../projects/14-insider-threat-detection/)
→ Next: [Week 17 — Zero Trust Architecture](../week-17/README.md)
