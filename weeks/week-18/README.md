# Week 18 — Cloud Forensics & Digital Investigations

**Phase 5: Advanced Topics | Project: 18-cloud-forensics-timeline**

---

## Learning Objectives

By the end of this week you will be able to:

- Apply the NIST IR lifecycle (Preparation, Detection, Containment, Eradication, Recovery, Lessons Learned) to cloud incidents
- Collect and preserve forensic evidence from AWS logs without destroying it
- Build an automated incident timeline tool that correlates CloudTrail + VPC Flow Logs by entity
- Reconstruct an attack chain from log artifacts and map it to MITRE ATT&CK
- Write an executive-ready incident report
- Conduct a cloud forensic investigation using the Volatility-equivalent techniques (log analysis, IAM reconstruction, network timeline)

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | Cloud forensics fundamentals — evidence sources, chain of custody, NIST IR lifecycle | 2 hrs |
| Tue | Evidence collection — CloudTrail, VPC Flow Logs, S3 access logs, CloudWatch, Systems Manager | 2 hrs |
| Wed | Build timeline correlator — correlate events by entity (IP, user, resource) | 2 hrs |
| Thu | Attack chain reconstruction — map timeline to MITRE ATT&CK navigator | 2 hrs |
| Fri | Write incident report using the simulated incident dataset | 2 hrs |
| Sat | Automated forensic timeline tool, README, push to GitHub | 3 hrs |
| Sun | Mentor review — present incident findings as if to incident commander | 1 hr |

---

## Topics Covered

### Cloud Evidence Sources

| Source | Contains | Delay | Retention Default |
|--------|----------|-------|------------------|
| CloudTrail | API calls, who/what/when/where | ~15 min | 90 days (console), indefinite (S3) |
| VPC Flow Logs | Network connections (5-tuple: src IP, dst IP, src port, dst port, protocol) | ~10 min | CloudWatch retention |
| S3 Access Logs | Object-level access, GET/PUT/DELETE with requester | ~hours | Bucket access logging |
| CloudWatch Logs | Application and service logs | Real-time | Configurable |
| Route 53 Logs | DNS queries | Near real-time | S3 |
| ELB Access Logs | HTTP requests, TLS handshakes | ~5 min | S3 |
| Systems Manager Session Manager | Interactive session commands | Real-time | S3/CloudWatch |
| GuardDuty Findings | Anomaly detection results | Minutes | 90 days |

### Evidence Preservation Principles

**Chain of custody** — document every person who accessed evidence, when, and what they did. For cloud evidence, this means:
1. Export logs to an immutable S3 bucket (MFA delete, versioning, Object Lock) in a separate forensic account
2. Generate SHA-256 hashes of all exported log files
3. Record timestamps, account IDs, and CloudTrail validation hashes
4. Never analyze from the original source — work from copies

**Volatility order** (from most volatile to most persistent in cloud):
1. Running processes / memory (EC2 instance — must capture before termination)
2. Network connections (VPC Flow Logs — available for minutes after connection)
3. CloudTrail events (available within 15 minutes, S3 backed)
4. S3 objects (persist until deleted)
5. EBS snapshots (persist until deleted)

### Simulated Incident — "Operation CloudSnatch"

Use this scenario for your Week 18 forensic investigation:

**Scenario:** At 03:17 UTC on 2024-01-15, an alert fires in GuardDuty: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`. The alert indicates that EC2 instance credentials are being used from an external IP address.

**Timeline to reconstruct:**
- 03:00 — Attacker exploits a web shell on EC2 instance `i-0abc123def456789`
- 03:05 — Attacker reads IMDS at `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- 03:08 — Attacker uses the stolen EC2 role credentials from IP `198.51.100.42`
- 03:10 — Calls to `sts:GetCallerIdentity`, `iam:ListUsers`, `iam:ListRoles` (enumeration)
- 03:12 — `s3:ListBuckets`, `s3:GetObject` on `company-financial-reports` bucket
- 03:15 — Attempt to create a new IAM user (blocked by SCP)
- 03:17 — GuardDuty fires alert
- 03:20 — SOAR isolates instance
- 03:45 — Incident declared

---

## Instructor Mentoring Guidance

**Week 18 connects all previous skills into a realistic investigation.** Students who can narrate an attack timeline from logs and map it to MITRE are ready for SOC analyst and cloud security engineer roles.

**Key coaching points:**
- Emphasize that forensic investigation is methodical, not intuitive. The process: timeline first, hypothesis second, evidence third.
- The MITRE ATT&CK Navigator layer output is a powerful portfolio artifact — it shows exactly which techniques were observed
- Report writing is a skill unto itself. The executive summary must be understandable by a non-technical reader.

**Mentoring session agenda (60 min):**
1. (5 min) Student presents the incident timeline — 5 minutes to reconstruct what happened
2. (20 min) Deep dive: how did the attacker get the IMDS credentials? What could have prevented it?
3. (20 min) Report review — is the executive summary clear? Are the findings actionable?
4. (15 min) Mock interview: "Walk me through a cloud forensic investigation you've performed"

---

## Hands-on Lab

### Lab 1: Forensic Evidence Collector

```python
# src/evidence_collector.py
"""
Cloud forensic evidence collector with chain of custody tracking.
Collects CloudTrail and VPC Flow Logs for a given time window.
"""
import boto3
import hashlib
import json
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict


@dataclass
class EvidenceItem:
    source: str
    s3_key: str
    sha256: str
    size_bytes: int
    collected_at: str
    collector_identity: str


class ForensicEvidenceCollector:

    def __init__(self, region: str = 'us-east-1', output_dir: str = 'evidence'):
        self.region = region
        self.output = Path(output_dir)
        self.output.mkdir(exist_ok=True)
        self.s3 = boto3.client('s3', region_name=region)
        self.sts = boto3.client('sts', region_name=region)
        self.evidence_log: list[EvidenceItem] = []
        self.collector_identity = self._get_identity()

    def _get_identity(self) -> str:
        resp = self.sts.get_caller_identity()
        return f"{resp['UserId']}@{resp['Account']}"

    def _sha256_file(self, filepath: Path) -> str:
        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    def collect_cloudtrail_s3(self, bucket: str, prefix: str,
                               start: datetime, end: datetime):
        """Download CloudTrail logs from S3 for given time window."""
        print(f'[*] Collecting CloudTrail logs from s3://{bucket}/{prefix}')
        paginator = self.s3.get_paginator('list_objects_v2')
        collected = 0

        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get('Contents', []):
                key = obj['Key']
                # Filter by date embedded in key path (CloudTrail uses YYYY/MM/DD/)
                key_parts = key.split('/')
                try:
                    year, month, day = int(key_parts[-4]), int(key_parts[-3]), int(key_parts[-2])
                    file_date = datetime(year, month, day, tzinfo=timezone.utc)
                    if not (start.date() <= file_date.date() <= end.date()):
                        continue
                except (ValueError, IndexError):
                    continue

                local_path = self.output / 'cloudtrail' / key.replace('/', '_')
                local_path.parent.mkdir(parents=True, exist_ok=True)
                self.s3.download_file(bucket, key, str(local_path))

                sha = self._sha256_file(local_path)
                self.evidence_log.append(EvidenceItem(
                    source='CloudTrail',
                    s3_key=key,
                    sha256=sha,
                    size_bytes=obj['Size'],
                    collected_at=datetime.now(timezone.utc).isoformat(),
                    collector_identity=self.collector_identity
                ))
                collected += 1

        print(f'    Collected {collected} CloudTrail log files')

    def generate_coc(self):
        """Generate chain of custody document."""
        coc = {
            'incident_id': f"IR-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'collection_started': datetime.now(timezone.utc).isoformat(),
            'collector': self.collector_identity,
            'evidence_items': [asdict(e) for e in self.evidence_log],
            'total_items': len(self.evidence_log),
            'total_size_bytes': sum(e.size_bytes for e in self.evidence_log),
        }
        coc_file = self.output / 'chain-of-custody.json'
        coc_file.write_text(json.dumps(coc, indent=2))
        print(f'[+] Chain of custody saved → {coc_file}')
        return coc
```

### Lab 2: Incident Timeline Builder

```python
# src/timeline_builder.py
"""
Build a correlated incident timeline from CloudTrail events.
Groups events by entity (user/IP/resource) and sorts chronologically.
"""
import json
import gzip
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
import pandas as pd


MITRE_MAPPING = {
    'GetCallerIdentity': ('T1033', 'System Owner/User Discovery', 'Discovery'),
    'ListUsers': ('T1087.004', 'Cloud Account Enumeration', 'Discovery'),
    'ListRoles': ('T1087.004', 'Cloud Account Enumeration', 'Discovery'),
    'ListBuckets': ('T1619', 'Cloud Storage Object Discovery', 'Discovery'),
    'GetObject': ('T1530', 'Data from Cloud Storage Object', 'Collection'),
    'CreateUser': ('T1136.003', 'Cloud Account Create', 'Persistence'),
    'CreateAccessKey': ('T1098.001', 'Additional Cloud Credentials', 'Persistence'),
    'UpdateAssumeRolePolicy': ('T1098.003', 'Additional Cloud Roles', 'Persistence'),
    'PutUserPolicy': ('T1098', 'Account Manipulation', 'Privilege Escalation'),
    'StopLogging': ('T1562.008', 'Disable Cloud Logs', 'Defense Evasion'),
    'DeleteTrail': ('T1562.008', 'Disable Cloud Logs', 'Defense Evasion'),
    'ConsoleLogin': ('T1078', 'Valid Accounts', 'Initial Access'),
    'AssumeRole': ('T1548.005', 'Abuse Elevation Control Mechanism', 'Privilege Escalation'),
}


def load_cloudtrail_events(evidence_dir: str) -> list[dict]:
    events = []
    for path in Path(evidence_dir).rglob('*.json*'):
        try:
            if path.suffix == '.gz':
                with gzip.open(path, 'rt') as f:
                    data = json.load(f)
            else:
                data = json.loads(path.read_text())
            records = data.get('Records', data if isinstance(data, list) else [])
            events.extend(records)
        except Exception as e:
            print(f'  [WARN] Could not parse {path}: {e}')
    return events


def build_timeline(events: list[dict], entity_filter: dict = None) -> pd.DataFrame:
    """
    Build a sorted timeline DataFrame.
    entity_filter: {'ip': '198.51.100.42'} or {'user': 'arn:...'} to focus investigation
    """
    rows = []
    for event in events:
        user = event.get('userIdentity', {})
        actor = user.get('arn', user.get('userName', 'unknown'))
        source_ip = event.get('sourceIPAddress', '')
        event_name = event.get('eventName', '')
        event_time = event.get('eventTime', '')

        # Apply entity filter
        if entity_filter:
            if 'ip' in entity_filter and source_ip != entity_filter['ip']:
                continue
            if 'user' in entity_filter and entity_filter['user'] not in actor:
                continue

        mitre = MITRE_MAPPING.get(event_name, ('', '', ''))
        rows.append({
            'event_time': event_time,
            'event_name': event_name,
            'event_source': event.get('eventSource', ''),
            'actor': actor,
            'source_ip': source_ip,
            'region': event.get('awsRegion', ''),
            'error_code': event.get('errorCode', ''),
            'request_params': str(event.get('requestParameters', ''))[:100],
            'mitre_id': mitre[0],
            'mitre_name': mitre[1],
            'mitre_tactic': mitre[2],
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        df['event_time'] = pd.to_datetime(df['event_time'])
        df = df.sort_values('event_time').reset_index(drop=True)
    return df


def generate_attack_narrative(df: pd.DataFrame, incident_id: str) -> str:
    """Generate human-readable attack narrative from timeline."""
    if df.empty:
        return "No events found for the specified entity."

    tactics_seen = df[df['mitre_tactic'] != '']['mitre_tactic'].unique().tolist()
    techniques_seen = df[df['mitre_id'] != ''][['mitre_id', 'mitre_name']].drop_duplicates()

    start = df['event_time'].min()
    end = df['event_time'].max()
    duration = end - start

    narrative = f"""# Incident Timeline — {incident_id}

## Attack Summary
- **Duration:** {start.strftime('%Y-%m-%d %H:%M UTC')} → {end.strftime('%H:%M UTC')} ({duration})
- **Total Events:** {len(df)}
- **Unique Actors:** {df['actor'].nunique()}
- **Source IPs:** {', '.join(df['source_ip'].unique()[:5])}

## MITRE ATT&CK Tactics Observed (in sequence)
{chr(10).join(f'- {t}' for t in tactics_seen)}

## Techniques Identified
| MITRE ID | Technique | Count |
|----------|-----------|-------|
"""
    for _, row in techniques_seen.iterrows():
        count = len(df[df['mitre_id'] == row['mitre_id']])
        narrative += f"| {row['mitre_id']} | {row['mitre_name']} | {count} |\n"

    narrative += "\n## Chronological Event Log\n\n"
    narrative += "| Time (UTC) | Event | Actor | Source IP | MITRE |\n"
    narrative += "|------------|-------|-------|-----------|-------|\n"

    for _, row in df.iterrows():
        narrative += (f"| {row['event_time'].strftime('%H:%M:%S')} "
                      f"| {row['event_name']} "
                      f"| {str(row['actor'])[-40:]} "
                      f"| {row['source_ip']} "
                      f"| {row['mitre_id']} |\n")

    return narrative


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence-dir', default='evidence')
    parser.add_argument('--filter-ip', default=None)
    parser.add_argument('--filter-user', default=None)
    parser.add_argument('--output', default='reports')
    args = parser.parse_args()

    events = load_cloudtrail_events(args.evidence_dir)
    print(f'[*] Loaded {len(events)} CloudTrail events')

    entity_filter = {}
    if args.filter_ip:
        entity_filter['ip'] = args.filter_ip
    if args.filter_user:
        entity_filter['user'] = args.filter_user

    df = build_timeline(events, entity_filter or None)
    print(f'[*] Timeline contains {len(df)} events')

    incident_id = f"IR-{datetime.now().strftime('%Y%m%d')}-001"
    narrative = generate_attack_narrative(df, incident_id)

    out = Path(args.output)
    out.mkdir(exist_ok=True)
    (out / 'timeline.csv').write_text(df.to_csv(index=False))
    (out / 'attack-narrative.md').write_text(narrative)

    print(f'[+] Timeline saved → {out}/timeline.csv')
    print(f'[+] Narrative saved → {out}/attack-narrative.md')
    print(narrative[:2000])
```

---

## Interview Skills Gained

**Q: Walk me through a cloud forensic investigation.**
> (1) Alert fires — GuardDuty or manual detection. (2) Preserve evidence immediately — don't terminate instances, take EBS snapshots, export logs to immutable forensic S3 bucket with chain of custody. (3) Identify the compromised entity — which user, role, or instance? (4) Build the timeline — CloudTrail events sorted chronologically for that entity. (5) Reconstruct the attack chain — what was accessed, what was exfiltrated, what was changed? (6) Determine root cause — how did the attacker gain initial access? (7) Scope — are there lateral movement indicators? Other systems compromised? (8) Eradicate and recover. (9) Document and report.

**Q: What is the difference between containment and eradication in incident response?**
> Containment stops the bleeding — isolate the compromised resource, revoke credentials, block the attacker's IP. Eradication removes the threat — delete the malware, patch the vulnerability, close the attack vector. You contain first (fast) and then eradicate (thorough). Eradicating before containing risks the attacker returning; containing indefinitely without eradication leaves the root cause in place.

**Q: Why should you never terminate a compromised EC2 instance immediately?**
> A terminated instance loses its ephemeral storage and running processes. Memory forensics (running processes, network connections, unencrypted data in RAM) is lost permanently. Take an EBS snapshot first, then isolate via security group, then collect memory artifacts via Systems Manager if possible. Only terminate after evidence is preserved.

---

## Submission Checklist

- [ ] Evidence collector running and producing chain of custody JSON
- [ ] Timeline builder processes the simulated incident dataset
- [ ] Attack narrative generated mapping all events to MITRE ATT&CK
- [ ] MITRE ATT&CK Navigator layer JSON committed (for attacker.mitre.org upload)
- [ ] Executive incident report written (non-technical summary + technical appendix)
- [ ] Timeline visualization (CSV opened in notebook or Streamlit chart)
- [ ] `docs/incident-report-template.md` for future use

---

## Links

→ Full project: [projects/18-cloud-forensics-timeline/](../../projects/18-cloud-forensics-timeline/)
→ Next: [Week 19 — Threat Intelligence & CTI](../week-19/README.md)
