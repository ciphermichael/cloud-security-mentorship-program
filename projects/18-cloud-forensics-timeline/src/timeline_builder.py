"""
Forensic Timeline Builder — correlates CloudTrail events by entity,
builds chronological attack timelines, and maps to MITRE ATT&CK.
"""
import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

# MITRE ATT&CK mapping for common CloudTrail events
MITRE_MAP: dict[str, tuple[str, str, str]] = {
    # (technique_id, technique_name, tactic)
    'GetCallerIdentity':    ('T1033',     'System Owner Discovery',      'Discovery'),
    'ListUsers':            ('T1087.004', 'Cloud Account Enumeration',   'Discovery'),
    'ListRoles':            ('T1087.004', 'Cloud Account Enumeration',   'Discovery'),
    'ListBuckets':          ('T1619',     'Cloud Storage Discovery',     'Discovery'),
    'DescribeInstances':    ('T1526',     'Cloud Service Discovery',     'Discovery'),
    'DescribeSecurityGroups':('T1526',    'Cloud Service Discovery',     'Discovery'),
    'GetObject':            ('T1530',     'Data from Cloud Storage',     'Collection'),
    'PutObject':            ('T1537',     'Transfer to Cloud Account',   'Exfiltration'),
    'CreateUser':           ('T1136.003', 'Cloud Account Create',        'Persistence'),
    'CreateAccessKey':      ('T1098.001', 'Additional Cloud Credentials','Persistence'),
    'CreateLoginProfile':   ('T1098',     'Account Manipulation',        'Persistence'),
    'UpdateLoginProfile':   ('T1098',     'Account Manipulation',        'Privilege Escalation'),
    'AttachUserPolicy':     ('T1098',     'Account Manipulation',        'Privilege Escalation'),
    'AttachRolePolicy':     ('T1098',     'Account Manipulation',        'Privilege Escalation'),
    'PutUserPolicy':        ('T1098',     'Account Manipulation',        'Privilege Escalation'),
    'PutRolePolicy':        ('T1098',     'Account Manipulation',        'Privilege Escalation'),
    'CreatePolicyVersion':  ('T1098.003', 'Additional Cloud Roles',      'Privilege Escalation'),
    'UpdateAssumeRolePolicy':('T1098.003','Additional Cloud Roles',      'Privilege Escalation'),
    'AssumeRole':           ('T1548.005', 'Abuse Elevation Control',     'Privilege Escalation'),
    'DeleteTrail':          ('T1562.008', 'Disable Cloud Logs',          'Defense Evasion'),
    'StopLogging':          ('T1562.008', 'Disable Cloud Logs',          'Defense Evasion'),
    'UpdateTrail':          ('T1562.008', 'Disable Cloud Logs',          'Defense Evasion'),
    'ConsoleLogin':         ('T1078',     'Valid Accounts',              'Initial Access'),
    'RunInstances':         ('T1578.002', 'Create Cloud Instance',       'Defense Evasion'),
    'TerminateInstances':   ('T1485',     'Data Destruction',            'Impact'),
    'DeleteBucket':         ('T1485',     'Data Destruction',            'Impact'),
}


def load_cloudtrail_events(evidence_dir: str) -> list[dict]:
    """Load all CloudTrail events from evidence directory."""
    events = []
    for path in sorted(Path(evidence_dir).rglob('*.json*')):
        if 'chain-of-custody' in path.name:
            continue
        try:
            content = path.read_bytes()
            if path.suffix == '.gz':
                content = gzip.decompress(content)
            data = json.loads(content)
            records = data.get('Records', data if isinstance(data, list) else [])
            events.extend(records)
        except Exception as e:
            print(f'  [WARN] Could not parse {path.name}: {e}')
    return events


def build_timeline(events: list[dict],
                   entity_filter: dict | None = None) -> pd.DataFrame:
    """
    Build a sorted, MITRE-annotated timeline DataFrame.

    Args:
        events: Raw CloudTrail event records
        entity_filter: Optional filter e.g. {'ip': '1.2.3.4'} or {'user': 'alice'}
    """
    rows = []
    for event in events:
        user = event.get('userIdentity', {})
        actor = user.get('arn', user.get('userName', 'unknown'))
        source_ip = event.get('sourceIPAddress', '')
        event_name = event.get('eventName', '')
        event_time = event.get('eventTime', '')

        if entity_filter:
            if 'ip' in entity_filter and source_ip != entity_filter['ip']:
                continue
            if 'user' in entity_filter and entity_filter['user'] not in actor:
                continue
            if 'event' in entity_filter and event_name != entity_filter['event']:
                continue

        mitre = MITRE_MAP.get(event_name, ('', '', ''))
        rows.append({
            'event_time': event_time,
            'event_name': event_name,
            'event_source': event.get('eventSource', '').replace('.amazonaws.com', ''),
            'actor_arn': actor,
            'actor_type': user.get('type', ''),
            'source_ip': source_ip,
            'region': event.get('awsRegion', ''),
            'error_code': event.get('errorCode', ''),
            'error_message': event.get('errorMessage', ''),
            'request_params': str(event.get('requestParameters', ''))[:120],
            'mitre_id': mitre[0],
            'mitre_name': mitre[1],
            'mitre_tactic': mitre[2],
            'user_agent': event.get('userAgent', ''),
        })

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    df['event_time'] = pd.to_datetime(df['event_time'], utc=True, errors='coerce')
    df = df.sort_values('event_time').reset_index(drop=True)
    return df


def get_mitre_tactic(event_name: str) -> str:
    """Return the MITRE tactic for a CloudTrail event name."""
    return MITRE_MAP.get(event_name, ('', '', ''))[2]


def detect_kill_chain_stages(events: list[dict]) -> list[str]:
    """Return the ordered list of unique MITRE tactics present in the event list."""
    tactic_order = [
        'Initial Access', 'Execution', 'Persistence',
        'Privilege Escalation', 'Defense Evasion', 'Credential Access',
        'Discovery', 'Lateral Movement', 'Collection',
        'Command and Control', 'Exfiltration', 'Impact',
    ]
    seen = set()
    for event in events:
        tactic = get_mitre_tactic(event.get('eventName', ''))
        if tactic:
            seen.add(tactic)
    return [t for t in tactic_order if t in seen]


def build_actor_timeline(events: list[dict], actor_arn: str) -> list[dict]:
    """Return events for a specific actor, sorted chronologically."""
    actor_events = [
        e for e in events
        if actor_arn in e.get('userIdentity', {}).get('arn', '')
    ]
    return sorted(actor_events, key=lambda x: x.get('eventTime', ''))


def generate_narrative(df: pd.DataFrame, incident_id: str) -> str:
    """Generate a human-readable attack narrative markdown document."""
    if df.empty:
        return '# Incident Timeline\n\nNo events found for the specified filter.\n'

    start = df['event_time'].min()
    end = df['event_time'].max()
    duration = end - start
    tactics = [t for t in df['mitre_tactic'].unique() if t]
    techniques = df[df['mitre_id'] != ''][['mitre_id', 'mitre_name']].drop_duplicates()

    lines = [
        f'# Incident Timeline — {incident_id}',
        '',
        '## Attack Summary',
        '',
        f'| Field | Value |',
        f'|-------|-------|',
        f'| Start | {start.strftime("%Y-%m-%d %H:%M:%S UTC")} |',
        f'| End | {end.strftime("%Y-%m-%d %H:%M:%S UTC")} |',
        f'| Duration | {duration} |',
        f'| Total Events | {len(df)} |',
        f'| Unique Actors | {df["actor_arn"].nunique()} |',
        f'| Source IPs | {", ".join(df["source_ip"].unique()[:5])} |',
        '',
        '## MITRE ATT&CK Tactics (chronological order)',
        '',
    ]
    for t in tactics:
        lines.append(f'- {t}')

    lines += [
        '',
        '## Techniques Observed',
        '',
        '| Technique ID | Name | Occurrences |',
        '|-------------|------|-------------|',
    ]
    for _, row in techniques.iterrows():
        count = len(df[df['mitre_id'] == row['mitre_id']])
        lines.append(f'| {row["mitre_id"]} | {row["mitre_name"]} | {count} |')

    lines += [
        '',
        '## Chronological Event Log',
        '',
        '| Time (UTC) | Event | Actor | Source IP | MITRE Tactic |',
        '|------------|-------|-------|-----------|--------------|',
    ]
    for _, row in df.iterrows():
        time_str = row['event_time'].strftime('%H:%M:%S') if pd.notna(row['event_time']) else '?'
        actor_short = str(row['actor_arn'])[-45:]
        lines.append(
            f'| {time_str} | {row["event_name"]} | {actor_short} '
            f'| {row["source_ip"]} | {row["mitre_tactic"]} |'
        )

    return '\n'.join(lines) + '\n'
