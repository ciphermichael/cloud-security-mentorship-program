"""
Generate a realistic simulated CloudTrail incident dataset for forensic practice.

Scenario — "Operation CloudSnatch":
  An attacker compromises an EC2 instance via a web shell, reads the IMDS
  to steal the instance's IAM role credentials, then uses those credentials
  externally to enumerate, escalate, and exfiltrate data.

Usage:
    python scripts/generate_incident.py --incident-id IR-2024-001
    python scripts/generate_incident.py --scenario imds_theft
"""
import argparse
import json
import random
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

ATTACKER_IP = '198.51.100.42'          # External attacker IP (RFC5737 documentation range)
VICTIM_ACCOUNT = '123456789012'
VICTIM_ROLE = 'ec2-app-role'
VICTIM_ROLE_ARN = f'arn:aws:iam::{VICTIM_ACCOUNT}:role/{VICTIM_ROLE}'
ASSUMED_ROLE_ARN = f'arn:aws:sts::{VICTIM_ACCOUNT}:assumed-role/{VICTIM_ROLE}/i-1234567890abcdef0'
INTERNAL_IP = '10.0.1.100'


def make_event(event_name: str, ts: datetime, actor_arn: str,
               source_ip: str, actor_type: str = 'AssumedRole',
               event_source: str = 'iam.amazonaws.com',
               params: dict | None = None,
               error: str | None = None) -> dict:
    """Build a realistic CloudTrail event record."""
    event: dict = {
        'eventVersion': '1.08',
        'userIdentity': {
            'type': actor_type,
            'principalId': f'AROA{uuid.uuid4().hex[:16].upper()}',
            'arn': actor_arn,
            'accountId': VICTIM_ACCOUNT,
            'sessionContext': {
                'sessionIssuer': {
                    'type': 'Role',
                    'arn': VICTIM_ROLE_ARN,
                    'accountId': VICTIM_ACCOUNT,
                    'userName': VICTIM_ROLE,
                },
                'attributes': {
                    'mfaAuthenticated': 'false',
                    'creationDate': ts.isoformat(),
                }
            } if actor_type == 'AssumedRole' else {},
        },
        'eventTime': ts.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'eventSource': event_source,
        'eventName': event_name,
        'awsRegion': 'us-east-1',
        'sourceIPAddress': source_ip,
        'userAgent': 'aws-cli/2.9.0 Python/3.11.0 Linux/5.15.0',
        'requestID': str(uuid.uuid4()),
        'eventID': str(uuid.uuid4()),
        'readOnly': event_name.startswith(('Get', 'Describe', 'List')),
        'requestParameters': params or {},
        'responseElements': None,
    }
    if error:
        event['errorCode'] = error
        event['errorMessage'] = f'User is not authorized to perform {event_name}'
    return event


def generate_imds_theft_scenario(base_time: datetime) -> list[dict]:
    """
    Full attack kill chain: IMDS credential theft → enumeration → escalation → exfil.
    Returns events in chronological order.
    """
    events = []
    t = base_time

    # Phase 1: Initial recon (from internal IP — via compromised EC2)
    events.append(make_event(
        'GetCallerIdentity', t, ASSUMED_ROLE_ARN, INTERNAL_IP,
        event_source='sts.amazonaws.com',
    ))
    t += timedelta(seconds=30)

    # Phase 2: Enumeration from external IP — attacker has stolen IMDS creds
    for event_name in ['ListUsers', 'ListRoles', 'ListPolicies', 'ListBuckets',
                        'DescribeInstances', 'DescribeSecurityGroups',
                        'ListFunctions20150331', 'GetAccountSummary']:
        events.append(make_event(
            event_name, t, ASSUMED_ROLE_ARN, ATTACKER_IP,
            event_source=('iam.amazonaws.com' if 'User' in event_name or 'Role' in event_name
                           or 'Policy' in event_name or 'Account' in event_name
                           else 's3.amazonaws.com' if 'Bucket' in event_name
                           else 'ec2.amazonaws.com' if 'Instance' in event_name or 'Security' in event_name
                           else 'lambda.amazonaws.com'),
        ))
        t += timedelta(seconds=random.randint(10, 45))

    # Phase 3: Privilege escalation attempt
    events.append(make_event(
        'AttachRolePolicy', t, ASSUMED_ROLE_ARN, ATTACKER_IP,
        params={
            'roleName': VICTIM_ROLE,
            'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'
        }
    ))
    t += timedelta(seconds=15)

    # Blocked by SCP — access denied
    events.append(make_event(
        'CreateUser', t, ASSUMED_ROLE_ARN, ATTACKER_IP,
        params={'userName': 'backup-admin'},
        error='AccessDenied'
    ))
    t += timedelta(seconds=20)

    # Phase 4: Data exfiltration — S3 mass download
    for i in range(25):
        events.append(make_event(
            'GetObject', t, ASSUMED_ROLE_ARN, ATTACKER_IP,
            event_source='s3.amazonaws.com',
            params={
                'bucketName': 'company-financial-reports',
                'key': f'2024/Q{random.randint(1,4)}/report-{i:04d}.pdf',
            }
        ))
        t += timedelta(seconds=random.randint(2, 8))

    # Phase 5: Persistence attempt
    events.append(make_event(
        'CreateAccessKey', t, ASSUMED_ROLE_ARN, ATTACKER_IP,
        params={'userName': 'service-account-backup'}
    ))
    t += timedelta(seconds=10)

    # Phase 6: Cover tracks — attempt to delete CloudTrail (blocked)
    events.append(make_event(
        'StopLogging', t, ASSUMED_ROLE_ARN, ATTACKER_IP,
        event_source='cloudtrail.amazonaws.com',
        params={'name': 'security-trail'},
        error='AccessDenied'
    ))

    return events


def main():
    parser = argparse.ArgumentParser(description='Generate simulated CloudTrail incident')
    parser.add_argument('--incident-id', default='IR-2024-001')
    parser.add_argument('--scenario', default='imds_theft',
                        choices=['imds_theft'],
                        help='Attack scenario to generate')
    parser.add_argument('--output-dir', default='data/simulated_incidents')
    parser.add_argument('--start-time',
                        default='2024-01-15T03:00:00Z',
                        help='Incident start time (ISO 8601 UTC)')
    args = parser.parse_args()

    base_time = datetime.fromisoformat(
        args.start_time.replace('Z', '+00:00')
    )

    print(f'[*] Generating scenario: {args.scenario}')
    print(f'[*] Incident ID: {args.incident_id}')
    print(f'[*] Start time: {base_time.strftime("%Y-%m-%d %H:%M UTC")}')

    if args.scenario == 'imds_theft':
        events = generate_imds_theft_scenario(base_time)

    out_dir = Path(args.output_dir) / args.incident_id
    out_dir.mkdir(parents=True, exist_ok=True)

    output_file = out_dir / 'cloudtrail_events.json'
    output_file.write_text(json.dumps({'Records': events}, indent=2))

    print(f'[+] Generated {len(events)} events → {output_file}')
    print(f'\n    Attack timeline:')
    print(f'    {base_time.strftime("%H:%M:%S")} — Attacker reads IMDS, gets EC2 role creds')
    print(f'    +2 min — Enumeration begins from external IP {ATTACKER_IP}')
    print(f'    +5 min — Privilege escalation attempts')
    print(f'    +8 min — S3 data exfiltration (25 objects)')
    print(f'    +12 min — Persistence + cover tracks')
    print(f'\n    To analyse:')
    print(f'    python -m src.timeline_builder \\')
    print(f'      --evidence-dir {out_dir} \\')
    print(f'      --filter-ip {ATTACKER_IP} \\')
    print(f'      --output reports')


if __name__ == '__main__':
    main()
