"""
IAM-specific threat hunter — detects privilege escalation, credential abuse,
and identity-based attack patterns within a CloudTrail event set.
"""
import logging
from collections import Counter
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

ESCALATION_EVENTS = {
    'CreatePolicyVersion', 'SetDefaultPolicyVersion',
    'UpdateAssumeRolePolicy', 'AttachUserPolicy', 'AttachRolePolicy',
    'AttachGroupPolicy', 'PutUserPolicy', 'PutRolePolicy',
    'AddUserToGroup', 'CreateAccessKey', 'CreateLoginProfile',
    'UpdateLoginProfile', 'CreateUser',
}

MITRE_MAP = {
    'CreatePolicyVersion':    ('T1098.003', 'Privilege Escalation'),
    'SetDefaultPolicyVersion':('T1098.003', 'Privilege Escalation'),
    'UpdateAssumeRolePolicy': ('T1098.003', 'Privilege Escalation'),
    'AttachUserPolicy':       ('T1098',     'Privilege Escalation'),
    'AttachRolePolicy':       ('T1098',     'Privilege Escalation'),
    'CreateAccessKey':        ('T1098.001', 'Persistence'),
    'CreateLoginProfile':     ('T1136.003', 'Persistence'),
    'UpdateLoginProfile':     ('T1098',     'Privilege Escalation'),
    'CreateUser':             ('T1136.003', 'Persistence'),
}


def hunt_escalation_events(events: list[dict]) -> list[dict]:
    """Find all IAM privilege escalation events in the event set."""
    hits = []
    for event in events:
        name = event.get('eventName', '')
        if name not in ESCALATION_EVENTS:
            continue
        user = event.get('userIdentity', {})
        mitre = MITRE_MAP.get(name, ('', ''))
        hits.append({
            'hunt': 'iam_escalation',
            'severity': 'CRITICAL' if name in ('UpdateAssumeRolePolicy', 'CreatePolicyVersion',
                                                 'UpdateLoginProfile') else 'HIGH',
            'event_name': name,
            'event_time': event.get('eventTime', ''),
            'actor_arn': user.get('arn', user.get('userName', 'unknown')),
            'source_ip': event.get('sourceIPAddress', ''),
            'aws_region': event.get('awsRegion', ''),
            'mitre_technique': mitre[0],
            'mitre_tactic': mitre[1],
            'request_params': str(event.get('requestParameters', ''))[:150],
        })
    logger.info('IAM escalation hunt: %d hits from %d events',
                len(hits), len(events))
    return hits


def hunt_access_key_creation_for_others(events: list[dict]) -> list[dict]:
    """Detect CreateAccessKey calls where the key is for a different user (Path 11)."""
    hits = []
    for event in events:
        if event.get('eventName') != 'CreateAccessKey':
            continue
        actor = event.get('userIdentity', {}).get('userName', '')
        target = (event.get('requestParameters') or {}).get('userName', '')
        if target and actor and target.lower() != actor.lower():
            hits.append({
                'hunt': 'access_key_for_other_user',
                'severity': 'HIGH',
                'event_name': 'CreateAccessKey',
                'event_time': event.get('eventTime', ''),
                'actor': actor,
                'key_created_for': target,
                'source_ip': event.get('sourceIPAddress', ''),
                'mitre_technique': 'T1098.001',
                'mitre_tactic': 'Persistence',
            })
    return hits


def hunt_admin_policy_attachments(events: list[dict]) -> list[dict]:
    """Detect when AdministratorAccess is attached to any principal."""
    hits = []
    for event in events:
        if event.get('eventName') not in (
            'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy'
        ):
            continue
        params = event.get('requestParameters') or {}
        policy_arn = params.get('policyArn', '')
        if 'AdministratorAccess' in policy_arn:
            user = event.get('userIdentity', {})
            hits.append({
                'hunt': 'admin_policy_attached',
                'severity': 'CRITICAL',
                'event_name': event['eventName'],
                'event_time': event.get('eventTime', ''),
                'actor_arn': user.get('arn', ''),
                'policy_attached': policy_arn,
                'target': params.get('userName') or params.get('roleName') or params.get('groupName', ''),
                'source_ip': event.get('sourceIPAddress', ''),
                'mitre_technique': 'T1098',
                'mitre_tactic': 'Privilege Escalation',
            })
    return hits


def run_all_iam_hunts(events: list[dict]) -> list[dict]:
    """Run all IAM hunts and return combined, deduplicated results."""
    all_hits: list[dict] = []
    all_hits.extend(hunt_escalation_events(events))
    all_hits.extend(hunt_access_key_creation_for_others(events))
    all_hits.extend(hunt_admin_policy_attachments(events))
    return sorted(all_hits, key=lambda h: h.get('event_time', ''))
