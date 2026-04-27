"""Shared AWS helper utilities used across all projects."""
import time
import logging
from datetime import datetime, timezone
from typing import Optional, Iterator

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


# ── Session & Identity ─────────────────────────────────────────────────────────

def get_session(profile: Optional[str] = None, region: str = 'us-east-1') -> boto3.Session:
    """Create a boto3 session with an optional named profile."""
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def get_account_id(session: boto3.Session) -> str:
    """Return the AWS account ID for the current session."""
    return session.client('sts').get_caller_identity()['Account']


def get_current_identity(region: str = 'us-east-1') -> dict:
    """Return caller identity: Account, UserId, Arn."""
    sts = boto3.client('sts', region_name=region)
    return sts.get_caller_identity()


def get_all_regions(session: boto3.Session) -> list[str]:
    """Return all enabled AWS regions for the account."""
    ec2 = session.client('ec2', region_name='us-east-1')
    resp = ec2.describe_regions(
        Filters=[{
            'Name': 'opt-in-status',
            'Values': ['opt-in-not-required', 'opted-in']
        }]
    )
    return [r['RegionName'] for r in resp['Regions']]


# ── Pagination ─────────────────────────────────────────────────────────────────

def paginate(client, method: str, result_key: str, **kwargs) -> list:
    """
    Generic boto3 paginator.

    Example:
        users = paginate(iam_client, 'list_users', 'Users')
    """
    results = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs):
        results.extend(page.get(result_key, []))
    return results


def paginate_iter(client, method: str, result_key: str,
                  **kwargs) -> Iterator:
    """Yield items one by one — memory-efficient for large result sets."""
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs):
        yield from page.get(result_key, [])


# ── Finding Schema ─────────────────────────────────────────────────────────────

SEVERITY_SCORES = {'CRITICAL': 100, 'HIGH': 70, 'MEDIUM': 40, 'LOW': 10, 'INFO': 2}


def format_finding(severity: str, check_id: str, resource: str,
                   description: str, remediation: str,
                   mitre_technique: str = '',
                   mitre_tactic: str = '',
                   **extra) -> dict:
    """Standard finding schema used across all audit tools."""
    return {
        'severity': severity,
        'severity_score': SEVERITY_SCORES.get(severity, 0),
        'check_id': check_id,
        'resource': resource,
        'description': description,
        'remediation': remediation,
        'mitre_technique': mitre_technique,
        'mitre_tactic': mitre_tactic,
        'detected_at': datetime.now(timezone.utc).isoformat(),
        **extra,
    }


def sort_findings(findings: list[dict]) -> list[dict]:
    """Sort findings by severity score descending."""
    return sorted(findings, key=lambda f: f.get('severity_score', 0), reverse=True)


def count_by_severity(findings: list[dict]) -> dict[str, int]:
    """Return count per severity level."""
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get('severity', 'UNKNOWN')
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ── Retry / Rate Limit Helpers ─────────────────────────────────────────────────

def retry_on_throttle(fn, max_attempts: int = 5,
                      base_delay: float = 1.0):
    """
    Call `fn()` and retry with exponential backoff on ThrottlingException.
    """
    for attempt in range(max_attempts):
        try:
            return fn()
        except ClientError as e:
            code = e.response['Error']['Code']
            if code in ('ThrottlingException', 'RequestLimitExceeded',
                        'TooManyRequestsException') and attempt < max_attempts - 1:
                delay = base_delay * (2 ** attempt)
                logger.warning(f'Rate limited — retrying in {delay:.1f}s '
                               f'(attempt {attempt + 1}/{max_attempts})')
                time.sleep(delay)
            else:
                raise


# ── Tag Helpers ────────────────────────────────────────────────────────────────

def get_tag(tags: list[dict], key: str, default: str = '') -> str:
    """Extract a tag value from an AWS tags list."""
    for tag in tags:
        if tag.get('Key') == key:
            return tag.get('Value', default)
    return default


def make_tags(tags_dict: dict) -> list[dict]:
    """Convert a plain dict to AWS tag format [{Key:..., Value:...}]."""
    return [{'Key': k, 'Value': v} for k, v in tags_dict.items()]
