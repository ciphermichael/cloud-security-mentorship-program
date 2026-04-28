"""
CIS-aligned credential report checks.
Parses the IAM credential report CSV and produces structured findings.
"""
import csv
import io
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

STALE_DAYS = 90


def _parse_date(value: str) -> Optional[datetime]:
    if not value or value in ('N/A', 'not_supported', 'no_information', ''):
        return None
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def _age_days(dt: Optional[datetime]) -> Optional[int]:
    if dt is None:
        return None
    return (datetime.now(timezone.utc) - dt).days


def fetch_credential_report(iam_client) -> list[dict]:
    """Generate and download the IAM credential report as a list of row dicts."""
    iam_client.generate_credential_report()
    for _ in range(15):
        resp = iam_client.get_credential_report()
        if resp['State'] == 'COMPLETE':
            content = resp['Content'].decode('utf-8')
            return list(csv.DictReader(io.StringIO(content)))
        time.sleep(2)
    raise RuntimeError('Credential report timed out after 30 seconds')


def check_root_account(row: dict) -> list[dict]:
    """CIS 1.4, 1.5 — root account checks."""
    from shared.utils.aws_helpers import format_finding
    findings = []
    arn = row['arn']

    if row['mfa_active'] == 'false':
        findings.append(format_finding(
            'CRITICAL', 'IAM-001', arn,
            'Root account has no MFA device enabled.',
            'Enable hardware MFA on root via IAM → Security credentials.',
            'T1078', 'Initial Access',
        ))
    for k in ('1', '2'):
        if row.get(f'access_key_{k}_active') == 'true':
            findings.append(format_finding(
                'CRITICAL', 'IAM-002', arn,
                f'Root account has active access key {k}.',
                'Delete all root access keys. Use IAM users/roles instead.',
                'T1098.001', 'Persistence',
            ))
    return findings


def check_user_mfa(row: dict) -> list[dict]:
    """CIS 1.10 — MFA for all console users."""
    from shared.utils.aws_helpers import format_finding
    if row['password_enabled'] != 'true' or row['mfa_active'] == 'true':
        return []
    return [format_finding(
        'HIGH', 'IAM-003', row['arn'],
        f'Console user "{row["user"]}" has no MFA device.',
        'Enforce MFA with IAM policy condition '
        '"aws:MultiFactorAuthPresent": "true".',
        'T1078', 'Initial Access',
    )]


def check_stale_login(row: dict) -> list[dict]:
    """CIS 1.12 — remove credentials unused for 90+ days."""
    from shared.utils.aws_helpers import format_finding
    if row['password_enabled'] != 'true':
        return []
    last_login = _parse_date(row.get('password_last_used', ''))
    age = _age_days(last_login)
    if age is None or age <= STALE_DAYS:
        return []
    return [format_finding(
        'MEDIUM', 'IAM-004', row['arn'],
        f'User "{row["user"]}" has not logged in for {age} days.',
        'Disable or delete inactive accounts. Review access quarterly.',
        'T1078', 'Persistence',
    )]


def check_access_keys(row: dict) -> list[dict]:
    """CIS 1.14 — access key rotation; CIS 1.13 — unused keys."""
    from shared.utils.aws_helpers import format_finding
    findings = []
    for k in ('1', '2'):
        if row.get(f'access_key_{k}_active') != 'true':
            continue
        rotated = _parse_date(row.get(f'access_key_{k}_last_rotated', ''))
        rot_age = _age_days(rotated)
        if rot_age is not None and rot_age > STALE_DAYS:
            findings.append(format_finding(
                'HIGH', 'IAM-005', row['arn'],
                f'Access key {k} for "{row["user"]}" is {rot_age} days old '
                f'(threshold: {STALE_DAYS} days).',
                'Rotate access keys every 90 days. Prefer IAM roles.',
                'T1098.001', 'Credential Access',
            ))
        last_used = _parse_date(row.get(f'access_key_{k}_last_used_date', ''))
        if last_used is None:
            findings.append(format_finding(
                'MEDIUM', 'IAM-006', row['arn'],
                f'Access key {k} for "{row["user"]}" is active but never used.',
                'Delete access keys that have never been used.',
                'T1098.001', 'Persistence',
            ))
    return findings


def run_all_credential_checks(iam_client) -> list[dict]:
    """Run all credential report checks and return consolidated findings."""
    rows = fetch_credential_report(iam_client)
    findings = []
    for row in rows:
        if row['user'] == '<root_account>':
            findings.extend(check_root_account(row))
        else:
            findings.extend(check_user_mfa(row))
            findings.extend(check_stale_login(row))
            findings.extend(check_access_keys(row))
    logger.info('Credential report: %d findings', len(findings))
    return findings
