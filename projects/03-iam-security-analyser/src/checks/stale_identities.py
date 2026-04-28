"""
Stale identity checks — unused users, roles with no last activity,
service accounts with no recent API calls.
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

INACTIVE_DAYS = 90


def _days_since(dt_str: str) -> Optional[int]:
    if not dt_str:
        return None
    try:
        dt = datetime.fromisoformat(str(dt_str).replace('Z', '+00:00'))
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError):
        return None


def check_unused_roles(iam_client) -> list[dict]:
    """
    Flag IAM roles that have not been used in 90+ days.
    Uses IAM role last-used data (available via get_role).
    """
    from shared.utils.aws_helpers import format_finding, paginate
    findings = []
    for role in paginate(iam_client, 'list_roles', 'Roles'):
        detail = iam_client.get_role(RoleName=role['RoleName'])['Role']
        last_used = detail.get('RoleLastUsed', {})
        last_used_date = last_used.get('LastUsedDate')
        role_name = role['RoleName']

        if last_used_date is None:
            # Role has never been used
            created_days = _days_since(str(role.get('CreateDate', '')))
            if created_days is not None and created_days > INACTIVE_DAYS:
                findings.append(format_finding(
                    'MEDIUM', 'IAM-011', role['Arn'],
                    f'Role "{role_name}" has never been used '
                    f'(created {created_days} days ago).',
                    'Delete or deactivate unused roles. '
                    'Review with resource owners.',
                    'T1078', 'Persistence',
                ))
        else:
            age = _days_since(str(last_used_date))
            if age is not None and age > INACTIVE_DAYS:
                findings.append(format_finding(
                    'LOW', 'IAM-012', role['Arn'],
                    f'Role "{role_name}" last used {age} days ago '
                    f'(threshold: {INACTIVE_DAYS} days).',
                    'Investigate whether role is still needed. '
                    'Delete if not required.',
                    'T1078', 'Persistence',
                ))
    logger.info('Unused role check: %d findings', len(findings))
    return findings


def check_users_no_activity(iam_client) -> list[dict]:
    """
    Flag IAM users that have both console access AND access keys but
    show no activity in either for 90+ days. Complements credential report.
    """
    from shared.utils.aws_helpers import format_finding, paginate
    findings = []
    for user in paginate(iam_client, 'list_users', 'Users'):
        name = user['UserName']
        last_used_date = user.get('PasswordLastUsed')

        # Check access key last used
        keys = iam_client.list_access_keys(UserName=name)['AccessKeyMetadata']
        active_keys = [k for k in keys if k['Status'] == 'Active']
        latest_key_use: Optional[datetime] = None
        for key in active_keys:
            key_detail = iam_client.get_access_key_last_used(
                AccessKeyId=key['AccessKeyId']
            )['AccessKeyLastUsed']
            key_last = key_detail.get('LastUsedDate')
            if key_last:
                key_last = key_last.replace(tzinfo=timezone.utc) \
                    if key_last.tzinfo is None else key_last
                if latest_key_use is None or key_last > latest_key_use:
                    latest_key_use = key_last

        # Combine console and key last-use dates
        all_dates = [d for d in [last_used_date, latest_key_use] if d is not None]
        if not all_dates:
            # No activity at all
            created_days = _days_since(str(user.get('CreateDate', '')))
            if created_days is not None and created_days > INACTIVE_DAYS:
                findings.append(format_finding(
                    'MEDIUM', 'IAM-013', user['Arn'],
                    f'User "{name}" has no recorded activity '
                    f'(created {created_days} days ago).',
                    'Remove if not needed. '
                    'Prefer IAM roles over long-lived user credentials.',
                    'T1078', 'Persistence',
                ))
        else:
            most_recent = max(all_dates)
            most_recent_utc = most_recent.replace(tzinfo=timezone.utc) \
                if most_recent.tzinfo is None else most_recent
            age = (datetime.now(timezone.utc) - most_recent_utc).days
            if age > INACTIVE_DAYS:
                findings.append(format_finding(
                    'LOW', 'IAM-014', user['Arn'],
                    f'User "{name}" last active {age} days ago.',
                    'Review with user. Disable or delete if no longer needed.',
                    'T1078', 'Persistence',
                ))
    logger.info('User activity check: %d findings', len(findings))
    return findings
