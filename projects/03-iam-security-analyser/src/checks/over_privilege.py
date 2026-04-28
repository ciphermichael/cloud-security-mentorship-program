"""
Over-privilege checks — wildcard policies, admin attachments, inline policies.
"""
import json
import logging

logger = logging.getLogger(__name__)

ADMIN_POLICY_ARN = 'arn:aws:iam::aws:policy/AdministratorAccess'
DANGEROUS_ACTIONS = {'iam:*', 'iam:PassRole', 's3:*', 'ec2:*', 'lambda:*'}


def _is_wildcard_statement(stmt: dict) -> bool:
    """Return True if an Allow statement grants Action:* on Resource:*."""
    if stmt.get('Effect') != 'Allow':
        return False
    actions = stmt.get('Action', [])
    resources = stmt.get('Resource', [])
    if isinstance(actions, str):
        actions = [actions]
    if isinstance(resources, str):
        resources = [resources]
    return '*' in actions and '*' in resources


def check_overprivileged_customer_policies(iam_client) -> list[dict]:
    """CIS 1.16 — customer-managed policies must not grant Action:* Resource:*."""
    from shared.utils.aws_helpers import format_finding
    findings = []
    paginator = iam_client.get_paginator('list_policies')
    for page in paginator.paginate(Scope='Local'):
        for pol in page['Policies']:
            ver = iam_client.get_policy_version(
                PolicyArn=pol['Arn'],
                VersionId=pol['DefaultVersionId'],
            )['PolicyVersion']['Document']
            for stmt in ver.get('Statement', []):
                if _is_wildcard_statement(stmt):
                    findings.append(format_finding(
                        'CRITICAL', 'IAM-007', pol['Arn'],
                        f'Policy "{pol["PolicyName"]}" grants '
                        f'Action:* on Resource:* (full admin).',
                        'Replace wildcards with specific actions and resource ARNs.',
                        'T1098', 'Privilege Escalation',
                    ))
                    break  # one finding per policy
    logger.info('Policy over-privilege check: %d findings', len(findings))
    return findings


def check_admin_attached_to_users(iam_client) -> list[dict]:
    """Flag users with AdministratorAccess directly attached (not via group)."""
    from shared.utils.aws_helpers import format_finding, paginate
    findings = []
    for user in paginate(iam_client, 'list_users', 'Users'):
        attached = iam_client.list_attached_user_policies(
            UserName=user['UserName']
        )['AttachedPolicies']
        for pol in attached:
            if pol['PolicyArn'] == ADMIN_POLICY_ARN:
                findings.append(format_finding(
                    'CRITICAL', 'IAM-008', user['Arn'],
                    f'User "{user["UserName"]}" has AdministratorAccess '
                    f'directly attached.',
                    'Detach admin policy from user. Assign via groups instead.',
                    'T1078', 'Privilege Escalation',
                ))
    return findings


def check_inline_policies(iam_client) -> list[dict]:
    """Flag inline policies on users — hard to audit, encourage managed policies."""
    from shared.utils.aws_helpers import format_finding, paginate
    findings = []
    for user in paginate(iam_client, 'list_users', 'Users'):
        inline = iam_client.list_user_policies(
            UserName=user['UserName']
        )['PolicyNames']
        for pol_name in inline:
            findings.append(format_finding(
                'LOW', 'IAM-009', user['Arn'],
                f'User "{user["UserName"]}" has inline policy "{pol_name}".',
                'Convert inline policies to customer-managed for governance.',
                'T1078', 'Persistence',
            ))
    return findings


def check_passrole_without_condition(iam_client) -> list[dict]:
    """Flag policies granting iam:PassRole on Resource:* without conditions."""
    from shared.utils.aws_helpers import format_finding
    findings = []
    paginator = iam_client.get_paginator('list_policies')
    for page in paginator.paginate(Scope='Local'):
        for pol in page['Policies']:
            ver = iam_client.get_policy_version(
                PolicyArn=pol['Arn'],
                VersionId=pol['DefaultVersionId'],
            )['PolicyVersion']['Document']
            for stmt in ver.get('Statement', []):
                if stmt.get('Effect') != 'Allow':
                    continue
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                resources = stmt.get('Resource', [])
                if isinstance(resources, str):
                    resources = [resources]
                if ('iam:PassRole' in actions or '*' in actions) \
                        and '*' in resources \
                        and not stmt.get('Condition'):
                    findings.append(format_finding(
                        'HIGH', 'IAM-010', pol['Arn'],
                        f'Policy "{pol["PolicyName"]}" grants iam:PassRole '
                        f'on Resource:* without conditions — escalation path.',
                        'Restrict PassRole to specific role ARNs and add '
                        'iam:PassedToService condition.',
                        'T1098.003', 'Privilege Escalation',
                    ))
                    break
    return findings
