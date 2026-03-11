#!/usr/bin/env python3
"""
IAM Security Analyser
Week 4 Project — Cloud Security Mentorship Programme
Audits AWS IAM for stale credentials, missing MFA, over-privilege, and more.
"""
import sys
import json
import csv
import argparse
import logging
from datetime import datetime, timezone, timedelta
from typing import List
sys.path.insert(0, "../../shared")

import boto3
from utils.aws_helpers import get_session, get_account_id, paginate, format_finding
from utils.report_generator import generate_html_report, generate_markdown_report

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

KEY_MAX_AGE_DAYS = 90
PASSWORD_MAX_AGE_DAYS = 90

# IAM actions that indicate admin-level permissions
ADMIN_ACTIONS = {"*", "iam:*", "s3:*", "ec2:*", "lambda:*"}
DANGEROUS_ACTIONS = {
    "iam:PassRole", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:CreateAccessKey",
    "iam:UpdateLoginProfile", "sts:AssumeRole",
}


def check_users_without_mfa(iam_client) -> List[dict]:
    """Detect IAM users with console access but no MFA."""
    findings = []
    users = paginate(iam_client, "list_users", "Users")

    for user in users:
        username = user["UserName"]
        # Check login profile (console access)
        try:
            iam_client.get_login_profile(UserName=username)
            has_console = True
        except iam_client.exceptions.NoSuchEntityException:
            has_console = False

        if not has_console:
            continue

        # Check MFA devices
        mfa_devices = paginate(iam_client, "list_mfa_devices",
                               "MFADevices", UserName=username)
        if not mfa_devices:
            findings.append(format_finding(
                severity="CRITICAL",
                check_id="IAM-001",
                resource=f"iam/user/{username}",
                description=f"User '{username}' has console access but NO MFA device enrolled",
                remediation="Immediately enforce MFA. Use IAM policy: Deny all actions when "
                            "aws:MultiFactorAuthPresent is false. Enable MFA enforcement via SCP."
            ))

    return findings


def check_stale_access_keys(iam_client) -> List[dict]:
    """Find access keys older than 90 days."""
    findings = []
    users = paginate(iam_client, "list_users", "Users")

    for user in users:
        username = user["UserName"]
        keys = paginate(iam_client, "list_access_keys",
                        "AccessKeyMetadata", UserName=username)

        for key in keys:
            key_id = key["AccessKeyId"]
            status = key["Status"]
            created = key["CreateDate"]

            if not created.tzinfo:
                created = created.replace(tzinfo=timezone.utc)

            age_days = (datetime.now(timezone.utc) - created).days

            if status == "Active" and age_days > KEY_MAX_AGE_DAYS:
                severity = "HIGH" if age_days < 180 else "CRITICAL"
                findings.append(format_finding(
                    severity=severity,
                    check_id="IAM-002",
                    resource=f"iam/user/{username}/key/{key_id}",
                    description=f"Access key {key_id} for '{username}' is {age_days} days old (>{KEY_MAX_AGE_DAYS} day limit)",
                    remediation=f"Rotate access key immediately. Implement 90-day rotation via aws iam create-access-key "
                                f"then aws iam delete-access-key. Use IAM Access Advisor to verify key is still needed."
                ))

            # Inactive key still present
            if status == "Inactive" and age_days > 30:
                findings.append(format_finding(
                    severity="LOW",
                    check_id="IAM-003",
                    resource=f"iam/user/{username}/key/{key_id}",
                    description=f"Inactive access key {key_id} still exists ({age_days} days old) — clean-up risk",
                    remediation="Delete inactive access keys. Inactive keys can be re-activated by attackers."
                ))

    return findings


def check_root_account_usage(iam_client) -> List[dict]:
    """Check for recent root account usage."""
    findings = []
    try:
        summary = iam_client.get_account_summary()["SummaryMap"]

        # Root access keys
        if summary.get("AccountAccessKeysPresent", 0) > 0:
            findings.append(format_finding(
                severity="CRITICAL",
                check_id="IAM-004",
                resource="iam/root-account",
                description="Root account has active access keys — critically dangerous",
                remediation="Delete root access keys immediately. Root API access is unnecessary. "
                            "Use IAM roles with least-privilege for all automation."
            ))

        # Root MFA
        if summary.get("AccountMFAEnabled", 0) == 0:
            findings.append(format_finding(
                severity="CRITICAL",
                check_id="IAM-005",
                resource="iam/root-account",
                description="Root account does NOT have MFA enabled",
                remediation="Enable hardware MFA on root account immediately. "
                            "This is the single most important AWS security action."
            ))
    except Exception as e:
        logger.warning(f"Could not check root account: {e}")

    return findings


def check_admin_policies(iam_client) -> List[dict]:
    """Find users/roles/groups with wildcard admin policies."""
    findings = []

    # Check attached managed policies with wildcard actions
    users = paginate(iam_client, "list_users", "Users")
    for user in users:
        username = user["UserName"]
        attached = paginate(iam_client, "list_attached_user_policies",
                            "AttachedPolicies", UserName=username)
        for policy in attached:
            if policy["PolicyName"] == "AdministratorAccess":
                findings.append(format_finding(
                    severity="HIGH",
                    check_id="IAM-006",
                    resource=f"iam/user/{username}",
                    description=f"User '{username}' has AdministratorAccess policy attached",
                    remediation="Replace AdministratorAccess with a least-privilege policy scoped to "
                                "specific resources and actions needed for the user's role."
                ))

    # Check for inline policies with wildcards
    for user in users:
        username = user["UserName"]
        inline_policies = paginate(iam_client, "list_user_policies",
                                   "PolicyNames", UserName=username)
        for policy_name in inline_policies:
            doc = iam_client.get_user_policy(UserName=username,
                                              PolicyName=policy_name)
            import urllib.parse
            policy_doc = json.loads(
                urllib.parse.unquote(doc.get("PolicyDocument", "{}"))
                if isinstance(doc.get("PolicyDocument"), str)
                else json.dumps(doc.get("PolicyDocument", {}))
            )
            for statement in policy_doc.get("Statement", []):
                if statement.get("Effect") == "Allow":
                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if "*" in actions or "iam:*" in actions:
                        findings.append(format_finding(
                            severity="HIGH",
                            check_id="IAM-007",
                            resource=f"iam/user/{username}/policy/{policy_name}",
                            description=f"Inline policy contains wildcard action (*) — effectively administrator",
                            remediation="Replace wildcard actions with specific permissions using IAM Policy Simulator."
                        ))

    return findings


def check_unused_credentials(iam_client) -> List[dict]:
    """Find users who have never used their credentials."""
    findings = []
    try:
        report_response = iam_client.generate_credential_report()
        import time
        time.sleep(2)  # Wait for report generation

        report = iam_client.get_credential_report()
        content = report["Content"].decode("utf-8").splitlines()
        reader = csv.DictReader(content)

        for row in reader:
            if row.get("user") == "<root_account>":
                continue
            username = row.get("user", "unknown")

            # Never used password
            pwd_last_used = row.get("password_last_used", "")
            pwd_enabled = row.get("password_enabled", "false")
            if pwd_enabled == "true" and pwd_last_used in ("N/A", "no_information", ""):
                findings.append(format_finding(
                    severity="MEDIUM",
                    check_id="IAM-008",
                    resource=f"iam/user/{username}",
                    description=f"User '{username}' has console access but has NEVER logged in",
                    remediation="Disable or delete unused IAM users. Apply the principle of least privilege: "
                                "only create accounts for users who need them."
                ))
    except Exception as e:
        logger.warning(f"Could not check credential report: {e}")

    return findings


def main():
    parser = argparse.ArgumentParser(description="IAM Security Analyser")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", choices=["html", "markdown", "json", "console"],
                        default="console")
    parser.add_argument("--output-file", default=None)
    args = parser.parse_args()

    session = get_session(args.profile, args.region)
    account_id = get_account_id(session)
    iam = session.client("iam")

    logger.info(f"Analysing IAM for account: {account_id}")
    all_findings = []

    checks = [
        ("MFA enforcement", check_users_without_mfa),
        ("Stale access keys", check_stale_access_keys),
        ("Root account", check_root_account_usage),
        ("Admin policies", check_admin_policies),
        ("Unused credentials", check_unused_credentials),
    ]

    for check_name, check_fn in checks:
        logger.info(f"Running: {check_name}")
        all_findings.extend(check_fn(iam))

    all_findings.sort(key=lambda x: -x.get("severity_score", 0))
    logger.info(f"IAM analysis complete: {len(all_findings)} findings")

    title = f"IAM Security Analysis — {account_id}"
    if args.output == "console":
        sev_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        for f in all_findings:
            print(f"{sev_icons.get(f['severity'], '⚪')} [{f['severity']}] {f['check_id']}")
            print(f"   Resource: {f['resource']}")
            print(f"   Issue: {f['description']}")
            print(f"   Fix: {f['remediation']}")
            print()
    elif args.output == "html":
        content = generate_html_report(all_findings, title, account_id)
        path = args.output_file or "reports/iam_audit.html"
        with open(path, "w") as fh:
            fh.write(content)
        logger.info(f"HTML report: {path}")
    elif args.output == "markdown":
        content = generate_markdown_report(all_findings, title)
        path = args.output_file or "reports/iam_audit.md"
        with open(path, "w") as fh:
            fh.write(content)
    elif args.output == "json":
        print(json.dumps(all_findings, indent=2))


if __name__ == "__main__":
    main()
