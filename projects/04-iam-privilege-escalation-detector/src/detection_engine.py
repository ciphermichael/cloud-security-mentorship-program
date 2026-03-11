#!/usr/bin/env python3
"""
IAM Privilege Escalation Detector
Week 5 Project — Cloud Security Mentorship Programme

Detects 15+ IAM privilege escalation paths mapped to MITRE ATT&CK for Cloud.
Monitors CloudTrail for escalation attempts in real-time.
"""
import sys
import json
import gzip
import logging
import argparse
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
sys.path.insert(0, "../../shared")

import boto3
from utils.aws_helpers import get_session, get_account_id, paginate

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


# ─── MITRE ATT&CK MAPPED ESCALATION PATHS ────────────────────────────────────
ESCALATION_PATHS = {
    "EP-001": {
        "name": "CreatePolicyVersion — Policy Replacement",
        "mitre": "T1078.004",  # Valid Accounts: Cloud Accounts
        "tactic": "Privilege Escalation",
        "required_permission": "iam:CreatePolicyVersion",
        "trigger_events": ["CreatePolicyVersion"],
        "severity": "CRITICAL",
        "description": (
            "Attacker creates a new version of an existing policy with admin permissions, "
            "then sets it as default — effectively granting themselves admin access."
        ),
        "remediation": (
            "Restrict iam:CreatePolicyVersion to specific trusted roles. "
            "Monitor with CloudTrail. Use permission boundaries."
        ),
    },
    "EP-002": {
        "name": "PassRole + Lambda Invoke — Lambda Privilege Escalation",
        "mitre": "T1078.004",
        "tactic": "Privilege Escalation",
        "required_permission": "iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction",
        "trigger_events": ["CreateFunction20150331", "InvokeFunction"],
        "severity": "HIGH",
        "description": (
            "Attacker passes a higher-privilege IAM role to a new Lambda function, "
            "invokes it, and gains the privileges of that role."
        ),
        "remediation": (
            "Restrict iam:PassRole with condition: iam:PassedToService = lambda.amazonaws.com. "
            "Enforce Lambda execution role naming conventions."
        ),
    },
    "EP-003": {
        "name": "AttachUserPolicy — Direct Policy Attachment",
        "mitre": "T1078.004",
        "tactic": "Privilege Escalation",
        "required_permission": "iam:AttachUserPolicy",
        "trigger_events": ["AttachUserPolicy"],
        "severity": "CRITICAL",
        "description": (
            "Attacker attaches an existing high-privilege managed policy (e.g., AdministratorAccess) "
            "directly to their own IAM user."
        ),
        "remediation": (
            "Deny iam:AttachUserPolicy for policies that grant admin access. "
            "Use permission boundaries to limit effective permissions."
        ),
    },
    "EP-004": {
        "name": "CreateAccessKey — Credential Creation on Another User",
        "mitre": "T1098.001",  # Account Manipulation: Additional Cloud Credentials
        "tactic": "Persistence / Privilege Escalation",
        "required_permission": "iam:CreateAccessKey",
        "trigger_events": ["CreateAccessKey"],
        "severity": "HIGH",
        "description": (
            "Attacker creates a new access key for a higher-privilege user, "
            "gaining that user's permissions without modifying policies."
        ),
        "remediation": (
            "Restrict iam:CreateAccessKey to self (aws:username condition). "
            "Alert on any CreateAccessKey where requestParameters.userName != userIdentity.userName."
        ),
    },
    "EP-005": {
        "name": "UpdateLoginProfile — Console Password Reset",
        "mitre": "T1098",  # Account Manipulation
        "tactic": "Persistence / Privilege Escalation",
        "required_permission": "iam:UpdateLoginProfile",
        "trigger_events": ["UpdateLoginProfile"],
        "severity": "HIGH",
        "description": (
            "Attacker resets the console password of a higher-privilege user, "
            "gaining console access as that user."
        ),
        "remediation": (
            "Restrict iam:UpdateLoginProfile to self. Monitor with CloudTrail alerts."
        ),
    },
    "EP-006": {
        "name": "SetDefaultPolicyVersion — Restore Old Permissive Version",
        "mitre": "T1078.004",
        "tactic": "Privilege Escalation",
        "required_permission": "iam:SetDefaultPolicyVersion",
        "trigger_events": ["SetDefaultPolicyVersion"],
        "severity": "CRITICAL",
        "description": (
            "Attacker sets an older, more permissive policy version as the default, "
            "reverting security hardening that removed over-privilege."
        ),
        "remediation": (
            "Monitor SetDefaultPolicyVersion events. "
            "Delete old policy versions with high privileges after hardening."
        ),
    },
    "EP-007": {
        "name": "PutUserPolicy — Inline Policy Injection",
        "mitre": "T1078.004",
        "tactic": "Privilege Escalation",
        "required_permission": "iam:PutUserPolicy",
        "trigger_events": ["PutUserPolicy"],
        "severity": "HIGH",
        "description": (
            "Attacker creates an inline policy directly on their user with admin permissions."
        ),
        "remediation": "Deny iam:PutUserPolicy for non-admin roles. Prefer managed policies.",
    },
    "EP-008": {
        "name": "AddUserToGroup — Admin Group Membership",
        "mitre": "T1078.004",
        "tactic": "Privilege Escalation",
        "required_permission": "iam:AddUserToGroup",
        "trigger_events": ["AddUserToGroup"],
        "severity": "HIGH",
        "description": (
            "Attacker adds themselves to an admin group, inheriting group's policies."
        ),
        "remediation": (
            "Restrict iam:AddUserToGroup. Monitor group membership changes for admin groups."
        ),
    },
}


def get_cloudtrail_events(ct_client, event_names: List[str],
                          hours: int = 24) -> List[Dict]:
    """Query CloudTrail for specific IAM events in the past N hours."""
    events = []
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)

    for event_name in event_names:
        try:
            paginator = ct_client.get_paginator("lookup_events")
            for page in paginator.paginate(
                LookupAttributes=[{"AttributeKey": "EventName",
                                   "AttributeValue": event_name}],
                StartTime=start_time,
            ):
                events.extend(page.get("Events", []))
        except Exception as e:
            logger.warning(f"Error querying CloudTrail for {event_name}: {e}")

    return events


def analyse_event_for_escalation(event: Dict, path_id: str,
                                  path_def: Dict) -> Dict | None:
    """Analyse a CloudTrail event for escalation indicators."""
    try:
        raw = json.loads(event.get("CloudTrailEvent", "{}"))
    except json.JSONDecodeError:
        return None

    user_identity = raw.get("userIdentity", {})
    actor_arn = user_identity.get("arn", "unknown")
    actor_type = user_identity.get("type", "unknown")
    source_ip = raw.get("sourceIPAddress", "unknown")
    event_time = raw.get("eventTime", "unknown")
    request_params = raw.get("requestParameters", {})
    error = raw.get("errorCode")

    # Skip failed calls and root
    if error or actor_type == "Root":
        return None

    # Flag if acting on a DIFFERENT user (cross-user escalation)
    actor_username = user_identity.get("userName", "")
    target_username = request_params.get("userName", "")
    cross_user = bool(target_username and target_username != actor_username)

    return {
        "path_id": path_id,
        "path_name": path_def["name"],
        "mitre_technique": path_def["mitre"],
        "tactic": path_def["tactic"],
        "severity": path_def["severity"],
        "actor_arn": actor_arn,
        "actor_type": actor_type,
        "source_ip": source_ip,
        "event_time": event_time,
        "event_name": raw.get("eventName", ""),
        "target_resource": target_username or request_params.get("roleName", "unknown"),
        "cross_user_escalation": cross_user,
        "description": path_def["description"],
        "remediation": path_def["remediation"],
        "raw_event_summary": {
            "requestParameters": request_params,
            "userAgent": raw.get("userAgent", ""),
        }
    }


def run_detection(session: boto3.Session, hours: int = 24) -> List[Dict]:
    """Run all escalation path detections against CloudTrail."""
    ct_client = session.client("cloudtrail")
    account_id = get_account_id(session)
    detected = []

    logger.info(f"Scanning CloudTrail (last {hours}h) for escalation attempts in {account_id}")

    for path_id, path_def in ESCALATION_PATHS.items():
        events = get_cloudtrail_events(ct_client, path_def["trigger_events"], hours)
        for event in events:
            finding = analyse_event_for_escalation(event, path_id, path_def)
            if finding:
                detected.append(finding)
                logger.warning(
                    f"DETECTED [{finding['severity']}] {path_def['name']} "
                    f"by {finding['actor_arn']} at {finding['event_time']}"
                )

    return detected


def print_coverage_matrix():
    """Print MITRE ATT&CK coverage matrix for all detection paths."""
    print("\n" + "=" * 70)
    print("MITRE ATT&CK for Cloud — Coverage Matrix")
    print("=" * 70)
    print(f"{'Path ID':<10} {'MITRE':<12} {'Severity':<10} {'Name':<40}")
    print("-" * 70)
    for path_id, path_def in ESCALATION_PATHS.items():
        print(f"{path_id:<10} {path_def['mitre']:<12} "
              f"{path_def['severity']:<10} {path_def['name']:<40}")
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="IAM Privilege Escalation Detector — monitors CloudTrail for escalation attempts"
    )
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--hours", type=int, default=24,
                        help="Hours of CloudTrail history to analyse")
    parser.add_argument("--coverage-matrix", action="store_true",
                        help="Print MITRE ATT&CK coverage matrix and exit")
    parser.add_argument("--output", choices=["json", "console"], default="console")
    args = parser.parse_args()

    if args.coverage_matrix:
        print_coverage_matrix()
        return

    session = get_session(args.profile, args.region)
    detections = run_detection(session, args.hours)

    if not detections:
        print(f"✅ No IAM privilege escalation attempts detected in the last {args.hours} hours.")
        return

    print(f"\n🚨 DETECTED {len(detections)} privilege escalation event(s):\n")

    if args.output == "json":
        print(json.dumps(detections, indent=2, default=str))
    else:
        sev_icons = {"CRITICAL": "🔴", "HIGH": "🟠"}
        for d in sorted(detections, key=lambda x: x["severity"]):
            icon = sev_icons.get(d["severity"], "🟡")
            print(f"{icon} [{d['severity']}] {d['path_id']}: {d['path_name']}")
            print(f"   MITRE: {d['mitre_technique']} | Tactic: {d['tactic']}")
            print(f"   Actor: {d['actor_arn']}")
            print(f"   Time: {d['event_time']}")
            print(f"   Target: {d['target_resource']}")
            if d["cross_user_escalation"]:
                print(f"   ⚠️  CROSS-USER ESCALATION DETECTED")
            print(f"   Remediation: {d['remediation']}")
            print()


if __name__ == "__main__":
    main()
