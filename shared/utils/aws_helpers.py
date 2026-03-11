"""Shared AWS helper utilities used across all projects."""
import boto3
import logging
from typing import Optional, List

logger = logging.getLogger(__name__)


def get_session(profile: Optional[str] = None, region: str = "us-east-1") -> boto3.Session:
    """Create a boto3 session with optional named profile."""
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def get_account_id(session: boto3.Session) -> str:
    """Get the AWS account ID for the current session."""
    sts = session.client("sts")
    return sts.get_caller_identity()["Account"]


def paginate(client, method: str, key: str, **kwargs) -> list:
    """Generic paginator helper for boto3 list/describe calls."""
    results = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs):
        results.extend(page.get(key, []))
    return results


def format_finding(severity: str, check_id: str, resource: str,
                   description: str, remediation: str) -> dict:
    """Standard finding format used across all audit tools."""
    severity_scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    return {
        "severity": severity,
        "severity_score": severity_scores.get(severity, 0),
        "check_id": check_id,
        "resource": resource,
        "description": description,
        "remediation": remediation,
    }


def get_all_regions(session: boto3.Session) -> List[str]:
    """Return list of all enabled AWS regions."""
    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(
        Filters=[{"Name": "opt-in-status",
                  "Values": ["opt-in-not-required", "opted-in"]}]
    )
    return [r["RegionName"] for r in response["Regions"]]
