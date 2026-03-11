#!/usr/bin/env python3
"""
Cloud Storage Security Scanner
Week 3 Project — Cloud Security Mentorship Programme
Scans S3 buckets for public exposure, encryption gaps, and sensitive data patterns.
"""
import sys
import re
import json
import argparse
import logging
from typing import List, Tuple
sys.path.insert(0, "../../shared")

import boto3
from utils.aws_helpers import get_session, get_account_id, format_finding
from utils.report_generator import generate_html_report, generate_markdown_report

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


# ─── SENSITIVE DATA PATTERNS ──────────────────────────────────────────────────
SENSITIVE_PATTERNS = {
    "AWS_ACCESS_KEY": (
        re.compile(r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])"),
        "CRITICAL", "Potential AWS Access Key ID"
    ),
    "AWS_SECRET_KEY": (
        re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
        "HIGH", "Potential AWS Secret Access Key"
    ),
    "CREDIT_CARD": (
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
        "CRITICAL", "Potential credit card number (PCI DSS scope)"
    ),
    "SSN": (
        re.compile(r"\b(?!000|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        "CRITICAL", "Potential US Social Security Number (PII)"
    ),
    "EMAIL": (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "MEDIUM", "Email address found (potential PII)"
    ),
    "PRIVATE_KEY": (
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "CRITICAL", "Private key file detected"
    ),
    "PASSWORD_IN_FILE": (
        re.compile(r"(?i)password\s*[:=]\s*['\"]?[\w!@#$%^&*]{8,}"),
        "HIGH", "Password string in file content"
    ),
    "SLACK_TOKEN": (
        re.compile(r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}"),
        "CRITICAL", "Slack API token"
    ),
    "GITHUB_TOKEN": (
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "CRITICAL", "GitHub Personal Access Token"
    ),
    "API_KEY_GENERIC": (
        re.compile(r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
        "HIGH", "Generic API key pattern"
    ),
}


# ─── S3 CHECKS ────────────────────────────────────────────────────────────────

def check_bucket_public_access(s3_client, bucket_name: str) -> List[dict]:
    findings = []
    resource = f"s3://{bucket_name}"

    # Check Block Public Access settings
    try:
        bpa = s3_client.get_public_access_block(Bucket=bucket_name)
        cfg = bpa["PublicAccessBlockConfiguration"]
        if not all([
            cfg.get("BlockPublicAcls"),
            cfg.get("IgnorePublicAcls"),
            cfg.get("BlockPublicPolicy"),
            cfg.get("RestrictPublicBuckets"),
        ]):
            findings.append(format_finding(
                severity="HIGH",
                check_id="S3-001",
                resource=resource,
                description="S3 Block Public Access is not fully enabled on this bucket",
                remediation="Enable all 4 Block Public Access settings: BlockPublicAcls, "
                            "IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets"
            ))
    except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
        findings.append(format_finding(
            severity="HIGH",
            check_id="S3-001",
            resource=resource,
            description="S3 Block Public Access is NOT configured on this bucket",
            remediation="Enable S3 Block Public Access. Also enable at account level: "
                        "aws s3control put-public-access-block --account-id ACCOUNT_ID ..."
        ))
    except Exception as e:
        logger.warning(f"Could not check BPA for {bucket_name}: {e}")

    # Check bucket ACL
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                perm = grant.get("Permission", "")
                severity = "CRITICAL" if perm in ("FULL_CONTROL", "WRITE") else "HIGH"
                findings.append(format_finding(
                    severity=severity,
                    check_id="S3-002",
                    resource=resource,
                    description=f"Bucket ACL grants {perm} to {uri.split('/')[-1]}",
                    remediation="Remove public ACL grants. Use bucket policies instead of ACLs "
                                "(ACLs are a legacy access control mechanism)."
                ))
    except Exception as e:
        logger.warning(f"Could not check ACL for {bucket_name}: {e}")

    return findings


def check_bucket_encryption(s3_client, bucket_name: str) -> List[dict]:
    findings = []
    resource = f"s3://{bucket_name}"
    try:
        enc = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
        for rule in rules:
            default_enc = rule.get("ApplyServerSideEncryptionByDefault", {})
            algo = default_enc.get("SSEAlgorithm", "")
            if algo == "AES256":
                findings.append(format_finding(
                    severity="LOW",
                    check_id="S3-003",
                    resource=resource,
                    description="Bucket uses SSE-S3 (AES256) — consider SSE-KMS for key management audit trail",
                    remediation="Upgrade to SSE-KMS with a Customer Managed Key (CMK) for CloudTrail-visible key usage logs."
                ))
    except s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
        findings.append(format_finding(
            severity="HIGH",
            check_id="S3-003",
            resource=resource,
            description="Bucket has NO server-side encryption configured",
            remediation="Enable SSE-KMS with CMK: aws s3api put-bucket-encryption --bucket BUCKET_NAME ..."
        ))
    except Exception as e:
        logger.warning(f"Could not check encryption for {bucket_name}: {e}")
    return findings


def check_bucket_logging(s3_client, bucket_name: str) -> List[dict]:
    findings = []
    try:
        logging_cfg = s3_client.get_bucket_logging(Bucket=bucket_name)
        if "LoggingEnabled" not in logging_cfg:
            findings.append(format_finding(
                severity="MEDIUM",
                check_id="S3-004",
                resource=f"s3://{bucket_name}",
                description="S3 server access logging is not enabled — no audit trail for object access",
                remediation="Enable S3 server access logging to a dedicated logging bucket. "
                            "Required for PCI DSS and ISO 27001 audit trails."
            ))
    except Exception as e:
        logger.warning(f"Could not check logging for {bucket_name}: {e}")
    return findings


def check_bucket_versioning(s3_client, bucket_name: str) -> List[dict]:
    findings = []
    try:
        ver = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = ver.get("Status", "")
        if status != "Enabled":
            findings.append(format_finding(
                severity="LOW",
                check_id="S3-005",
                resource=f"s3://{bucket_name}",
                description=f"S3 versioning is {status or 'Disabled'} — no protection against ransomware overwrites",
                remediation="Enable versioning and S3 Object Lock (if applicable) to protect against "
                            "accidental deletion and ransomware. Consider MFA Delete for critical buckets."
            ))
    except Exception as e:
        logger.warning(f"Could not check versioning for {bucket_name}: {e}")
    return findings


def scan_bucket_for_sensitive_data(s3_client, bucket_name: str,
                                   max_files: int = 20) -> List[dict]:
    """Sample bucket objects and scan for sensitive data patterns."""
    findings = []
    TEXT_EXTENSIONS = {".txt", ".json", ".csv", ".yaml", ".yml", ".env",
                       ".cfg", ".conf", ".ini", ".xml", ".log", ".md"}
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=max_files)
        for obj in response.get("Contents", []):
            key = obj["Key"]
            ext = "." + key.rsplit(".", 1)[-1].lower() if "." in key else ""

            if ext not in TEXT_EXTENSIONS:
                continue

            if obj["Size"] > 5 * 1024 * 1024:  # Skip files > 5MB
                continue

            try:
                body = s3_client.get_object(Bucket=bucket_name, Key=key)
                content = body["Body"].read().decode("utf-8", errors="ignore")

                for pattern_name, (regex, severity, description) in SENSITIVE_PATTERNS.items():
                    if regex.search(content):
                        findings.append(format_finding(
                            severity=severity,
                            check_id=f"S3-DATA-{pattern_name}",
                            resource=f"s3://{bucket_name}/{key}",
                            description=f"{description} detected in object content",
                            remediation="Remove sensitive data from S3. Use AWS Secrets Manager for secrets. "
                                        "Enable Amazon Macie for ongoing sensitive data discovery."
                        ))
            except Exception:
                pass  # Skip unreadable objects
    except Exception as e:
        logger.warning(f"Could not scan objects in {bucket_name}: {e}")

    return findings


def main():
    parser = argparse.ArgumentParser(description="Cloud Storage Security Scanner")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--scan-data", action="store_true",
                        help="Enable sensitive data scanning (slower)")
    parser.add_argument("--output", choices=["html", "markdown", "json", "console"],
                        default="console")
    parser.add_argument("--output-file", default=None)
    args = parser.parse_args()

    session = get_session(args.profile, args.region)
    account_id = get_account_id(session)
    s3 = session.client("s3")

    buckets = s3.list_buckets().get("Buckets", [])
    logger.info(f"Found {len(buckets)} S3 buckets in account {account_id}")

    all_findings = []
    for bucket in buckets:
        name = bucket["Name"]
        logger.info(f"Scanning: {name}")
        all_findings.extend(check_bucket_public_access(s3, name))
        all_findings.extend(check_bucket_encryption(s3, name))
        all_findings.extend(check_bucket_logging(s3, name))
        all_findings.extend(check_bucket_versioning(s3, name))
        if args.scan_data:
            all_findings.extend(scan_bucket_for_sensitive_data(s3, name))

    all_findings.sort(key=lambda x: -x.get("severity_score", 0))

    title = "S3 Storage Security Scan Report"
    if args.output == "console":
        sev_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        for f in all_findings:
            print(f"{sev_icons.get(f['severity'], '⚪')} [{f['severity']}] {f['check_id']}")
            print(f"   {f['resource']}")
            print(f"   {f['description']}")
            print()
    elif args.output == "html":
        content = generate_html_report(all_findings, title, account_id)
        path = args.output_file or "sample_output/s3_scan.html"
        with open(path, "w") as fh:
            fh.write(content)
        logger.info(f"Report: {path}")
    elif args.output == "markdown":
        content = generate_markdown_report(all_findings, title)
        path = args.output_file or "sample_output/s3_scan.md"
        with open(path, "w") as fh:
            fh.write(content)
    elif args.output == "json":
        print(json.dumps(all_findings, indent=2))


if __name__ == "__main__":
    main()
