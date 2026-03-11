#!/usr/bin/env python3
"""
AWS Network Security Auditor
Week 2 Project — Cloud Security Mentorship Programme
Detects VPC/Security Group/NACL misconfigurations across an AWS account.
"""
import sys
import json
import argparse
import logging
from datetime import datetime
sys.path.insert(0, "../../shared")

import boto3
from utils.aws_helpers import get_session, get_account_id, paginate, format_finding
from utils.report_generator import generate_html_report, generate_markdown_report
from checks.security_groups import audit_security_groups
from checks.flow_logs import audit_flow_logs
from checks.public_exposure import audit_public_exposure
from checks.nacls import audit_nacls

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def run_audit(session: boto3.Session, region: str) -> list:
    """Run all network security checks and return consolidated findings."""
    findings = []
    logger.info(f"Starting network security audit in region: {region}")

    regional_session = boto3.Session(
        region_name=region,
        botocore_session=session._session
    )

    logger.info("Running security group checks...")
    findings.extend(audit_security_groups(regional_session, region))

    logger.info("Running VPC Flow Log checks...")
    findings.extend(audit_flow_logs(regional_session, region))

    logger.info("Running public exposure checks...")
    findings.extend(audit_public_exposure(regional_session, region))

    logger.info("Running NACL checks...")
    findings.extend(audit_nacls(regional_session, region))

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="AWS Network Security Auditor — detect VPC/SG misconfigurations"
    )
    parser.add_argument("--profile", help="AWS CLI profile name", default=None)
    parser.add_argument("--region", help="AWS region to audit", default="us-east-1")
    parser.add_argument("--all-regions", action="store_true",
                        help="Audit all enabled regions")
    parser.add_argument("--output", choices=["html", "markdown", "json", "console"],
                        default="console")
    parser.add_argument("--output-file", help="Output file path", default=None)
    args = parser.parse_args()

    session = get_session(args.profile, args.region)
    account_id = get_account_id(session)
    logger.info(f"Auditing AWS Account: {account_id}")

    all_findings = []

    if args.all_regions:
        ec2 = session.client("ec2")
        regions = [r["RegionName"] for r in
                   ec2.describe_regions()["Regions"]]
    else:
        regions = [args.region]

    for region in regions:
        all_findings.extend(run_audit(session, region))

    # Sort by severity
    all_findings.sort(key=lambda x: -x.get("severity_score", 0))

    logger.info(f"Audit complete. Found {len(all_findings)} issues.")

    # Output
    title = f"AWS Network Security Audit — {account_id}"

    if args.output == "console":
        sev_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}
        for f in all_findings:
            icon = sev_icons.get(f["severity"], "⚪")
            print(f"{icon} [{f['severity']}] {f['check_id']}")
            print(f"   Resource: {f['resource']}")
            print(f"   Issue: {f['description']}")
            print(f"   Fix: {f['remediation']}")
            print()
        print(f"Total: {len(all_findings)} findings")

    elif args.output == "json":
        content = json.dumps(all_findings, indent=2)
        if args.output_file:
            with open(args.output_file, "w") as fh:
                fh.write(content)
        else:
            print(content)

    elif args.output == "html":
        content = generate_html_report(all_findings, title, account_id)
        out_path = args.output_file or f"reports/audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(out_path, "w") as fh:
            fh.write(content)
        logger.info(f"HTML report written to: {out_path}")

    elif args.output == "markdown":
        content = generate_markdown_report(all_findings, title)
        out_path = args.output_file or f"reports/audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(out_path, "w") as fh:
            fh.write(content)
        logger.info(f"Markdown report written to: {out_path}")

    # Exit non-zero if critical/high findings
    critical_count = sum(1 for f in all_findings if f["severity"] in ("CRITICAL", "HIGH"))
    if critical_count > 0:
        logger.warning(f"{critical_count} CRITICAL/HIGH findings require immediate attention!")
        sys.exit(1)


if __name__ == "__main__":
    main()
