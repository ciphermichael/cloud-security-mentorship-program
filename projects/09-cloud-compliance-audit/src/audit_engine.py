#!/usr/bin/env python3
"""
Cloud Compliance Audit Tool
Week 10 Project — Cloud Security Mentorship Programme
Automated CIS Benchmark + ISO 27001 assessment with evidence-backed reporting.
"""
import sys, json, argparse, logging
from datetime import datetime, timezone
sys.path.insert(0, "../../shared")
from utils.aws_helpers import get_session, get_account_id, paginate, format_finding
from utils.report_generator import generate_html_report, generate_markdown_report

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# CIS → ISO 27001 control mapping subset
CIS_ISO_MAPPING = {
    "CIS-1.1":  "A.9.2.1 User Registration",
    "CIS-1.5":  "A.9.4.3 Password Management",
    "CIS-1.8":  "A.9.2.6 Access Rights Removal",
    "CIS-1.13": "A.9.1.2 Access to Networks",
    "CIS-1.14": "A.9.2.5 Review of User Access Rights",
    "CIS-2.1":  "A.12.4.1 Event Logging",
    "CIS-2.2":  "A.12.4.1 Event Logging",
    "CIS-3.1":  "A.12.4.1 Event Logging",
    "CIS-3.3":  "A.12.4.3 Administrator and Operator Logs",
    "CIS-4.1":  "A.10.1.1 Policy on the Use of Cryptographic Controls",
}


def check_cis_1_1_mfa_root(iam) -> list:
    """CIS 1.1 — Root MFA enabled."""
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) == 0:
        return [format_finding("CRITICAL","CIS-1.1",
            "iam/root-account",
            "CIS 1.1: Root account MFA is NOT enabled",
            "Enable hardware MFA on root. ISO 27001 A.9.4.3")]
    return []


def check_cis_1_4_no_root_keys(iam) -> list:
    """CIS 1.4 — No root access keys."""
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountAccessKeysPresent", 0) > 0:
        return [format_finding("CRITICAL","CIS-1.4",
            "iam/root-account",
            "CIS 1.4: Root account has active access keys",
            "Delete root access keys immediately. Use IAM roles instead. ISO 27001 A.9.2.3")]
    return []


def check_cis_1_8_mfa_all_users(iam) -> list:
    """CIS 1.10 — MFA for all IAM users with console access."""
    findings = []
    users = paginate(iam, "list_users", "Users")
    for user in users:
        uname = user["UserName"]
        try:
            iam.get_login_profile(UserName=uname)
        except iam.exceptions.NoSuchEntityException:
            continue
        mfa = paginate(iam, "list_mfa_devices", "MFADevices", UserName=uname)
        if not mfa:
            findings.append(format_finding("HIGH","CIS-1.10",
                f"iam/user/{uname}",
                f"CIS 1.10: User '{uname}' has console access but no MFA",
                "Enforce MFA via IAM policy condition aws:MultiFactorAuthPresent. ISO 27001 A.9.4.3"))
    return findings


def check_cis_2_1_cloudtrail_enabled(ct, region) -> list:
    """CIS 2.1 — CloudTrail enabled in all regions."""
    trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
    if not multi_region:
        return [format_finding("HIGH","CIS-2.1",
            f"cloudtrail/{region}",
            "CIS 2.1: No multi-region CloudTrail trail exists",
            "Create a multi-region trail with log file validation. ISO 27001 A.12.4.1")]
    # Check log file validation
    for trail in multi_region:
        if not trail.get("LogFileValidationEnabled"):
            return [format_finding("MEDIUM","CIS-2.2",
                f"cloudtrail/{trail['Name']}",
                "CIS 2.2: CloudTrail log file validation NOT enabled",
                "Enable log file validation to detect tampering. ISO 27001 A.12.4.2")]
    return []


def check_cis_2_6_s3_logging(s3, ct) -> list:
    """CIS 2.6 — S3 bucket access logging on CloudTrail buckets."""
    findings = []
    trails = ct.describe_trails().get("trailList", [])
    for trail in trails:
        bucket = trail.get("S3BucketName","")
        if not bucket:
            continue
        try:
            log = s3.get_bucket_logging(Bucket=bucket)
            if "LoggingEnabled" not in log:
                findings.append(format_finding("MEDIUM","CIS-2.6",
                    f"s3://{bucket}",
                    f"CIS 2.6: CloudTrail bucket '{bucket}' has no access logging",
                    "Enable S3 server access logging on the CloudTrail bucket. ISO 27001 A.12.4.1"))
        except Exception:
            pass
    return findings


def check_cis_3_1_log_metric_filters(logs, region) -> list:
    """CIS 3.1-3.14 — CloudWatch metric filters for security events."""
    required_patterns = {
        "CIS-3.1":  ("root account usage", "userIdentity.type = Root"),
        "CIS-3.3":  ("console login without MFA",
                     "($.eventName = ConsoleLogin) && ($.additionalEventData.MFAUsed != Yes)"),
        "CIS-3.4":  ("IAM policy changes",
                     "($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)"),
        "CIS-3.10": ("security group changes",
                     "($.eventName = AuthorizeSecurityGroupIngress)"),
    }
    findings = []
    try:
        metric_filters = []
        pag = logs.get_paginator("describe_metric_filters")
        for page in pag.paginate():
            metric_filters.extend(page.get("metricFilters", []))
        existing_patterns = [f.get("filterPattern","") for f in metric_filters]
        for cis_id, (description, pattern_fragment) in required_patterns.items():
            if not any(pattern_fragment.split("(")[0] in p for p in existing_patterns):
                findings.append(format_finding("MEDIUM", cis_id,
                    f"cloudwatch/metric-filters/{region}",
                    f"{cis_id}: No metric filter for {description}",
                    f"Create CloudWatch metric filter and alarm for: {description}. ISO 27001 A.12.4.1"))
    except Exception as e:
        logger.warning(f"CWL check failed: {e}")
    return findings


def check_cis_4_1_ebs_encryption(ec2) -> list:
    """CIS 4.1 — Default EBS encryption enabled."""
    try:
        enc = ec2.get_ebs_encryption_by_default()
        if not enc.get("EbsEncryptionByDefault"):
            return [format_finding("MEDIUM","CIS-4.1",
                "ec2/ebs-default-encryption",
                "CIS 4.1: EBS encryption by default is NOT enabled in this region",
                "Enable: aws ec2 enable-ebs-encryption-by-default. ISO 27001 A.10.1.1")]
    except Exception:
        pass
    return []


def check_cis_5_1_no_wide_open_sg(ec2) -> list:
    """CIS 5.1 — No security groups with 0.0.0.0/0 on port 22/3389."""
    findings = []
    sgs = paginate(ec2, "describe_security_groups", "SecurityGroups")
    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            for cidr_r in rule.get("IpRanges", []):
                if cidr_r.get("CidrIp") == "0.0.0.0/0":
                    port = rule.get("FromPort", -1)
                    if port in (22, 3389):
                        findings.append(format_finding("CRITICAL","CIS-5.2",
                            f"ec2/sg/{sg['GroupId']}",
                            f"CIS 5.2: Port {port} open to 0.0.0.0/0 in SG {sg['GroupId']}",
                            "Restrict SSH/RDP to known CIDRs or use Systems Manager Session Manager."))
    return findings


COMPLIANCE_CHECKS = [
    ("CIS 1.1 — Root MFA",        lambda iam,_s3,_ct,_logs,_ec2,_r: check_cis_1_1_mfa_root(iam)),
    ("CIS 1.4 — No Root Keys",    lambda iam,_s3,_ct,_logs,_ec2,_r: check_cis_1_4_no_root_keys(iam)),
    ("CIS 1.10 — User MFA",       lambda iam,_s3,_ct,_logs,_ec2,_r: check_cis_1_8_mfa_all_users(iam)),
    ("CIS 2.1 — CloudTrail",      lambda _iam,_s3,ct,_logs,_ec2,r: check_cis_2_1_cloudtrail_enabled(ct,r)),
    ("CIS 2.6 — S3 CT Logging",   lambda _iam,s3,ct,_logs,_ec2,_r: check_cis_2_6_s3_logging(s3,ct)),
    ("CIS 3.x — Metric Filters",  lambda _iam,_s3,_ct,logs,_ec2,r: check_cis_3_1_log_metric_filters(logs,r)),
    ("CIS 4.1 — EBS Encryption",  lambda _iam,_s3,_ct,_logs,ec2,_r: check_cis_4_1_ebs_encryption(ec2)),
    ("CIS 5.2 — No Open SSH/RDP", lambda _iam,_s3,_ct,_logs,ec2,_r: check_cis_5_1_no_wide_open_sg(ec2)),
]


def run_compliance_audit(session, region) -> list:
    iam  = session.client("iam")
    s3   = session.client("s3")
    ct   = session.client("cloudtrail",       region_name=region)
    logs = session.client("logs",             region_name=region)
    ec2  = session.client("ec2",             region_name=region)
    all_findings = []
    for name, check_fn in COMPLIANCE_CHECKS:
        logger.info(f"  ✓ {name}")
        try:
            all_findings.extend(check_fn(iam, s3, ct, logs, ec2, region))
        except Exception as e:
            logger.warning(f"  ✗ {name} failed: {e}")
    return all_findings


def compliance_score(findings: list) -> float:
    """Calculate CIS compliance score as a percentage."""
    total_checks = len(COMPLIANCE_CHECKS)
    failed = len({f["check_id"] for f in findings})
    passed = max(0, total_checks - failed)
    return round((passed / total_checks) * 100, 1)


def main():
    parser = argparse.ArgumentParser(description="Cloud Compliance Audit Tool — CIS + ISO 27001")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region",  default="us-east-1")
    parser.add_argument("--output",  choices=["html","markdown","json","console"], default="console")
    parser.add_argument("--output-file", default=None)
    args = parser.parse_args()

    session    = get_session(args.profile, args.region)
    account_id = get_account_id(session)
    logger.info(f"Running compliance audit on account {account_id} ({args.region})")

    findings = run_compliance_audit(session, args.region)
    findings.sort(key=lambda x: -x.get("severity_score", 0))
    score = compliance_score(findings)
    logger.info(f"Compliance Score: {score}% | Findings: {len(findings)}")

    title = f"CIS / ISO 27001 Compliance Audit — {account_id}"
    if args.output == "console":
        sev_icons = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
        print(f"\n{'='*60}\n  Compliance Score: {score}%\n  Findings: {len(findings)}\n{'='*60}\n")
        for f in findings:
            iso = CIS_ISO_MAPPING.get(f["check_id"], "")
            print(f"{sev_icons.get(f['severity'],'•')} [{f['severity']}] {f['check_id']}  {iso}")
            print(f"   {f['description']}")
            print(f"   Fix: {f['remediation']}\n")
    elif args.output == "html":
        path = args.output_file or "report_templates/compliance_report.html"
        with open(path,"w") as fh:
            fh.write(generate_html_report(findings, title, account_id))
        logger.info(f"Report: {path}")
    elif args.output == "markdown":
        path = args.output_file or "report_templates/compliance_report.md"
        with open(path,"w") as fh:
            fh.write(generate_markdown_report(findings, title))
    elif args.output == "json":
        print(json.dumps({"score": score, "findings": findings}, indent=2))

if __name__ == "__main__":
    main()
