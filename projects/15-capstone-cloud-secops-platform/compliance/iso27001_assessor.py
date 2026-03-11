"""ISO 27001:2022 Annex A control assessor — maps AWS findings to ISO controls."""
import sys, json, logging
sys.path.insert(0, "../../../shared")
from utils.aws_helpers import get_session, get_account_id

logger = logging.getLogger(__name__)

ISO_CONTROLS = {
    "A.5.1":  "Policies for information security",
    "A.8.3":  "Information access restriction",
    "A.8.5":  "Secure authentication",
    "A.8.7":  "Protection against malware",
    "A.8.12": "Data leakage prevention",
    "A.8.16": "Monitoring activities",
    "A.8.20": "Network security controls",
    "A.8.24": "Use of cryptography",
}

FINDING_TO_ISO = {
    "IAM-001": ["A.8.5"],    # No MFA → secure authentication
    "IAM-002": ["A.8.5"],    # Stale keys → secure authentication
    "IAM-004": ["A.8.5"],    # Root keys → secure authentication
    "SG-001":  ["A.8.20"],   # Open SG → network controls
    "S3-003":  ["A.8.24"],   # No encryption → cryptography
    "S3-001":  ["A.8.12"],   # Public bucket → data leakage
    "FL-001":  ["A.8.16"],   # No flow logs → monitoring
    "CIS-2.1": ["A.8.16"],   # No CloudTrail → monitoring
}

def map_findings_to_iso(findings: list) -> dict:
    """Map a list of findings to ISO 27001:2022 controls."""
    control_gaps = {}
    for f in findings:
        check_id = f.get("check_id", "")
        controls = FINDING_TO_ISO.get(check_id, [])
        for ctrl in controls:
            if ctrl not in control_gaps:
                control_gaps[ctrl] = {"control": ISO_CONTROLS.get(ctrl, ctrl), "findings": []}
            control_gaps[ctrl]["findings"].append(f)
    return control_gaps

def generate_statement_of_applicability(findings: list) -> dict:
    """Produce simplified Statement of Applicability from findings."""
    gaps = map_findings_to_iso(findings)
    soa = {}
    for ctrl, ctrl_data in ISO_CONTROLS.items():
        gap_count = len(gaps.get(ctrl, {}).get("findings", []))
        soa[ctrl] = {
            "control_name": ctrl_data,
            "applicable": True,
            "implemented": gap_count == 0,
            "gap_count": gap_count,
            "status": "COMPLIANT" if gap_count == 0 else f"NON-COMPLIANT ({gap_count} gaps)",
        }
    return soa

if __name__ == "__main__":
    # Demo with sample findings
    sample = [
        {"check_id": "IAM-001", "severity": "CRITICAL", "resource": "iam/user/alice"},
        {"check_id": "SG-001",  "severity": "CRITICAL", "resource": "sg/sg-123"},
        {"check_id": "FL-001",  "severity": "HIGH",     "resource": "vpc/vpc-abc"},
    ]
    soa = generate_statement_of_applicability(sample)
    print("\nISO 27001:2022 Statement of Applicability\n" + "="*50)
    for ctrl, data in soa.items():
        status = "✅" if data["implemented"] else "❌"
        print(f"{status} {ctrl}: {data['control_name']} — {data['status']}")
