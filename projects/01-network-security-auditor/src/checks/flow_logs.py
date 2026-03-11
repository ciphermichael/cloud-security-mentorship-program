"""VPC Flow Log coverage checks."""
import sys
sys.path.insert(0, "../../../shared")
from utils.aws_helpers import format_finding, paginate


def audit_flow_logs(session, region: str) -> list:
    """Ensure all VPCs have flow logging enabled."""
    findings = []
    ec2 = session.client("ec2", region_name=region)

    vpcs = paginate(ec2, "describe_vpcs", "Vpcs")
    flow_logs = paginate(ec2, "describe_flow_logs", "FlowLogs")

    # Map VPC ID -> flow log status
    logged_vpcs = {}
    for fl in flow_logs:
        resource_id = fl.get("ResourceId", "")
        status = fl.get("FlowLogStatus", "")
        log_dest = fl.get("LogDestinationType", "cloud-watch-logs")
        if status == "ACTIVE":
            if resource_id not in logged_vpcs:
                logged_vpcs[resource_id] = []
            logged_vpcs[resource_id].append(log_dest)

    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        is_default = vpc.get("IsDefault", False)
        name = next((t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"), vpc_id)

        if vpc_id not in logged_vpcs:
            severity = "HIGH" if not is_default else "MEDIUM"
            findings.append(format_finding(
                severity=severity,
                check_id="FL-001",
                resource=f"vpc/{vpc_id} ({name})",
                description=f"VPC has no active flow logs — network traffic is invisible to security monitoring",
                remediation="Enable VPC Flow Logs to CloudWatch Logs or S3. "
                            "Recommended: ALL traffic (ACCEPT+REJECT) with 1-minute aggregation."
            ))
        else:
            # Check if only S3 delivery (no real-time alerting)
            dests = logged_vpcs[vpc_id]
            if all(d == "s3" for d in dests):
                findings.append(format_finding(
                    severity="LOW",
                    check_id="FL-002",
                    resource=f"vpc/{vpc_id} ({name})",
                    description="VPC Flow Logs delivered to S3 only — no real-time CloudWatch alerting possible",
                    remediation="Add a CloudWatch Logs destination for flow logs to enable real-time metric filters and alarms."
                ))

    return findings
