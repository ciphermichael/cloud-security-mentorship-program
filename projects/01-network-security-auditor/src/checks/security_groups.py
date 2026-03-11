"""Security group misconfiguration checks for AWS Network Auditor."""
import sys
sys.path.insert(0, "../../../shared")
from utils.aws_helpers import format_finding, paginate


# Ports that should NEVER be open to 0.0.0.0/0
CRITICAL_PORTS = {
    22: "SSH",
    3389: "RDP",
    5900: "VNC",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}

HIGH_RISK_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    445: "SMB",
    2049: "NFS",
    4333: "mSQL",
}

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def audit_security_groups(session, region: str) -> list:
    """Check all security groups for dangerous inbound rules."""
    findings = []
    ec2 = session.client("ec2", region_name=region)

    sgs = paginate(ec2, "describe_security_groups", "SecurityGroups")

    for sg in sgs:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "unnamed")
        vpc_id = sg.get("VpcId", "no-vpc")
        resource = f"sg/{sg_id} ({sg_name}) in {vpc_id}"

        # Check 1: Wide-open inbound rules
        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", -1)
            to_port = rule.get("ToPort", -1)
            protocol = rule.get("IpProtocol", "-1")

            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                if cidr in OPEN_CIDRS:
                    # Protocol -1 means ALL traffic
                    if protocol == "-1":
                        findings.append(format_finding(
                            severity="CRITICAL",
                            check_id="SG-001",
                            resource=resource,
                            description=f"Security group allows ALL traffic from {cidr}",
                            remediation="Remove the 0.0.0.0/0 rule and restrict to known CIDRs or security group references."
                        ))
                    # Specific critical port
                    elif from_port in CRITICAL_PORTS:
                        port_name = CRITICAL_PORTS[from_port]
                        findings.append(format_finding(
                            severity="CRITICAL",
                            check_id="SG-002",
                            resource=resource,
                            description=f"Port {from_port} ({port_name}) open to {cidr}",
                            remediation=f"Restrict {port_name} (port {from_port}) to specific IP ranges or use Systems Manager Session Manager instead."
                        ))
                    elif from_port in HIGH_RISK_PORTS:
                        port_name = HIGH_RISK_PORTS[from_port]
                        findings.append(format_finding(
                            severity="HIGH",
                            check_id="SG-003",
                            resource=resource,
                            description=f"Port {from_port} ({port_name}) open to {cidr}",
                            remediation=f"Restrict {port_name} access to specific IP ranges only."
                        ))
                    # Port range check — wide ranges
                    elif from_port == 0 and to_port == 65535:
                        findings.append(format_finding(
                            severity="HIGH",
                            check_id="SG-004",
                            resource=resource,
                            description=f"All ports (0-65535) open to {cidr}",
                            remediation="Restrict to only required ports. Apply principle of least privilege."
                        ))

            # Check IPv6 too
            for ip_range in rule.get("Ipv6Ranges", []):
                cidr = ip_range.get("CidrIpv6", "")
                if cidr == "::/0" and protocol == "-1":
                    findings.append(format_finding(
                        severity="CRITICAL",
                        check_id="SG-001",
                        resource=resource,
                        description=f"Security group allows ALL IPv6 traffic from ::/0",
                        remediation="Remove ::/0 inbound rule. Restrict to specific IPv6 CIDRs."
                    ))

        # Check 2: Unrestricted egress
        for rule in sg.get("IpPermissionsEgress", []):
            protocol = rule.get("IpProtocol", "-1")
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0" and protocol == "-1":
                    findings.append(format_finding(
                        severity="MEDIUM",
                        check_id="SG-005",
                        resource=resource,
                        description="Unrestricted egress (all ports to 0.0.0.0/0) — potential data exfiltration path",
                        remediation="Restrict egress to required destinations and ports only (defence-in-depth)."
                    ))
                    break  # One finding per SG for egress

        # Check 3: Default security group has rules
        if sg_name == "default":
            inbound = sg.get("IpPermissions", [])
            outbound = sg.get("IpPermissionsEgress", [])
            if inbound or outbound:
                findings.append(format_finding(
                    severity="MEDIUM",
                    check_id="SG-006",
                    resource=resource,
                    description="Default security group has inbound/outbound rules (should have none)",
                    remediation="Remove all rules from the default security group. Use dedicated SGs for all resources."
                ))

    return findings
