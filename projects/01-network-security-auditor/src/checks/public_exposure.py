"""Public exposure checks — EC2 instances and Elastic IPs."""
import sys
sys.path.insert(0, "../../../shared")
from utils.aws_helpers import format_finding, paginate


def audit_public_exposure(session, region: str) -> list:
    """Find EC2 instances with public IPs and flag exposure risk."""
    findings = []
    ec2 = session.client("ec2", region_name=region)

    reservations = paginate(ec2, "describe_instances", "Reservations")
    for res in reservations:
        for instance in res.get("Instances", []):
            if instance.get("State", {}).get("Name") != "running":
                continue
            instance_id = instance["InstanceId"]
            public_ip = instance.get("PublicIpAddress")
            name = next((t["Value"] for t in instance.get("Tags", [])
                         if t["Key"] == "Name"), instance_id)

            if public_ip:
                # Check if instance is in a public subnet
                subnet_id = instance.get("SubnetId", "unknown")
                findings.append(format_finding(
                    severity="MEDIUM",
                    check_id="PE-001",
                    resource=f"ec2/{instance_id} ({name})",
                    description=f"Running EC2 instance has public IP {public_ip} — directly internet-routable",
                    remediation="Use a load balancer for public-facing services. "
                                "Move instances to private subnets; use NAT Gateway for outbound traffic."
                ))

    # Check Elastic IPs not associated to anything
    eips = ec2.describe_addresses().get("Addresses", [])
    for eip in eips:
        if "AssociationId" not in eip:
            findings.append(format_finding(
                severity="LOW",
                check_id="PE-002",
                resource=f"eip/{eip.get('AllocationId', 'unknown')}",
                description=f"Elastic IP {eip.get('PublicIp')} is allocated but unassociated (cost + attack surface)",
                remediation="Release unused Elastic IPs to reduce attack surface and avoid unnecessary costs."
            ))

    return findings


def audit_nacls(session, region: str) -> list:
    """Check NACLs for overly permissive rules."""
    findings = []
    ec2 = session.client("ec2", region_name=region)

    nacls = paginate(ec2, "describe_network_acls", "NetworkAcls")

    for nacl in nacls:
        nacl_id = nacl["NetworkAclId"]
        is_default = nacl.get("IsDefault", False)

        for entry in nacl.get("Entries", []):
            # Egress=False means inbound
            if entry.get("Egress"):
                continue
            rule_action = entry.get("RuleAction", "allow")
            protocol = entry.get("Protocol", "-1")
            cidr = entry.get("CidrBlock", "")

            # Rule allows ALL traffic from 0.0.0.0/0
            if (rule_action == "allow" and
                    protocol == "-1" and cidr == "0.0.0.0/0"):
                findings.append(format_finding(
                    severity="MEDIUM",
                    check_id="NACL-001",
                    resource=f"nacl/{nacl_id}",
                    description=f"NACL inbound rule #{entry.get('RuleNumber')} allows ALL traffic from 0.0.0.0/0",
                    remediation="NACLs are stateless — restrict inbound to required ports only. "
                                "Use layered defence with security groups."
                ))

    return findings
