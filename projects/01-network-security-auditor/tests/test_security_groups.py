"""
Unit tests for Network Security Auditor — Security Group checks.
Uses moto to mock AWS EC2 API — no real AWS credentials needed.

Run:
    pip install pytest moto[ec2]
    pytest tests/ -v
"""
import pytest
import boto3
from moto import mock_ec2


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_sg(ec2_client, vpc_id: str, name: str, ingress_rules: list) -> str:
    sg = ec2_client.create_security_group(
        GroupName=name, Description=name, VpcId=vpc_id
    )
    sg_id = sg['GroupId']
    if ingress_rules:
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id, IpPermissions=ingress_rules
        )
    return sg_id


def get_findings_for_sg(sg_id: str, region: str = 'us-east-1') -> list:
    """Import and run the check against a specific SG."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
    from checks.security_groups import audit_security_groups
    session = boto3.Session(region_name=region)
    findings = audit_security_groups(session, region)
    return [f for f in findings if f.get('resource', '').startswith(sg_id)
            or sg_id in f.get('resource', '')]


# ── Security Group Tests ──────────────────────────────────────────────────────

@mock_ec2
class TestSSHDetection:

    def setup_method(self):
        self.ec2 = boto3.client('ec2', region_name='us-east-1')
        self.vpc_id = self.ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']['VpcId']

    def test_open_ssh_flagged_critical(self):
        """SSH open to 0.0.0.0/0 must be CRITICAL."""
        sg_id = make_sg(self.ec2, self.vpc_id, 'open-ssh', [{
            'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }])
        findings = get_findings_for_sg(sg_id)
        assert any(f.get('severity') == 'CRITICAL' for f in findings), \
            f'Expected CRITICAL for open SSH, got: {findings}'

    def test_open_rdp_flagged_critical(self):
        """RDP open to 0.0.0.0/0 must be CRITICAL."""
        sg_id = make_sg(self.ec2, self.vpc_id, 'open-rdp', [{
            'IpProtocol': 'tcp', 'FromPort': 3389, 'ToPort': 3389,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }])
        findings = get_findings_for_sg(sg_id)
        assert any(f.get('severity') == 'CRITICAL' for f in findings)

    def test_ssh_private_cidr_not_flagged(self):
        """SSH restricted to private CIDR must not be flagged."""
        sg_id = make_sg(self.ec2, self.vpc_id, 'private-ssh', [{
            'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
            'IpRanges': [{'CidrIp': '10.0.0.0/8'}]
        }])
        findings = get_findings_for_sg(sg_id)
        open_world = [f for f in findings if '0.0.0.0/0' in str(f)]
        assert len(open_world) == 0

    def test_open_ssh_ipv6_flagged(self):
        """SSH open to ::/0 (all IPv6) must also be flagged."""
        sg_id = make_sg(self.ec2, self.vpc_id, 'ipv6-ssh', [{
            'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
            'Ipv6Ranges': [{'CidrIpv6': '::/0'}]
        }])
        findings = get_findings_for_sg(sg_id)
        assert any('22' in str(f) or 'SSH' in str(f).upper() for f in findings), \
            'IPv6 open SSH should be detected'


@mock_ec2
class TestDatabasePortDetection:

    def setup_method(self):
        self.ec2 = boto3.client('ec2', region_name='us-east-1')
        self.vpc_id = self.ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']['VpcId']

    @pytest.mark.parametrize("port,service", [
        (3306, 'MySQL'), (5432, 'PostgreSQL'), (1433, 'MSSQL'),
        (27017, 'MongoDB'), (6379, 'Redis'),
    ])
    def test_database_port_open_to_world(self, port, service):
        sg_id = make_sg(self.ec2, self.vpc_id, f'open-{port}', [{
            'IpProtocol': 'tcp', 'FromPort': port, 'ToPort': port,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }])
        findings = get_findings_for_sg(sg_id)
        assert len(findings) >= 1, f'{service} port {port} open to world not detected'


@mock_ec2
class TestAllTrafficRule:

    def setup_method(self):
        self.ec2 = boto3.client('ec2', region_name='us-east-1')
        self.vpc_id = self.ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']['VpcId']

    def test_all_traffic_open_flagged_critical(self):
        """Allow all inbound from 0.0.0.0/0 (-1 protocol) must be CRITICAL."""
        sg_id = make_sg(self.ec2, self.vpc_id, 'all-traffic', [{
            'IpProtocol': '-1',
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }])
        findings = get_findings_for_sg(sg_id)
        assert any(f.get('severity') == 'CRITICAL' for f in findings)

    def test_clean_sg_has_no_findings(self):
        """A SG with only HTTPS (443) from 0.0.0.0/0 should produce LOW/no finding."""
        make_sg(self.ec2, self.vpc_id, 'clean-https', [{
            'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }])
        # A SG with no dangerous ports should have no CRITICAL findings
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
        from checks.security_groups import audit_security_groups
        session = boto3.Session(region_name='us-east-1')
        findings = audit_security_groups(session, 'us-east-1')
        critical = [f for f in findings if f.get('severity') == 'CRITICAL']
        # None of the critical findings should be about port 443
        assert not any('443' in str(f) for f in critical)
