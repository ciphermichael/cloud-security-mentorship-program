"""Tests for VPC Flow Log audit checks."""
import boto3
import pytest
from moto import mock_ec2


@mock_ec2
class TestVPCFlowLogs:

    def setup_method(self):
        self.ec2 = boto3.client('ec2', region_name='us-east-1')
        self.vpc = self.ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']
        self.vpc_id = self.vpc['VpcId']

    def _run_audit(self) -> list:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
        from checks.flow_logs import audit_flow_logs
        session = boto3.Session(region_name='us-east-1')
        return audit_flow_logs(session, 'us-east-1')

    def test_vpc_without_flow_logs_flagged(self):
        """VPC with no flow logs must be flagged HIGH."""
        findings = self._run_audit()
        vpc_findings = [f for f in findings if self.vpc_id in str(f)]
        assert len(vpc_findings) >= 1
        assert any(f.get('severity') in ('HIGH', 'CRITICAL') for f in vpc_findings)

    def test_finding_has_remediation(self):
        """Each finding must include a remediation field."""
        findings = self._run_audit()
        for f in findings:
            assert 'remediation' in f, f'Finding missing remediation: {f}'
            assert len(f['remediation']) > 10

    def test_finding_has_resource_id(self):
        """Each finding must reference a resource ID."""
        findings = self._run_audit()
        for f in findings:
            assert 'resource' in f or 'vpc_id' in str(f).lower()
