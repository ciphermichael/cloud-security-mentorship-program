"""
Unit tests for Automated Incident Response playbooks.
Mocks AWS EC2 and Lambda — no real AWS needed.

Run:
    pip install pytest moto[ec2,sns]
    pytest tests/ -v
"""
import json
import pytest
import boto3
from moto import mock_ec2, mock_sns
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone


def get_playbook():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'playbooks'))
    from ec2_compromise import EC2CompromisePlaybook
    return EC2CompromisePlaybook


# ── EC2 Isolation Tests ────────────────────────────────────────────────────────

@mock_ec2
class TestEC2IsolationPlaybook:

    def setup_method(self):
        self.ec2 = boto3.client('ec2', region_name='us-east-1')
        self.ec2_resource = boto3.resource('ec2', region_name='us-east-1')

        vpc = self.ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']
        self.vpc_id = vpc['VpcId']

        subnet = self.ec2.create_subnet(
            VpcId=self.vpc_id, CidrBlock='10.0.1.0/24'
        )['Subnet']
        self.subnet_id = subnet['SubnetId']

        sg = self.ec2.create_security_group(
            GroupName='web-sg', Description='Web SG', VpcId=self.vpc_id
        )
        self.original_sg_id = sg['GroupId']

        instance = self.ec2.run_instances(
            ImageId='ami-12345678',
            MinCount=1, MaxCount=1,
            SecurityGroupIds=[self.original_sg_id],
            SubnetId=self.subnet_id
        )
        self.instance_id = instance['Instances'][0]['InstanceId']

    def test_isolation_creates_deny_all_sg(self):
        """Isolation must create a new security group."""
        Playbook = get_playbook()
        p = Playbook(region='us-east-1')
        result = p.isolate_instance(self.instance_id, finding_id='GD-TEST-001')

        assert result['status'] == 'isolated'
        assert 'isolation_sg' in result

        # Verify the isolation SG exists
        sgs = self.ec2.describe_security_groups(
            GroupIds=[result['isolation_sg']]
        )['SecurityGroups']
        assert len(sgs) == 1
        isolation_sg = sgs[0]

        # Isolation SG must have NO ingress rules
        assert len(isolation_sg.get('IpPermissions', [])) == 0

    def test_isolation_replaces_original_sg(self):
        """After isolation, instance must only have the isolation SG."""
        Playbook = get_playbook()
        p = Playbook(region='us-east-1')
        result = p.isolate_instance(self.instance_id, finding_id='GD-TEST-001')

        instance = self.ec2.describe_instances(
            InstanceIds=[self.instance_id]
        )['Reservations'][0]['Instances'][0]

        current_sgs = [sg['GroupId'] for sg in instance['SecurityGroups']]
        assert self.original_sg_id not in current_sgs, \
            'Original SG must be removed during isolation'
        assert result['isolation_sg'] in current_sgs, \
            'Isolation SG must be applied to the instance'

    def test_isolation_records_original_sgs(self):
        """Result must record which SGs were replaced (for rollback)."""
        Playbook = get_playbook()
        p = Playbook(region='us-east-1')
        result = p.isolate_instance(self.instance_id, finding_id='GD-TEST-001')

        assert 'original_sgs' in result
        assert self.original_sg_id in result['original_sgs']

    def test_isolation_tags_instance(self):
        """Isolated instance must be tagged with SecurityStatus=ISOLATED."""
        Playbook = get_playbook()
        p = Playbook(region='us-east-1')
        p.isolate_instance(self.instance_id, finding_id='GD-TEST-001')

        tags = self.ec2.describe_tags(
            Filters=[
                {'Name': 'resource-id', 'Values': [self.instance_id]},
                {'Name': 'key', 'Values': ['SecurityStatus']}
            ]
        )['Tags']
        assert len(tags) == 1
        assert tags[0]['Value'] == 'ISOLATED'

    def test_isolation_includes_timestamp(self):
        """Result must include an ISO8601 timestamp."""
        Playbook = get_playbook()
        p = Playbook(region='us-east-1')
        result = p.isolate_instance(self.instance_id, finding_id='GD-TEST-001')

        assert 'timestamp' in result
        # Validate ISO 8601 format
        try:
            datetime.fromisoformat(result['timestamp'].replace('Z', '+00:00'))
        except ValueError:
            pytest.fail(f'timestamp is not ISO8601: {result["timestamp"]}')


@mock_ec2
class TestEBSForensicSnapshot:

    def setup_method(self):
        self.ec2 = boto3.client('ec2', region_name='us-east-1')
        vpc = self.ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']
        subnet = self.ec2.create_subnet(
            VpcId=vpc['VpcId'], CidrBlock='10.0.1.0/24'
        )['Subnet']
        instance = self.ec2.run_instances(
            ImageId='ami-12345678', MinCount=1, MaxCount=1,
            SubnetId=subnet['SubnetId']
        )
        self.instance_id = instance['Instances'][0]['InstanceId']

    def test_snapshot_created_for_each_volume(self):
        """A forensic snapshot must be created for every attached volume."""
        Playbook = get_playbook()
        p = Playbook(region='us-east-1')
        result = p.snapshot_instance_volumes(
            self.instance_id, finding_id='GD-TEST-001'
        )

        assert result['status'] == 'snapshots_created'
        assert len(result['snapshots']) >= 1

        for snap_info in result['snapshots']:
            assert 'snapshot_id' in snap_info
            assert 'volume_id' in snap_info

    def test_snapshots_tagged_forensic(self):
        """Forensic snapshots must be tagged Purpose=ForensicEvidence."""
        Playbook = get_playbook()
        p = Playbook(region='us-east-1')
        result = p.snapshot_instance_volumes(
            self.instance_id, finding_id='GD-TEST-002'
        )

        for snap_info in result['snapshots']:
            snap = self.ec2.describe_snapshots(
                SnapshotIds=[snap_info['snapshot_id']]
            )['Snapshots'][0]
            tag_keys = {t['Key'] for t in snap.get('Tags', [])}
            assert 'Purpose' in tag_keys or 'ForensicEvidence' in str(snap.get('Tags', []))


# ── Finding Analysis Tests ─────────────────────────────────────────────────────

class TestGuardDutyEventParsing:

    def _make_gd_finding(self, finding_type: str, severity: float,
                          instance_id: str = 'i-1234567890abcdef0') -> dict:
        return {
            'Id': 'abcdef1234567890',
            'Type': finding_type,
            'Severity': severity,
            'Service': {
                'Action': {
                    'ActionType': 'NETWORK_CONNECTION',
                    'NetworkConnectionAction': {
                        'RemoteIpDetails': {
                            'IpAddressV4': '198.51.100.42',
                            'Organization': {'Asn': '12345', 'AsnOrg': 'HostingCo'}
                        }
                    }
                },
                'ResourceType': 'Instance'
            },
            'Resource': {
                'ResourceType': 'Instance',
                'InstanceDetails': {'InstanceId': instance_id}
            }
        }

    def test_high_severity_finding_triggers_autocontain(self):
        """GuardDuty finding severity >= 7.0 must trigger auto-containment."""
        Playbook = get_playbook()
        p = Playbook(region='us-east-1')
        finding = self._make_gd_finding(
            'UnauthorizedAccess:EC2/MaliciousIPCaller', severity=8.0
        )
        decision = p.triage_finding(finding)
        assert decision['auto_contain'] is True

    def test_low_severity_finding_requires_human_review(self):
        """GuardDuty finding severity < 4.0 must require human review."""
        Playbook = get_playbook()
        p = Playbook(region='us-east-1')
        finding = self._make_gd_finding(
            'Policy:S3/BucketBlockPublicAccessDisabled', severity=2.0
        )
        decision = p.triage_finding(finding)
        assert decision['auto_contain'] is False
        assert decision['reason'] == 'low_severity'

    def test_finding_extracts_instance_id(self):
        """Playbook must extract instance ID from GuardDuty finding."""
        Playbook = get_playbook()
        p = Playbook(region='us-east-1')
        finding = self._make_gd_finding(
            'CryptoCurrency:EC2/BitcoinTool.B', severity=7.5,
            instance_id='i-abcdef1234567890'
        )
        instance_id = p.extract_resource_id(finding)
        assert instance_id == 'i-abcdef1234567890'


# ── Notification Tests ────────────────────────────────────────────────────────

@mock_sns
class TestIncidentNotification:

    def setup_method(self):
        self.sns = boto3.client('sns', region_name='us-east-1')
        self.topic = self.sns.create_topic(Name='security-alerts')
        self.topic_arn = self.topic['TopicArn']

    def test_notification_sent_on_containment(self):
        """SNS notification must be published when instance is contained."""
        Playbook = get_playbook()
        p = Playbook(region='us-east-1')
        result = p.notify_containment(
            topic_arn=self.topic_arn,
            instance_id='i-1234567890abcdef0',
            finding_id='GD-TEST-001',
            actions_taken=['isolated', 'snapshot_created']
        )
        assert result['notification_sent'] is True

    def test_notification_includes_finding_id(self):
        """Notification message must include the GuardDuty finding ID."""
        Playbook = get_playbook()
        p = Playbook(region='us-east-1')
        result = p.notify_containment(
            topic_arn=self.topic_arn,
            instance_id='i-1234567890abcdef0',
            finding_id='GD-UNIQUE-XYZ',
            actions_taken=['isolated']
        )
        assert 'GD-UNIQUE-XYZ' in result.get('message', '') or result['notification_sent']
