"""
Unit tests for CIS AWS Foundations Benchmark compliance checker.
Uses moto to mock AWS services — no real credentials needed.

Run:
    pip install pytest moto[iam,ec2,cloudtrail,s3]
    pytest tests/ -v
"""
import json
import pytest
import boto3
from moto import mock_iam, mock_ec2, mock_cloudtrail, mock_s3
from unittest.mock import patch, MagicMock


def get_checker():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
    from audit_engine import CISChecker, ControlResult
    return CISChecker, ControlResult


# ── CIS 1.x IAM Checks ────────────────────────────────────────────────────────

@mock_iam
class TestCIS1RootAccount:

    def _run_check(self, method_name: str) -> list:
        Checker, _ = get_checker()
        c = Checker(region='us-east-1')
        getattr(c, method_name)()
        return c.results

    def test_1_4_root_key_detection(self):
        """CIS 1.4: Root account access keys must be detected."""
        with patch.object(
            boto3.client('iam', region_name='us-east-1').__class__,
            'get_account_summary',
            return_value={'SummaryMap': {'AccountAccessKeysPresent': 1}}
        ):
            Checker, _ = get_checker()
            c = Checker.__new__(Checker)
            c.iam = MagicMock()
            c.iam.get_account_summary.return_value = {
                'SummaryMap': {'AccountAccessKeysPresent': 1, 'AccountMFAEnabled': 1}
            }
            c.results = []
            c.check_1_4_no_root_access_keys()
            fails = [r for r in c.results if r.status == 'FAIL']
            assert len(fails) >= 1
            assert all(r.severity == 'CRITICAL' for r in fails)

    def test_1_4_no_root_key_passes(self):
        """CIS 1.4: Account with no root keys must PASS."""
        Checker, _ = get_checker()
        c = Checker.__new__(Checker)
        c.iam = MagicMock()
        c.iam.get_account_summary.return_value = {
            'SummaryMap': {'AccountAccessKeysPresent': 0, 'AccountMFAEnabled': 1}
        }
        c.results = []
        c.check_1_4_no_root_access_keys()
        passes = [r for r in c.results if r.status == 'PASS']
        assert len(passes) == 1

    def test_1_5_root_mfa_disabled_fails(self):
        """CIS 1.5: Root account without MFA must FAIL."""
        Checker, _ = get_checker()
        c = Checker.__new__(Checker)
        c.iam = MagicMock()
        c.iam.get_account_summary.return_value = {
            'SummaryMap': {'AccountMFAEnabled': 0}
        }
        c.results = []
        c.check_1_5_mfa_for_root()
        fails = [r for r in c.results if r.status == 'FAIL']
        assert len(fails) >= 1
        assert any(r.severity == 'CRITICAL' for r in fails)

    def test_1_5_root_mfa_enabled_passes(self):
        """CIS 1.5: Root account with MFA must PASS."""
        Checker, _ = get_checker()
        c = Checker.__new__(Checker)
        c.iam = MagicMock()
        c.iam.get_account_summary.return_value = {
            'SummaryMap': {'AccountMFAEnabled': 1}
        }
        c.results = []
        c.check_1_5_mfa_for_root()
        passes = [r for r in c.results if r.status == 'PASS']
        assert len(passes) == 1


@mock_iam
class TestCIS1PasswordPolicy:

    def test_1_9_weak_password_policy_fails(self):
        """CIS 1.9: Password policy with < 14 chars must FAIL."""
        iam = boto3.client('iam', region_name='us-east-1')
        iam.update_account_password_policy(MinimumPasswordLength=8)

        Checker, _ = get_checker()
        c = Checker(region='us-east-1')
        c.check_1_9_password_policy()
        fails = [r for r in c.results if r.control_id == '1.9' and r.status == 'FAIL']
        assert len(fails) >= 1

    def test_1_9_strong_password_policy_passes(self):
        """CIS 1.9: Password policy meeting all requirements must PASS."""
        iam = boto3.client('iam', region_name='us-east-1')
        iam.update_account_password_policy(
            MinimumPasswordLength=14,
            RequireSymbols=True,
            RequireNumbers=True,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            PasswordReusePrevention=24,
            MaxPasswordAge=365
        )
        Checker, _ = get_checker()
        c = Checker(region='us-east-1')
        c.check_1_9_password_policy()
        passes = [r for r in c.results if r.control_id == '1.9' and r.status == 'PASS']
        assert len(passes) >= 1


@mock_iam
class TestCIS1PolicyAttachment:

    def test_1_16_policy_on_user_fails(self):
        """CIS 1.16: User with directly attached policy must FAIL."""
        iam = boto3.client('iam', region_name='us-east-1')
        iam.create_user(UserName='direct-policy-user')
        iam.attach_user_policy(
            UserName='direct-policy-user',
            PolicyArn='arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess'
        )
        Checker, _ = get_checker()
        c = Checker(region='us-east-1')
        c.check_1_16_no_policies_on_users()
        fails = [r for r in c.results if r.control_id == '1.16' and r.status == 'FAIL']
        assert len(fails) >= 1

    def test_1_16_no_direct_policies_passes(self):
        """CIS 1.16: Account with no direct user policy attachments must PASS."""
        iam = boto3.client('iam', region_name='us-east-1')
        iam.create_user(UserName='clean-user')
        # No policy attachment — clean
        Checker, _ = get_checker()
        c = Checker(region='us-east-1')
        c.check_1_16_no_policies_on_users()
        passes = [r for r in c.results if r.control_id == '1.16' and r.status == 'PASS']
        assert len(passes) >= 1


# ── CIS 3.x Logging Checks ────────────────────────────────────────────────────

@mock_cloudtrail
@mock_s3
class TestCIS3Logging:

    def test_3_1_no_cloudtrail_fails(self):
        """CIS 3.1: Account with no CloudTrail trails must FAIL."""
        Checker, _ = get_checker()
        c = Checker(region='us-east-1')
        c.check_3_1_cloudtrail_enabled_all_regions()
        fails = [r for r in c.results if r.control_id == '3.1' and r.status == 'FAIL']
        assert len(fails) >= 1

    def test_3_1_multi_region_trail_passes(self):
        """CIS 3.1: Multi-region trail that is logging must PASS."""
        s3 = boto3.client('s3', region_name='us-east-1')
        s3.create_bucket(Bucket='cloudtrail-test-bucket')

        ct = boto3.client('cloudtrail', region_name='us-east-1')
        ct.create_trail(
            Name='multi-region-trail',
            S3BucketName='cloudtrail-test-bucket',
            IsMultiRegionTrail=True,
            IncludeGlobalServiceEvents=True,
            EnableLogFileValidation=True
        )
        ct.start_logging(Name='multi-region-trail')

        Checker, _ = get_checker()
        c = Checker(region='us-east-1')
        c.check_3_1_cloudtrail_enabled_all_regions()
        passes = [r for r in c.results if r.control_id == '3.1' and r.status == 'PASS']
        assert len(passes) >= 1

    def test_3_2_no_log_validation_fails(self):
        """CIS 3.2: Trail without log file validation must FAIL."""
        s3 = boto3.client('s3', region_name='us-east-1')
        s3.create_bucket(Bucket='ct-bucket-no-validation')
        ct = boto3.client('cloudtrail', region_name='us-east-1')
        ct.create_trail(
            Name='no-validation-trail',
            S3BucketName='ct-bucket-no-validation',
            IsMultiRegionTrail=True,
            EnableLogFileValidation=False  # Deliberately off
        )
        ct.start_logging(Name='no-validation-trail')

        Checker, _ = get_checker()
        c = Checker(region='us-east-1')
        c.check_3_2_cloudtrail_log_validation()
        fails = [r for r in c.results if r.control_id == '3.2' and r.status == 'FAIL']
        assert len(fails) >= 1


# ── CIS 5.x Networking Checks ─────────────────────────────────────────────────

@mock_ec2
class TestCIS5Networking:

    def setup_method(self):
        self.ec2 = boto3.client('ec2', region_name='us-east-1')
        self.vpc_id = self.ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']['VpcId']

    def test_5_3_open_ssh_fails(self):
        """CIS 5.3: SG with SSH open to 0.0.0.0/0 must FAIL."""
        sg = self.ec2.create_security_group(
            GroupName='open-ssh-sg', Description='test', VpcId=self.vpc_id
        )
        self.ec2.authorize_security_group_ingress(
            GroupId=sg['GroupId'],
            IpPermissions=[{
                'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        )
        Checker, _ = get_checker()
        c = Checker(region='us-east-1')
        c.check_5_3_no_ssh_open_to_world()
        fails = [r for r in c.results if r.control_id == '5.3' and r.status == 'FAIL']
        assert len(fails) >= 1
        assert any(r.severity == 'CRITICAL' for r in fails)

    def test_5_3_no_open_ssh_passes(self):
        """CIS 5.3: Account with no world-open SSH must PASS."""
        self.ec2.create_security_group(
            GroupName='clean-sg', Description='clean', VpcId=self.vpc_id
        )
        Checker, _ = get_checker()
        c = Checker(region='us-east-1')
        c.check_5_3_no_ssh_open_to_world()
        passes = [r for r in c.results if r.control_id == '5.3' and r.status == 'PASS']
        assert len(passes) >= 1


# ── Compliance Score Tests ─────────────────────────────────────────────────────

class TestComplianceScore:

    def test_score_100_percent_all_pass(self):
        """All controls PASS must produce 100% score."""
        Checker, ControlResult = get_checker()
        c = Checker.__new__(Checker)
        c.results = [
            ControlResult('1.4', 'No root keys', 'IAM', 'PASS', 'CRITICAL', 'ok', 'n/a'),
            ControlResult('1.5', 'Root MFA', 'IAM', 'PASS', 'CRITICAL', 'ok', 'n/a'),
            ControlResult('3.1', 'CloudTrail', 'Logging', 'PASS', 'HIGH', 'ok', 'n/a'),
        ]
        report = c.generate_report()
        assert report['score'] == '100.0%'

    def test_score_0_percent_all_fail(self):
        """All controls FAIL must produce 0% score."""
        Checker, ControlResult = get_checker()
        c = Checker.__new__(Checker)
        c.results = [
            ControlResult('1.4', 'No root keys', 'IAM', 'FAIL', 'CRITICAL', 'bad', 'fix it'),
            ControlResult('1.5', 'Root MFA', 'IAM', 'FAIL', 'CRITICAL', 'bad', 'fix it'),
        ]
        report = c.generate_report()
        assert report['score'] == '0.0%'

    def test_report_lists_failed_controls(self):
        """Report must include a list of all failed controls."""
        Checker, ControlResult = get_checker()
        c = Checker.__new__(Checker)
        c.results = [
            ControlResult('1.4', 'Root keys', 'IAM', 'FAIL', 'CRITICAL', 'present', 'delete'),
            ControlResult('1.5', 'Root MFA', 'IAM', 'PASS', 'CRITICAL', 'enabled', 'n/a'),
        ]
        report = c.generate_report()
        assert len(report['failed_controls']) == 1
        assert report['failed_controls'][0]['control_id'] == '1.4'
