"""
Unit tests for IAM Security Analyser.
Uses moto to mock IAM API — no real AWS needed.

Run:
    pip install pytest moto[iam]
    pytest tests/ -v
"""
import csv
import io
import json
import time
import pytest
import boto3
from moto import mock_iam
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock


def get_analyser():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
    from analyser import IAMSecurityAnalyser
    return IAMSecurityAnalyser


# ── Credential Report Tests ───────────────────────────────────────────────────

class TestCredentialReportParsing:
    """Test parsing logic with mocked CSV data (no live AWS needed)."""

    def _make_row(self, **overrides) -> dict:
        defaults = {
            'user': 'testuser',
            'arn': 'arn:aws:iam::123456789012:user/testuser',
            'user_creation_time': '2023-01-01T00:00:00+00:00',
            'password_enabled': 'true',
            'password_last_used': 'N/A',
            'password_last_changed': '2023-01-01T00:00:00+00:00',
            'password_next_rotation': 'N/A',
            'mfa_active': 'false',
            'access_key_1_active': 'false',
            'access_key_1_last_rotated': 'N/A',
            'access_key_1_last_used_date': 'N/A',
            'access_key_1_last_used_region': 'N/A',
            'access_key_1_last_used_service': 'N/A',
            'access_key_2_active': 'false',
            'access_key_2_last_rotated': 'N/A',
            'access_key_2_last_used_date': 'N/A',
            'access_key_2_last_used_region': 'N/A',
            'access_key_2_last_used_service': 'N/A',
            'cert_1_active': 'false',
            'cert_1_last_rotated': 'N/A',
            'cert_2_active': 'false',
            'cert_2_last_rotated': 'N/A',
        }
        defaults.update(overrides)
        return defaults

    def test_no_mfa_flagged_high(self):
        """Console user without MFA must produce HIGH finding."""
        Analyser = get_analyser()
        a = Analyser.__new__(Analyser)
        a.findings = []
        a._now = datetime.now(timezone.utc)

        row = self._make_row(mfa_active='false', password_enabled='true')
        a._check_row(row)
        assert any(f.severity in ('HIGH', 'CRITICAL') and 'mfa' in f.rule_id.lower()
                   for f in a.findings), f'No MFA finding: {a.findings}'

    def test_mfa_enabled_not_flagged(self):
        """User with MFA enabled must not get an MFA finding."""
        Analyser = get_analyser()
        a = Analyser.__new__(Analyser)
        a.findings = []
        a._now = datetime.now(timezone.utc)

        row = self._make_row(mfa_active='true', password_enabled='true')
        a._check_row(row)
        mfa_findings = [f for f in a.findings if 'mfa' in f.rule_id.lower()]
        assert len(mfa_findings) == 0

    def test_stale_access_key_flagged(self):
        """Access key older than 90 days must produce HIGH finding."""
        Analyser = get_analyser()
        a = Analyser.__new__(Analyser)
        a.findings = []
        a._now = datetime.now(timezone.utc)

        old_date = (a._now - timedelta(days=100)).isoformat()
        row = self._make_row(
            access_key_1_active='true',
            access_key_1_last_rotated=old_date,
            access_key_1_last_used_date=old_date,
        )
        a._check_row(row)
        stale_findings = [f for f in a.findings if 'IAM-005' in f.rule_id]
        assert len(stale_findings) >= 1

    def test_fresh_access_key_not_flagged(self):
        """Access key under 90 days old must not produce a stale finding."""
        Analyser = get_analyser()
        a = Analyser.__new__(Analyser)
        a.findings = []
        a._now = datetime.now(timezone.utc)

        fresh_date = (a._now - timedelta(days=30)).isoformat()
        row = self._make_row(
            access_key_1_active='true',
            access_key_1_last_rotated=fresh_date,
            access_key_1_last_used_date=fresh_date,
        )
        a._check_row(row)
        stale_findings = [f for f in a.findings if 'IAM-005' in f.rule_id]
        assert len(stale_findings) == 0

    def test_never_used_key_flagged(self):
        """Active key that has never been used must be flagged MEDIUM."""
        Analyser = get_analyser()
        a = Analyser.__new__(Analyser)
        a.findings = []
        a._now = datetime.now(timezone.utc)

        fresh_date = (a._now - timedelta(days=10)).isoformat()
        row = self._make_row(
            access_key_1_active='true',
            access_key_1_last_rotated=fresh_date,
            access_key_1_last_used_date='N/A',  # Never used
        )
        a._check_row(row)
        unused_findings = [f for f in a.findings if 'IAM-006' in f.rule_id]
        assert len(unused_findings) >= 1


# ── Policy Checks ─────────────────────────────────────────────────────────────

@mock_iam
class TestOverPrivilegeDetection:

    def setup_method(self):
        self.iam = boto3.client('iam', region_name='us-east-1')

    def test_wildcard_admin_policy_flagged_critical(self):
        """Customer policy with Action:* and Resource:* must be CRITICAL."""
        self.iam.create_policy(
            PolicyName='WildcardAdmin',
            PolicyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]
            })
        )
        Analyser = get_analyser()
        a = Analyser(region='us-east-1')
        a.check_overprivileged_policies()
        critical = [f for f in a.findings if f.severity == 'CRITICAL' and 'IAM-007' in f.rule_id]
        assert len(critical) >= 1

    def test_scoped_policy_not_flagged(self):
        """Policy with specific actions and resources must not be flagged."""
        self.iam.create_policy(
            PolicyName='ScopedS3Read',
            PolicyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': ['s3:GetObject', 's3:ListBucket'],
                    'Resource': 'arn:aws:s3:::my-specific-bucket/*'
                }]
            })
        )
        Analyser = get_analyser()
        a = Analyser(region='us-east-1')
        a.check_overprivileged_policies()
        wildcard_findings = [f for f in a.findings if 'IAM-007' in f.rule_id]
        assert len(wildcard_findings) == 0

    def test_admin_attached_to_user_flagged(self):
        """User with AdministratorAccess directly attached must be CRITICAL."""
        self.iam.create_user(UserName='admin-user')
        self.iam.attach_user_policy(
            UserName='admin-user',
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        Analyser = get_analyser()
        a = Analyser(region='us-east-1')
        a.check_admin_attached_to_users()
        admin_findings = [f for f in a.findings if 'IAM-008' in f.rule_id
                          and f.resource_name == 'admin-user']
        assert len(admin_findings) >= 1

    def test_inline_policy_flagged_low(self):
        """User with inline policy must produce a LOW finding."""
        self.iam.create_user(UserName='inline-user')
        self.iam.put_user_policy(
            UserName='inline-user',
            PolicyName='InlinePolicy',
            PolicyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{'Effect': 'Allow', 'Action': 's3:ListBuckets', 'Resource': '*'}]
            })
        )
        Analyser = get_analyser()
        a = Analyser(region='us-east-1')
        a.check_inline_policies()
        inline_findings = [f for f in a.findings if 'IAM-009' in f.rule_id]
        assert len(inline_findings) >= 1


# ── Report Tests ──────────────────────────────────────────────────────────────

class TestReportGeneration:

    def test_report_structure(self):
        """Report must have generated_at, summary, and findings."""
        Analyser = get_analyser()
        a = Analyser.__new__(Analyser)
        a.findings = []
        a._now = datetime.now(timezone.utc)
        report = a.generate_report()
        assert 'generated_at' in report
        assert 'summary' in report
        assert 'findings' in report
        assert 'total' in report['summary']

    def test_severity_ordering_in_report(self):
        """Report findings must be sorted CRITICAL → HIGH → MEDIUM → LOW."""
        from dataclasses import dataclass, field

        Analyser = get_analyser()
        a = Analyser.__new__(Analyser)
        a._now = datetime.now(timezone.utc)

        # Import Finding from the analyser module
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
        from analyser import Finding

        a.findings = [
            Finding('R-003', 'LOW', 'USER', 'u', 'arn', 'desc', 'fix'),
            Finding('R-001', 'CRITICAL', 'USER', 'u', 'arn', 'desc', 'fix'),
            Finding('R-002', 'HIGH', 'USER', 'u', 'arn', 'desc', 'fix'),
        ]
        report = a.generate_report()
        severities = [f['severity'] for f in report['findings']]
        order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        for i in range(len(severities) - 1):
            assert order[severities[i]] <= order[severities[i + 1]], \
                f'Report findings not sorted: {severities}'
