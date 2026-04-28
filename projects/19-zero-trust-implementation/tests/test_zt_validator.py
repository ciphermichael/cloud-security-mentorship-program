"""
Unit tests for Zero Trust Identity Validator.
Uses moto to mock IAM — no real AWS credentials needed.

Run:
    pip install pytest moto[iam]
    pytest tests/ -v
"""
import pytest
import boto3
from moto import mock_iam
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.zt_validator import ZeroTrustValidator, TrustDecision, DEFAULT_POLICY


# ── Helper to create test IAM user with MFA ────────────────────────────────────

@mock_iam
def _setup_user_with_mfa(username: str = 'test-user') -> str:
    iam = boto3.client('iam', region_name='us-east-1')
    iam.create_user(UserName=username)
    # Create and assign a virtual MFA device
    mfa = iam.create_virtual_mfa_device(VirtualMFADeviceName=f'mfa-{username}')
    serial = mfa['VirtualMFADevice']['SerialNumber']
    iam.enable_mfa_device(
        UserName=username,
        SerialNumber=serial,
        AuthenticationCode1='123456',
        AuthenticationCode2='654321',
    )
    return serial


# ── MFA Enrolled Tests ─────────────────────────────────────────────────────────

class TestMFACheck:

    @mock_iam
    def test_user_with_mfa_passes(self):
        iam = boto3.client('iam', region_name='us-east-1')
        iam.create_user(UserName='alice')
        mfa = iam.create_virtual_mfa_device(VirtualMFADeviceName='mfa-alice')
        iam.enable_mfa_device(
            UserName='alice',
            SerialNumber=mfa['VirtualMFADevice']['SerialNumber'],
            AuthenticationCode1='111111',
            AuthenticationCode2='222222',
        )
        validator = ZeroTrustValidator.__new__(ZeroTrustValidator)
        validator.iam = iam
        validator.policy = DEFAULT_POLICY.copy()
        result = validator._check_mfa_enabled('alice')
        assert result.passed is True

    @mock_iam
    def test_user_without_mfa_fails(self):
        iam = boto3.client('iam', region_name='us-east-1')
        iam.create_user(UserName='bob')
        validator = ZeroTrustValidator.__new__(ZeroTrustValidator)
        validator.iam = iam
        validator.policy = DEFAULT_POLICY.copy()
        result = validator._check_mfa_enabled('bob')
        assert result.passed is False
        assert result.severity == 'CRITICAL'


# ── Key Age Tests ──────────────────────────────────────────────────────────────

class TestKeyAgeCheck:

    @mock_iam
    def test_fresh_key_passes(self):
        iam = boto3.client('iam', region_name='us-east-1')
        iam.create_user(UserName='carol')
        iam.create_access_key(UserName='carol')

        validator = ZeroTrustValidator.__new__(ZeroTrustValidator)
        validator.iam = iam
        validator.policy = {**DEFAULT_POLICY, 'max_key_age_days': 90}
        result = validator._check_access_key_age('carol')
        assert result.passed is True

    @mock_iam
    def test_no_active_keys_passes(self):
        iam = boto3.client('iam', region_name='us-east-1')
        iam.create_user(UserName='dave')

        validator = ZeroTrustValidator.__new__(ZeroTrustValidator)
        validator.iam = iam
        validator.policy = DEFAULT_POLICY.copy()
        result = validator._check_access_key_age('dave')
        assert result.passed is True  # No active keys = no stale key risk


# ── Region Check Tests ─────────────────────────────────────────────────────────

class TestRegionCheck:

    def _make_validator(self, approved_regions: list) -> ZeroTrustValidator:
        v = ZeroTrustValidator.__new__(ZeroTrustValidator)
        v.policy = {**DEFAULT_POLICY, 'approved_regions': approved_regions}
        return v

    def test_approved_region_passes(self):
        v = self._make_validator(['us-east-1', 'us-west-2'])
        result = v._check_source_region('us-east-1')
        assert result.passed is True

    def test_unapproved_region_fails(self):
        v = self._make_validator(['us-east-1', 'us-west-2'])
        result = v._check_source_region('ap-northeast-1')
        assert result.passed is False
        assert result.severity == 'HIGH'

    def test_no_restriction_always_passes(self):
        v = self._make_validator([])
        result = v._check_source_region('ap-northeast-1')
        assert result.passed is True


# ── MFA Age Tests ──────────────────────────────────────────────────────────────

class TestMFAAge:

    def _make_validator(self) -> ZeroTrustValidator:
        v = ZeroTrustValidator.__new__(ZeroTrustValidator)
        v.policy = {**DEFAULT_POLICY, 'max_mfa_age_seconds': 3600}
        return v

    def test_recent_mfa_passes(self):
        v = self._make_validator()
        recent = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
        ctx = {'attributes': {'creationDate': recent.replace('+00:00', 'Z')}}
        result = v._check_mfa_age(ctx)
        assert result.passed is True

    def test_old_mfa_fails(self):
        v = self._make_validator()
        old = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        ctx = {'attributes': {'creationDate': old.replace('+00:00', 'Z')}}
        result = v._check_mfa_age(ctx)
        assert result.passed is False

    def test_missing_mfa_timestamp_fails(self):
        v = self._make_validator()
        ctx = {'attributes': {}}
        result = v._check_mfa_age(ctx)
        assert result.passed is False


# ── Trust Decision Tests ───────────────────────────────────────────────────────

class TestTrustDecision:

    def test_deny_when_any_check_fails(self):
        from src.zt_validator import TrustCheckResult
        decision = TrustDecision(
            identity_arn='arn:aws:iam::123:user/test',
            trust_decision='DENY',
            overall_passed=False,
            checks=[
                TrustCheckResult('mfa', True, 'OK'),
                TrustCheckResult('region', False, 'Unapproved region', 'HIGH'),
            ]
        )
        assert decision.trust_decision == 'DENY'
        assert not decision.overall_passed
        assert len(decision.failed_checks) == 1
        assert 'Unapproved region' in decision.reasons

    def test_allow_when_all_checks_pass(self):
        from src.zt_validator import TrustCheckResult
        decision = TrustDecision(
            identity_arn='arn:aws:iam::123:user/test',
            trust_decision='ALLOW',
            overall_passed=True,
            checks=[
                TrustCheckResult('mfa', True, 'MFA enrolled'),
                TrustCheckResult('region', True, 'Region approved'),
                TrustCheckResult('key_age', True, 'Keys fresh'),
            ]
        )
        assert decision.trust_decision == 'ALLOW'
        assert decision.overall_passed
        assert len(decision.failed_checks) == 0
        assert decision.reasons == []


# ── Policy Defaults Tests ──────────────────────────────────────────────────────

class TestDefaultPolicy:

    def test_mfa_required_by_default(self):
        assert DEFAULT_POLICY['require_mfa'] is True

    def test_mfa_age_one_hour_by_default(self):
        assert DEFAULT_POLICY['max_mfa_age_seconds'] == 3600

    def test_key_rotation_90_days_by_default(self):
        assert DEFAULT_POLICY['max_key_age_days'] == 90

    def test_approved_regions_list_not_empty(self):
        assert len(DEFAULT_POLICY['approved_regions']) >= 1
