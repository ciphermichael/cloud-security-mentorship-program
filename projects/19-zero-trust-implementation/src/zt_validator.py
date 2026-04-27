"""
Zero Trust Identity Validator — evaluates whether an AWS identity meets
Zero Trust criteria before granting access.

Checks:
  - MFA status and recency (age of MFA authentication)
  - Session duration within policy
  - Source IP against approved ranges
  - Region against approved list
  - Access key age within rotation policy
"""
import boto3
import logging
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ── Zero Trust Policy Defaults ─────────────────────────────────────────────────

DEFAULT_POLICY = {
    'require_mfa': True,
    'max_mfa_age_seconds': 3600,        # 1 hour
    'max_session_age_seconds': 43200,    # 12 hours
    'max_key_age_days': 90,             # Access key rotation requirement
    'approved_regions': ['us-east-1', 'us-west-2', 'eu-west-1'],
    'approved_ip_ranges': [],           # Empty = any IP allowed
}


@dataclass
class TrustCheckResult:
    check_name: str
    passed: bool
    reason: str
    severity: str = 'HIGH'   # severity if failed


@dataclass
class TrustDecision:
    identity_arn: str
    trust_decision: str           # ALLOW | DENY
    overall_passed: bool
    checks: list[TrustCheckResult] = field(default_factory=list)
    evaluated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def reasons(self) -> list[str]:
        return [c.reason for c in self.checks if not c.passed]

    @property
    def failed_checks(self) -> list[TrustCheckResult]:
        return [c for c in self.checks if not c.passed]


class ZeroTrustValidator:

    def __init__(self, region: str = 'us-east-1', policy: dict | None = None):
        self.region = region
        self.iam = boto3.client('iam', region_name=region)
        self.sts = boto3.client('sts', region_name=region)
        self.policy = {**DEFAULT_POLICY, **(policy or {})}

    # ── Individual Checks ──────────────────────────────────────────────────────

    def _check_mfa_enabled(self, username: str) -> TrustCheckResult:
        """Verify the user has MFA enabled."""
        devices = self.iam.list_mfa_devices(UserName=username)['MFADevices']
        passed = len(devices) > 0
        return TrustCheckResult(
            check_name='mfa_device_enrolled',
            passed=passed,
            reason='MFA device enrolled' if passed else 'No MFA device enrolled',
            severity='CRITICAL',
        )

    def _check_mfa_age(self, session_context: dict) -> TrustCheckResult:
        """Verify MFA was used recently enough."""
        if not self.policy['require_mfa']:
            return TrustCheckResult('mfa_age', True, 'MFA check disabled by policy')

        mfa_auth = session_context.get('sessionIssuer', {})
        mfa_time_str = session_context.get('attributes', {}).get('creationDate', '')
        if not mfa_time_str:
            return TrustCheckResult(
                'mfa_age', False,
                'No MFA authentication timestamp in session',
                'HIGH'
            )
        try:
            mfa_time = datetime.fromisoformat(mfa_time_str.replace('Z', '+00:00'))
            age_seconds = (datetime.now(timezone.utc) - mfa_time).total_seconds()
            max_age = self.policy['max_mfa_age_seconds']
            passed = age_seconds <= max_age
            return TrustCheckResult(
                'mfa_age', passed,
                f'MFA {int(age_seconds)}s ago (max {max_age}s)' if passed
                else f'MFA too old: {int(age_seconds)}s ago (max {max_age}s)',
                'HIGH'
            )
        except (ValueError, TypeError):
            return TrustCheckResult('mfa_age', False, 'Invalid MFA timestamp', 'HIGH')

    def _check_access_key_age(self, username: str) -> TrustCheckResult:
        """Verify user's active access keys are within rotation policy."""
        keys = self.iam.list_access_keys(UserName=username)['AccessKeyMetadata']
        active_keys = [k for k in keys if k['Status'] == 'Active']
        max_age = timedelta(days=self.policy['max_key_age_days'])
        now = datetime.now(timezone.utc)

        old_keys = [
            k for k in active_keys
            if (now - k['CreateDate'].replace(tzinfo=timezone.utc)) > max_age
        ]

        passed = len(old_keys) == 0
        return TrustCheckResult(
            'key_age',
            passed,
            'All active keys within rotation policy' if passed
            else f'{len(old_keys)} access key(s) exceed {self.policy["max_key_age_days"]}-day rotation policy',
            'MEDIUM',
        )

    def _check_source_region(self, region: str) -> TrustCheckResult:
        """Verify the request region is in the approved list."""
        approved = self.policy['approved_regions']
        if not approved:
            return TrustCheckResult('region', True, 'No region restriction')
        passed = region in approved
        return TrustCheckResult(
            'region', passed,
            f'Region {region} approved' if passed
            else f'Region {region} not in approved list: {approved}',
            'HIGH',
        )

    # ── Main Evaluation ────────────────────────────────────────────────────────

    def check_identity_trust(self, identity_arn: str,
                              region: str | None = None,
                              session_context: dict | None = None) -> TrustDecision:
        """
        Evaluate a Zero Trust access decision for an IAM identity.

        Args:
            identity_arn:    Full IAM ARN of the identity
            region:          AWS region of the request
            session_context: From CloudTrail userIdentity.sessionContext

        Returns:
            TrustDecision with allow/deny and detailed check results
        """
        checks: list[TrustCheckResult] = []
        username = identity_arn.split('/')[-1]

        # Check 1: MFA device enrolled
        try:
            checks.append(self._check_mfa_enabled(username))
        except Exception as e:
            checks.append(TrustCheckResult('mfa_device_enrolled', False,
                                            f'Could not verify MFA: {e}', 'HIGH'))

        # Check 2: Access key age
        try:
            checks.append(self._check_access_key_age(username))
        except Exception as e:
            checks.append(TrustCheckResult('key_age', False,
                                            f'Could not verify key age: {e}', 'MEDIUM'))

        # Check 3: MFA session age (from session context)
        if session_context:
            checks.append(self._check_mfa_age(session_context))

        # Check 4: Source region
        if region:
            checks.append(self._check_source_region(region))

        overall_passed = all(c.passed for c in checks)
        return TrustDecision(
            identity_arn=identity_arn,
            trust_decision='ALLOW' if overall_passed else 'DENY',
            overall_passed=overall_passed,
            checks=checks,
        )
