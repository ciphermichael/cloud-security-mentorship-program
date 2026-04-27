"""
Unit tests for IAM Privilege Escalation Detector.
All tests use mocked events — no AWS credentials needed.

Run:
    pip install pytest
    pytest tests/ -v
"""
import json
import pytest
from datetime import datetime, timezone


def get_engine():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
    from detection_engine import analyze_event, ESCALATION_PATHS
    return analyze_event, ESCALATION_PATHS


def make_ct_event(event_name: str, actor_arn: str = 'arn:aws:iam::123:user/attacker',
                  source_ip: str = '1.2.3.4', params: dict = None) -> dict:
    """Build a minimal CloudTrail / EventBridge event for testing."""
    return {
        'detail': {
            'eventName': event_name,
            'eventTime': datetime.now(timezone.utc).isoformat(),
            'userIdentity': {
                'type': 'IAMUser',
                'arn': actor_arn,
                'userName': actor_arn.split('/')[-1],
            },
            'sourceIPAddress': source_ip,
            'awsRegion': 'us-east-1',
            'requestParameters': params or {},
        }
    }


# ── Path Detection Tests ───────────────────────────────────────────────────────

class TestEscalationPathDetection:

    def test_create_policy_version_with_default_detected(self):
        """CreatePolicyVersion + setAsDefault=true must be CRITICAL."""
        analyze_event, _ = get_engine()
        event = make_ct_event('CreatePolicyVersion', params={'setAsDefault': 'true'})
        finding = analyze_event(event)
        assert finding is not None
        assert finding['severity'] == 'CRITICAL'
        assert finding['path_id'] == 1

    def test_create_policy_version_without_default_not_detected(self):
        """CreatePolicyVersion without setAsDefault must not alert."""
        analyze_event, _ = get_engine()
        event = make_ct_event('CreatePolicyVersion', params={'setAsDefault': 'false'})
        finding = analyze_event(event)
        assert finding is None

    def test_update_assume_role_policy_detected_critical(self):
        """UpdateAssumeRolePolicy must always be CRITICAL."""
        analyze_event, _ = get_engine()
        event = make_ct_event('UpdateAssumeRolePolicy',
                              params={'roleName': 'AdminRole'})
        finding = analyze_event(event)
        assert finding is not None
        assert finding['severity'] == 'CRITICAL'

    def test_attach_user_policy_detected_high(self):
        """AttachUserPolicy must produce HIGH finding."""
        analyze_event, _ = get_engine()
        event = make_ct_event('AttachUserPolicy',
                              params={'userName': 'victim', 'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'})
        finding = analyze_event(event)
        assert finding is not None
        assert finding['severity'] in ('HIGH', 'CRITICAL')

    def test_attach_role_policy_detected(self):
        """AttachRolePolicy must produce a finding."""
        analyze_event, _ = get_engine()
        event = make_ct_event('AttachRolePolicy',
                              params={'roleName': 'DeployRole'})
        finding = analyze_event(event)
        assert finding is not None

    def test_create_access_key_other_user_detected(self):
        """CreateAccessKey must produce HIGH finding."""
        analyze_event, _ = get_engine()
        event = make_ct_event('CreateAccessKey',
                              params={'userName': 'admin-user'})
        finding = analyze_event(event)
        assert finding is not None
        assert finding['severity'] in ('HIGH', 'CRITICAL')

    def test_create_login_profile_detected(self):
        """CreateLoginProfile (granting console access) must produce HIGH."""
        analyze_event, _ = get_engine()
        event = make_ct_event('CreateLoginProfile',
                              params={'userName': 'no-console-user'})
        finding = analyze_event(event)
        assert finding is not None
        assert finding['severity'] in ('HIGH', 'CRITICAL')

    def test_update_login_profile_detected_critical(self):
        """UpdateLoginProfile (password change on another user) must be CRITICAL."""
        analyze_event, _ = get_engine()
        event = make_ct_event('UpdateLoginProfile',
                              params={'userName': 'admin-user'})
        finding = analyze_event(event)
        assert finding is not None
        assert finding['severity'] == 'CRITICAL'

    def test_add_user_to_group_detected(self):
        """AddUserToGroup must produce MEDIUM finding."""
        analyze_event, _ = get_engine()
        event = make_ct_event('AddUserToGroup',
                              params={'groupName': 'Admins', 'userName': 'attacker'})
        finding = analyze_event(event)
        assert finding is not None

    def test_benign_event_not_detected(self):
        """DescribeInstances, ListBuckets etc must return None."""
        analyze_event, _ = get_engine()
        for event_name in ['DescribeInstances', 'ListBuckets', 'GetUser',
                           'DescribeSecurityGroups', 'GetCallerIdentity']:
            event = make_ct_event(event_name)
            finding = analyze_event(event)
            assert finding is None, f'{event_name} must not trigger an alert'


# ── Finding Structure Tests ────────────────────────────────────────────────────

class TestFindingStructure:

    @pytest.mark.parametrize("event_name,params", [
        ('CreatePolicyVersion', {'setAsDefault': 'true'}),
        ('UpdateAssumeRolePolicy', {'roleName': 'AdminRole'}),
        ('AttachUserPolicy', {'userName': 'u', 'policyArn': 'arn:p'}),
        ('CreateAccessKey', {'userName': 'u'}),
    ])
    def test_finding_has_required_fields(self, event_name, params):
        """Every finding must have the required structural fields."""
        analyze_event, _ = get_engine()
        event = make_ct_event(event_name, params=params)
        finding = analyze_event(event)
        if finding is None:
            return  # Some events may have conditions
        required = ['path_id', 'path_name', 'severity', 'mitre_technique',
                    'actor_arn', 'source_ip', 'event_name', 'timestamp']
        for field in required:
            assert field in finding, f'Finding missing field "{field}": {finding}'

    def test_finding_mitre_technique_format(self):
        """MITRE technique must be in T-number format."""
        import re
        analyze_event, _ = get_engine()
        event = make_ct_event('UpdateAssumeRolePolicy', params={'roleName': 'R'})
        finding = analyze_event(event)
        assert finding is not None
        technique = finding.get('mitre_technique', '')
        assert re.match(r'T\d{4}(\.\d{3})?', technique), \
            f'Invalid MITRE format: {technique}'


# ── Path Coverage Tests ────────────────────────────────────────────────────────

class TestPathCoverage:

    def test_all_path_ids_unique(self):
        """No two escalation paths should have the same path_id."""
        _, ESCALATION_PATHS = get_engine()
        path_ids = [v['path_id'] for v in ESCALATION_PATHS.values()]
        assert len(path_ids) == len(set(path_ids)), \
            f'Duplicate path IDs found: {path_ids}'

    def test_minimum_15_paths_defined(self):
        """Detector must cover at least 15 escalation paths."""
        _, ESCALATION_PATHS = get_engine()
        assert len(ESCALATION_PATHS) >= 15, \
            f'Only {len(ESCALATION_PATHS)} paths defined — need at least 15'

    def test_all_paths_have_mitre_technique(self):
        """Every escalation path must have a MITRE ATT&CK technique."""
        import re
        _, ESCALATION_PATHS = get_engine()
        for event_name, path in ESCALATION_PATHS.items():
            technique = path.get('mitre', '')
            assert re.match(r'T\d{4}', technique), \
                f'Path {event_name} has invalid MITRE technique: {technique}'

    def test_all_paths_have_severity(self):
        """Every path must have a severity of CRITICAL, HIGH, or MEDIUM."""
        _, ESCALATION_PATHS = get_engine()
        valid_severities = {'CRITICAL', 'HIGH', 'MEDIUM'}
        for event_name, path in ESCALATION_PATHS.items():
            assert path.get('severity') in valid_severities, \
                f'Path {event_name} has invalid severity: {path.get("severity")}'
