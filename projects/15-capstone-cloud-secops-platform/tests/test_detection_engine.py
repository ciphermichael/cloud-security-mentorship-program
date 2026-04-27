"""
Unit tests for Capstone — Cloud SecOps Platform detection engine.
Tests rule evaluation, finding storage schema, and MITRE mapping.

Run:
    pip install pytest moto[dynamodb]
    pytest tests/ -v
"""
import json
import pytest
import boto3
from moto import mock_dynamodb
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch


def get_evaluator():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'detection_engine'))
    from rule_evaluator import RuleEvaluator
    return RuleEvaluator


def make_cloudtrail_event(event_name: str, actor: str = 'arn:aws:iam::123:user/test',
                           source_ip: str = '10.0.0.1',
                           user_type: str = 'IAMUser',
                           params: dict = None) -> dict:
    return {
        'eventName': event_name,
        'eventTime': datetime.now(timezone.utc).isoformat(),
        'userIdentity': {
            'type': user_type,
            'arn': actor,
            'userName': actor.split('/')[-1],
        },
        'sourceIPAddress': source_ip,
        'awsRegion': 'us-east-1',
        'requestParameters': params or {},
        'eventSource': 'iam.amazonaws.com',
    }


# ── Rule Evaluation Tests ──────────────────────────────────────────────────────

class TestRuleEvaluation:

    def test_root_usage_triggers_critical(self):
        """Root account API call must trigger CRITICAL finding."""
        Evaluator = get_evaluator()
        ev = Evaluator()
        event = make_cloudtrail_event('GetCallerIdentity', user_type='Root',
                                       actor='arn:aws:iam::123:root')
        findings = ev.evaluate(event)
        assert any(f['severity'] == 'CRITICAL' for f in findings), \
            f'Root usage must be CRITICAL: {findings}'

    def test_cloudtrail_delete_triggers_critical(self):
        """DeleteTrail must trigger CRITICAL (defense evasion)."""
        Evaluator = get_evaluator()
        ev = Evaluator()
        event = make_cloudtrail_event('DeleteTrail',
                                       params={'name': 'my-trail'})
        findings = ev.evaluate(event)
        assert len(findings) >= 1
        assert any(f['severity'] == 'CRITICAL' for f in findings)

    def test_stop_logging_triggers_critical(self):
        """StopLogging must trigger CRITICAL finding."""
        Evaluator = get_evaluator()
        ev = Evaluator()
        event = make_cloudtrail_event('StopLogging')
        findings = ev.evaluate(event)
        assert any(f['severity'] == 'CRITICAL' for f in findings)

    def test_describe_instances_no_finding(self):
        """Read-only API calls must not produce findings."""
        Evaluator = get_evaluator()
        ev = Evaluator()
        for event_name in ['DescribeInstances', 'ListBuckets', 'GetUser',
                           'DescribeVpcs', 'ListRoles']:
            event = make_cloudtrail_event(event_name)
            findings = ev.evaluate(event)
            assert len(findings) == 0, \
                f'{event_name} must not produce a finding'

    def test_iam_escalation_triggers_high(self):
        """IAM escalation events must trigger HIGH+ findings."""
        Evaluator = get_evaluator()
        ev = Evaluator()
        escalation_events = [
            'AttachUserPolicy', 'AttachRolePolicy', 'CreateUser',
            'CreateAccessKey', 'PutUserPolicy',
        ]
        for event_name in escalation_events:
            event = make_cloudtrail_event(event_name)
            findings = ev.evaluate(event)
            assert len(findings) >= 1, f'{event_name} produced no findings'
            assert any(f['severity'] in ('HIGH', 'CRITICAL') for f in findings), \
                f'{event_name}: expected HIGH+, got {[f["severity"] for f in findings]}'


# ── Finding Schema Tests ───────────────────────────────────────────────────────

class TestFindingSchema:

    REQUIRED_FIELDS = {
        'severity', 'title', 'description', 'mitre_technique',
        'mitre_tactic', 'actor_arn', 'source_ip', 'event_time',
        'source', 'rule_id',
    }

    @pytest.mark.parametrize('event_name,params', [
        ('DeleteTrail', {'name': 'trail'}),
        ('AttachUserPolicy', {'userName': 'user', 'policyArn': 'arn:p'}),
        ('CreateAccessKey', {'userName': 'user'}),
    ])
    def test_finding_has_all_required_fields(self, event_name, params):
        """Every finding must have all required schema fields."""
        Evaluator = get_evaluator()
        ev = Evaluator()
        event = make_cloudtrail_event(event_name, params=params)
        findings = ev.evaluate(event)
        for finding in findings:
            missing = self.REQUIRED_FIELDS - set(finding.keys())
            assert not missing, \
                f'Finding for {event_name} missing fields: {missing}'

    def test_mitre_technique_format(self):
        """MITRE technique must match T-number format."""
        import re
        Evaluator = get_evaluator()
        ev = Evaluator()
        event = make_cloudtrail_event('DeleteTrail')
        findings = ev.evaluate(event)
        for finding in findings:
            technique = finding.get('mitre_technique', '')
            if technique:
                assert re.match(r'T\d{4}(\.\d{3})?', technique), \
                    f'Invalid MITRE format: {technique}'

    def test_severity_is_valid_level(self):
        """Severity must be one of the 4 valid levels."""
        Evaluator = get_evaluator()
        ev = Evaluator()
        valid = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}
        event = make_cloudtrail_event('AttachUserPolicy')
        findings = ev.evaluate(event)
        for finding in findings:
            assert finding.get('severity') in valid, \
                f'Invalid severity: {finding.get("severity")}'


# ── Rule Loading Tests ─────────────────────────────────────────────────────────

class TestRuleLoading:

    def test_yaml_rules_loaded(self):
        """Evaluator must load rules from YAML files."""
        Evaluator = get_evaluator()
        ev = Evaluator()
        assert hasattr(ev, 'rules'), 'Evaluator must have a rules attribute'
        assert len(ev.rules) >= 5, \
            f'Expected at least 5 rules, got {len(ev.rules)}'

    def test_each_rule_has_id_and_severity(self):
        """Each loaded rule must have an ID and severity."""
        Evaluator = get_evaluator()
        ev = Evaluator()
        for rule in ev.rules:
            assert 'id' in rule, f'Rule missing id: {rule}'
            assert 'severity' in rule, f'Rule {rule.get("id")} missing severity'


# ── DynamoDB Storage Tests ─────────────────────────────────────────────────────

@mock_dynamodb
class TestFindingStorage:

    def setup_method(self):
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        self.table = dynamodb.create_table(
            TableName='secops-findings',
            KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
        )

    def test_finding_saved_to_dynamodb(self):
        """Findings must be persisted to DynamoDB."""
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        try:
            from ingestion.cloudtrail_ingestor import save_finding
        except ImportError:
            pytest.skip('cloudtrail_ingestor not yet implemented with save_finding')

        finding = {
            'id': 'test-uuid-001',
            'severity': 'HIGH',
            'title': 'Test Finding',
            'description': 'Test',
            'source': 'cloudtrail',
            'event_time': datetime.now(timezone.utc).isoformat(),
        }
        save_finding(finding, table_name='secops-findings', region='us-east-1')

        item = self.table.get_item(Key={'id': 'test-uuid-001'}).get('Item')
        assert item is not None
        assert item['severity'] == 'HIGH'
