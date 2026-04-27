"""
Unit tests for CloudTrail Threat Hunting Lab.
Tests query construction, result parsing, and kill-chain detection logic.

Run:
    pip install pytest moto[athena]
    pytest tests/ -v
"""
import json
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta


def get_hunter():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
    from threat_hunter import ThreatHunter
    return ThreatHunter


# ── Query Construction Tests ───────────────────────────────────────────────────

class TestQueryConstruction:
    """Test that SQL queries are well-formed before sending to Athena."""

    def test_root_usage_query_has_where_clause(self):
        """Root usage query must filter on userIdentity.type = 'Root'."""
        Hunter = get_hunter()
        h = Hunter.__new__(Hunter)
        query = h.build_root_usage_query()
        assert 'Root' in query
        assert 'WHERE' in query.upper() or 'where' in query.lower()

    def test_brute_force_query_has_having_clause(self):
        """Brute force query must use HAVING count >= threshold."""
        Hunter = get_hunter()
        h = Hunter.__new__(Hunter)
        query = h.build_brute_force_query(threshold=5)
        assert 'HAVING' in query.upper()
        assert '5' in query

    def test_s3_exfil_query_has_count_threshold(self):
        """S3 exfiltration query must filter by download count."""
        Hunter = get_hunter()
        h = Hunter.__new__(Hunter)
        query = h.build_s3_exfil_query(threshold=100)
        assert 'GetObject' in query or 'getobject' in query.lower()
        assert '100' in query

    def test_no_mfa_login_query_filters_mfa(self):
        """Console login without MFA query must check MFAUsed."""
        Hunter = get_hunter()
        h = Hunter.__new__(Hunter)
        query = h.build_no_mfa_login_query()
        assert 'MFAUsed' in query or 'mfa' in query.lower()
        assert 'ConsoleLogin' in query

    def test_iam_escalation_query_covers_key_events(self):
        """IAM escalation query must include key event names."""
        Hunter = get_hunter()
        h = Hunter.__new__(Hunter)
        query = h.build_iam_escalation_query()
        key_events = ['CreatePolicyVersion', 'AttachUserPolicy', 'CreateUser']
        for event in key_events:
            assert event in query, f'{event} missing from IAM escalation query'

    def test_queries_have_date_filter(self):
        """All queries should filter by date to avoid full table scans."""
        Hunter = get_hunter()
        h = Hunter.__new__(Hunter)
        queries = [
            h.build_root_usage_query(),
            h.build_brute_force_query(),
            h.build_s3_exfil_query(),
        ]
        for i, q in enumerate(queries):
            # Should reference eventTime or date partition
            has_time = 'eventTime' in q or 'date_add' in q or 'ago' in q.lower()
            assert has_time, f'Query {i} has no time filter — full table scan risk'


# ── Result Parsing Tests ────────────────────────────────────────────────────────

class TestResultParsing:
    """Test Athena result parsing logic."""

    def test_parse_athena_result_extracts_rows(self):
        """parse_athena_result must extract data rows (skip header)."""
        Hunter = get_hunter()
        h = Hunter.__new__(Hunter)

        mock_result = {
            'ResultSet': {
                'Rows': [
                    {'Data': [{'VarCharValue': 'eventTime'}, {'VarCharValue': 'eventName'}, {'VarCharValue': 'sourceIPAddress'}]},  # header
                    {'Data': [{'VarCharValue': '2024-01-15T03:00:00Z'}, {'VarCharValue': 'AttachRolePolicy'}, {'VarCharValue': '1.2.3.4'}]},
                    {'Data': [{'VarCharValue': '2024-01-15T03:01:00Z'}, {'VarCharValue': 'CreateUser'}, {'VarCharValue': '1.2.3.4'}]},
                ]
            }
        }

        rows = h.parse_result(mock_result)
        assert len(rows) == 2  # Header excluded
        assert rows[0]['eventName'] == 'AttachRolePolicy'
        assert rows[1]['eventName'] == 'CreateUser'

    def test_parse_empty_result(self):
        """Empty Athena result must return empty list."""
        Hunter = get_hunter()
        h = Hunter.__new__(Hunter)

        mock_result = {'ResultSet': {'Rows': [
            {'Data': [{'VarCharValue': 'eventTime'}, {'VarCharValue': 'eventName'}]}  # header only
        ]}}
        rows = h.parse_result(mock_result)
        assert rows == []


# ── Kill Chain Analysis Tests ─────────────────────────────────────────────────

class TestKillChainAnalysis:
    """Test kill chain detection and MITRE mapping."""

    def _make_event(self, name: str, ts: str, actor: str = 'arn:aws:iam::123:user/attacker',
                    ip: str = '1.2.3.4') -> dict:
        return {'eventName': name, 'eventTime': ts,
                'userIdentity_arn': actor, 'sourceIPAddress': ip}

    def test_single_actor_timeline_sorted(self):
        """Timeline for a single actor must be sorted chronologically."""
        Hunter = get_hunter()
        h = Hunter.__new__(Hunter)
        events = [
            self._make_event('CreateUser', '2024-01-15T03:05:00Z'),
            self._make_event('GetCallerIdentity', '2024-01-15T03:00:00Z'),
            self._make_event('AttachUserPolicy', '2024-01-15T03:10:00Z'),
        ]
        timeline = h.build_actor_timeline(events, 'arn:aws:iam::123:user/attacker')
        times = [e['eventTime'] for e in timeline]
        assert times == sorted(times), 'Timeline not sorted chronologically'

    def test_kill_chain_stage_mapping(self):
        """Events must map to correct MITRE kill chain stages."""
        Hunter = get_hunter()
        h = Hunter.__new__(Hunter)
        mappings = {
            'GetCallerIdentity': 'Discovery',
            'ListUsers': 'Discovery',
            'CreateUser': 'Persistence',
            'AttachUserPolicy': 'Privilege Escalation',
            'GetObject': 'Collection',
        }
        for event_name, expected_stage in mappings.items():
            stage = h.get_mitre_tactic(event_name)
            assert stage == expected_stage, \
                f'{event_name}: expected {expected_stage}, got {stage}'

    def test_multi_stage_attack_detected(self):
        """Attack spanning Discovery → Escalation → Exfiltration must be flagged."""
        Hunter = get_hunter()
        h = Hunter.__new__(Hunter)
        events = [
            self._make_event('GetCallerIdentity', '2024-01-15T03:00:00Z'),  # Discovery
            self._make_event('ListUsers', '2024-01-15T03:01:00Z'),           # Discovery
            self._make_event('CreatePolicyVersion', '2024-01-15T03:05:00Z'), # Escalation
            self._make_event('GetObject', '2024-01-15T03:10:00Z'),           # Collection
        ]
        stages_detected = h.detect_kill_chain_stages(events)
        assert 'Discovery' in stages_detected
        assert 'Privilege Escalation' in stages_detected or 'Collection' in stages_detected


# ── Report Tests ───────────────────────────────────────────────────────────────

class TestHuntReport:

    def test_hunt_report_structure(self):
        """Hunt report must have required top-level keys."""
        Hunter = get_hunter()
        h = Hunter.__new__(Hunter)
        report = h.generate_hunt_report(
            hunt_name='Test Hunt',
            findings=[{'eventName': 'CreateUser', 'severity': 'HIGH'}],
            queries_run=['root_usage', 'brute_force']
        )
        assert 'hunt_name' in report
        assert 'generated_at' in report
        assert 'findings' in report
        assert 'total_findings' in report
        assert 'queries_run' in report
