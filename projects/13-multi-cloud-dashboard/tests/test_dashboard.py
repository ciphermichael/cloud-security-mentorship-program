"""
Unit tests for multi-cloud dashboard — risk scorer and finding model.
No real cloud credentials needed.

Run:
    pytest tests/ -v
"""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.models.finding import Finding, calculate_risk_score, SEVERITY_SCORES


class TestFindingModel:

    def _make_finding(self, severity: str = 'HIGH', cloud: str = 'AWS') -> Finding:
        return Finding(
            cloud=cloud,
            id='test-001',
            title='Test finding',
            severity=severity,
            resource='arn:aws:s3:::test-bucket',
        )

    def test_finding_severity_score_critical(self):
        f = self._make_finding('CRITICAL')
        assert f.severity_score == SEVERITY_SCORES['CRITICAL']

    def test_finding_severity_score_high(self):
        f = self._make_finding('HIGH')
        assert f.severity_score == SEVERITY_SCORES['HIGH']

    def test_finding_severity_score_medium(self):
        f = self._make_finding('MEDIUM')
        assert f.severity_score == SEVERITY_SCORES['MEDIUM']

    def test_finding_severity_score_low(self):
        f = self._make_finding('LOW')
        assert f.severity_score == SEVERITY_SCORES['LOW']

    def test_sort_key_critical_before_high(self):
        critical = self._make_finding('CRITICAL')
        high = self._make_finding('HIGH')
        assert critical.sort_key < high.sort_key

    def test_to_dict_has_required_keys(self):
        f = self._make_finding()
        d = f.to_dict()
        for key in ('cloud', 'id', 'title', 'severity', 'resource', 'severity_score'):
            assert key in d, f'Missing key: {key}'

    def test_finding_from_azure(self):
        f = self._make_finding('HIGH', 'Azure')
        assert f.cloud == 'Azure'
        assert f.severity_score == 75


class TestRiskScorer:

    def test_no_findings_returns_100(self):
        result = calculate_risk_score([])
        assert result['overall_score'] == 100.0
        assert result['grade'] == 'A'
        assert result['total_findings'] == 0

    def test_critical_findings_reduce_score(self):
        findings = [
            {'severity': 'CRITICAL', 'cloud': 'AWS'},
            {'severity': 'CRITICAL', 'cloud': 'AWS'},
        ]
        result = calculate_risk_score(findings)
        assert result['overall_score'] < 100.0

    def test_by_severity_counts_correctly(self):
        findings = [
            {'severity': 'CRITICAL', 'cloud': 'AWS'},
            {'severity': 'HIGH', 'cloud': 'AWS'},
            {'severity': 'HIGH', 'cloud': 'Azure'},
            {'severity': 'MEDIUM', 'cloud': 'AWS'},
        ]
        result = calculate_risk_score(findings)
        assert result['by_severity']['CRITICAL'] == 1
        assert result['by_severity']['HIGH'] == 2
        assert result['by_severity']['MEDIUM'] == 1

    def test_by_cloud_counts_correctly(self):
        findings = [
            {'severity': 'HIGH', 'cloud': 'AWS'},
            {'severity': 'HIGH', 'cloud': 'AWS'},
            {'severity': 'MEDIUM', 'cloud': 'Azure'},
        ]
        result = calculate_risk_score(findings)
        assert result['by_cloud']['AWS'] == 2
        assert result['by_cloud']['Azure'] == 1

    def test_score_never_negative(self):
        findings = [{'severity': 'CRITICAL', 'cloud': 'AWS'}] * 100
        result = calculate_risk_score(findings)
        assert result['overall_score'] >= 0.0

    def test_grade_a_at_90_plus(self):
        findings = [{'severity': 'LOW', 'cloud': 'AWS'}]
        result = calculate_risk_score(findings)
        assert result['overall_score'] >= 90 or result['grade'] in ('A', 'B', 'C', 'D', 'F')

    def test_grade_f_with_many_criticals(self):
        findings = [{'severity': 'CRITICAL', 'cloud': 'AWS'}] * 20
        result = calculate_risk_score(findings)
        assert result['grade'] == 'F'
        assert result['overall_score'] == 0.0

    def test_accepts_finding_objects(self):
        findings = [
            Finding(cloud='AWS', id='1', title='T', severity='HIGH', resource='r'),
            Finding(cloud='Azure', id='2', title='T2', severity='MEDIUM', resource='r2'),
        ]
        result = calculate_risk_score(findings)
        assert result['total_findings'] == 2
        assert result['by_severity']['HIGH'] == 1
        assert result['by_severity']['MEDIUM'] == 1
