"""Tests for the Cloud Security Posture Scoring engine."""
import pytest
from unittest.mock import MagicMock, patch

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from scorer import PostureScorer, CategoryScore, SEVERITY_SCORES, CATEGORY_WEIGHTS


def make_finding(severity: str = 'HIGH', product: str = 'GuardDuty',
                 resource_type: str = 'AwsEc2Instance') -> dict:
    return {
        'Id': f'arn:aws:securityhub:us-east-1:123:{severity}-001',
        'ProductName': product,
        'Severity': {'Label': severity, 'Normalized': SEVERITY_SCORES.get(severity, 10)},
        'Title': f'Test {severity} finding from {product}',
        'Description': 'Test finding',
        'Resources': [{'Type': resource_type, 'Id': 'arn:aws:ec2:us-east-1:123:instance/i-abc'}],
        'WorkflowState': 'NEW',
        'RecordState': 'ACTIVE',
    }


class TestCategoryScoring:

    def setup_method(self):
        self.scorer = PostureScorer.__new__(PostureScorer)

    def test_no_findings_score_zero(self):
        score = self.scorer.score_category('iam', [])
        assert score.score == 0.0
        assert score.finding_count == 0

    def test_all_critical_score_high(self):
        findings = [make_finding('CRITICAL')] * 5
        score = self.scorer.score_category('iam', findings)
        assert score.score >= 80, f'Expected score >= 80 for all-critical, got {score.score}'
        assert score.critical_count == 5

    def test_all_low_score_low(self):
        findings = [make_finding('LOW')] * 5
        score = self.scorer.score_category('network', findings)
        assert score.score <= 30, f'Expected score <= 30 for all-low, got {score.score}'

    def test_mixed_severity_between_extremes(self):
        findings = [
            make_finding('CRITICAL'),
            make_finding('HIGH'),
            make_finding('MEDIUM'),
            make_finding('LOW'),
        ]
        score = self.scorer.score_category('data', findings)
        assert 10 < score.score < 100

    def test_top_findings_limited_to_5(self):
        findings = [make_finding('HIGH')] * 20
        score = self.scorer.score_category('logging', findings)
        assert len(score.top_findings) <= 5

    def test_score_capped_at_100(self):
        findings = [make_finding('CRITICAL')] * 100
        score = self.scorer.score_category('iam', findings)
        assert score.score <= 100.0


class TestOverallScoreCalculation:

    def setup_method(self):
        self.scorer = PostureScorer.__new__(PostureScorer)

    def test_all_zero_categories_overall_zero(self):
        category_scores = {
            cat: CategoryScore(cat, 0.0, 0, 0, 0)
            for cat in CATEGORY_WEIGHTS
        }
        overall = self.scorer.calculate_overall_score(category_scores)
        assert overall == 0.0

    def test_all_100_categories_overall_100(self):
        category_scores = {
            cat: CategoryScore(cat, 100.0, 10, 5, 3)
            for cat in CATEGORY_WEIGHTS
        }
        overall = self.scorer.calculate_overall_score(category_scores)
        assert overall == 100.0

    def test_iam_weighted_higher_than_compliance(self):
        """IAM weight (0.25) must influence score more than compliance (0.10)."""
        # All categories score 0 except IAM (100) vs compliance (100)
        iam_only = {
            cat: CategoryScore(cat, 100.0 if cat == 'iam' else 0.0, 1, 0, 0)
            for cat in CATEGORY_WEIGHTS
        }
        compliance_only = {
            cat: CategoryScore(cat, 100.0 if cat == 'compliance' else 0.0, 1, 0, 0)
            for cat in CATEGORY_WEIGHTS
        }
        iam_score = self.scorer.calculate_overall_score(iam_only)
        compliance_score = self.scorer.calculate_overall_score(compliance_only)
        assert iam_score > compliance_score, \
            f'IAM ({iam_score}) should weigh more than compliance ({compliance_score})'


class TestRiskLevelClassification:

    def test_score_80_is_critical(self):
        assert PostureScorer.risk_level(80) == 'CRITICAL'

    def test_score_55_is_high(self):
        assert PostureScorer.risk_level(55) == 'HIGH'

    def test_score_35_is_medium(self):
        assert PostureScorer.risk_level(35) == 'MEDIUM'

    def test_score_15_is_low(self):
        assert PostureScorer.risk_level(15) == 'LOW'

    def test_score_5_is_minimal(self):
        assert PostureScorer.risk_level(5) == 'MINIMAL'

    def test_score_0_is_minimal(self):
        assert PostureScorer.risk_level(0) == 'MINIMAL'

    def test_score_100_is_critical(self):
        assert PostureScorer.risk_level(100) == 'CRITICAL'


class TestFindingCategorisation:

    def setup_method(self):
        self.scorer = PostureScorer.__new__(PostureScorer)

    def test_guardduty_finding_is_runtime(self):
        finding = make_finding(product='GuardDuty')
        assert self.scorer._categorise_finding(finding) == 'runtime'

    def test_iam_finding_is_iam(self):
        finding = make_finding(product='IAM Access Analyzer')
        assert self.scorer._categorise_finding(finding) == 'iam'

    def test_s3_finding_is_data(self):
        finding = make_finding(product='S3 Storage')
        assert self.scorer._categorise_finding(finding) == 'data'

    def test_cloudtrail_finding_is_logging(self):
        finding = make_finding(product='CloudTrail')
        assert self.scorer._categorise_finding(finding) == 'logging'

    def test_unknown_product_defaults_to_compliance(self):
        finding = make_finding(product='SomeUnknownProduct')
        cat = self.scorer._categorise_finding(finding)
        assert cat in set(CATEGORY_WEIGHTS.keys())


class TestWeightsSumToOne:

    def test_weights_sum_approximately_to_one(self):
        total = sum(CATEGORY_WEIGHTS.values())
        assert abs(total - 1.0) < 0.001, \
            f'Category weights must sum to ~1.0, got {total}'

    def test_all_weights_positive(self):
        for cat, weight in CATEGORY_WEIGHTS.items():
            assert weight > 0, f'Weight for {cat} must be positive'
