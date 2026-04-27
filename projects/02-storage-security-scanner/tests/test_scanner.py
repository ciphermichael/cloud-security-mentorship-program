"""
Unit tests for Cloud Storage Security Scanner.
Uses moto to mock S3 — no real AWS needed.

Run:
    pip install pytest moto[s3]
    pytest tests/ -v
"""
import json
import boto3
import pytest
from moto import mock_s3


def get_scanner():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
    from scanner import StorageSecurityScanner
    return StorageSecurityScanner


@mock_s3
class TestPublicAccessDetection:

    def setup_method(self):
        self.s3 = boto3.client('s3', region_name='us-east-1')

    def _create_bucket(self, name: str) -> str:
        self.s3.create_bucket(Bucket=name)
        return name

    def test_bucket_without_public_access_block_flagged(self):
        """Bucket with no public access block must produce a HIGH+ finding."""
        bucket = self._create_bucket('no-block-bucket')
        # Don't put_public_access_block — simulates missing config
        Scanner = get_scanner()
        scanner = Scanner(region='us-east-1')
        findings = scanner.scan_bucket(bucket)
        assert any(
            'public' in f.get('description', '').lower() or
            'block' in f.get('description', '').lower()
            for f in findings
        ), f'Expected public access finding, got: {findings}'

    def test_bucket_with_full_block_clean(self):
        """Bucket with full public access block must have no public-access findings."""
        bucket = self._create_bucket('fully-blocked-bucket')
        self.s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True, 'IgnorePublicAcls': True,
                'BlockPublicPolicy': True, 'RestrictPublicBuckets': True
            }
        )
        Scanner = get_scanner()
        scanner = Scanner(region='us-east-1')
        findings = scanner.scan_bucket(bucket)
        public_access_findings = [
            f for f in findings
            if 'public' in f.get('check_id', '').lower()
        ]
        assert len(public_access_findings) == 0


@mock_s3
class TestEncryptionDetection:

    def setup_method(self):
        self.s3 = boto3.client('s3', region_name='us-east-1')

    def test_unencrypted_bucket_flagged(self):
        """Bucket with no SSE configuration must be flagged."""
        self.s3.create_bucket(Bucket='no-encrypt')
        Scanner = get_scanner()
        scanner = Scanner(region='us-east-1')
        findings = scanner.scan_bucket('no-encrypt')
        assert any(
            'encrypt' in f.get('description', '').lower() or
            'sse' in f.get('check_id', '').lower()
            for f in findings
        ), 'Expected encryption finding for unencrypted bucket'

    def test_sse_s3_encrypted_bucket(self):
        """Bucket with SSE-S3 should pass encryption check."""
        bucket = 'encrypted-bucket'
        self.s3.create_bucket(Bucket=bucket)
        self.s3.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
            }
        )
        Scanner = get_scanner()
        scanner = Scanner(region='us-east-1')
        findings = scanner.scan_bucket(bucket)
        encryption_fails = [
            f for f in findings
            if 'encrypt' in f.get('check_id', '').lower()
            and f.get('severity') in ('CRITICAL', 'HIGH')
        ]
        assert len(encryption_fails) == 0


@mock_s3
class TestVersioningDetection:

    def setup_method(self):
        self.s3 = boto3.client('s3', region_name='us-east-1')

    def test_bucket_without_versioning_flagged(self):
        """Bucket with no versioning enabled should be flagged MEDIUM+."""
        self.s3.create_bucket(Bucket='no-version')
        Scanner = get_scanner()
        scanner = Scanner(region='us-east-1')
        findings = scanner.scan_bucket('no-version')
        assert any(
            'version' in str(f).lower() for f in findings
        ), 'Expected versioning finding'

    def test_bucket_with_versioning_passes(self):
        """Bucket with versioning enabled should pass versioning check."""
        bucket = 'versioned-bucket'
        self.s3.create_bucket(Bucket=bucket)
        self.s3.put_bucket_versioning(
            Bucket=bucket,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        Scanner = get_scanner()
        scanner = Scanner(region='us-east-1')
        findings = scanner.scan_bucket(bucket)
        version_fails = [f for f in findings if 'version' in f.get('check_id', '').lower()
                         and f.get('severity') in ('HIGH', 'CRITICAL')]
        assert len(version_fails) == 0


@mock_s3
class TestPIIDetection:

    def setup_method(self):
        self.s3 = boto3.client('s3', region_name='us-east-1')

    def test_credit_card_in_object_flagged(self):
        """Object containing a credit card pattern must be flagged CRITICAL."""
        self.s3.create_bucket(Bucket='pii-bucket')
        self.s3.put_object(
            Bucket='pii-bucket',
            Key='data.txt',
            Body=b'Customer card: 4532015112830366 expires 12/25'
        )
        Scanner = get_scanner()
        scanner = Scanner(region='us-east-1')
        findings = scanner.scan_object_content('pii-bucket', 'data.txt')
        assert any(f.get('severity') == 'CRITICAL' for f in findings), \
            'Credit card number must trigger CRITICAL PII finding'

    def test_ssn_in_object_flagged(self):
        """Object containing SSN pattern must be flagged."""
        self.s3.create_bucket(Bucket='ssn-bucket')
        self.s3.put_object(
            Bucket='ssn-bucket', Key='records.csv',
            Body=b'name,ssn\nJohn Doe,123-45-6789'
        )
        Scanner = get_scanner()
        scanner = Scanner(region='us-east-1')
        findings = scanner.scan_object_content('ssn-bucket', 'records.csv')
        assert any('ssn' in str(f).lower() or 'social' in str(f).lower()
                   for f in findings), 'SSN must be detected'

    def test_clean_object_has_no_pii_findings(self):
        """Object with no PII should produce no PII findings."""
        self.s3.create_bucket(Bucket='clean-bucket')
        self.s3.put_object(
            Bucket='clean-bucket', Key='readme.txt',
            Body=b'This is a public README with no sensitive data.'
        )
        Scanner = get_scanner()
        scanner = Scanner(region='us-east-1')
        findings = scanner.scan_object_content('clean-bucket', 'readme.txt')
        critical = [f for f in findings if f.get('severity') == 'CRITICAL']
        assert len(critical) == 0


@mock_s3
class TestReportGeneration:

    def setup_method(self):
        self.s3 = boto3.client('s3', region_name='us-east-1')

    def test_report_has_required_fields(self):
        """Generated report must include metadata, summary, and findings."""
        self.s3.create_bucket(Bucket='report-test')
        Scanner = get_scanner()
        scanner = Scanner(region='us-east-1')
        scanner.scan_all_buckets()
        report = scanner.generate_report()
        assert 'generated_at' in report
        assert 'summary' in report
        assert 'findings' in report
        assert 'total' in report['summary']

    def test_severity_counts_are_accurate(self):
        """Severity counts in summary must match actual findings list."""
        self.s3.create_bucket(Bucket='count-test')
        Scanner = get_scanner()
        scanner = Scanner(region='us-east-1')
        scanner.scan_all_buckets()
        report = scanner.generate_report()
        summary = report['summary']
        actual_critical = sum(1 for f in report['findings'] if f.get('severity') == 'CRITICAL')
        assert summary.get('critical', 0) == actual_critical
