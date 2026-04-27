"""
Unit tests for Container Security Framework.
Tests Trivy result parsing and Falco rule validation — no Docker daemon needed.

Run:
    pip install pytest pyyaml
    pytest tests/ -v
"""
import json
import re
import subprocess
import pytest
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock


PROJECT_ROOT = Path(__file__).parent.parent


# ── Trivy Result Parsing ───────────────────────────────────────────────────────

class TestTrivyResultParsing:
    """Test parsing of Trivy JSON scan output."""

    def _make_trivy_result(self, vuln_count: int = 0,
                            severity: str = 'CRITICAL') -> dict:
        vulns = [
            {
                'VulnerabilityID': f'CVE-2024-{i:04d}',
                'PkgName': f'package-{i}',
                'Severity': severity,
                'Title': f'Test vulnerability {i}',
                'FixedVersion': '1.2.3',
                'InstalledVersion': '1.0.0',
            }
            for i in range(vuln_count)
        ]
        return {
            'SchemaVersion': 2,
            'ArtifactType': 'container_image',
            'Results': [
                {
                    'Target': 'nginx:latest',
                    'Type': 'alpine',
                    'Vulnerabilities': vulns
                }
            ]
        }

    def test_no_critical_vulns_passes_gate(self):
        """Trivy result with no CRITICAL CVEs must pass the CI gate."""
        import sys, os
        sys.path.insert(0, str(PROJECT_ROOT / 'src'))
        try:
            from scanner import parse_trivy_result, passes_gate
        except ImportError:
            pytest.skip('scanner module not yet implemented')

        result = self._make_trivy_result(vuln_count=0)
        assert passes_gate(parse_trivy_result(result), severity_threshold='CRITICAL')

    def test_critical_vuln_fails_gate(self):
        """Trivy result with CRITICAL CVEs must fail the CI gate."""
        import sys, os
        sys.path.insert(0, str(PROJECT_ROOT / 'src'))
        try:
            from scanner import parse_trivy_result, passes_gate
        except ImportError:
            pytest.skip('scanner module not yet implemented')

        result = self._make_trivy_result(vuln_count=3, severity='CRITICAL')
        assert not passes_gate(parse_trivy_result(result), severity_threshold='CRITICAL')

    def test_severity_counts_extracted(self):
        """parse_trivy_result must return counts by severity."""
        import sys, os
        sys.path.insert(0, str(PROJECT_ROOT / 'src'))
        try:
            from scanner import parse_trivy_result
        except ImportError:
            pytest.skip('scanner module not yet implemented')

        result = self._make_trivy_result(vuln_count=5, severity='HIGH')
        parsed = parse_trivy_result(result)
        assert parsed.get('HIGH', 0) == 5
        assert parsed.get('CRITICAL', 0) == 0


# ── Falco Rules Validation ─────────────────────────────────────────────────────

class TestFalcoRulesValid:
    """Validate Falco YAML rule files are well-formed."""

    @pytest.fixture
    def rules_dir(self):
        d = PROJECT_ROOT / 'rules'
        if not d.exists():
            pytest.skip('rules/ directory not yet created')
        return d

    def test_rules_files_are_valid_yaml(self, rules_dir):
        """All .yaml files in rules/ must parse as valid YAML."""
        yaml_files = list(rules_dir.glob('*.yaml')) + list(rules_dir.glob('*.yml'))
        assert len(yaml_files) >= 1, 'No YAML rule files found in rules/'
        for f in yaml_files:
            try:
                docs = yaml.safe_load_all(f.read_text())
                for doc in docs:
                    pass  # Just validate it parses
            except yaml.YAMLError as e:
                pytest.fail(f'{f.name} is not valid YAML: {e}')

    def test_rules_have_required_fields(self, rules_dir):
        """Each Falco rule must have: rule, desc, condition, output, priority."""
        required_fields = {'rule', 'desc', 'condition', 'output', 'priority'}
        for yaml_file in rules_dir.glob('*.yaml'):
            content = list(yaml.safe_load_all(yaml_file.read_text()))
            rules = [item for item in content
                     if isinstance(item, dict) and 'rule' in item]
            for rule in rules:
                missing = required_fields - set(rule.keys())
                assert not missing, \
                    f'Rule "{rule.get("rule")}" in {yaml_file.name} missing fields: {missing}'

    def test_rules_have_valid_priority(self, rules_dir):
        """Falco rule priority must be one of the valid values."""
        valid_priorities = {'DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERROR', 'CRITICAL', 'ALERT', 'EMERGENCY'}
        for yaml_file in rules_dir.glob('*.yaml'):
            content = list(yaml.safe_load_all(yaml_file.read_text()))
            rules = [item for item in content
                     if isinstance(item, dict) and 'rule' in item]
            for rule in rules:
                priority = rule.get('priority', '').upper()
                assert priority in valid_priorities, \
                    f'Rule "{rule["rule"]}" has invalid priority: {priority}'

    def test_at_least_5_custom_rules(self, rules_dir):
        """Project must define at least 5 custom Falco rules."""
        total_rules = 0
        for yaml_file in rules_dir.glob('*.yaml'):
            content = list(yaml.safe_load_all(yaml_file.read_text()))
            total_rules += sum(1 for item in content
                               if isinstance(item, dict) and 'rule' in item)
        assert total_rules >= 5, f'Only {total_rules} Falco rules — need at least 5'


# ── Dockerfile Security Checks ─────────────────────────────────────────────────

class TestDockerfileHardening:
    """Validate the hardened Dockerfile follows security best practices."""

    @pytest.fixture
    def dockerfile(self):
        # Check multiple possible locations
        for path in [
            PROJECT_ROOT / 'secure_dockerfiles' / 'python_app' / 'Dockerfile',
            PROJECT_ROOT / 'Dockerfile',
            PROJECT_ROOT / 'docker' / 'Dockerfile',
        ]:
            if path.exists():
                return path.read_text()
        pytest.skip('No Dockerfile found in project')

    def test_dockerfile_has_non_root_user(self, dockerfile):
        """Dockerfile must set a non-root USER."""
        lines = [l.strip() for l in dockerfile.splitlines()]
        user_instructions = [l for l in lines if l.upper().startswith('USER ')]
        assert len(user_instructions) >= 1, 'Dockerfile must have a USER instruction'
        # USER must not be root or 0
        for user_line in user_instructions:
            user = user_line.split(None, 1)[1].strip()
            assert user not in ('root', '0'), \
                f'USER must not be root, got: {user_line}'

    def test_dockerfile_has_healthcheck(self, dockerfile):
        """Dockerfile should include a HEALTHCHECK instruction."""
        assert 'HEALTHCHECK' in dockerfile.upper(), \
            'Dockerfile must include a HEALTHCHECK instruction'

    def test_dockerfile_pins_base_image(self, dockerfile):
        """FROM instruction should pin to a digest or specific version tag."""
        from_lines = [l.strip() for l in dockerfile.splitlines()
                      if l.strip().upper().startswith('FROM ')
                      and 'AS' not in l.upper() or l.strip().upper().startswith('FROM ')]
        assert len(from_lines) >= 1
        for from_line in from_lines:
            # Should use digest (@sha256:) or specific version, not :latest
            assert ':latest' not in from_line.lower(), \
                f'Base image must not use :latest tag: {from_line}'

    def test_dockerfile_no_sensitive_env_vars(self, dockerfile):
        """Dockerfile must not contain ENV with secrets."""
        sensitive_patterns = [
            r'ENV\s+\S*(PASSWORD|SECRET|KEY|TOKEN)\s*=\s*\S+',
            r'ENV\s+\S*(password|secret|key|token)\s*=\s*\S+',
        ]
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, dockerfile, re.IGNORECASE)
            assert not matches, \
                f'Dockerfile contains sensitive ENV var pattern: {matches}'
