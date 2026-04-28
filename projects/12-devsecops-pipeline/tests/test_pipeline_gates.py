"""
Unit tests for the DevSecOps pipeline security gates.
Tests SAST finding detection in the sample_app and custom Semgrep rule structure.

Run:
    pip install pytest pyyaml bandit semgrep
    pytest tests/ -v
"""
import ast
import re
import subprocess
import sys
from pathlib import Path
import pytest
import yaml

SAMPLE_APP = Path(__file__).parent.parent / 'sample_app' / 'app.py'
SEMGREP_RULES = Path(__file__).parent.parent / 'src' / 'semgrep_rules' / 'custom-security-rules.yaml'
CHECKOV_POLICIES = Path(__file__).parent.parent / 'src' / 'checkov_policies'


class TestSampleAppVulnerabilities:
    """Verify the sample app actually contains the expected vulnerabilities."""

    def _read_source(self) -> str:
        return SAMPLE_APP.read_text()

    def test_sample_app_exists(self):
        assert SAMPLE_APP.exists(), f'Sample app not found: {SAMPLE_APP}'

    def test_sql_injection_present(self):
        source = self._read_source()
        assert 'f"SELECT' in source or "'" + 'username' + "'" in source, \
            'Sample app must contain an obvious SQL injection for testing'

    def test_hardcoded_secret_present(self):
        source = self._read_source()
        assert 'SECRET_KEY' in source or 'hardcoded' in source.lower(), \
            'Sample app must contain a hardcoded secret'

    def test_shell_true_present(self):
        source = self._read_source()
        assert 'shell=True' in source, \
            'Sample app must contain shell=True for command injection testing'

    def test_eval_present(self):
        source = self._read_source()
        assert 'eval(' in source, \
            'Sample app must contain eval() for code injection testing'

    def test_md5_present(self):
        source = self._read_source()
        assert 'md5' in source.lower(), \
            'Sample app must contain MD5 usage for weak crypto testing'

    def test_app_is_valid_python(self):
        """The sample app must be syntactically valid Python."""
        source = self._read_source()
        try:
            ast.parse(source)
        except SyntaxError as e:
            pytest.fail(f'sample_app/app.py has syntax error: {e}')


class TestBanditDetection:
    """Verify Bandit actually catches the expected issues in sample_app."""

    def _run_bandit(self) -> str:
        result = subprocess.run(
            [sys.executable, '-m', 'bandit', '-r', str(SAMPLE_APP),
             '-f', 'txt', '-ll'],
            capture_output=True, text=True
        )
        return result.stdout + result.stderr

    @pytest.mark.skipif(
        subprocess.run([sys.executable, '-m', 'bandit', '--version'],
                       capture_output=True).returncode != 0,
        reason='bandit not installed'
    )
    def test_bandit_detects_sql_injection(self):
        output = self._run_bandit()
        assert 'B608' in output or 'sql' in output.lower(), \
            'Bandit must detect SQL injection (B608) in sample_app'

    @pytest.mark.skipif(
        subprocess.run([sys.executable, '-m', 'bandit', '--version'],
                       capture_output=True).returncode != 0,
        reason='bandit not installed'
    )
    def test_bandit_detects_command_injection(self):
        output = self._run_bandit()
        assert 'B602' in output or 'B605' in output or 'shell' in output.lower(), \
            'Bandit must detect command injection (B602/B605) in sample_app'


class TestSemgrepRulesStructure:
    """Validate custom Semgrep rules are well-formed YAML."""

    def test_rules_file_exists(self):
        assert SEMGREP_RULES.exists(), f'Semgrep rules file not found: {SEMGREP_RULES}'

    def test_rules_are_valid_yaml(self):
        content = yaml.safe_load(SEMGREP_RULES.read_text())
        assert isinstance(content, dict), 'Semgrep rules file must be a YAML dict'
        assert 'rules' in content, 'Must have top-level "rules" key'

    def test_minimum_5_custom_rules(self):
        content = yaml.safe_load(SEMGREP_RULES.read_text())
        rules = content.get('rules', [])
        assert len(rules) >= 5, f'Need at least 5 custom Semgrep rules, got {len(rules)}'

    def test_each_rule_has_required_fields(self):
        content = yaml.safe_load(SEMGREP_RULES.read_text())
        required = {'id', 'message', 'severity', 'languages'}
        for rule in content.get('rules', []):
            missing = required - set(rule.keys())
            assert not missing, \
                f'Rule "{rule.get("id","?")}" missing fields: {missing}'

    def test_rule_ids_are_unique(self):
        content = yaml.safe_load(SEMGREP_RULES.read_text())
        ids = [r.get('id', '') for r in content.get('rules', [])]
        assert len(ids) == len(set(ids)), f'Duplicate rule IDs: {ids}'

    def test_rule_severities_are_valid(self):
        valid = {'ERROR', 'WARNING', 'INFO'}
        content = yaml.safe_load(SEMGREP_RULES.read_text())
        for rule in content.get('rules', []):
            sev = rule.get('severity', '')
            assert sev in valid, \
                f'Rule "{rule.get("id","?")}" has invalid severity: {sev}'

    def test_sql_injection_rule_present(self):
        content = yaml.safe_load(SEMGREP_RULES.read_text())
        ids = [r.get('id', '') for r in content.get('rules', [])]
        assert any('sql' in rid.lower() for rid in ids), \
            'Must have at least one SQL injection rule'

    def test_command_injection_rule_present(self):
        content = yaml.safe_load(SEMGREP_RULES.read_text())
        ids = [r.get('id', '') for r in content.get('rules', [])]
        assert any('shell' in rid.lower() or 'command' in rid.lower() or 'injection' in rid.lower()
                   for rid in ids), \
            'Must have at least one command injection rule'
