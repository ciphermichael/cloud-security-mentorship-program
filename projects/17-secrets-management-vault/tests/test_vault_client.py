"""
Unit tests for VaultClient, rotator, and audit_analyser.
Uses unittest.mock — no real Vault server needed.

Run:
    pip install pytest hvac
    pytest tests/ -v
"""
import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, call


def get_vault_client():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from src.vault_client import VaultClient
    return VaultClient


def get_audit_analyser():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from src.audit_analyser import analyse_vault_audit
    return analyse_vault_audit


class TestVaultClientKV:

    def _make_client(self) -> object:
        Client = get_vault_client()
        with patch('src.vault_client.hvac.Client') as MockHvac:
            mock_instance = MagicMock()
            mock_instance.is_authenticated.return_value = True
            MockHvac.return_value = mock_instance
            client = Client(addr='http://localhost:8200', token='test-token')
            client.client = mock_instance
            return client

    def test_get_secret_calls_kv_v2(self):
        client = self._make_client()
        client.client.secrets.kv.v2.read_secret_version.return_value = {
            'data': {'data': {'username': 'admin', 'password': 'secret'}}
        }
        result = client.get_secret('myapp/database')
        assert result == {'username': 'admin', 'password': 'secret'}
        client.client.secrets.kv.v2.read_secret_version.assert_called_once_with(
            path='myapp/database', mount_point='secret', version=None
        )

    def test_put_secret_calls_kv_v2(self):
        client = self._make_client()
        client.client.secrets.kv.v2.create_or_update_secret.return_value = {
            'data': {'version': 3}
        }
        result = client.put_secret('myapp/test', {'key': 'value'})
        assert result['version'] == 3
        client.client.secrets.kv.v2.create_or_update_secret.assert_called_once()

    def test_rotate_secret_adds_rotated_at(self):
        client = self._make_client()
        client.client.secrets.kv.v2.create_or_update_secret.return_value = {
            'data': {'version': 5}
        }
        result = client.rotate_secret('myapp/db', {'password': 'newpass'})
        assert result['version'] == 5
        call_args = client.client.secrets.kv.v2.create_or_update_secret.call_args
        secret_written = call_args.kwargs.get('secret', {})
        assert 'rotated_at' in secret_written
        assert secret_written['password'] == 'newpass'

    def test_list_secrets_returns_keys(self):
        client = self._make_client()
        client.client.secrets.kv.v2.list_secrets.return_value = {
            'data': {'keys': ['myapp/db', 'myapp/api-keys']}
        }
        keys = client.list_secrets('myapp')
        assert 'myapp/db' in keys

    def test_dynamic_aws_creds_called(self):
        client = self._make_client()
        client.client.secrets.aws.generate_credentials.return_value = {
            'data': {'access_key': 'AKIATEST', 'secret_key': 'testsecret'},
            'lease_duration': 3600,
        }
        creds = client.get_dynamic_aws_creds('s3-readonly')
        assert creds['access_key'] == 'AKIATEST'
        client.client.secrets.aws.generate_credentials.assert_called_with(
            name='s3-readonly'
        )

    def test_authentication_failure_raises(self):
        Client = get_vault_client()
        with patch('src.vault_client.hvac.Client') as MockHvac:
            mock_instance = MagicMock()
            mock_instance.is_authenticated.return_value = False
            MockHvac.return_value = mock_instance
            with pytest.raises(RuntimeError, match='authentication failed'):
                Client(addr='http://localhost:8200', token='bad-token')


class TestAuditAnalyser:

    def _write_audit_log(self, entries: list[dict]) -> str:
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.log',
                                        delete=False, dir='/tmp')
        for entry in entries:
            f.write(json.dumps(entry) + '\n')
        f.close()
        return f.name

    def _make_entry(self, operation: str = 'read', path: str = 'secret/data/test',
                    display_name: str = 'user-alice', status: int = 200,
                    token_type: str = 'service',
                    hour: int = 10) -> dict:
        return {
            'time': f'2024-01-15T{hour:02d}:00:00.000Z',
            'auth': {
                'display_name': display_name,
                'token_type': token_type,
                'accessor': f'accessor-{display_name}',
            },
            'request': {'operation': operation, 'path': path},
            'response': {'status_code': status},
            'error': '',
        }

    def test_root_token_usage_flagged_critical(self):
        analyse = get_audit_analyser()
        log = self._write_audit_log([
            self._make_entry(display_name='root', token_type='service')
        ])
        findings = analyse(log)
        critical = [f for f in findings if f.rule_id == 'VAULT-001']
        assert len(critical) >= 1
        assert all(f.severity == 'CRITICAL' for f in critical)
        Path(log).unlink()

    def test_access_denied_burst_flagged(self):
        analyse = get_audit_analyser()
        entries = [
            self._make_entry(status=403, display_name='attacker')
            for _ in range(15)
        ]
        log = self._write_audit_log(entries)
        findings = analyse(log)
        denied_findings = [f for f in findings if f.rule_id == 'VAULT-002']
        assert len(denied_findings) >= 1
        assert denied_findings[0].severity == 'HIGH'
        Path(log).unlink()

    def test_normal_access_no_findings(self):
        analyse = get_audit_analyser()
        entries = [self._make_entry(status=200, display_name='alice')]
        log = self._write_audit_log(entries)
        findings = analyse(log)
        assert len(findings) == 0
        Path(log).unlink()

    def test_after_hours_access_flagged(self):
        analyse = get_audit_analyser()
        entries = [
            self._make_entry(hour=2, display_name='night-user')
            for _ in range(10)
        ]
        log = self._write_audit_log(entries)
        findings = analyse(log)
        after_hours = [f for f in findings if f.rule_id == 'VAULT-004']
        assert len(after_hours) >= 1
        Path(log).unlink()

    def test_nonexistent_log_returns_empty(self):
        analyse = get_audit_analyser()
        findings = analyse('/nonexistent/path/vault-audit.log')
        assert findings == []

    def test_invalid_json_line_skipped(self):
        analyse = get_audit_analyser()
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.log',
                                        delete=False, dir='/tmp')
        f.write('not valid json\n')
        f.write(json.dumps(self._make_entry()) + '\n')
        f.close()
        findings = analyse(f.name)  # Should not raise
        Path(f.name).unlink()
