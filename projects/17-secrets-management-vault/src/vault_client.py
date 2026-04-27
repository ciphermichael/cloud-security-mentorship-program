"""
HashiCorp Vault Python client — KV v2, dynamic AWS credentials, secret rotation.

Requirements:
    pip install hvac boto3

Usage:
    export VAULT_ADDR=http://localhost:8200
    export VAULT_TOKEN=dev-root-token

    from src.vault_client import VaultClient
    vault = VaultClient()
    vault.put_secret('myapp/database', {'host': 'db.internal', 'password': 'secret'})
    creds = vault.get_secret('myapp/database')
"""
import os
import logging
from datetime import datetime, timezone
from typing import Optional

try:
    import hvac
except ImportError as e:
    raise ImportError("Install hvac: pip install hvac") from e

logger = logging.getLogger(__name__)


class VaultClient:
    """
    Thin wrapper around the hvac client with convenience methods for
    the patterns used most in cloud security automation.
    """

    def __init__(self, addr: Optional[str] = None, token: Optional[str] = None,
                 mount_point: str = 'secret'):
        """
        Args:
            addr:        Vault server URL. Defaults to VAULT_ADDR env var.
            token:       Vault token. Defaults to VAULT_TOKEN env var.
            mount_point: KV v2 mount path (default: 'secret').
        """
        self._addr = addr or os.environ.get('VAULT_ADDR', 'http://localhost:8200')
        self._token = token or os.environ.get('VAULT_TOKEN', '')
        self.mount_point = mount_point

        self.client = hvac.Client(url=self._addr, token=self._token)

        if not self.client.is_authenticated():
            raise RuntimeError(
                f'Vault authentication failed for {self._addr}. '
                'Check VAULT_ADDR and VAULT_TOKEN environment variables.'
            )
        logger.info('Vault client authenticated: %s', self._addr)

    # ── KV v2 Operations ───────────────────────────────────────────────────────

    def get_secret(self, path: str, version: Optional[int] = None) -> dict:
        """
        Retrieve a KV v2 secret.

        Args:
            path:    Secret path (e.g. 'myapp/database')
            version: Specific version to retrieve (None = latest)

        Returns:
            Secret data dict
        """
        resp = self.client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point=self.mount_point,
            version=version,
        )
        return resp['data']['data']

    def put_secret(self, path: str, secret: dict) -> dict:
        """
        Create or update a KV v2 secret.

        Args:
            path:   Secret path
            secret: Dict of key/value pairs to store

        Returns:
            Vault response metadata
        """
        resp = self.client.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret=secret,
            mount_point=self.mount_point,
        )
        version = resp['data']['version']
        logger.info('Secret written: %s (version %s)', path, version)
        return resp['data']

    def delete_secret(self, path: str) -> None:
        """Soft-delete the latest version of a secret (recoverable)."""
        self.client.secrets.kv.v2.delete_latest_version_of_secret(
            path=path, mount_point=self.mount_point
        )
        logger.warning('Secret deleted: %s', path)

    def list_secrets(self, path: str = '') -> list[str]:
        """List all secret paths under a given prefix."""
        try:
            resp = self.client.secrets.kv.v2.list_secrets(
                path=path, mount_point=self.mount_point
            )
            return resp['data']['keys']
        except hvac.exceptions.InvalidPath:
            return []

    def rotate_secret(self, path: str, new_value: dict) -> dict:
        """
        Rotate a secret — writes a new version, keeping history.

        Args:
            path:      Secret path
            new_value: New secret dict (will be merged with 'rotated_at' timestamp)
        """
        new_value = {
            **new_value,
            'rotated_at': datetime.now(timezone.utc).isoformat(),
        }
        result = self.put_secret(path, new_value)
        logger.info('Secret rotated: %s → version %s', path, result['version'])
        return result

    def get_secret_metadata(self, path: str) -> dict:
        """Return metadata (versions, creation time, deletion info) for a secret."""
        resp = self.client.secrets.kv.v2.read_secret_metadata(
            path=path, mount_point=self.mount_point
        )
        return resp['data']

    # ── Dynamic AWS Credentials ────────────────────────────────────────────────

    def get_dynamic_aws_creds(self, role: str = 's3-readonly') -> dict:
        """
        Generate dynamic AWS credentials from the AWS secrets engine.

        The credentials are short-lived (TTL configured in Vault role).
        They are automatically revoked when the lease expires.

        Args:
            role: AWS role name configured in Vault (e.g. 's3-readonly')

        Returns:
            Dict with access_key, secret_key, security_token, lease_duration
        """
        resp = self.client.secrets.aws.generate_credentials(name=role)
        creds = resp['data']
        logger.info(
            'Dynamic AWS credentials generated for role "%s" '
            '(lease: %ss)', role, resp.get('lease_duration', '?')
        )
        return creds

    # ── Audit Helpers ──────────────────────────────────────────────────────────

    def check_health(self) -> dict:
        """Return Vault health status."""
        return self.client.sys.read_health_status(method='GET')

    def is_authenticated(self) -> bool:
        return self.client.is_authenticated()
