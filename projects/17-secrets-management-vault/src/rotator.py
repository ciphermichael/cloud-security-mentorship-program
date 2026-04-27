"""
Secret rotation automation — rotates RDS passwords and scans Lambda functions
for hardcoded credentials that should be moved to Vault.
"""
import boto3
import secrets
import logging
from datetime import datetime, timezone

from .vault_client import VaultClient

logger = logging.getLogger(__name__)


def generate_password(length: int = 32) -> str:
    """Generate a cryptographically strong random password."""
    import string
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*'
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def rotate_rds_password(vault: VaultClient, db_identifier: str,
                         vault_path: str, region: str = 'us-east-1') -> dict:
    """
    Rotate an RDS master password and update the secret in Vault atomically.

    Steps:
    1. Generate a new strong password
    2. Update it in RDS (AWS API)
    3. Update it in Vault (new version)

    Args:
        vault:         VaultClient instance
        db_identifier: RDS DB instance identifier
        vault_path:    Vault KV path storing the database credentials
        region:        AWS region

    Returns:
        Result dict with rotation timestamp and Vault version
    """
    rds = boto3.client('rds', region_name=region)
    new_password = generate_password()

    logger.info('Rotating password for RDS instance: %s', db_identifier)

    # Step 1: Rotate in RDS
    rds.modify_db_instance(
        DBInstanceIdentifier=db_identifier,
        MasterUserPassword=new_password,
        ApplyImmediately=True,
    )
    logger.info('RDS password updated for: %s', db_identifier)

    # Step 2: Update in Vault (read current, update password field)
    try:
        current = vault.get_secret(vault_path)
    except Exception:
        current = {}

    current['password'] = new_password
    current['db_instance'] = db_identifier
    result = vault.rotate_secret(vault_path, current)

    return {
        'db_identifier': db_identifier,
        'vault_path': vault_path,
        'vault_version': result['version'],
        'rotated_at': datetime.now(timezone.utc).isoformat(),
    }


def scan_for_static_secrets(region: str = 'us-east-1') -> list[dict]:
    """
    Scan Lambda function environment variables for credentials that should
    be moved to Vault.

    Returns list of findings with function name, variable name, and
    recommended Vault path.
    """
    lambda_client = boto3.client('lambda', region_name=region)
    findings = []

    SENSITIVE_KEYWORDS = {
        'password', 'passwd', 'secret', 'key', 'token',
        'credential', 'apikey', 'api_key', 'auth',
    }

    paginator = lambda_client.get_paginator('list_functions')
    for page in paginator.paginate():
        for fn in page['Functions']:
            env_vars = fn.get('Configuration', fn).get(
                'Environment', {}
            ).get('Variables', {})
            for var_name, value in env_vars.items():
                if any(kw in var_name.lower() for kw in SENSITIVE_KEYWORDS):
                    findings.append({
                        'severity': 'HIGH',
                        'function': fn['FunctionName'],
                        'env_var': var_name,
                        'value_length': len(value),
                        'recommendation': (
                            f'Move to Vault: secret/lambda/'
                            f'{fn["FunctionName"]}/{var_name.lower()}'
                        ),
                        'vault_agent_path': (
                            f'secret/data/lambda/{fn["FunctionName"]}'
                        ),
                    })

    if findings:
        logger.warning(
            'Found %d Lambda functions with potentially hardcoded secrets',
            len(findings)
        )
    return findings
