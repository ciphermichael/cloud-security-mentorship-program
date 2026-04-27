# Project 17 — Secrets Management with HashiCorp Vault: Step-by-Step Guide

> **Skill Level:** Advanced | **Time:** ~10 hours | **Week:** 17

---

## Overview

Deploy HashiCorp Vault locally and on AWS, configure the AWS secrets engine for dynamic IAM credentials, implement Python-based secret retrieval, automate rotation, and audit all secret access.

**Architecture:**
```
Applications
    ↓ (hvac Python client — short-lived tokens)
HashiCorp Vault (Docker / ECS)
  ├── AWS Secrets Engine   → dynamic IAM creds (TTL 1hr, auto-revoked)
  ├── KV v2 Secrets Engine → static app secrets (versioned)
  ├── PKI Secrets Engine   → TLS certificates (auto-renewed)
  └── Audit Log            → CloudWatch / S3
    ↓ (sync)
AWS Secrets Manager        → backup for Vault-managed secrets
```

---

## Prerequisites

```bash
pip install hvac boto3 pytest

# Docker for local Vault
docker --version   # must be installed
```

---

## Step 1 — Start Vault in Dev Mode

```bash
cd projects/17-secrets-management-vault

# Start a local Vault dev server
docker run -d \
  --name vault-dev \
  --cap-add IPC_LOCK \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=dev-root-token \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  hashicorp/vault:1.15

# Verify
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-root-token
docker exec vault-dev vault status
```

---

## Step 2 — Configure the AWS Secrets Engine

```bash
# Enable the engine
docker exec -e VAULT_TOKEN=dev-root-token vault-dev \
  vault secrets enable aws

# Configure root AWS credentials (use a dedicated IAM user with CreateUser permissions)
docker exec -e VAULT_TOKEN=dev-root-token vault-dev \
  vault write aws/config/root \
    access_key=$AWS_ACCESS_KEY_ID \
    secret_key=$AWS_SECRET_ACCESS_KEY \
    region=us-east-1

# Create a role that generates temp S3 read-only credentials
docker exec -e VAULT_TOKEN=dev-root-token vault-dev \
  vault write aws/roles/s3-readonly \
    credential_type=iam_user \
    default_ttl=1h \
    max_ttl=4h \
    policy_document='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}'

# Generate dynamic credentials
docker exec -e VAULT_TOKEN=dev-root-token vault-dev \
  vault read aws/creds/s3-readonly
# Returns: access_key, secret_key — valid for 1 hour then auto-revoked
```

---

## Step 3 — Configure KV v2 Secrets Engine

```bash
# Enable KV v2
docker exec -e VAULT_TOKEN=dev-root-token vault-dev \
  vault secrets enable -path=secret kv-v2

# Store app secrets
docker exec -e VAULT_TOKEN=dev-root-token vault-dev \
  vault kv put secret/myapp/database \
    host=prod-db.internal \
    username=app_user \
    password=SuperSecret123 \
    port=5432

# Read them back
docker exec -e VAULT_TOKEN=dev-root-token vault-dev \
  vault kv get secret/myapp/database
```

---

## Step 4 — Python Client

```bash
pip install hvac
```

```python
# test the vault_client.py
from src.vault_client import VaultClient

vault = VaultClient(
    addr='http://localhost:8200',
    token='dev-root-token'
)

# Store and retrieve
vault.put_secret('myapp/test', {'api_key': 'sk-test-12345', 'version': '1'})
secret = vault.get_secret('myapp/test')
print(secret)  # {'api_key': 'sk-test-12345', 'version': '1'}

# Dynamic AWS credentials
aws_creds = vault.get_dynamic_aws_creds('s3-readonly')
print(f"Access Key: {aws_creds['access_key']} (expires 1hr)")

# Rotate a secret
vault.rotate_secret('myapp/test', {'api_key': 'sk-test-67890', 'version': '2'})
```

---

## Step 5 — Audit Log Analysis

```bash
# Enable file audit log
docker exec -e VAULT_TOKEN=dev-root-token vault-dev \
  vault audit enable file file_path=/tmp/vault-audit.log

# Perform some operations, then analyse
docker exec vault-dev cat /tmp/vault-audit.log | python -c "
import json, sys
for line in sys.stdin:
    entry = json.loads(line)
    req = entry.get('request', {})
    auth = entry.get('auth', {})
    print(f'{req.get(\"operation\",\"\")} {req.get(\"path\",\"\")} '
          f'by {auth.get(\"display_name\",\"?\")}')
"
```

---

## Step 6 — Scan Lambda Functions for Hardcoded Secrets

```bash
python -c "
from src.rotator import scan_for_static_secrets
findings = scan_for_static_secrets()
for f in findings:
    print(f'[HIGH] {f[\"function\"]} → {f[\"env_var\"]}')
    print(f'       Fix: {f[\"recommendation\"]}')
"
```

---

## Step 7 — Cleanup

```bash
docker stop vault-dev && docker rm vault-dev
```

---

## GitHub Portfolio Checklist

- [ ] `src/vault_client.py` — KV v2, dynamic AWS creds, rotation
- [ ] `src/rotator.py` — RDS password rotation + Lambda env var scanner
- [ ] `src/audit_analyser.py` — root token and access denied detection
- [ ] `docker-compose.yml` — single-command Vault startup
- [ ] `vault-config/config.hcl` — production Vault configuration
- [ ] `tests/` — unit tests using mock Vault responses
- [ ] README with architecture diagram, setup steps, and security concepts

---

## Common Issues

| Issue | Fix |
|-------|-----|
| `hvac.exceptions.VaultError: permission denied` | Token expired or wrong token — `export VAULT_TOKEN=dev-root-token` |
| `VaultNotInitialized` | Dev mode auto-initialises; for prod mode run `vault operator init` |
| `InvalidRequest: no handler for route 'aws/...'` | AWS secrets engine not enabled — run Step 2 |
| Dynamic creds don't appear in AWS | Vault's root IAM user needs `iam:CreateUser`, `iam:CreateAccessKey`, `iam:PutUserPolicy` |
