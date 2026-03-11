# 🆕 Project 17 — Secrets Management with HashiCorp Vault

> **New Project** | Skill Level: Advanced | Phase 5

## Overview
Deploy HashiCorp Vault on AWS, configure dynamic AWS credentials, rotate secrets automatically, and audit all secret access.

## Architecture
```
Applications → Vault Agent (sidecar)
                    ↓
             HashiCorp Vault (ECS/EC2)
             ├── AWS Secrets Engine  → Dynamic IAM credentials (TTL 1hr)
             ├── KV Secrets Engine   → Static app secrets
             ├── PKI Secrets Engine  → TLS certificates
             └── Audit Log           → CloudWatch / S3
                    ↓
              AWS Secrets Manager    ← Vault sync (backup)
```

## Step 1 — Deploy Vault on AWS (Docker)
```bash
# docker-compose.yml
version: '3.9'
services:
  vault:
    image: hashicorp/vault:1.15
    ports:
      - "8200:8200"
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: "dev-root-token"
      VAULT_DEV_LISTEN_ADDRESS: "0.0.0.0:8200"
    cap_add:
      - IPC_LOCK
    volumes:
      - vault-data:/vault/data
      - ./vault-config:/vault/config
    command: vault server -config=/vault/config/config.hcl

volumes:
  vault-data:
```

```hcl
# vault-config/config.hcl
ui = true
disable_mlock = true

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true   # Enable TLS in production!
}

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true
}
```

```bash
docker-compose up -d
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-root-token
vault status
```

## Step 2 — Configure AWS Secrets Engine (Dynamic Credentials)
```bash
# Enable the AWS secrets engine
vault secrets enable aws

# Configure AWS credentials (use least-priv role)
vault write aws/config/root \
  access_key=$AWS_ACCESS_KEY_ID \
  secret_key=$AWS_SECRET_ACCESS_KEY \
  region=us-east-1

# Create a role — Vault will generate temp IAM creds with this policy
vault write aws/roles/dev-s3-readonly \
  credential_type=iam_user \
  policy_document='{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": "*"
    }]
  }' \
  default_ttl=1h \
  max_ttl=4h

# Generate dynamic credentials
vault read aws/creds/dev-s3-readonly
# Returns: access_key, secret_key, security_token — EXPIRES in 1h
```

## Step 3 — KV Secrets Engine & Python Integration
```bash
# Enable KV v2 secrets engine
vault secrets enable -path=secret kv-v2

# Store app secrets
vault kv put secret/myapp/database \
  host=prod-db.internal \
  username=app_user \
  password=supersecret123 \
  port=5432

vault kv put secret/myapp/api-keys \
  stripe_key=sk_live_xxx \
  sendgrid_key=SG.xxx
```

```python
# src/vault_client.py
import hvac   # pip install hvac
import os

class VaultClient:
    def __init__(self, addr: str = None, token: str = None):
        self.client = hvac.Client(
            url=addr or os.environ.get('VAULT_ADDR', 'http://localhost:8200'),
            token=token or os.environ.get('VAULT_TOKEN'),
        )
        if not self.client.is_authenticated():
            raise RuntimeError('Vault authentication failed')

    def get_secret(self, path: str) -> dict:
        """Retrieve a KV v2 secret."""
        result = self.client.secrets.kv.v2.read_secret_version(path=path)
        return result['data']['data']

    def put_secret(self, path: str, secret: dict) -> None:
        """Store a KV v2 secret."""
        self.client.secrets.kv.v2.create_or_update_secret(path=path, secret=secret)

    def get_dynamic_aws_creds(self, role: str = 'dev-s3-readonly') -> dict:
        """Generate dynamic AWS credentials via Vault."""
        result = self.client.secrets.aws.generate_credentials(name=role)
        return result['data']

    def rotate_secret(self, path: str, new_value: dict) -> None:
        """Rotate a secret — Vault keeps version history."""
        self.put_secret(path, new_value)
        print(f'[+] Secret rotated: {path}')

# Usage
vault = VaultClient()
db_creds = vault.get_secret('myapp/database')
print(f'DB Host: {db_creds["host"]}')

aws_creds = vault.get_dynamic_aws_creds()
print(f'Dynamic Key: {aws_creds["access_key"]} (expires 1hr)')
```

## Step 4 — Secret Rotation Automation
```python
# src/rotator.py
import boto3, string, secrets, datetime
from vault_client import VaultClient

def rotate_db_password(vault: VaultClient, db_identifier: str, vault_path: str):
    """Rotate RDS password and update Vault in one atomic-ish operation."""
    rds = boto3.client('rds')
    
    # Generate new password (32 chars, alphanumeric + symbols)
    new_password = secrets.token_urlsafe(32)
    
    # Rotate in RDS
    rds.modify_db_instance(
        DBInstanceIdentifier=db_identifier,
        MasterUserPassword=new_password,
        ApplyImmediately=True
    )
    
    # Update in Vault
    current = vault.get_secret(vault_path)
    current['password'] = new_password
    current['rotated_at'] = datetime.datetime.utcnow().isoformat()
    vault.put_secret(vault_path, current)
    
    print(f'[+] DB password rotated for {db_identifier}')

def scan_for_static_secrets():
    """Find hardcoded secrets in running Lambda functions."""
    lambda_client = boto3.client('lambda')
    findings = []
    for fn in lambda_client.list_functions()['Functions']:
        env_vars = fn.get('Environment', {}).get('Variables', {})
        for key, val in env_vars.items():
            if any(kw in key.lower() for kw in ['password', 'secret', 'key', 'token']):
                findings.append({
                    'function': fn['FunctionName'],
                    'env_var': key,
                    'recommendation': f'Move to Vault path: secret/lambda/{fn["FunctionName"]}'
                })
    return findings
```

## Step 5 — Audit Logging
```hcl
# Enable file audit log in Vault
vault audit enable file file_path=/vault/logs/audit.log

# Enable syslog (sends to CloudWatch if configured)
vault audit enable syslog
```

```python
# src/audit_analyser.py
import json

def analyse_vault_audit(log_path: str) -> list:
    """Parse Vault audit log and flag suspicious access."""
    findings = []
    with open(log_path) as f:
        for line in f:
            try:
                entry = json.loads(line)
                auth = entry.get('auth', {})
                req = entry.get('request', {})
                resp = entry.get('response', {})

                # Flag: too many denied requests from one token
                if resp.get('status') == 403:
                    findings.append({
                        'severity': 'HIGH',
                        'issue': 'VAULT_ACCESS_DENIED',
                        'detail': f"Access denied to {req.get('path')} by {auth.get('display_name','?')}"
                    })

                # Flag: root token used
                if auth.get('token_type') == 'service' and auth.get('display_name') == 'root':
                    findings.append({
                        'severity': 'CRITICAL',
                        'issue': 'ROOT_TOKEN_USED',
                        'detail': f"Root token used to access {req.get('path')}"
                    })
            except json.JSONDecodeError:
                continue
    return findings
```

## Step 6 — Terraform Production Deployment
```hcl
# infra/vault/main.tf
resource "aws_instance" "vault" {
  ami           = "ami-0c55b159cbfafe1f0"  # Amazon Linux 2
  instance_type = "t3.small"
  subnet_id     = var.private_subnet_id
  iam_instance_profile = aws_iam_instance_profile.vault.name

  user_data = <<-EOF
    #!/bin/bash
    yum install -y docker
    systemctl start docker
    docker run -d \
      --name vault \
      --cap-add IPC_LOCK \
      -p 8200:8200 \
      -v /opt/vault/data:/vault/data \
      -v /opt/vault/config:/vault/config \
      hashicorp/vault:1.15 vault server -config=/vault/config/config.hcl
  EOF

  tags = { Name = "vault-server", Environment = "production" }
}

resource "aws_security_group" "vault" {
  name = "vault-sg"
  # Only allow inbound 8200 from app subnet
  ingress {
    from_port   = 8200
    to_port     = 8200
    protocol    = "tcp"
    cidr_blocks = [var.app_subnet_cidr]
  }
}
```

## Step 7 — Run & Test
```bash
# Start local Vault
docker-compose up -d

# Configure
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-root-token
./scripts/setup.sh   # Enable engines, create roles

# Test Python client
python -c "
from src.vault_client import VaultClient
v = VaultClient()
print('Auth:', v.client.is_authenticated())
v.put_secret('myapp/test', {'key': 'value123'})
print('Stored:', v.get_secret('myapp/test'))
creds = v.get_dynamic_aws_creds()
print('AWS Key:', creds['access_key'])
"
```
