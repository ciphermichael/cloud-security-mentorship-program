# 🆕 Project 19 — Zero Trust Network Implementation

> **New Project** | Skill Level: Advanced | Phase 5

## Overview
Implement Zero Trust architecture on AWS: identity-aware access via AWS Verified Access, mTLS between services, continuous device posture evaluation, and just-in-time access controls.

## Zero Trust Principles Applied
| Principle | Implementation |
|-----------|---------------|
| Verify Explicitly | AWS Verified Access + MFA enforcement |
| Least Privilege | Per-session IAM roles, no persistent access |
| Assume Breach | mTLS everywhere, network micro-segmentation |
| Continuous Verification | GuardDuty → auto-revoke on threat detection |

## Architecture
```
User → Identity Provider (Cognito/Okta)
         ↓ (OIDC token + device posture)
    AWS Verified Access
         ↓ (per-request policy evaluation)
    Application (private, no public IP)
         ↓ (mTLS)
    Internal Services → Database
```

## Step 1 — AWS Verified Access Setup
```bash
# Create a Verified Access instance
aws ec2 create-verified-access-instance \
  --description "Zero Trust App Access"

# Create a trust provider (OIDC with Cognito)
aws ec2 create-verified-access-trust-provider \
  --trust-provider-type user \
  --user-trust-provider-type oidc \
  --oidc-options '{
    "Issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXXX",
    "AuthorizationEndpoint": "https://myapp.auth.us-east-1.amazoncognito.com/oauth2/authorize",
    --token-endpoint "https://myapp.auth.us-east-1.amazoncognito.com/oauth2/token",
    "UserInfoEndpoint": "https://myapp.auth.us-east-1.amazoncognito.com/oauth2/userInfo",
    "ClientId": "YOUR_CLIENT_ID",
    "ClientSecret": "YOUR_CLIENT_SECRET",
    "Scope": "openid email profile"
  }' \
  --description "Cognito OIDC Trust Provider"
```

## Step 2 — Verified Access Policy (Cedar)
```python
# policies/app_access_policy.cedar
# Only allow access if:
# - User is authenticated (MFA required)
# - User is in the "engineers" group
# - Device is managed (MDM enrolled)
# - Request is within business hours (optional)

permit (
  principal,
  action == AWS::VerifiedAccess::Action::"connect",
  resource == AWS::VerifiedAccess::Endpoint::"vae-YOUR-ENDPOINT-ID"
)
when {
  context.identity.groups.contains("engineers") &&
  context.identity.mfa_authenticated == true &&
  context.device.managed == true
};

# Deny all others
forbid (
  principal,
  action == AWS::VerifiedAccess::Action::"connect",
  resource == AWS::VerifiedAccess::Endpoint::"vae-YOUR-ENDPOINT-ID"
)
unless {
  context.identity.groups.contains("engineers") &&
  context.identity.mfa_authenticated == true
};
```

## Step 3 — mTLS Certificate Authority
```python
# src/cert_authority.py
"""Internal PKI using AWS Private CA for mTLS certificates."""
import boto3, base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

class InternalCA:
    def __init__(self, ca_arn: str):
        self.acm_pca = boto3.client('acm-pca')
        self.ca_arn = ca_arn

    def issue_service_cert(self, service_name: str, validity_days: int = 30) -> dict:
        """Issue an mTLS certificate for a service."""
        # Generate key pair
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ).decode()

        # Create CSR
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, service_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'MyOrg Internal'),
            ]))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(f'{service_name}.internal')]),
                critical=False
            )
            .sign(key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

        # Issue via AWS Private CA
        resp = self.acm_pca.issue_certificate(
            CertificateAuthorityArn=self.ca_arn,
            Csr=csr_pem,
            SigningAlgorithm='SHA256WITHRSA',
            Validity={'Value': validity_days, 'Type': 'DAYS'},
        )
        cert_arn = resp['CertificateArn']

        import time; time.sleep(3)  # Wait for issuance
        cert_resp = self.acm_pca.get_certificate(
            CertificateAuthorityArn=self.ca_arn,
            CertificateArn=cert_arn
        )
        return {
            'service': service_name,
            'cert_arn': cert_arn,
            'certificate': cert_resp['Certificate'],
            'private_key': private_key_pem,
            'valid_days': validity_days,
        }
```

## Step 4 — mTLS Enforcing Flask App
```python
# src/app.py
"""Microservice that requires mTLS on all incoming connections."""
import ssl, os
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

def verify_client_cert():
    """Verify the client presented a valid certificate from our internal CA."""
    client_cert = request.environ.get('SSL_CLIENT_CERT')
    if not client_cert:
        abort(401, 'Client certificate required')
    
    dn = request.environ.get('SSL_CLIENT_S_DN', '')
    if 'MyOrg Internal' not in dn:
        abort(403, f'Untrusted certificate issuer: {dn}')
    
    return dn

@app.before_request
def require_mtls():
    verify_client_cert()

@app.route('/api/data')
def get_data():
    client_dn = request.environ.get('SSL_CLIENT_S_DN')
    return jsonify({'data': 'protected', 'authenticated_as': client_dn})

@app.route('/health')
def health():
    # Health check doesn't require mTLS
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations('certs/ca-chain.pem')      # Client cert CA
    context.load_cert_chain('certs/server.crt', 'certs/server.key')
    app.run(host='0.0.0.0', port=8443, ssl_context=context)
```

## Step 5 — Just-in-Time (JIT) Access Controller
```python
# src/jit_access.py
"""Issue temporary, scoped IAM credentials for specific tasks."""
import boto3
from datetime import datetime, timedelta
import uuid, json

class JITAccessController:
    def __init__(self):
        self.sts = boto3.client('sts')
        self.iam = boto3.client('iam')

    def request_access(self, user_arn: str, resource: str, reason: str,
                       duration_seconds: int = 3600) -> dict:
        """Issue a temporary scoped role assumption for the requested resource."""
        if duration_seconds > 3600:
            raise ValueError('Max JIT duration is 1 hour')

        # Generate minimal policy for just this resource
        policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Action': ['s3:GetObject', 's3:ListBucket'],
                'Resource': [resource, f'{resource}/*'],
                'Condition': {
                    'StringEquals': {'aws:RequestedRegion': 'us-east-1'}
                }
            }]
        }

        # Assume a base role with inline scope-down policy
        response = self.sts.assume_role(
            RoleArn='arn:aws:iam::ACCOUNT:role/JITBaseRole',
            RoleSessionName=f'jit-{uuid.uuid4().hex[:8]}',
            DurationSeconds=duration_seconds,
            Policy=json.dumps(policy),
            Tags=[
                {'Key': 'RequestedBy', 'Value': user_arn.split('/')[-1]},
                {'Key': 'JITReason', 'Value': reason[:256]},
                {'Key': 'ExpiresAt', 'Value': (datetime.utcnow() + timedelta(seconds=duration_seconds)).isoformat()},
            ]
        )

        creds = response['Credentials']
        print(f'[+] JIT access granted to {user_arn} for {resource} ({duration_seconds}s)')
        return {
            'access_key': creds['AccessKeyId'],
            'secret_key': creds['SecretAccessKey'],
            'session_token': creds['SessionToken'],
            'expires': creds['Expiration'].isoformat(),
            'resource': resource,
        }
```

## Step 6 — Continuous Verification (GuardDuty → Revoke)
```python
# src/continuous_verifier.py
import boto3, json

def lambda_handler(event, context):
    """Revoke access when GuardDuty detects a threat for an active session."""
    detail = event.get('detail', {})
    severity = detail.get('severity', 0)

    if severity < 7:  # Only respond to high/critical
        return

    # Extract the compromised entity
    resource = detail.get('resource', {})
    access_key = resource.get('accessKeyDetails', {}).get('accessKeyId')

    if access_key:
        iam = boto3.client('iam')
        iam.update_access_key(AccessKeyId=access_key, Status='Inactive')
        print(f'[!] ZERO TRUST: Deactivated key {access_key} due to GuardDuty finding severity={severity}')

        # Revoke all sessions for this user
        username = resource.get('accessKeyDetails', {}).get('userName')
        if username:
            iam.attach_user_policy(
                UserName=username,
                PolicyArn='arn:aws:iam::aws:policy/AWSDenyAll'
            )
            print(f'[!] Applied DenyAll policy to user {username} — pending investigation')

        # Notify security team
        sns = boto3.client('sns')
        sns.publish(
            TopicArn='arn:aws:sns:us-east-1:ACCOUNT:SecurityAlerts',
            Subject=f'[CRITICAL] Zero Trust Violation — Access Revoked for {username}',
            Message=json.dumps({'event': detail, 'action': 'ACCESS_REVOKED'}, indent=2)
        )
```

## Step 7 — Run & Test
```bash
# Install dependencies
pip install flask cryptography boto3 requests

# Generate test certificates
openssl genrsa -out certs/ca.key 4096
openssl req -x509 -new -key certs/ca.key -sha256 -days 365 -out certs/ca.crt \
  -subj "/C=GB/O=MyOrg Internal/CN=Internal CA"

openssl genrsa -out certs/server.key 2048
openssl req -new -key certs/server.key -out certs/server.csr \
  -subj "/C=GB/O=MyOrg Internal/CN=api.internal"
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/server.crt -days 365 -sha256

# Start mTLS app
python src/app.py

# Test with client cert (should succeed)
curl --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt \
  https://localhost:8443/api/data

# Test without cert (should fail with 401)
curl --cacert certs/ca.crt https://localhost:8443/api/data
```
