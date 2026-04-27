# Project 19 — Zero Trust Architecture & Implementation: Step-by-Step Guide

> **Skill Level:** Advanced | **Time:** ~10 hours | **Week:** 17

---

## Overview

Implement Zero Trust security controls on AWS following NIST SP 800-207:
verify every identity explicitly, enforce least-privilege per session,
and assume breach by encrypting all service-to-service traffic with mTLS.

**Zero Trust Controls Implemented:**

| Control | Tool | NIST Tenet |
|---------|------|-----------|
| Identity-aware application proxy | AWS Verified Access | Verify explicitly |
| MFA + session age conditions | IAM policy conditions | Verify explicitly |
| Short-lived credentials (1hr max) | STS session duration | Least privilege |
| Service-to-service mTLS | OpenSSL + ACM Private CA | Assume breach |
| Network micro-segmentation | Security Groups + NACLs | Assume breach |
| Continuous monitoring | CloudTrail + GuardDuty | Assume breach |

---

## Prerequisites

```bash
pip install boto3 cryptography pytest moto

# OpenSSL for mTLS demo
openssl version   # must be installed
```

---

## Step 1 — Create a Zero Trust IAM Policy

```bash
# Deploy the Zero Trust policy — denies access without MFA and enforces session age
cat > zt-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireMFAWithin1Hour",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "NumericGreaterThan": {
          "aws:MultiFactorAuthAge": "3600"
        }
      }
    },
    {
      "Sid": "DenyWithoutMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:GetVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:ListMFADevices",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    },
    {
      "Sid": "RestrictToApprovedRegions",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["us-east-1", "us-west-2"]
        }
      }
    }
  ]
}
EOF

aws iam create-policy \
  --policy-name ZeroTrustBaseline \
  --policy-document file://zt-policy.json \
  --description "Zero Trust baseline: requires MFA within 1 hour, approved regions only"
```

---

## Step 2 — Generate mTLS Certificates

```bash
# Create a private CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
  -subj "/CN=ZeroTrustCA/O=MyCompany/C=US"

# Create server certificate (api-service identity)
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/CN=api-service/O=MyCompany/C=US"
openssl x509 -req -days 90 -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# Create client certificate (frontend-service identity)
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
  -subj "/CN=frontend-service/O=MyCompany/C=US"
openssl x509 -req -days 90 -in client.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt

# Verify both certs are signed by the same CA
openssl verify -CAfile ca.crt server.crt
openssl verify -CAfile ca.crt client.crt
```

---

## Step 3 — Test mTLS Enforcement

```bash
# Start a test TLS server requiring client certificates
openssl s_server \
  -cert server.crt -key server.key \
  -CAfile ca.crt -Verify 1 \
  -port 8443 -www &

# Test 1: connection WITH valid client cert — must succeed
curl https://localhost:8443 \
  --cert client.crt --key client.key \
  --cacert ca.crt \
  --silent --output /dev/null --write-out "HTTP %{http_code}\n"
# Expected: HTTP 200

# Test 2: connection WITHOUT client cert — must be rejected
curl https://localhost:8443 \
  --cacert ca.crt \
  --silent --output /dev/null --write-out "HTTP %{http_code}\n" 2>&1
# Expected: SSL handshake error

kill %1  # Stop the test server
```

---

## Step 4 — AWS Verified Access (Application-Level Zero Trust)

```bash
# Note: AWS Verified Access requires an actual AWS environment
# This creates the infrastructure for identity-aware application access

# Create a Verified Access instance
VA_INSTANCE=$(aws ec2 create-verified-access-instance \
  --description "Zero Trust App Proxy" \
  --query 'VerifiedAccessInstance.VerifiedAccessInstanceId' \
  --output text)

echo "Verified Access Instance: $VA_INSTANCE"

# Create a trust provider (OIDC / Cognito)
VA_TRUST=$(aws ec2 create-verified-access-trust-provider \
  --trust-provider-type user \
  --user-trust-provider-type oidc \
  --oidc-options '{
    "Issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXXX",
    "ClientId": "your-client-id",
    "ClientSecret": "your-client-secret",
    "Scope": "openid email",
    "AuthorizationEndpoint": "https://yourapp.auth.us-east-1.amazoncognito.com/oauth2/authorize",
    "TokenEndpoint": "https://yourapp.auth.us-east-1.amazoncognito.com/oauth2/token",
    "UserInfoEndpoint": "https://yourapp.auth.us-east-1.amazoncognito.com/oauth2/userInfo"
  }' \
  --description "Cognito OIDC Trust Provider" \
  --query 'VerifiedAccessTrustProvider.VerifiedAccessTrustProviderId' \
  --output text)

echo "Trust Provider: $VA_TRUST"

# Attach trust provider to instance
aws ec2 attach-verified-access-trust-provider \
  --verified-access-instance-id $VA_INSTANCE \
  --verified-access-trust-provider-id $VA_TRUST
```

---

## Step 5 — Run the Python Zero Trust Validator

```bash
python -c "
from src.zt_validator import ZeroTrustValidator

# Validate an IAM identity against Zero Trust criteria
validator = ZeroTrustValidator(region='us-east-1')

result = validator.check_identity_trust(
    identity_arn='arn:aws:iam::123456789012:user/developer-alice',
    required_mfa=True,
    max_session_age_seconds=3600
)
print(f'Trust decision: {result[\"trust_decision\"]}')
print(f'Reasons: {result[\"reasons\"]}')
"
```

---

## Step 6 — Run Tests

```bash
pytest tests/ -v --tb=short

# Tests cover:
# - IAM policy condition logic
# - mTLS certificate validation
# - Zero Trust policy evaluation
# - Session age enforcement
```

---

## GitHub Portfolio Checklist

- [ ] `src/zt_validator.py` — Zero Trust policy evaluation engine
- [ ] `certs/` — CA + server + client certificates (in .gitignore — never commit private keys!)
- [ ] `docs/zero-trust-architecture.md` — architecture diagram and design decisions
- [ ] `infrastructure/` — Terraform for Verified Access + IAM policies
- [ ] `tests/` — unit tests for trust evaluation logic
- [ ] README with NIST SP 800-207 tenet mapping and architecture diagram

---

## Common Issues

| Issue | Fix |
|-------|-----|
| `SSL handshake failed: sslv3 alert bad certificate` | Client cert not signed by the expected CA — check `openssl verify` |
| `BoolIfExists` condition not working | Condition key is case-sensitive: `aws:MultiFactorAuthPresent` not `MultifactorAuthPresent` |
| Verified Access: `InvalidVpcId` | Verified Access requires a VPC endpoint in the same VPC as your app |
| `NumericGreaterThan` not matching | STS session tokens use unix timestamp for `aws:MultiFactorAuthAge` — check the token issue time |

---

## Security Concepts Demonstrated

- **NIST SP 800-207 Tenet 1:** All resources verified per request (Verified Access)
- **NIST SP 800-207 Tenet 2:** All communication secured (mTLS)
- **NIST SP 800-207 Tenet 3:** Access granted per-session (1hr max STS)
- **NIST SP 800-207 Tenet 4:** Dynamic policy (MFA age condition)
- **MITRE T1078:** Valid Accounts — Zero Trust prevents lateral movement with stolen credentials
- **MITRE T1550:** Use Alternate Authentication Material — mTLS prevents token replay
