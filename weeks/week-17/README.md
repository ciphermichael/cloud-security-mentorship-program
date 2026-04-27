# Week 17 — Zero Trust Architecture & Implementation

**Phase 5: Advanced Topics | Project: 19-zero-trust-implementation**

---

## Learning Objectives

By the end of this week you will be able to:

- Explain all 7 tenets of NIST SP 800-207 Zero Trust Architecture
- Implement AWS Verified Access to enforce identity + device posture for application access
- Configure mutual TLS (mTLS) between microservices for service-to-service Zero Trust
- Apply Zero Trust IAM: time-bound access, just-in-time privilege, continuous verification
- Design a Zero Trust network architecture replacing VPN-based access
- Explain why "network location is not sufficient for trust" and what replaces it

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | Zero Trust principles — NIST 800-207, 7 tenets, ZTA vs perimeter models | 2 hrs |
| Tue | AWS Verified Access — setup, trust providers, access policies, logging | 2 hrs |
| Wed | Implement mTLS with AWS Certificate Manager Private CA or Istio | 2 hrs |
| Thu | IAM Zero Trust: Permission Sets, JIT access with IAM Identity Center | 2 hrs |
| Fri | Design full Zero Trust architecture diagram for a 3-tier web app | 2 hrs |
| Sat | Implementation in Terraform, documentation, push to GitHub | 3 hrs |
| Sun | Mentor review — Zero Trust architecture presentation | 1 hr |

---

## Topics Covered

### NIST SP 800-207 — 7 Tenets of Zero Trust

1. **All data sources and computing services are considered resources** — not just "inside the network"
2. **All communication is secured regardless of network location** — encrypt everything, always
3. **Access to individual enterprise resources is granted on a per-session basis** — no standing access
4. **Access to resources is determined by dynamic policy** — device health, user identity, behavior context
5. **The enterprise monitors and measures the integrity of all owned and associated assets** — continuous assessment
6. **All resource authentication and authorization are dynamic and strictly enforced** — re-verify continuously
7. **The enterprise collects as much information as possible** — used to improve posture and detect threats

### Zero Trust vs Perimeter (Castle-and-Moat)

| Dimension | Perimeter Model | Zero Trust |
|-----------|----------------|------------|
| Trust basis | Network location (inside = trusted) | Identity + device + context (always verify) |
| Lateral movement | Easy once inside | Prevented by micro-segmentation |
| Remote access | VPN (network trust) | Identity-aware proxy (app-level) |
| Standing access | Permanent credentials | Just-in-time, time-limited tokens |
| Encryption | At perimeter only | End-to-end, everywhere |
| Monitoring | Perimeter traffic | All traffic, all layers |

### AWS Zero Trust Services

| Service | Zero Trust Role |
|---------|----------------|
| AWS Verified Access | Identity-aware application proxy — replace VPN |
| IAM Identity Center (SSO) | Centralized identity, fine-grained permission sets |
| AWS Network Firewall | East-west traffic control (micro-segmentation) |
| AWS Certificate Manager Private CA | mTLS certificates for service-to-service |
| Amazon Cognito | User identity and device trust |
| AWS Config + GuardDuty | Continuous device and behavior assessment |

---

## Instructor Mentoring Guidance

**Week 17 is the most architecturally mature week in the program.** Zero Trust is a design philosophy, not a product — students who can design it earn significantly more in interviews.

**Key coaching points:**
- Zero Trust does NOT mean "never trust, verify nothing" — it means "verify explicitly, continuously, at every access decision"
- AWS Verified Access requires some budget (it's not in free tier) — students can diagram the design and implement the IAM/mTLS components
- The most valuable deliverable this week is the architecture diagram — a well-drawn ZTA diagram demonstrates senior-level thinking

**Mentoring session agenda (60 min):**
1. (15 min) Student presents their Zero Trust architecture diagram — critique and improve it
2. (20 min) "Walk me through what happens when a developer opens their laptop and tries to access the internal app" — trace through all Zero Trust checkpoints
3. (15 min) Mock interview: "Our CISO says we need to implement Zero Trust. Where do you start?"
4. (10 min) Preview Weeks 18-19 — forensics and threat intelligence

---

## Hands-on Lab

### Lab 1: AWS IAM Identity Center Permission Sets (JIT Access Approximation)

```bash
# List existing permission sets
aws sso-admin list-permission-sets \
  --instance-arn "arn:aws:sso:::instance/ssoins-xxxxxxxx"

# Create a time-limited permission set via IAM Identity Center
# (True JIT access requires a ticketing integration — this shows the IAM side)

# Create an IAM role that can only be assumed for 1 hour max
cat > zero-trust-role-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::ACCOUNT_ID:saml-provider/MyIdP"
    },
    "Action": "sts:AssumeRoleWithSAML",
    "Condition": {
      "StringEquals": {
        "SAML:aud": "https://signin.aws.amazon.com/saml"
      },
      "NumericLessThanEquals": {
        "aws:TokenIssueTime": 3600  // 1 hour max session
      }
    }
  }]
}
EOF

# Session duration: enforce short-lived credentials
aws iam create-role \
  --role-name ZeroTrustAppRole \
  --assume-role-policy-document file://zero-trust-role-policy.json \
  --max-session-duration 3600  # 1 hour maximum
```

### Lab 2: mTLS with OpenSSL (Local Demo)

```bash
# Create a private CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
  -subj "/CN=InternalCA/O=Company/C=US"

# Create server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/CN=api-service/O=Company/C=US"
openssl x509 -req -days 90 \
  -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt

# Create client certificate (service identity)
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
  -subj "/CN=frontend-service/O=Company/C=US"
openssl x509 -req -days 90 \
  -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt

# Test mTLS: start a server
openssl s_server \
  -cert server.crt -key server.key \
  -CAfile ca.crt -Verify 1 \
  -port 8443 -www &

# Connect with client cert (mTLS success)
curl https://localhost:8443 \
  --cert client.crt \
  --key client.key \
  --cacert ca.crt

# Connect without client cert (mTLS rejection)
curl https://localhost:8443 \
  --cacert ca.crt
# Expected: SSL handshake failure
```

### Lab 3: Zero Trust IAM Policy — Deny Without Device Compliance Tag

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireCompliantDevice",
      "Effect": "Deny",
      "Action": ["s3:GetObject", "s3:PutObject", "rds:*"],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalTag/DeviceCompliant": "true"
        }
      }
    },
    {
      "Sid": "RequireRecentMFA",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "NumericGreaterThan": {
          "aws:MultiFactorAuthAge": 3600
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
```

### Lab 4: Zero Trust Architecture Design Document

Create `docs/zero-trust-architecture.md` with:

```markdown
# Zero Trust Architecture — 3-Tier Web Application

## Architecture Overview

```
[User + Device]
    ↓ (1) Identity verification via SSO/SAML
[AWS Verified Access Endpoint]
    ↓ (2) Access policy evaluated: MFA + device trust + user group
[Application Load Balancer]
    ↓ (3) mTLS to backend — service identity verified
[App Tier - EC2/ECS]
    ↓ (4) IAM role with session conditions — max 1hr, MFA required
[Data Tier - RDS]
    ↓ (5) Database IAM authentication — no static passwords
```

## Access Decision Points

| Layer | Verification | If Failed |
|-------|-------------|-----------|
| 1. DNS | SPF/DKIM/DMARC | Blocked at email/phishing level |
| 2. Identity | MFA + IdP assertion | Denied, logged |
| 3. Device | Intune/Jamf compliance | Policy blocks access |
| 4. Network | Security group + WAF | Dropped |
| 5. Service | mTLS certificate | Handshake failure |
| 6. IAM | Time-bound role + conditions | AccessDenied + alert |
| 7. Data | RDS IAM auth | Auth failure + logged |
```

---

## Interview Skills Gained

**Q: What are the core principles of Zero Trust?**
> "Never trust, always verify." The three pillars: (1) Verify explicitly — authenticate and authorize based on all available data points (identity, location, device health, behavior). (2) Use least-privilege access — just-in-time, just-enough-access, time-limited credentials. (3) Assume breach — minimize blast radius, segment access, encrypt everything, monitor continuously.

**Q: How does Zero Trust differ from a VPN?**
> VPN grants network-level access — once on the VPN, you can reach any internal resource as if you're on the office network. Zero Trust grants application-level access — you get access only to the specific application you need, based on your identity and device posture, verified per session. Zero Trust is more granular, more auditable, and far more resistant to lateral movement.

**Q: What is mTLS and when do you use it?**
> Mutual TLS means both parties in a TLS connection present certificates — not just the server. The client (a microservice) presents a certificate to prove its identity, and the server verifies it. Use it for service-to-service communication where you need to ensure only authorized services can call your API. In Zero Trust, mTLS replaces "trust because it's internal network" with "trust because it has a verified certificate."

---

## Submission Checklist

- [ ] Zero Trust architecture diagram (draw.io, Lucidchart, or similar) committed to `docs/`
- [ ] Terraform code for at least one Zero Trust control (Verified Access policy, or least-privilege IAM with conditions)
- [ ] mTLS demonstration (certificates created, server/client test) with screenshots
- [ ] IAM policy implementing at least 2 Zero Trust conditions (MFA age, device tag)
- [ ] `docs/zero-trust-architecture.md` with full design write-up
- [ ] README explains the 7 NIST tenets and how each is addressed

---

## Links

→ Full project: [projects/19-zero-trust-implementation/](../../projects/19-zero-trust-implementation/)
→ Next: [Week 18 — Cloud Forensics & Digital Investigations](../week-18/README.md)
