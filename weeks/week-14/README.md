# Week 14 — Infrastructure as Code Security (Terraform + CloudFormation)

**Phase 4: DevSecOps & Automation | Project: 12-devsecops-pipeline (IaC extension)**

---

## Learning Objectives

By the end of this week you will be able to:

- Identify the 15 most common Terraform and CloudFormation security misconfigurations
- Run Checkov and tfsec against real IaC files and interpret every finding
- Write 3 custom Checkov checks using Python for organization-specific policies
- Implement cfn-guard rules for CloudFormation template validation
- Achieve 100% Checkov pass rate on a deliberately vulnerable configuration
- Explain how IaC security fits into the "shift left" security model

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | IaC security fundamentals — why misconfigs happen, most common patterns | 2 hrs |
| Tue | Write a deliberately vulnerable Terraform config with 10 known issues | 2 hrs |
| Wed | Run Checkov and tfsec, understand every finding, fix them one by one | 2 hrs |
| Thu | Write 3 custom Checkov checks (Python API) for org-specific policies | 2 hrs |
| Fri | CloudFormation: cfn-guard rules, cfn-nag, integrate into CI | 2 hrs |
| Sat | Documentation, before/after comparison, push to GitHub | 3 hrs |
| Sun | Mentor review — IaC interview questions and real-world misconfiguration stories | 1 hr |

---

## Topics Covered

### Top 15 IaC Misconfigurations to Know

**S3 / Storage:**
1. S3 bucket with `acl = "public-read"` — public read access
2. S3 bucket without `server_side_encryption_configuration` — no encryption at rest
3. S3 bucket without versioning — no recovery from ransomware
4. S3 bucket without access logging — no audit trail

**Compute:**
5. Security group with `cidr_blocks = ["0.0.0.0/0"]` on port 22 or 3389 — exposed SSH/RDP
6. EC2 instance with `associate_public_ip_address = true` in production — unnecessary exposure
7. Lambda function without `reserved_concurrent_executions` — denial of wallet risk

**Database:**
8. RDS instance with `publicly_accessible = true` — exposed database
9. RDS without `storage_encrypted = true` — no encryption at rest
10. RDS without `backup_retention_period > 7` — inadequate backup

**IAM:**
11. IAM role with `"*"` in both Action and Resource — overly permissive
12. IAM policy with `iam:*` — allows privilege escalation
13. No CloudTrail or CloudTrail without `enable_log_file_validation = true`

**Networking:**
14. Default VPC used for production resources
15. VPC without flow logs — no network visibility

---

## Instructor Mentoring Guidance

**Week 14 is about developing an attacker's eye for IaC.** The most effective way to teach this is making students write vulnerable Terraform first — then they understand why Checkov flags it.

**Common mistakes:**
- Students run Checkov and immediately suppress all findings with `#checkov:skip=...` instead of understanding them
- Missing that `tfsec` and `Checkov` have different rule sets and complement each other
- Custom Checkov checks in Python are powerful but the API documentation is sparse — spend office hours on this

**Mentoring session agenda (60 min):**
1. (10 min) Show a real-world misconfiguration story: "Capital One was breached via an over-permissive EC2 role. What Terraform config created it? How would Checkov catch it?"
2. (20 min) Live code a custom Checkov check together
3. (20 min) Code review of their before/after Terraform configs
4. (10 min) Preview Week 15 — CSPM and multi-cloud visibility

---

## Hands-on Lab

### Lab 1: Deliberately Vulnerable Terraform

```hcl
# infrastructure/vulnerable/main.tf
# This file has 10 intentional security issues — your task is to find and fix all of them

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

# ISSUE 1: Public S3 bucket
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data-bucket"
  acl    = "public-read"  # VULN: public read
}

# ISSUE 2: No encryption on S3
# (no aws_s3_bucket_server_side_encryption_configuration)

# ISSUE 3: No versioning
# (no aws_s3_bucket_versioning)

# ISSUE 4: Open SSH to the world
resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULN: SSH open to world
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULN: RDP open to world
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ISSUE 5: RDS publicly accessible
resource "aws_db_instance" "main" {
  engine                 = "mysql"
  instance_class         = "db.t3.micro"
  username               = "admin"
  password               = "SuperSecret123!"  # ISSUE 6: Hardcoded password
  publicly_accessible    = true               # VULN: public RDS
  storage_encrypted      = false              # ISSUE 7: No encryption
  backup_retention_period = 0                 # ISSUE 8: No backups
  skip_final_snapshot    = true
  allocated_storage      = 20
}

# ISSUE 9: Over-privileged IAM role
resource "aws_iam_role_policy" "admin" {
  name = "admin-policy"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"           # VULN: full admin
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# ISSUE 10: No CloudTrail
# (no aws_cloudtrail resource)
```

### Lab 2: Run Checkov and tfsec

```bash
# Install tools
pip install checkov
brew install tfsec  # macOS

# Run Checkov against the vulnerable config
checkov -d infrastructure/vulnerable/ \
  --framework terraform \
  --output json \
  --output-file-path reports/ \
  --compact

# Run with human-readable output
checkov -d infrastructure/vulnerable/ --quiet

# Run tfsec
tfsec infrastructure/vulnerable/ \
  --format lovely \
  --minimum-severity HIGH

# Count the findings
echo "Checkov failures:"
checkov -d infrastructure/vulnerable/ --quiet 2>&1 | grep -c "FAILED"

echo "tfsec issues:"
tfsec infrastructure/vulnerable/ --minimum-severity HIGH 2>&1 | \
  grep -c "FAIL"
```

### Lab 3: Fixed Terraform Configuration

```hcl
# infrastructure/hardened/main.tf

# Fixed S3 bucket — encrypted, versioned, private
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_kms_key" "s3" {
  description             = "S3 bucket encryption key"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

# Fixed Security Group — no world-open ports
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # HTTPS only
    description = "Allow HTTPS from internet"
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS outbound"
  }
}

# Fixed RDS — private, encrypted, backed up
resource "aws_db_instance" "main" {
  engine                  = "mysql"
  instance_class          = "db.t3.micro"
  username                = "admin"
  password                = random_password.db.result  # From secrets manager
  publicly_accessible     = false
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.rds.arn
  backup_retention_period = 7
  skip_final_snapshot     = false
  final_snapshot_identifier = "db-final-snapshot"
  multi_az                = true
  deletion_protection     = true
  db_subnet_group_name    = aws_db_subnet_group.main.name
  vpc_security_group_ids  = [aws_security_group.rds.id]
  allocated_storage       = 20
}

resource "random_password" "db" {
  length  = 32
  special = true
}
```

### Lab 4: Custom Checkov Check

```python
# custom-checks/check_require_tags.py
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class CheckRequiredTags(BaseResourceCheck):
    """Ensure all AWS resources have required cost allocation tags."""

    REQUIRED_TAGS = {'Owner', 'Environment', 'CostCenter', 'Project'}

    def __init__(self):
        name = 'Ensure required cost allocation tags are present'
        id = 'CKV_CUSTOM_001'
        supported_resources = [
            'aws_instance', 'aws_s3_bucket', 'aws_db_instance',
            'aws_lambda_function', 'aws_ecs_service'
        ]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id,
                         categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf) -> CheckResult:
        tags = conf.get('tags', [{}])
        if isinstance(tags, list):
            tags = tags[0] if tags else {}

        if not isinstance(tags, dict):
            return CheckResult.FAILED

        existing_tags = set(tags.keys())
        missing = self.REQUIRED_TAGS - existing_tags

        if missing:
            self.details.append(f'Missing required tags: {", ".join(sorted(missing))}')
            return CheckResult.FAILED

        return CheckResult.PASSED


scanner = CheckRequiredTags()
```

```python
# custom-checks/check_no_default_vpc.py
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class CheckNoDefaultVPC(BaseResourceCheck):
    """Ensure EC2 instances are not placed in the default VPC."""

    def __init__(self):
        super().__init__(
            name='Ensure EC2 instances are not launched in the default VPC',
            id='CKV_CUSTOM_002',
            categories=[CheckCategories.NETWORKING],
            supported_resources=['aws_instance']
        )

    def scan_resource_conf(self, conf) -> CheckResult:
        # Check if subnet_id is specified (non-default VPC requirement)
        subnet = conf.get('subnet_id', [None])
        if isinstance(subnet, list):
            subnet = subnet[0]
        if not subnet:
            self.details.append(
                'No subnet_id specified. Instance may launch in default VPC. '
                'Specify a subnet_id in a custom VPC.'
            )
            return CheckResult.FAILED
        return CheckResult.PASSED


scanner = CheckNoDefaultVPC()
```

```bash
# Run with custom checks
checkov -d infrastructure/hardened/ \
  --external-checks-dir custom-checks/ \
  --check CKV_CUSTOM_001,CKV_CUSTOM_002
```

---

## Interview Skills Gained

**Q: What is infrastructure as code and why is security scanning of IaC important?**
> IaC defines cloud infrastructure in code files (Terraform, CloudFormation, Bicep) that are version-controlled and repeatable. Security scanning of IaC catches misconfigurations before they are deployed — it's far cheaper to fix a misconfiguration in a PR review than after a breach. IaC security scanning is the "shift left" of cloud security — move security checks as early in the SDLC as possible.

**Q: Name 5 Terraform misconfigurations that Checkov would flag.**
> (1) `publicly_accessible = true` on RDS, (2) S3 bucket with `acl = "public-read"`, (3) Security group with `0.0.0.0/0` on port 22, (4) `storage_encrypted = false` on RDS/EBS, (5) IAM role policy with `Action: "*"` and `Resource: "*"`.

**Q: How do you handle a Checkov finding that's a false positive?**
> Add a suppression comment inline in the Terraform code: `#checkov:skip=CKV_AWS_24: Reason why this is acceptable in our context`. Document the business justification and create a ticket for periodic review. Suppressions should be reviewed in every quarterly security review to ensure the justification is still valid.

---

## Submission Checklist

- [ ] Vulnerable Terraform config with 10 issues committed to `infrastructure/vulnerable/`
- [ ] Hardened Terraform config with all issues fixed committed to `infrastructure/hardened/`
- [ ] Before/after Checkov report showing improvement from X fails to 0 fails
- [ ] 3 custom Checkov checks in `custom-checks/` with passing tests
- [ ] cfn-guard or cfn-nag rules for at least 3 CloudFormation controls
- [ ] CI integration: Checkov runs automatically on every PR
- [ ] README includes a table mapping each finding to the Checkov rule ID and the fix applied

---

## Links

→ Project: [projects/12-devsecops-pipeline/](../../projects/12-devsecops-pipeline/)
→ Next: [Week 15 — CSPM & Multi-Cloud Dashboard](../week-15/README.md)
