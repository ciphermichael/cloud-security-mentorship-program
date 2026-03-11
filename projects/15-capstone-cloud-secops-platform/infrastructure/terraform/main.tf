# =============================================================================
# Cloud Security Operations Platform — Terraform
# Capstone Project — Cloud Security Mentorship Programme
# =============================================================================

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  backend "s3" {
    bucket         = "csop-terraform-state"
    key            = "csop-platform/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "csop-terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "CloudSecOps-Platform"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# ── GuardDuty ─────────────────────────────────────────────────────────────────
resource "aws_guardduty_detector" "main" {
  enable = true
  datasources {
    s3_logs          { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection { scan_ec2_instance_with_findings { ebs_volumes { enable = true } } }
  }
  tags = { Name = "csop-guardduty" }
}

# ── Security Hub ──────────────────────────────────────────────────────────────
resource "aws_securityhub_account" "main" {}
resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0"
}
resource "aws_securityhub_standards_subscription" "fsbp" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

# ── CloudTrail ────────────────────────────────────────────────────────────────
resource "aws_cloudtrail" "main" {
  name                          = "csop-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw.arn
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
  tags = { Name = "csop-cloudtrail" }
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "csop-cloudtrail-${var.account_id}"
  force_destroy = false
}
resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.csop.arn
    }
  }
}
resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── KMS ───────────────────────────────────────────────────────────────────────
resource "aws_kms_key" "csop" {
  description             = "CSOP Platform CMK"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags = { Name = "csop-cmk" }
}
resource "aws_kms_alias" "csop" {
  name          = "alias/csop-platform"
  target_key_id = aws_kms_key.csop.key_id
}

# ── CloudWatch Log Groups ──────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/csop/cloudtrail"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.csop.arn
}
resource "aws_cloudwatch_log_group" "platform" {
  name              = "/csop/platform"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.csop.arn
}

# ── SNS Alerts ────────────────────────────────────────────────────────────────
resource "aws_sns_topic" "security_alerts" {
  name              = "csop-security-alerts"
  kms_master_key_id = aws_kms_key.csop.arn
}
resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ── EventBridge — GuardDuty High Severity ─────────────────────────────────────
resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "csop-guardduty-high-severity"
  description = "Route HIGH/CRITICAL GuardDuty findings to IR Lambda"
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail      = { severity = [{ numeric = [">=", 7] }] }
  })
}
resource "aws_cloudwatch_event_target" "ir_lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_high.name
  target_id = "csop-ir-lambda"
  arn       = aws_lambda_function.ir_handler.arn
}

# ── IR Lambda ─────────────────────────────────────────────────────────────────
resource "aws_lambda_function" "ir_handler" {
  function_name = "csop-ir-handler"
  filename      = "ir_handler.zip"
  handler       = "lambda_handler.handler"
  runtime       = "python3.11"
  role          = aws_iam_role.ir_lambda.arn
  timeout       = 300
  memory_size   = 256
  environment {
    variables = {
      SNS_TOPIC_ARN      = aws_sns_topic.security_alerts.arn
      FORENSIC_S3_BUCKET = aws_s3_bucket.forensic.id
    }
  }
  tracing_config { mode = "Active" }
  tags = { Name = "csop-ir-handler" }
}

resource "aws_s3_bucket" "forensic" {
  bucket        = "csop-forensic-evidence-${var.account_id}"
  force_destroy = false
  tags = { Name = "csop-forensic-evidence", Classification = "Restricted" }
}
resource "aws_s3_bucket_public_access_block" "forensic" {
  bucket                  = aws_s3_bucket.forensic.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "forensic" {
  bucket = aws_s3_bucket.forensic.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.csop.arn
    }
  }
}

# ── IAM Roles (stubs — full policies in modules/security/) ───────────────────
resource "aws_iam_role" "cloudtrail_cw" {
  name               = "csop-cloudtrail-cw-role"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json
}
data "aws_iam_policy_document" "cloudtrail_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals { type = "Service"; identifiers = ["cloudtrail.amazonaws.com"] }
  }
}
resource "aws_iam_role" "ir_lambda" {
  name               = "csop-ir-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals { type = "Service"; identifiers = ["lambda.amazonaws.com"] }
  }
}
