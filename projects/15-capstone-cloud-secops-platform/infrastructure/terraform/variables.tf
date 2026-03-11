variable "aws_region"   { type = string; default = "us-east-1" }
variable "environment"  { type = string; default = "production" }
variable "account_id"   { type = string; description = "AWS account ID for globally-unique bucket names" }
variable "alert_email"  { type = string; description = "Security alert email address" }
