output "guardduty_detector_id"    { value = aws_guardduty_detector.main.id }
output "cloudtrail_bucket"        { value = aws_s3_bucket.cloudtrail.bucket }
output "forensic_bucket"          { value = aws_s3_bucket.forensic.bucket }
output "security_alerts_topic"    { value = aws_sns_topic.security_alerts.arn }
output "kms_key_id"               { value = aws_kms_key.csop.key_id }
output "ir_lambda_arn"            { value = aws_lambda_function.ir_handler.arn }
