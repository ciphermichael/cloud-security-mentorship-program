# Project 16 — Cloud WAF Security Monitor: Step-by-Step Guide

> **Skill Level:** Intermediate | **Time:** ~10 hours | **Week:** 15-16

---

## Overview

Build a real-time AWS WAF security monitor that parses WAF logs from S3, classifies attack types (SQLi, XSS, path traversal, Log4Shell), fires Slack/SNS alerts on thresholds, and displays a live Streamlit attack dashboard.

**Architecture:**
```
AWS WAF Logs (S3)
      ↓  (S3:ObjectCreated event)
AWS Lambda (alerter.py)
  ├─ parse_waf_log_file()    — parse NDJSON events
  ├─ classify attack type    — regex signatures
  ├─ build_alert_payload()   — aggregate stats
  └─ if threshold exceeded:
       ├─ Slack webhook
       └─ SNS → email/PagerDuty
      ↓
DynamoDB (optional persistent storage)
      ↑
Streamlit Dashboard (dashboard.py)
  ├─ Load recent logs from S3
  ├─ Attack type breakdown chart
  ├─ Top attacker IPs table
  └─ CSV export
```

---

## Prerequisites

```bash
pip install boto3 streamlit pandas plotly pytest moto
```

AWS permissions needed:
- `s3:GetObject`, `s3:ListBucket` on the WAF log bucket
- `wafv2:ListWebACLs`, `wafv2:PutLoggingConfiguration`
- `sns:Publish` on your alerts topic (for alerter)
- `lambda:CreateFunction` (for deployment)

---

## Step 1 — Enable WAF Logging

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET="aws-waf-logs-${ACCOUNT_ID}"

# Create the WAF log bucket
aws s3 mb s3://$BUCKET --region us-east-1

# Enable access logging (WAF requires bucket prefix aws-waf-logs-)
aws s3api put-bucket-policy --bucket $BUCKET --policy '{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":{"Service":"delivery.logs.amazonaws.com"},
    "Action":"s3:PutObject",
    "Resource":"arn:aws:s3:::'"$BUCKET"'/*",
    "Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}
  }]
}'

# Get your WebACL ARN
WEB_ACL_ARN=$(aws wafv2 list-web-acls --scope REGIONAL \
  --query 'WebACLs[0].ARN' --output text)

# Enable logging
aws wafv2 put-logging-configuration \
  --logging-configuration "{
    \"ResourceArn\": \"$WEB_ACL_ARN\",
    \"LogDestinationConfigs\": [\"arn:aws:s3:::$BUCKET\"]
  }"

echo "WAF logging enabled → s3://$BUCKET"
```

---

## Step 2 — Run the Parser Locally

```bash
# Clone/navigate to the project
cd projects/16-cloud-waf-security-monitor

# Install dependencies
pip install -r requirements.txt

# Test the parser on a local WAF log sample
python -c "
from src.log_parser import parse_waf_log_line
import json

# Simulate a blocked SQL injection
line = json.dumps({
    'timestamp': 1705280400000,
    'action': 'BLOCK',
    'httpRequest': {
        'clientIp': '198.51.100.42',
        'country': 'RU',
        'uri': \"/login?id=1' UNION SELECT * FROM users--\",
        'httpMethod': 'GET',
        'queryString': '',
        'headers': [{'name': 'User-Agent', 'value': 'sqlmap/1.7'}],
    },
    'terminatingRuleMatchDetails': [],
    'nonTerminatingMatchingRules': [],
})
event = parse_waf_log_line(line)
print(f'Attack type: {event.attack_type}')       # SQL_INJECTION
print(f'Severity:    {event.attack_severity}')   # CRITICAL
print(f'Blocked:     {event.blocked}')           # True
"
```

---

## Step 3 — Run Tests

```bash
pytest tests/ -v --tb=short

# Expected output:
# tests/test_log_parser.py::TestLogLineParsing::test_blocked_request_parsed PASSED
# tests/test_log_parser.py::TestLogLineParsing::test_sql_injection_classified PASSED
# tests/test_log_parser.py::TestLogLineParsing::test_xss_classified PASSED
# tests/test_log_parser.py::TestLogLineParsing::test_log4shell_classified PASSED
# ...
```

---

## Step 4 — Launch the Dashboard

```bash
export WAF_LOG_BUCKET=aws-waf-logs-YOUR-ACCOUNT

streamlit run src/dashboard.py
# Opens at http://localhost:8501
```

The dashboard shows:
- Total / blocked / CRITICAL counts
- Attack type bar chart
- Country pie chart
- Allow vs Block donut
- Top attacker IPs table
- Filterable raw events table with CSV export

---

## Step 5 — Deploy Lambda Alerter

```bash
# Package the Lambda
pip install -r requirements.txt -t lambda-package/
cp -r src/ lambda-package/
cd lambda-package && zip -r ../lambda.zip . && cd ..

# Create the Lambda function
aws lambda create-function \
  --function-name waf-security-monitor \
  --runtime python3.12 \
  --handler src.alerter.lambda_handler \
  --role arn:aws:iam::ACCOUNT_ID:role/lambda-waf-role \
  --zip-file fileb://lambda.zip \
  --environment "Variables={
    SLACK_WEBHOOK_URL=$SLACK_WEBHOOK,
    SNS_TOPIC_ARN=arn:aws:sns:us-east-1:ACCOUNT_ID:security-alerts,
    BLOCK_THRESHOLD=50,
    CRITICAL_THRESHOLD=10
  }"

# Add S3 trigger
aws lambda add-permission \
  --function-name waf-security-monitor \
  --statement-id S3Invoke \
  --action lambda:InvokeFunction \
  --principal s3.amazonaws.com \
  --source-arn arn:aws:s3:::$BUCKET

aws s3api put-bucket-notification-configuration \
  --bucket $BUCKET \
  --notification-configuration '{
    "LambdaFunctionConfigurations":[{
      "LambdaFunctionArn":"arn:aws:lambda:us-east-1:ACCOUNT_ID:function:waf-security-monitor",
      "Events":["s3:ObjectCreated:*"]
    }]
  }'
```

---

## Step 6 — Run Detection Queries

See `queries/waf_athena_queries.sql` for Athena queries:
- Top blocked IPs
- Attack type distribution
- Hourly request trend
- Brute force login detection
- Country block rate

---

## Step 7 — GitHub Portfolio Checklist

- [ ] `src/log_parser.py` — parses WAF NDJSON, classifies 6 attack types
- [ ] `src/alerter.py` — Lambda handler with Slack + SNS integration
- [ ] `src/dashboard.py` — Streamlit dashboard with 3 charts + IP table
- [ ] `queries/waf_athena_queries.sql` — 6 Athena hunting queries
- [ ] `tests/test_log_parser.py` — 12 unit tests, all passing
- [ ] `reports/.gitkeep` — output directory ready
- [ ] README with architecture diagram and dashboard screenshot
- [ ] At least one screenshot of the Streamlit dashboard in action

---

## Common Issues

| Issue | Fix |
|-------|-----|
| `ClientError: NoSuchBucket` | Bucket name must start with `aws-waf-logs-` for WAF delivery |
| `ParserError` on WAF logs | WAF logs are NDJSON (one JSON per line) not JSON arrays — use `split('\n')` |
| Empty dashboard | WAF logs take 15-30 minutes to appear in S3 after enabling |
| Lambda timeout | Increase timeout to 60s — large log files take time |
