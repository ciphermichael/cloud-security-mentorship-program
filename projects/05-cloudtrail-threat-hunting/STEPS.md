# Project 05 — CloudTrail Threat Hunting Lab

## Overview
Perform kill-chain threat hunting against CloudTrail logs using Athena SQL and Python orchestration.

## Step 1 — Create Athena Table for CloudTrail
```sql
CREATE EXTERNAL TABLE cloudtrail_logs (
    eventVersion STRING,
    userIdentity STRUCT<type:STRING, arn:STRING, accountId:STRING, userName:STRING>,
    eventTime STRING,
    eventSource STRING,
    eventName STRING,
    awsRegion STRING,
    sourceIPAddress STRING,
    userAgent STRING,
    errorCode STRING,
    requestParameters STRING,
    responseElements STRING
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://YOUR-CLOUDTRAIL-BUCKET/AWSLogs/ACCOUNT-ID/CloudTrail/';
```

## Step 2 — Core Hunting Queries
```sql
-- Hunt 1: Root account usage
SELECT eventTime, eventName, sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE userIdentity.type = 'Root'
ORDER BY eventTime DESC LIMIT 100;

-- Hunt 2: Console login without MFA
SELECT eventTime, userIdentity.userName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventName = 'ConsoleLogin'
  AND json_extract_scalar(additionalEventData, '$.MFAUsed') = 'No';

-- Hunt 3: Brute force — 5+ failed auths
SELECT sourceIPAddress, userIdentity.userName, count(*) AS failures
FROM cloudtrail_logs
WHERE errorCode IN ('Client.UnauthorizedOperation', 'AccessDenied')
GROUP BY 1, 2 HAVING count(*) >= 5
ORDER BY failures DESC;

-- Hunt 4: S3 mass download (exfiltration indicator)
SELECT userIdentity.arn, sourceIPAddress, count(*) AS get_count
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com' AND eventName = 'GetObject'
GROUP BY 1, 2 HAVING count(*) > 100
ORDER BY get_count DESC;

-- Hunt 5: New IAM user created
SELECT eventTime, userIdentity.arn, json_extract_scalar(requestParameters, '$.userName') AS new_user
FROM cloudtrail_logs
WHERE eventName = 'CreateUser'
ORDER BY eventTime DESC;
```

## Step 3 — Python Hunting Orchestrator
```python
# src/hunter.py
import boto3, time, json
from pathlib import Path

class ThreatHunter:
    def __init__(self, database: str, output_bucket: str):
        self.athena = boto3.client('athena')
        self.database = database
        self.output = f's3://{output_bucket}/athena-results/'

    def run_query(self, name: str, sql: str) -> list:
        resp = self.athena.start_query_execution(
            QueryString=sql,
            QueryExecutionContext={'Database': self.database},
            ResultConfiguration={'OutputLocation': self.output}
        )
        qid = resp['QueryExecutionId']
        for _ in range(30):
            state = self.athena.get_query_execution(QueryExecutionId=qid)['QueryExecution']['Status']['State']
            if state in ('SUCCEEDED','FAILED','CANCELLED'): break
            time.sleep(2)
        if state != 'SUCCEEDED':
            return [{'error': f'Query {name} failed: {state}'}]
        rows = self.athena.get_query_results(QueryExecutionId=qid)['ResultSet']['Rows']
        headers = [c['VarCharValue'] for c in rows[0]['Data']]
        return [dict(zip(headers, [c.get('VarCharValue','') for c in row['Data']])) for row in rows[1:]]

    def run_all_hunts(self, queries: dict) -> dict:
        results = {}
        for name, sql in queries.items():
            print(f'  [*] Running hunt: {name}')
            results[name] = self.run_query(name, sql)
        return results

# Usage
HUNTS = {
    'root_usage': "SELECT eventTime, eventName, sourceIPAddress FROM cloudtrail_logs WHERE userIdentity.type = 'Root' LIMIT 50",
}

hunter = ThreatHunter('cloudtrail_db', 'my-results-bucket')
findings = hunter.run_all_hunts(HUNTS)
Path('reports').mkdir(exist_ok=True)
with open('reports/hunt-results.json','w') as f:
    json.dump(findings, f, indent=2)
```

## Step 4 — Attack Timeline Builder
```python
# src/timeline.py
KILL_CHAIN = {
    'ConsoleLogin': 'Initial Access',
    'CreateAccessKey': 'Persistence',
    'AttachUserPolicy': 'Privilege Escalation',
    'GetObject': 'Collection',
    'RunInstances': 'Execution',
    'DescribeInstances': 'Discovery',
}

def build_timeline(events: list) -> list:
    return sorted([
        {**e, 'kill_chain_stage': KILL_CHAIN.get(e.get('eventName',''), 'Other')}
        for e in events
    ], key=lambda x: x.get('eventTime',''))
```

## Step 5 — Run
```bash
python -m src.hunter --database cloudtrail_db --bucket my-results-bucket
cat reports/hunt-results.json | python -m json.tool
```
