-- ============================================================
-- AWS WAF Security Monitor — Athena Queries
-- Project: 16-cloud-waf-security-monitor
-- WAF logs delivered to S3 as NDJSON (one event per line)
-- ============================================================

-- First: create the WAF logs Athena table
CREATE EXTERNAL TABLE IF NOT EXISTS waf_logs (
    timestamp        BIGINT,
    formatVersion    INT,
    webaclId         STRING,
    terminatingRuleId    STRING,
    terminatingRuleType  STRING,
    action           STRING,
    httpSourceName   STRING,
    httpSourceId     STRING,
    ruleGroupList    ARRAY<STRUCT<ruleGroupId:STRING, terminatingRule:STRUCT<ruleId:STRING,action:STRING>>>,
    rateBasedRuleList ARRAY<STRUCT<rateBasedRuleId:STRING,limitKey:STRING,maxRateAllowed:INT>>,
    nonTerminatingMatchingRules ARRAY<STRUCT<ruleId:STRING,action:STRING>>,
    requestHeadersInserted  STRING,
    responseCodeSent  INT,
    httpRequest STRUCT<
        clientIp:STRING,
        country:STRING,
        headers:ARRAY<STRUCT<name:STRING,value:STRING>>,
        uri:STRING,
        args:STRING,
        httpVersion:STRING,
        httpMethod:STRING,
        requestId:STRING
    >,
    labels ARRAY<STRUCT<name:STRING>>
)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://YOUR-WAF-LOG-BUCKET/';


-- ── Query 1: Top blocked IPs (last 24h) ──────────────────────────────────────
SELECT
    httpRequest.clientIp        AS client_ip,
    httpRequest.country         AS country,
    count(*)                    AS blocked_requests
FROM waf_logs
WHERE action = 'BLOCK'
  AND from_unixtime(timestamp/1000) > now() - interval '24' hour
GROUP BY 1, 2
ORDER BY blocked_requests DESC
LIMIT 20;


-- ── Query 2: Attack type distribution ────────────────────────────────────────
SELECT
    CASE
        WHEN httpRequest.args LIKE '%union%select%'
          OR httpRequest.args LIKE '%1=1%'           THEN 'SQL_INJECTION'
        WHEN httpRequest.uri  LIKE '%<script%'
          OR httpRequest.args LIKE '%<script%'       THEN 'XSS'
        WHEN httpRequest.uri  LIKE '%../%'
          OR httpRequest.uri  LIKE '%/etc/passwd%'   THEN 'PATH_TRAVERSAL'
        WHEN httpRequest.args LIKE '%${jndi:%'       THEN 'LOG4SHELL'
        ELSE 'OTHER'
    END                         AS attack_type,
    count(*)                    AS count
FROM waf_logs
WHERE action = 'BLOCK'
  AND from_unixtime(timestamp/1000) > now() - interval '7' day
GROUP BY 1
ORDER BY count DESC;


-- ── Query 3: Requests per hour trend (last 48h) ───────────────────────────────
SELECT
    date_trunc('hour', from_unixtime(timestamp/1000))  AS hour_bucket,
    action,
    count(*)                                            AS requests
FROM waf_logs
WHERE from_unixtime(timestamp/1000) > now() - interval '48' hour
GROUP BY 1, 2
ORDER BY hour_bucket, action;


-- ── Query 4: Top targeted URIs ────────────────────────────────────────────────
SELECT
    httpRequest.uri             AS uri,
    httpRequest.httpMethod      AS method,
    count(*)                    AS hits,
    count_if(action = 'BLOCK')  AS blocked
FROM waf_logs
WHERE from_unixtime(timestamp/1000) > now() - interval '24' hour
GROUP BY 1, 2
ORDER BY hits DESC
LIMIT 20;


-- ── Query 5: Countries with highest block rate ────────────────────────────────
SELECT
    httpRequest.country                                 AS country,
    count(*)                                            AS total,
    count_if(action = 'BLOCK')                          AS blocked,
    round(100.0 * count_if(action = 'BLOCK') / count(*), 1) AS block_rate_pct
FROM waf_logs
WHERE from_unixtime(timestamp/1000) > now() - interval '7' day
GROUP BY 1
HAVING count(*) > 100
ORDER BY block_rate_pct DESC
LIMIT 15;


-- ── Query 6: Brute force login detection ──────────────────────────────────────
SELECT
    httpRequest.clientIp        AS client_ip,
    httpRequest.country         AS country,
    count(*)                    AS login_attempts,
    min(from_unixtime(timestamp/1000)) AS first_seen,
    max(from_unixtime(timestamp/1000)) AS last_seen
FROM waf_logs
WHERE httpRequest.uri LIKE '/login%'
  OR httpRequest.uri LIKE '/auth%'
  OR httpRequest.uri LIKE '/signin%'
  AND from_unixtime(timestamp/1000) > now() - interval '1' hour
GROUP BY 1, 2
HAVING count(*) >= 20
ORDER BY login_attempts DESC;
