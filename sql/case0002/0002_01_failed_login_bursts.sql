-- 0002_01_signin_failure_bursts.sql
-- 10-minute buckets with many failed sign-ins for an account (spray/stuffing proxy)

WITH failures AS (
  SELECT
    ts, org_id, account_id, ip, asn
  FROM identity_events
  WHERE event_type = 'auth.signin'
    AND outcome = 'failure'
),
bucketed AS (
  SELECT
    org_id,
    account_id,
    to_timestamp(floor(epoch(ts)/600)*600) AS bucket_start,
    count(*) AS failures_in_10m,
    min(ts) AS first_ts,
    max(ts) AS last_ts,
    any_value(ip) AS sample_ip,
    any_value(asn) AS sample_asn
  FROM failures
  GROUP BY 1,2,3
)
SELECT
  b.*,
  e.asn_type,
  e.provider_category,
  e.provider_brand_bucket
FROM bucketed b
LEFT JOIN enrichment_ip e
  ON e.ip = b.sample_ip
WHERE failures_in_10m >= 6
ORDER BY failures_in_10m DESC, last_ts DESC;
