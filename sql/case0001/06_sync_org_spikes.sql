-- Identify time buckets where multiple orgs spike on hosting/vpn infra.
WITH hv AS (
  SELECT
    time_bucket(INTERVAL '15 minutes', CAST(r.ts AS TIMESTAMPTZ)) AS bucket_ts,
    e.provider_brand_bucket,
    e.asn_type,
    COUNT(*) AS reqs,
    COUNT(DISTINCT r.org_id) AS orgs,
    COUNT(DISTINCT r.account_id) AS accounts
  FROM llm_requests r
  JOIN enrichment_ip e USING (asn)
  WHERE e.asn_type IN ('hosting','vpn')
  GROUP BY 1,2,3
)
SELECT *
FROM hv
WHERE orgs >= 10
ORDER BY orgs DESC, accounts DESC, reqs DESC, bucket_ts ASC
LIMIT 300;
