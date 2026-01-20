-- First-seen hosting/VPN ASNs and their early spread across orgs/accounts.
WITH asn_first AS (
  SELECT
    r.asn,
    MIN(CAST(r.ts AS TIMESTAMPTZ)) AS first_seen_ts,
    COUNT(*) AS requests,
    COUNT(DISTINCT r.org_id) AS distinct_orgs,
    COUNT(DISTINCT r.account_id) AS distinct_accounts
  FROM llm_requests r
  GROUP BY 1
),
enriched AS (
  SELECT
    f.asn,
    e.asn_type,
    e.provider_category,
    e.provider_brand_bucket,
    f.first_seen_ts,
    f.requests,
    f.distinct_orgs,
    f.distinct_accounts
  FROM asn_first f
  JOIN enrichment_ip e USING (asn)
)
SELECT *
FROM enriched
WHERE asn_type IN ('hosting', 'vpn')
ORDER BY distinct_orgs DESC, distinct_accounts DESC, requests DESC, first_seen_ts ASC
LIMIT 200;
