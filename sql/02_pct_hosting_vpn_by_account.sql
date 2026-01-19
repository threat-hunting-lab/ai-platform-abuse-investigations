-- For each account: what percent of requests originate from hosting/vpn?
WITH joined AS (
  SELECT
    r.account_id,
    r.org_id,
    e.asn_type
  FROM llm_requests r
  JOIN enrichment_ip e USING (asn)
),
agg AS (
  SELECT
    account_id,
    org_id,
    COUNT(*) AS total_reqs,
    SUM(CASE WHEN asn_type IN ('hosting','vpn') THEN 1 ELSE 0 END) AS hosting_vpn_reqs
  FROM joined
  GROUP BY 1,2
)
SELECT
  account_id,
  org_id,
  total_reqs,
  hosting_vpn_reqs,
  ROUND(100.0 * hosting_vpn_reqs / NULLIF(total_reqs, 0), 2) AS pct_hosting_vpn
FROM agg
ORDER BY pct_hosting_vpn DESC, hosting_vpn_reqs DESC, total_reqs DESC
LIMIT 500;
