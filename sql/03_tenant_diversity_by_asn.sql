-- Tenant/org diversity by ASN/provider bucket: strong coordination proxy.
SELECT
  r.asn,
  e.asn_type,
  e.provider_brand_bucket,
  COUNT(DISTINCT r.org_id) AS distinct_orgs,
  COUNT(DISTINCT r.account_id) AS distinct_accounts,
  COUNT(*) AS requests,
  ROUND(1.0 * COUNT(*) / NULLIF(COUNT(DISTINCT r.account_id), 0), 2) AS reqs_per_account
FROM llm_requests r
JOIN enrichment_ip e USING (asn)
GROUP BY 1,2,3
ORDER BY distinct_orgs DESC, distinct_accounts DESC, requests DESC
LIMIT 300;
