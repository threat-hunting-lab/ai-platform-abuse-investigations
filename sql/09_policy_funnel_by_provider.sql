-- Policy funnel concentration by provider bucket and ASN type.
SELECT
  e.asn_type,
  e.provider_brand_bucket,
  m.policy_action,
  COUNT(*) AS events,
  COUNT(DISTINCT r.account_id) AS accounts,
  COUNT(DISTINCT r.org_id) AS orgs
FROM llm_requests r
JOIN enrichment_ip e USING (asn)
JOIN moderation_events m USING (request_id)
GROUP BY 1,2,3
ORDER BY events DESC, orgs DESC, accounts DESC
LIMIT 300;
