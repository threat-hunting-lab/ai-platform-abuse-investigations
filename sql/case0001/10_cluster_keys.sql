-- Build "cluster keys" that combine infra + device + similarity signals.
-- This is the core investigation join: provider bucket × device fingerprint × content cluster.
WITH joined AS (
  SELECT
    e.asn_type,
    e.provider_brand_bucket,
    r.device_fingerprint,
    r.content_cluster_id,
    r.template_hash,
    r.language,
    r.topic_bucket,
    r.is_automation_suspected,
    r.org_id,
    r.account_id,
    CAST(r.ts AS TIMESTAMPTZ) AS ts
  FROM llm_requests r
  JOIN enrichment_ip e USING (asn)
)
SELECT
  asn_type,
  provider_brand_bucket,
  device_fingerprint,
  content_cluster_id,
  template_hash,
  COUNT(*) AS reqs,
  COUNT(DISTINCT org_id) AS orgs,
  COUNT(DISTINCT account_id) AS accounts,
  SUM(CASE WHEN is_automation_suspected THEN 1 ELSE 0 END) AS automation_flags,
  MIN(ts) AS first_seen_ts,
  MAX(ts) AS last_seen_ts
FROM joined
GROUP BY 1,2,3,4,5
HAVING orgs >= 5 AND accounts >= 8
ORDER BY orgs DESC, accounts DESC, reqs DESC, automation_flags DESC
LIMIT 300;
