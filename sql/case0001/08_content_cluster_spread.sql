-- Content cluster spread across orgs/accounts (narrative-level similarity).
SELECT
  content_cluster_id,
  COUNT(*) AS reqs,
  COUNT(DISTINCT account_id) AS accounts,
  COUNT(DISTINCT org_id) AS orgs,
  MIN(CAST(ts AS TIMESTAMPTZ)) AS first_seen_ts,
  MAX(CAST(ts AS TIMESTAMPTZ)) AS last_seen_ts
FROM llm_requests
GROUP BY 1
ORDER BY orgs DESC, accounts DESC, reqs DESC
LIMIT 200;
