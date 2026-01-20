-- 0003_03_exposed_accounts.sql
-- List accounts/devices with suspicious DNS exposure

SELECT
  account_id,
  org_id,
  device_fingerprint,
  COUNT(DISTINCT base_domain) AS distinct_suspicious_domains,
  SUM(score) AS total_risk_score,
  AVG(score) AS avg_risk_score,
  MAX(score) AS max_risk_score,
  
  -- Breakdown by heuristic
  SUM(CASE WHEN suspicious_tld THEN 1 ELSE 0 END) AS suspicious_tld_queries,
  SUM(CASE WHEN keyword_hit THEN 1 ELSE 0 END) AS keyword_hit_queries,
  SUM(CASE WHEN high_entropy THEN 1 ELSE 0 END) AS high_entropy_queries,
  
  MIN(ts) AS first_suspicious_query,
  MAX(ts) AS last_suspicious_query
  
FROM dns_events
WHERE score > 0
GROUP BY account_id, org_id, device_fingerprint
HAVING COUNT(DISTINCT base_domain) >= 2  -- At least 2 distinct suspicious domains
ORDER BY total_risk_score DESC, distinct_suspicious_domains DESC
LIMIT 500;
