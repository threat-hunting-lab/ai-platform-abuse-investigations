-- 0003_01_top_suspicious_domains.sql
-- Rank suspicious domains by score + volume with explainable "why" columns

SELECT
  base_domain,
  tld,
  COUNT(*) AS query_count,
  COUNT(DISTINCT account_id) AS affected_accounts,
  COUNT(DISTINCT org_id) AS affected_orgs,
  AVG(score) AS avg_score,
  MAX(score) AS max_score,
  
  -- Explainability: why is this suspicious?
  SUM(CASE WHEN suspicious_tld THEN 1 ELSE 0 END) AS suspicious_tld_count,
  SUM(CASE WHEN keyword_hit THEN 1 ELSE 0 END) AS keyword_hit_count,
  SUM(CASE WHEN high_entropy THEN 1 ELSE 0 END) AS high_entropy_count,
  SUM(CASE WHEN rare_domain THEN 1 ELSE 0 END) AS rare_domain_count,
  
  -- Sample evidence
  arbitrary(host_raw) AS sample_host
  
FROM dns_events
WHERE score > 0  -- Only suspicious domains
GROUP BY base_domain, tld
ORDER BY max_score DESC, query_count DESC
LIMIT 500;
