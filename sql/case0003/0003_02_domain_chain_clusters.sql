-- 0003_02_domain_chain_clusters.sql
-- Detect redirect-like sequences using parent_domain edges

SELECT
  parent_domain,
  base_domain AS child_domain,
  COUNT(*) AS chain_occurrences,
  COUNT(DISTINCT account_id) AS affected_accounts,
  AVG(score) AS avg_child_score,
  
  -- Classify chain risk
  CASE
    WHEN AVG(score) >= 4 THEN 'high_risk_chain'
    WHEN AVG(score) >= 2 THEN 'medium_risk_chain'
    ELSE 'low_risk_chain'
  END AS chain_risk_category
  
FROM dns_events
WHERE parent_domain IS NOT NULL AND parent_domain != ''
GROUP BY parent_domain, base_domain
HAVING COUNT(*) >= 3  -- Chains appearing at least 3 times
ORDER BY avg_child_score DESC, chain_occurrences DESC
LIMIT 300;
