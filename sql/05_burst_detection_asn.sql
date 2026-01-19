-- Burst detection per ASN using 15-minute buckets, z-score by ASN.
-- This flags synchronized spikes (campaign waves) especially on hosting/vpn ASNs.
WITH buckets AS (
  SELECT
    r.asn,
    time_bucket(INTERVAL '15 minutes', CAST(r.ts AS TIMESTAMPTZ)) AS bucket_ts,
    COUNT(*) AS reqs,
    COUNT(DISTINCT r.account_id) AS accounts,
    COUNT(DISTINCT r.org_id) AS orgs
  FROM llm_requests r
  GROUP BY 1,2
),
stats AS (
  SELECT
    asn,
    AVG(reqs) AS mean_reqs,
    STDDEV_POP(reqs) AS sd_reqs
  FROM buckets
  GROUP BY 1
),
scored AS (
  SELECT
    b.asn,
    b.bucket_ts,
    b.reqs,
    b.accounts,
    b.orgs,
    s.mean_reqs,
    s.sd_reqs,
    CASE
      WHEN s.sd_reqs IS NULL OR s.sd_reqs = 0 THEN NULL
      ELSE (b.reqs - s.mean_reqs) / s.sd_reqs
    END AS zscore
  FROM buckets b
  JOIN stats s USING (asn)
)
SELECT
  sc.asn,
  e.asn_type,
  e.provider_brand_bucket,
  sc.bucket_ts,
  sc.reqs,
  sc.accounts,
  sc.orgs,
  ROUND(sc.zscore, 2) AS zscore
FROM scored sc
JOIN enrichment_ip e USING (asn)
WHERE sc.zscore IS NOT NULL
ORDER BY zscore DESC, reqs DESC
LIMIT 400;
