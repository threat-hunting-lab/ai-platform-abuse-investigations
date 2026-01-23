-- 0004_06_correlated_signals.sql
-- Correlate multiple attack signals: pod creation + resource abuse + mining traffic
-- Signal: Pods that exhibit all three indicators (high confidence)

WITH suspicious_pods_creation AS (
    SELECT DISTINCT
        pod_id,
        namespace,
        pod_name,
        service_account,
        container_image,
        registry_type,
        timestamp AS created_at,
        is_malicious,
        attack_chain_id
    FROM k8s_audit_logs
    WHERE event_type = 'pod_create'
      AND registry_type = 'external'  -- Signal 1: External registry
      AND response_code BETWEEN 200 AND 299
),

high_resource_pods AS (
    SELECT 
        pod_id,
        AVG(gpu_utilization_pct) AS avg_gpu_util,
        AVG(cpu_cores_used) AS avg_cpu,
        MAX(is_malicious) AS is_malicious
    FROM resource_metrics
    GROUP BY 1
    HAVING AVG(gpu_utilization_pct) >= 80  -- Signal 2: High GPU usage
),

mining_traffic_pods AS (
    SELECT 
        pod_id,
        COUNT(DISTINCT dst_host) AS unique_mining_hosts,
        SUM(bytes_sent) / 1e9 AS total_gb_sent,
        MAX(is_malicious) AS is_malicious
    FROM network_flows
    WHERE is_mining_pool = true  -- Signal 3: Mining pool connection
    GROUP BY 1
)

SELECT 
    p.namespace,
    p.pod_id,
    p.pod_name,
    p.service_account,
    p.container_image,
    p.created_at,
    ROUND(r.avg_gpu_util, 1) AS avg_gpu_utilization,
    ROUND(r.avg_cpu, 1) AS avg_cpu_cores,
    m.unique_mining_hosts,
    ROUND(m.total_gb_sent, 2) AS gb_sent_to_pools,
    p.attack_chain_id,
    p.is_malicious,
    -- Composite confidence score (all 3 signals present)
    10 AS confidence_score,
    'HIGH CONFIDENCE: External registry + High GPU + Mining traffic' AS verdict
FROM suspicious_pods_creation p
INNER JOIN high_resource_pods r ON p.pod_id = r.pod_id
INNER JOIN mining_traffic_pods m ON p.pod_id = m.pod_id
ORDER BY m.total_gb_sent DESC, r.avg_gpu_util DESC
LIMIT 100;
