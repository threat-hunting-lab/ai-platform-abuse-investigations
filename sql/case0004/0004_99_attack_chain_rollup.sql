-- 0004_99_attack_chain_rollup.sql
-- Rollup of complete attack chains: compromised token → pods → abuse
-- Signal: End-to-end investigation summary by attack chain

WITH attack_chain_pods AS (
    SELECT 
        attack_chain_id,
        service_account,
        namespace,
        COUNT(DISTINCT pod_id) AS total_pods,
        MIN(timestamp) AS attack_start,
        MAX(timestamp) AS attack_end,
        SUM(resource_requests_cpu) AS total_cpu_requested,
        SUM(resource_requests_gpu) AS total_gpu_requested,
        COUNT(DISTINCT container_image) AS unique_images,
        MAX(is_malicious) AS is_malicious
    FROM k8s_audit_logs
    WHERE event_type = 'pod_create'
      AND attack_chain_id IS NOT NULL
    GROUP BY 1, 2, 3
),

resource_abuse_summary AS (
    SELECT 
        attack_chain_id,
        AVG(gpu_utilization_pct) AS avg_gpu_util,
        MAX(gpu_utilization_pct) AS max_gpu_util,
        SUM(cpu_cores_used) AS total_cpu_hours,
        COUNT(*) AS metric_samples
    FROM resource_metrics
    WHERE attack_chain_id IS NOT NULL
    GROUP BY 1
),

network_abuse_summary AS (
    SELECT 
        attack_chain_id,
        COUNT(DISTINCT dst_host) AS mining_hosts_contacted,
        SUM(bytes_sent) / 1e9 AS total_gb_egress,
        COUNT(*) AS total_connections,
        SUM(connection_duration_sec) / 3600 AS total_connection_hours
    FROM network_flows
    WHERE attack_chain_id IS NOT NULL
      AND is_mining_pool = true
    GROUP BY 1
)

SELECT 
    p.attack_chain_id,
    p.service_account AS compromised_account,
    p.namespace,
    p.total_pods,
    p.attack_start,
    p.attack_end,
    ROUND(EXTRACT(EPOCH FROM (p.attack_end - p.attack_start)) / 3600, 1) AS attack_duration_hours,
    p.total_cpu_requested,
    p.total_gpu_requested,
    p.unique_images,
    ROUND(r.avg_gpu_util, 1) AS avg_gpu_utilization,
    r.max_gpu_util,
    ROUND(r.total_cpu_hours, 0) AS total_cpu_hours_consumed,
    n.mining_hosts_contacted,
    ROUND(n.total_gb_egress, 2) AS gb_egressed_to_pools,
    n.total_connections AS mining_connections,
    ROUND(n.total_connection_hours, 1) AS hours_connected_to_pools,
    p.is_malicious,
    -- Overall severity score
    (CASE 
        WHEN p.total_pods >= 10 THEN 3
        WHEN p.total_pods >= 5 THEN 2
        ELSE 1
    END) +
    (CASE 
        WHEN r.avg_gpu_util >= 85 THEN 3
        WHEN r.avg_gpu_util >= 75 THEN 2
        ELSE 1
    END) +
    (CASE 
        WHEN n.total_gb_egress >= 10 THEN 3
        WHEN n.total_gb_egress >= 5 THEN 2
        ELSE 1
    END) AS severity_score
FROM attack_chain_pods p
LEFT JOIN resource_abuse_summary r ON p.attack_chain_id = r.attack_chain_id
LEFT JOIN network_abuse_summary n ON p.attack_chain_id = n.attack_chain_id
WHERE p.is_malicious = true  -- Focus on confirmed malicious chains
ORDER BY severity_score DESC, p.total_pods DESC
LIMIT 50;
