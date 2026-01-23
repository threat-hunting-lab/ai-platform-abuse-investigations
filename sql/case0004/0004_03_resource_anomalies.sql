-- 0004_03_resource_anomalies.sql
-- Detect pods with abnormally high GPU/CPU utilization
-- Signal: Sustained high resource usage inconsistent with inference workloads

WITH pod_resource_stats AS (
    SELECT 
        namespace,
        pod_id,
        pod_name,
        AVG(cpu_cores_used) AS avg_cpu_cores,
        MAX(cpu_cores_used) AS max_cpu_cores,
        AVG(memory_gb_used) AS avg_memory_gb,
        AVG(gpu_utilization_pct) AS avg_gpu_utilization,
        MAX(gpu_utilization_pct) AS max_gpu_utilization,
        COUNT(*) AS sample_count,
        MIN(timestamp) AS first_seen,
        MAX(timestamp) AS last_seen,
        EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))) / 3600 AS lifetime_hours,
        MAX(is_malicious) AS is_malicious
    FROM resource_metrics
    GROUP BY 1, 2, 3
),

anomaly_detection AS (
    SELECT 
        namespace,
        pod_id,
        pod_name,
        avg_cpu_cores,
        max_cpu_cores,
        avg_memory_gb,
        avg_gpu_utilization,
        max_gpu_utilization,
        sample_count,
        first_seen,
        last_seen,
        lifetime_hours,
        is_malicious,
        -- Anomaly score based on sustained high utilization
        (CASE 
            WHEN avg_gpu_utilization >= 85 THEN 3
            WHEN avg_gpu_utilization >= 75 THEN 2
            WHEN avg_gpu_utilization >= 65 THEN 1
            ELSE 0
        END) +
        (CASE 
            WHEN avg_cpu_cores >= 14 THEN 3
            WHEN avg_cpu_cores >= 10 THEN 2
            WHEN avg_cpu_cores >= 8 THEN 1
            ELSE 0
        END) +
        (CASE 
            WHEN lifetime_hours >= 48 THEN 2  -- Long-running high usage
            WHEN lifetime_hours >= 24 THEN 1
            ELSE 0
        END) AS resource_anomaly_score
    FROM pod_resource_stats
    WHERE avg_gpu_utilization > 0  -- Focus on GPU pods
)

SELECT 
    namespace,
    pod_id,
    pod_name,
    ROUND(avg_cpu_cores, 1) AS avg_cpu_cores,
    max_cpu_cores,
    ROUND(avg_memory_gb, 1) AS avg_memory_gb,
    ROUND(avg_gpu_utilization, 1) AS avg_gpu_utilization,
    max_gpu_utilization,
    sample_count,
    ROUND(lifetime_hours, 1) AS lifetime_hours,
    resource_anomaly_score,
    is_malicious
FROM anomaly_detection
WHERE resource_anomaly_score >= 5  -- High confidence: sustained high GPU + CPU
ORDER BY resource_anomaly_score DESC, avg_gpu_utilization DESC
LIMIT 100;
