-- 0004_01_unusual_pod_creation.sql
-- Detect pod creation spikes and off-hours creation patterns
-- Signal: High-volume pod creation in short time windows, especially off-hours

WITH hourly_pod_creation AS (
    SELECT 
        DATE_TRUNC('hour', timestamp) AS hour,
        namespace,
        service_account,
        COUNT(*) AS pod_creation_count,
        SUM(CASE WHEN EXTRACT(HOUR FROM timestamp) BETWEEN 9 AND 17 
                 AND EXTRACT(DOW FROM timestamp) BETWEEN 1 AND 5 
            THEN 0 ELSE 1 END) AS off_hours_count,
        COUNT(DISTINCT container_image) AS unique_images,
        SUM(resource_requests_cpu) AS total_cpu_requested,
        SUM(resource_requests_gpu) AS total_gpu_requested,
        MAX(is_malicious) AS is_malicious  -- Ground truth for eval
    FROM k8s_audit_logs
    WHERE event_type = 'pod_create'
      AND response_code BETWEEN 200 AND 299
    GROUP BY 1, 2, 3
),

pod_creation_stats AS (
    SELECT 
        hour,
        namespace,
        service_account,
        pod_creation_count,
        off_hours_count,
        ROUND(off_hours_count::DECIMAL / pod_creation_count * 100, 1) AS off_hours_pct,
        unique_images,
        total_cpu_requested,
        total_gpu_requested,
        is_malicious,
        -- Anomaly score: penalize high volume + off-hours + high resources
        (CASE 
            WHEN pod_creation_count >= 10 THEN 3
            WHEN pod_creation_count >= 5 THEN 2
            ELSE 1
        END) +
        (CASE 
            WHEN off_hours_pct >= 70 THEN 2
            WHEN off_hours_pct >= 50 THEN 1
            ELSE 0
        END) +
        (CASE 
            WHEN total_gpu_requested >= 10 THEN 2
            WHEN total_gpu_requested >= 5 THEN 1
            ELSE 0
        END) AS anomaly_score
    FROM hourly_pod_creation
)

SELECT 
    hour,
    namespace,
    service_account,
    pod_creation_count,
    off_hours_count,
    off_hours_pct,
    unique_images,
    total_cpu_requested,
    total_gpu_requested,
    anomaly_score,
    is_malicious
FROM pod_creation_stats
WHERE anomaly_score >= 4  -- High confidence threshold
ORDER BY anomaly_score DESC, pod_creation_count DESC
LIMIT 100;
