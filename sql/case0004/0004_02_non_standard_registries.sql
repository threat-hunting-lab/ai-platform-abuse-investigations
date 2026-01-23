-- 0004_02_non_standard_registries.sql
-- Detect pod creation from external/non-standard container registries
-- Signal: Use of public registries (DockerHub, GHCR, Quay) instead of internal

WITH registry_analysis AS (
    SELECT 
        namespace,
        service_account,
        container_image,
        registry_type,
        COUNT(*) AS pod_count,
        MIN(timestamp) AS first_seen,
        MAX(timestamp) AS last_seen,
        SUM(resource_requests_cpu) AS total_cpu,
        SUM(resource_requests_gpu) AS total_gpu,
        MAX(is_malicious) AS is_malicious
    FROM k8s_audit_logs
    WHERE event_type = 'pod_create'
      AND registry_type = 'external'
      AND response_code BETWEEN 200 AND 299
    GROUP BY 1, 2, 3, 4
),

registry_risk_score AS (
    SELECT 
        namespace,
        service_account,
        container_image,
        registry_type,
        pod_count,
        first_seen,
        last_seen,
        total_cpu,
        total_gpu,
        is_malicious,
        -- Risk scoring based on registry type and resource requests
        (CASE 
            WHEN registry_type = 'external' THEN 3
            ELSE 0
        END) +
        (CASE 
            WHEN total_gpu >= 10 THEN 3
            WHEN total_gpu >= 5 THEN 2
            WHEN total_gpu >= 1 THEN 1
            ELSE 0
        END) +
        (CASE 
            WHEN pod_count >= 10 THEN 2
            WHEN pod_count >= 5 THEN 1
            ELSE 0
        END) AS risk_score,
        -- Extract registry domain for grouping
        SPLIT_PART(container_image, '/', 1) AS registry_domain
    FROM registry_analysis
)

SELECT 
    namespace,
    service_account,
    registry_domain,
    COUNT(DISTINCT container_image) AS unique_images,
    SUM(pod_count) AS total_pods,
    MIN(first_seen) AS first_seen,
    MAX(last_seen) AS last_seen,
    SUM(total_cpu) AS total_cpu_requested,
    SUM(total_gpu) AS total_gpu_requested,
    AVG(risk_score) AS avg_risk_score,
    MAX(is_malicious) AS is_malicious
FROM registry_risk_score
WHERE risk_score >= 4  -- External registry + high resources
GROUP BY 1, 2, 3
ORDER BY avg_risk_score DESC, total_pods DESC
LIMIT 100;
