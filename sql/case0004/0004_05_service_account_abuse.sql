-- 0004_05_service_account_abuse.sql
-- Detect compromised service account tokens used from unusual locations
-- Signal: Service account used from external IPs or with unusual behaviors

WITH service_account_activity AS (
    SELECT 
        service_account,
        namespace,
        source_ip,
        event_type,
        COUNT(*) AS event_count,
        COUNT(DISTINCT namespace) AS namespace_diversity,
        MIN(timestamp) AS first_seen,
        MAX(timestamp) AS last_seen,
        SUM(CASE WHEN event_type = 'pod_create' THEN 1 ELSE 0 END) AS pod_creations,
        SUM(CASE WHEN registry_type = 'external' THEN 1 ELSE 0 END) AS external_registry_pulls,
        SUM(CASE WHEN response_code >= 400 THEN 1 ELSE 0 END) AS failed_attempts,
        MAX(is_malicious) AS is_malicious
    FROM k8s_audit_logs
    WHERE service_account IS NOT NULL
    GROUP BY 1, 2, 3, 4
),

ip_classification AS (
    SELECT 
        service_account,
        namespace,
        source_ip,
        SUM(event_count) AS total_events,
        MAX(namespace_diversity) AS namespace_count,
        SUM(pod_creations) AS total_pod_creations,
        SUM(external_registry_pulls) AS external_pulls,
        SUM(failed_attempts) AS total_failures,
        MIN(first_seen) AS first_seen,
        MAX(last_seen) AS last_seen,
        MAX(is_malicious) AS is_malicious,
        -- Classify IP as internal (10.x) or external
        CASE 
            WHEN SPLIT_PART(source_ip, '.', 1)::INT = 10 THEN 'internal'
            ELSE 'external'
        END AS ip_classification
    FROM service_account_activity
    GROUP BY 1, 2, 3, ip_classification
),

abuse_detection AS (
    SELECT 
        service_account,
        namespace,
        source_ip,
        ip_classification,
        total_events,
        namespace_count,
        total_pod_creations,
        external_pulls,
        total_failures,
        first_seen,
        last_seen,
        is_malicious,
        -- Abuse score
        (CASE 
            WHEN ip_classification = 'external' THEN 4  -- Service account from external IP = very suspicious
            ELSE 0
        END) +
        (CASE 
            WHEN total_pod_creations >= 10 THEN 3
            WHEN total_pod_creations >= 5 THEN 2
            WHEN total_pod_creations >= 1 THEN 1
            ELSE 0
        END) +
        (CASE 
            WHEN external_pulls >= 5 THEN 2
            WHEN external_pulls >= 1 THEN 1
            ELSE 0
        END) +
        (CASE 
            WHEN namespace_count >= 3 THEN 1  -- Cross-namespace activity
            ELSE 0
        END) AS abuse_score
    FROM ip_classification
)

SELECT 
    service_account,
    namespace,
    source_ip,
    ip_classification,
    total_events,
    namespace_count,
    total_pod_creations,
    external_pulls,
    total_failures,
    first_seen,
    last_seen,
    abuse_score,
    is_malicious
FROM abuse_detection
WHERE abuse_score >= 5  -- High confidence: external IP + pod creation + external registries
ORDER BY abuse_score DESC, total_pod_creations DESC
LIMIT 100;
