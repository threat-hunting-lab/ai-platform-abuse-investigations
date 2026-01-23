-- 0004_04_mining_pool_egress.sql
-- Detect network connections to known cryptomining pools
-- Signal: Egress to mining infrastructure (high confidence indicator)

WITH mining_pool_connections AS (
    SELECT 
        namespace,
        pod_id,
        pod_name,
        dst_host,
        dst_port,
        COUNT(*) AS connection_count,
        SUM(bytes_sent) AS total_bytes_sent,
        SUM(bytes_received) AS total_bytes_received,
        AVG(connection_duration_sec) AS avg_duration_sec,
        MIN(timestamp) AS first_connection,
        MAX(timestamp) AS last_connection,
        MAX(is_malicious) AS is_malicious
    FROM network_flows
    WHERE is_mining_pool = true
    GROUP BY 1, 2, 3, 4, 5
),

volume_analysis AS (
    SELECT 
        namespace,
        pod_id,
        pod_name,
        dst_host,
        dst_port,
        connection_count,
        ROUND(total_bytes_sent / 1e9, 2) AS gb_sent,
        ROUND(total_bytes_received / 1e6, 2) AS mb_received,
        ROUND(avg_duration_sec / 60, 1) AS avg_duration_min,
        first_connection,
        last_connection,
        EXTRACT(EPOCH FROM (last_connection - first_connection)) / 3600 AS connection_span_hours,
        is_malicious,
        -- Confidence score (mining pool connection = definitive indicator)
        10 AS confidence_score  -- Max score: this is a smoking gun
    FROM mining_pool_connections
)

SELECT 
    namespace,
    pod_id,
    pod_name,
    dst_host,
    dst_port,
    connection_count,
    gb_sent,
    mb_received,
    avg_duration_min,
    first_connection,
    last_connection,
    ROUND(connection_span_hours, 1) AS connection_span_hours,
    confidence_score,
    is_malicious,
    'CRITICAL: Mining pool connection detected' AS alert_message
FROM volume_analysis
ORDER BY gb_sent DESC, connection_count DESC
LIMIT 100;
