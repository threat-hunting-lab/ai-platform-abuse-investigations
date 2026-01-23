# CASE-0004 Scoring Configuration
# Add this to your existing scoring.py for CASE-0004 support

CASE_0004_SIGNALS = {
    "0004_01_unusual_pod_creation": {
        "weight": 0.15,
        "rationale": "Pod creation spikes and off-hours activity indicate potential abuse but can also be legitimate batch jobs",
        "threshold": "anomaly_score >= 4"
    },
    "0004_02_non_standard_registries": {
        "weight": 0.20,
        "rationale": "Use of external registries (DockerHub, GHCR) in production is suspicious but may have legitimate use cases",
        "threshold": "avg_risk_score >= 4"
    },
    "0004_03_resource_anomalies": {
        "weight": 0.25,
        "rationale": "Sustained high GPU/CPU utilization (85%+) is inconsistent with typical inference workloads",
        "threshold": "resource_anomaly_score >= 5"
    },
    "0004_04_mining_pool_egress": {
        "weight": 0.40,
        "rationale": "Connection to known mining pools is a definitive indicator of cryptomining (near-zero false positives)",
        "threshold": "confidence_score == 10"
    },
    "0004_05_service_account_abuse": {
        "weight": 0.22,
        "rationale": "Service account usage from external IPs indicates compromised credentials",
        "threshold": "abuse_score >= 5"
    },
    "0004_06_correlated_signals": {
        "weight": 0.50,
        "rationale": "Triple correlation (external registry + high GPU + mining traffic) eliminates false positives",
        "threshold": "confidence_score == 10"
    }
}

# Scoring logic example
def score_case_0004(findings: dict) -> dict:
    """
    Score CASE-0004 investigation findings.
    
    Args:
        findings: Dict of query results keyed by query name
        
    Returns:
        Scoring results with overall risk score and signal breakdown
    """
    total_score = 0.0
    signal_scores = {}
    
    for signal_name, config in CASE_0004_SIGNALS.items():
        if signal_name in findings:
            row_count = len(findings[signal_name])
            
            # Normalize by row count (more hits = higher confidence)
            normalized_score = min(1.0, row_count / 10.0)  # Cap at 10 rows
            weighted_score = normalized_score * config['weight']
            
            signal_scores[signal_name] = {
                "row_count": row_count,
                "normalized_score": round(normalized_score, 3),
                "weighted_score": round(weighted_score, 3),
                "weight": config['weight'],
                "rationale": config['rationale']
            }
            
            total_score += weighted_score
    
    # Overall risk assessment
    if total_score >= 0.40:
        risk_level = "CRITICAL"
        recommendation = "Immediate investigation required - high confidence cryptomining detected"
    elif total_score >= 0.25:
        risk_level = "HIGH"
        recommendation = "Priority investigation - multiple abuse indicators present"
    elif total_score >= 0.15:
        risk_level = "MEDIUM"
        recommendation = "Review flagged pods and service accounts for anomalous behavior"
    else:
        risk_level = "LOW"
        recommendation = "Continue monitoring - isolated signals detected"
    
    return {
        "case_id": "CASE-0004",
        "total_score": round(total_score, 3),
        "risk_level": risk_level,
        "recommendation": recommendation,
        "signals": signal_scores
    }


# Example expected output structure:
"""
{
    "case_id": "CASE-0004",
    "total_score": 0.425,
    "risk_level": "CRITICAL",
    "recommendation": "Immediate investigation required - high confidence cryptomining detected",
    "signals": {
        "0004_01_unusual_pod_creation": {
            "row_count": 12,
            "normalized_score": 1.0,
            "weighted_score": 0.15,
            "weight": 0.15,
            "rationale": "Pod creation spikes and off-hours activity..."
        },
        "0004_04_mining_pool_egress": {
            "row_count": 18,
            "normalized_score": 1.0,
            "weighted_score": 0.40,
            "weight": 0.40,
            "rationale": "Connection to known mining pools is a definitive indicator..."
        }
    }
}
"""
