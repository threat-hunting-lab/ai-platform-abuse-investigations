# CASE-0004: K8s Resource Hijacking via Compromised API Tokens

## Overview

This case study demonstrates detection of **API token abuse leading to Kubernetes infrastructure compromise and cryptomining resource theft** in AI platform environments. The attack chain connects application-layer credential compromise (CASE-0002) with infrastructure-layer abuse.

## Attack Scenario

**Threat Model:** Attacker obtains valid API tokens through credential stuffing/phishing (see CASE-0002), then leverages those tokens to:

1. **Access K8s API** - Authenticate using stolen service account credentials
2. **Deploy malicious pods** - Create pods with cryptomining containers from public registries
3. **Hijack GPU resources** - Allocate high-end compute resources (expensive for AI platforms)
4. **Establish mining connections** - Connect to external mining pools
5. **Sustain operations** - Run mining workloads for 24-72 hours before detection

**Business Impact:**
- Direct financial loss (GPU compute hours are the primary cost for AI companies)
- Resource exhaustion affecting legitimate workloads
- Infrastructure trust boundary violation
- Potential for lateral movement to production namespaces

## Synthetic Telemetry

Three primary data sources simulate K8s platform telemetry:

### k8s_audit_logs.parquet
K8s API server audit events capturing:
- Pod creation/deletion/update operations
- Service account authentication
- Container image source (internal registry vs. external DockerHub/GHCR)
- Resource requests (CPU/GPU/memory)
- RBAC authorization results
- Source IP addresses

**Ground truth:** ~200K total events, ~100-150 malicious pod creations from 18 compromised service accounts

### resource_metrics.parquet  
Pod-level resource utilization metrics (hourly samples):
- CPU core usage
- GPU utilization percentage
- Memory consumption
- Network throughput (RX/TX bytes)

**Attack signature:** Malicious pods exhibit sustained 85-98% GPU utilization vs. 40-75% for legitimate inference workloads

### network_flows.parquet
Egress network connections from pods:
- Source/destination IPs and ports
- Bytes sent/received
- Connection duration
- Destination hostnames

**Attack signature:** Connections to known cryptomining pools (pool.supportxmr.com, nanopool.org, moneroocean.stream)

## Detection Methodology

### Detection Signals (7 SQL Queries)

| Query | Signal | Confidence |
|-------|--------|------------|
| `0004_01_unusual_pod_creation.sql` | High-volume pod creation in short windows, especially off-hours | Medium |
| `0004_02_non_standard_registries.sql` | Container images from public registries (DockerHub, GHCR) vs. internal | Medium-High |
| `0004_03_resource_anomalies.sql` | Sustained high GPU/CPU utilization (85%+ for 24+ hours) | Medium-High |
| `0004_04_mining_pool_egress.sql` | Network connections to known cryptomining infrastructure | **Critical** |
| `0004_05_service_account_abuse.sql` | Service accounts used from external IPs or with unusual behaviors | High |
| `0004_06_correlated_signals.sql` | Pods exhibiting ALL THREE: external registry + high GPU + mining traffic | **Critical** |
| `0004_99_attack_chain_rollup.sql` | End-to-end attack chain summary by compromised service account | Investigation rollup |

### Scoring Heuristics

**Individual signal scores:**
- Unusual pod creation patterns: 1-5 points
- External container registry: 3-4 points  
- High GPU utilization (>80%): 2-3 points
- Mining pool connection: **10 points (definitive)**
- Service account from external IP: 4 points

**Composite confidence:**
- Score >= 5: Investigate
- Score >= 8: High priority
- Score == 10: Critical (mining pool connection or triple correlation)

## What to Look For

When running the investigation, expect to find:

### Timing Patterns
- **Off-hours pod creation spikes** - 70% of malicious pods created outside business hours (9am-6pm Mon-Fri)
- **Burst creation** - 10+ pods created within 1-hour windows
- **Sustained runtime** - Malicious pods run 24-72 hours vs. typical inference jobs (minutes to hours)

### Resource Indicators  
- **GPU saturation** - Consistent 85-98% GPU utilization (vs. bursty inference patterns)
- **CPU oversubscription** - 12-16 core usage per pod
- **Long-lived high usage** - No variance in resource consumption over pod lifetime

### Network Footprint
- **External egress** - Connections to non-internal IPs
- **Mining pool domains** - Direct connections to known Monero/XMR pools
- **High-volume outbound** - 0.5-2 GB/day egress per pod (mining pool shares)

### Infrastructure Abuse
- **Service account anomalies** - Tokens used from external ASNs
- **Registry violations** - Pulls from docker.io instead of gcr.io/company-project
- **Namespace boundary testing** - Cross-namespace API calls or permission enumeration

## Key Differentiators from CASE-0002

CASE-0002 (Account Takeover) focused on **identity-layer abuse** (credential stuffing, MFA bypass, mailbox rules).

CASE-0004 extends this by demonstrating **infrastructure-layer exploitation**:
- Credential compromise enables K8s API access
- Application security breach escalates to resource theft
- Detection requires correlation across identity + infrastructure telemetry

**Real-world parallel:** An attacker who steals an AI platform API key doesn't just abuse the API endpoints - they can potentially deploy workloads directly into the underlying K8s cluster.

## Evaluation Approach

Similar to CASE-0003, this case includes **ground truth labels** for evaluation:

- `is_malicious` flag on all telemetry records
- `attack_chain_id` groups related malicious pods by compromised service account
- Expected outcomes:
  - **Precision:** >95% (mining pool query should have near-zero false positives)
  - **Recall:** >90% (catch 16-17 of 18 attack chains)
  - **Time to detection:** <24 hours from first malicious pod creation

**Evaluation questions:**
1. Did the mining pool query (0004_04) catch all attack chains?
2. Which standalone signals (registry, resource, timing) have the highest precision?
3. Does the correlated signal query (0004_06) reduce false positives vs. individual signals?
4. What's the cost of missing signals vs. alert fatigue from over-detection?

## Relevance to AI Platform Security

This case is particularly relevant to AI companies like Anthropic because:

1. **GPU compute is the cost center** - Resource theft directly impacts P&L
2. **K8s is the standard** - Claude inference likely runs on K8s clusters  
3. **API tokens enable infrastructure access** - Stolen credentials can escalate beyond app-layer abuse
4. **Detection requires cross-layer visibility** - Must correlate identity events (CASE-0002) with infrastructure events (CASE-0004)

## Usage

Generate synthetic data:
```bash
python python/generate_k8s_events.py --config configs/case0004.yaml --out datasets/output_case0004
```

Run detection pipeline:
```bash
python python/run_queries.py \
  --duckdb artifacts/ai_abuse_case0004.duckdb \
  --data datasets/output_case0004 \
  --sql sql/case0004 \
  --case-dir case_studies/CASE-0004-k8s-resource-hijacking \
  --strict

python python/scoring.py --case-dir case_studies/CASE-0004-k8s-resource-hijacking
python python/render_report.py --case-dir case_studies/CASE-0004-k8s-resource-hijacking
```

## Future Extensions

Potential additions to this case:
- **Container escape attempts** - Detect privileged pod creation or host path mounts
- **Lateral movement** - Service account token theft from compromised pods
- **Persistence mechanisms** - DaemonSets, CronJobs for sustained access
- **Model exfiltration** - Detect reads from persistent volumes containing model weights
- **Supply chain attack** - Poisoned container images in internal registries

## References

- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [NSA/CISA Kubernetes Hardening Guidance](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [Crowdstrike: Cryptomining Attacks on K8s](https://www.crowdstrike.com/blog/compromised-kubernetes-clusters-used-for-cryptomining/)
