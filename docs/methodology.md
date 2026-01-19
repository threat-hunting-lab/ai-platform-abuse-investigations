# Methodology

This repo demonstrates an investigation workflow for coordinated AI platform misuse using **synthetic telemetry**.

## Investigation goals
1. Detect **coordinated behavior** across many tenants
2. Identify clusterable signals:
   - Infrastructure (ASN/provider bucket)
   - Timing (burst waves)
   - Similarity (template hashes / content clusters)
   - Automation indicators (device reuse, headless flags)
3. Produce **evidence-backed** artifacts and a human-readable report

## Data model (high-level)
Core tables:
- `llm_requests`: request-level telemetry (account/org/ip/asn/device/model/tokens + similarity fields)
- `enrichment_ip`: IP/ASN/provider categorization (synthetic buckets)
- `moderation_events`: policy actions (allow/warn/block) with coarse tags/scores
Optional realism tables:
- `sessions`: sessionization + auth strength
- `rate_limit_events`: throttle/block actions at account or infra scope
- `osint_observations`: synthetic corroboration keyed to `content_cluster_id`

## Signal logic

### A) Cross-tenant diversity
**Why it matters:** Coordinated campaigns often touch many orgs/tenants to avoid per-tenant rate limits and detection.

Operationalized as:
- Distinct orgs per ASN/provider bucket
- Distinct orgs per content cluster
- Distinct orgs per cluster key (infra × device × similarity)

### B) Infrastructure concentration
**Why it matters:** Operators reuse hosting/VPN infrastructure due to cost and operational constraints.

Operationalized as:
- Hosting/VPN ASN categories
- Provider bucket concentration
- First-seen hosting/VPN ASNs that spread quickly across orgs

### C) Timing synchronization
**Why it matters:** Bursts aligned in narrow windows indicate scheduling or centralized control.

Operationalized as:
- 15-minute bucket counts per ASN/provider
- Z-scores per ASN
- Multi-org spikes within the same buckets

### D) Similarity clustering
**Why it matters:** Influence-style operations reuse templates and paraphrases.

Operationalized as:
- `template_hash` reuse across many accounts/orgs
- `content_cluster_id` spread and volume
- Combined cluster key: provider bucket × device × content cluster/template

### E) Policy funnel concentration
**Why it matters:** Coordinated abuse tends to trigger policies disproportionately on specific infra/similarity patterns.

Operationalized as:
- policy_action counts by provider bucket and ASN type
- correlation with automation flags and similarity indicators

## Alternative explanations (what we check)
- Large enterprise egress NAT (many users behind one ASN)
- CDN/proxy services used by legitimate customers
- Viral organic behavior (timing waves, but not infra/device similarity)
- Normal seasonal spikes

We reduce confidence if:
- signals are confined to one tenant
- timing spikes are not repeated
- similarity is low or inconsistent
- infra reuse could plausibly be enterprise egress + normal customer behavior

## Reproducibility
- Synthetic dataset generated deterministically from:
  - fixed dictionaries
  - YAML parameters
  - fixed random seed
- All evidence exported as CSV artifacts.
- Report rendered from `findings.json` to avoid hidden state.
