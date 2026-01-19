# CASE-0001 — Coordinated Influence (Synthetic)

This case study demonstrates an investigation workflow for **coordinated influence-style misuse** of an AI platform using **synthetic telemetry**. The point is to show how a threat investigator can move from raw logs → clustered evidence → calibrated conclusions → mitigations.

## What you should see in this case
**High-confidence coordination** emerges when multiple signals align:

1) **Cross-tenant diversity**
- Many distinct orgs and accounts tied to the same infrastructure buckets

2) **Shared infrastructure**
- Hosting/VPN ASN/provider buckets reused across many orgs

3) **Synchronized bursts**
- Narrow time-window spikes repeated across the case window

4) **Similarity**
- Template reuse (`template_hash`) and narrative-level clustering (`content_cluster_id`)

5) **Policy funnel concentration**
- Higher warn/block rates and throttling on the same infrastructure + similarity clusters

## Quick start (from repo root)
```bash
make gen
make queries
make score
make report
