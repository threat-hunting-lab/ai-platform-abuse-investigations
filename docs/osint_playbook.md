# OSINT Playbook (Safe + Reproducible)

This playbook defines how to incorporate OSINT-like corroboration **without operational content** and without collecting sensitive data.

## Scope
Allowed:
- High-level platform observations (volume, timing)
- Non-sensitive taxonomy tags (e.g., content cluster ids)
- Publicly available metadata that does not identify individuals

Disallowed:
- Targeting individuals or private organizations
- Collecting/processing personal data
- Publishing exact operational tactics, evasion instructions, or harmful content
- Scraping that violates terms of service

## Minimal OSINT artifact format
A safe OSINT entry is keyed to a synthetic identifier:
- `content_cluster_id`
- `platform_bucket` (e.g., social_a, forum_a)
- `observed_volume`
- `confidence_bucket` (low/med/high)
- `notes` (non-sensitive)

Example:
- “Observed elevated volume for cluster CT-02 on social_a; non-sensitive corroboration.”

## How OSINT is used
OSINT does not prove ground truth.
It is used only to:
- corroborate that a cluster is “active” beyond internal telemetry
- strengthen confidence from Low→Medium or Medium→High if aligned with other signals

## Reproducibility
For public demo purposes, OSINT entries in this repo are **synthetically generated**.
If adapting this to real data:
- store only aggregate counts and timestamps
- document sources and collection method
- ensure legal/ToS compliance
