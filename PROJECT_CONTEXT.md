# PROJECT_CONTEXT.md
# ai-platform-abuse-investigations

## Project Overview

**Purpose:** Case-driven SQL + Python investigations of platform abuse & security telemetry using synthetic, privacy-safe datasets, explainable signals, and scored reports.

**Target Audience:** 
- Security engineers and threat hunters
- Detection engineers at AI/SaaS platforms
- Trust & Safety teams
- Security researchers

**Core Philosophy:**
- Privacy-first: All telemetry is synthetic
- Explainable heuristics over black-box models
- Reproducible investigations from config → findings → report
- Evaluation-driven: Measure precision/recall, not just "it works"

---

## Architecture & Data Flow

### High-Level Pipeline

```
1. CONFIGURE (YAML)
   ↓
2. GENERATE SYNTHETIC DATA (Python)
   ↓
3. LOAD INTO DUCKDB (run_queries.py)
   ↓
4. RUN SQL DETECTION PACK (case-specific queries)
   ↓
5. EXPORT ARTIFACTS (CSV evidence files)
   ↓
6. SCORE SIGNALS (deterministic heuristics)
   ↓
7. RENDER REPORT (human-readable investigation summary)
```

### Technology Stack

- **Data Generation:** Python 3.10+ with pandas, numpy, pyyaml
- **Data Storage:** Parquet files (columnar, compressed)
- **Query Engine:** DuckDB (in-process SQL OLAP)
- **Orchestration:** Python CLI scripts
- **Configuration:** YAML files
- **Outputs:** CSV artifacts + JSON findings + Markdown reports

### Why This Stack?

- **DuckDB:** Handles 1M-10M row datasets on laptops, no cluster needed
- **Parquet:** Columnar format, excellent compression, wide compatibility
- **Python:** Accessible to security analysts, rich data science ecosystem
- **YAML:** Human-readable configs, easy to version control
- **Synthetic data:** Privacy compliance, reproducible ground truth

---

## Repository Structure

```
ai-platform-abuse-investigations/
├── configs/                          # Case configurations (attack scenarios)
│   ├── case0001.yaml                # Coordinated influence
│   ├── case0002.yaml                # Account takeover (ATO)
│   ├── case0003.yaml                # DNS triage
│   └── case0004.yaml                # K8s resource hijacking (NEW)
│
├── datasets/
│   ├── output/                      # CASE-0001 data (gitignored)
│   ├── output_case0002/             # CASE-0002 data (gitignored)
│   ├── output_case0003/             # CASE-0003 data (gitignored)
│   ├── output_case0004/             # CASE-0004 data (gitignored)
│   └── schema.md                    # Dataset schema documentation
│
├── python/
│   ├── generate_dataset.py          # Base data generator (CASE-0001)
│   ├── generate_identity_events.py  # Identity events (CASE-0002)
│   ├── generate_dns_events.py       # DNS events (CASE-0003)
│   ├── generate_k8s_events.py       # K8s events (CASE-0004)
│   ├── run_queries.py               # SQL execution + artifact export
│   ├── scoring.py                   # Signal scoring + risk calculation
│   └── render_report.py             # Markdown report generation
│
├── sql/
│   ├── case0001/                    # 11 queries: coordinated influence
│   ├── case0002/                    # 8 queries: ATO chains
│   ├── case0003/                    # 5 queries: DNS triage
│   └── case0004/                    # 7 queries: K8s abuse (NEW)
│
├── case_studies/
│   ├── CASE-0001-coordinated-influence/
│   │   ├── README.md                # Case overview
│   │   ├── artifacts/*.csv          # Query results (gitignored)
│   │   ├── findings.json            # Machine-readable findings
│   │   ├── scoring.json             # Risk scores
│   │   └── REPORT.md                # Human-readable report
│   ├── CASE-0002-ato-identity-abuse/
│   ├── CASE-0003-dns-triage/
│   └── CASE-0004-k8s-resource-hijacking/
│
├── hunting_packages/
│   └── CVE-2025-12420/              # OSINT-to-hunt translation
│
├── intel_reports/                   # Threat intelligence writeups
│
├── docs/                            # Methodology documentation
│
├── Makefile                         # Build automation
├── requirements.txt                 # Python dependencies
└── README.md                        # Project documentation
```

---

## Case Studies

### CASE-0001: Coordinated Influence (Synthetic)

**Threat Model:** Multi-language coordinated activity across many organizations/tenants

**Attack Indicators:**
- Shared hosting/VPN provider buckets
- Synchronized burst posting
- Template/content similarity (template_hash, content_cluster_id)
- Enforcement funnel concentration (warn → throttle → block)

**Synthetic Data Tables:**
- accounts.parquet
- devices.parquet
- posts.parquet
- organizations.parquet
- enrichment_ip.parquet

**Detection Queries:** 11 SQL queries
- First-seen hosting ASN analysis
- Hosting/VPN percentage by account
- Tenant diversity by ASN
- Device reuse patterns
- Burst detection (ASN-based)
- Synchronized org spikes
- Template reuse detection
- Content cluster spread
- Policy funnel by provider
- Cluster keys analysis
- Rate limit summary

**Ground Truth:** 
- 20% of accounts are malicious (configurable)
- Campaigns defined in config with specific behaviors

---

### CASE-0002: Account Takeover & Identity Abuse (Synthetic)

**Threat Model:** Credential stuffing → compromise → persistence → abuse chain

**Attack Chain:**
1. Failed login bursts (credential stuffing/spraying)
2. Successful auth from new ASN
3. MFA device manipulation
4. Mailbox rule creation (persistence)
5. OAuth consent grants to malicious apps

**Synthetic Data Tables:**
- Base tables from CASE-0001
- identity_events.parquet (login attempts, MFA changes, mailbox rules, OAuth grants)

**Detection Queries:** 8 SQL queries
- Failed login bursts
- New ASN after failures
- MFA device added
- Success after MFA manipulation
- Mailbox rule creation
- OAuth consent grants
- ATO chain candidates
- ATO rollup

**Ground Truth:**
- ~24 compromised accounts per investigation
- Complete attack chains within 24-48 hours

---

### CASE-0003: DNS Triage + Redirect Chains (Synthetic)

**Threat Model:** Malicious DNS patterns with explainable heuristics

**Detection Approach:**
- Suspicious TLD scoring
- Keyword hit detection
- Domain entropy analysis
- Rarity scoring
- Redirect chain analysis

**Synthetic Data Tables:**
- Base tables from CASE-0001
- dns_events.parquet (~2-3M DNS queries)

**Detection Queries:** 5 SQL queries
- Top suspicious domains
- Domain chain clusters
- Exposed accounts
- Heuristic breakdown
- Rollup

**Evaluation:**
- Precision/recall against synthetic ground truth
- Empirical metrics for detection quality validation

---

### CASE-0004: K8s Resource Hijacking (Synthetic) [NEW]

**Threat Model:** API token abuse → K8s infrastructure compromise → cryptomining

**Attack Chain:**
1. Compromised API tokens (from CASE-0002)
2. K8s API access
3. Malicious pod creation (external registries)
4. GPU resource hijacking
5. Mining pool connections

**Synthetic Data Tables:**
- k8s_audit_logs.parquet (~200K API events)
- resource_metrics.parquet (~150K CPU/GPU samples)
- network_flows.parquet (~100K connections)

**Detection Queries:** 7 SQL queries
- Unusual pod creation patterns
- Non-standard container registries
- Resource anomalies (high GPU/CPU)
- Mining pool egress (CRITICAL signal)
- Service account abuse
- Correlated signals (triple correlation)
- Attack chain rollup

**Ground Truth:**
- 18 compromised service accounts
- ~108 malicious pods (6 per account average)
- Definitive mining pool connections (near-zero FP rate)

---

### CASE-OSINT-0001: CVE-2025-12420 (BodySnatcher)

**Type:** OSINT-to-hunt translation (no synthetic data)

**Purpose:** Demonstrate threat intelligence operationalization

**Deliverables:**
- Curated sources
- ATT&CK mapping
- IOC/observables structure
- Platform-agnostic hunt queries

---

## Configuration Schema

### YAML Config Structure

All case configs follow this pattern:

```yaml
case_id: "CASE-XXXX"
case_name: "descriptive-name"
description: "Brief threat model description"

time_window:
  start: "2025-01-01T00:00:00Z"
  end: "2025-01-08T00:00:00Z"

row_counts:
  table_name: 100000
  another_table: 50000

attack_config:
  # Attack-specific parameters
  compromised_accounts: 20
  attack_timing:
    business_hours_pct: 30
    off_hours_pct: 70
  # ... case-specific config

benign_config:
  # Benign baseline parameters
  normal_behavior_patterns: {}
  # ... case-specific config

detection_config:
  # Detection thresholds
  signal_thresholds: {}
  # ... case-specific config

ground_truth:
  # Evaluation targets
  total_malicious_entities: 100
  true_positive_threshold: 0.90
  false_positive_tolerance: 0.05
```

### Common Config Patterns

**Time Windows:**
- Typical: 7 days (1 week of activity)
- Can adjust based on attack duration

**Attack/Benign Split:**
- Usually 10-20% malicious, 80-90% benign
- Configurable via campaign_mix or similar params

**Ground Truth Labels:**
- `is_malicious` flag on all telemetry records
- `attack_chain_id` for grouping related activities
- Enables precision/recall calculation

---

## Data Generation Patterns

### Two-Phase Generation (CASE-0002, CASE-0003, CASE-0004)

Some cases require base data + specialized events:

```bash
# Phase 1: Generate base dataset (accounts, orgs, devices)
python python/generate_dataset.py --config configs/caseXXXX.yaml --out datasets/output_caseXXXX

# Phase 2: Generate specialized events (requires base dataset)
python python/generate_XXXX_events.py --config configs/caseXXXX.yaml --data datasets/output_caseXXXX
```

**Why two phases?**
- Base data is reusable (accounts, devices, orgs)
- Specialized events depend on base entities
- Allows testing event generators independently

### Synthetic Data Quality

**Realism factors:**
- Temporal patterns (business hours vs. off-hours)
- Geographic distribution (ASNs, countries)
- Behavioral variance (not all malicious actors behave identically)
- Noise injection (benign activity isn't perfectly clean)

**Privacy guarantees:**
- No real user data, organization names, or platform identifiers
- No PII, even synthetic
- Safe for public repositories

---

## SQL Query Conventions

### File Naming

Pattern: `XXXX_NN_descriptive_name.sql`
- `XXXX`: Case ID (e.g., 0004)
- `NN`: Query sequence (01, 02, ..., 99)
- `99`: Reserved for rollup/summary queries

### Query Structure

```sql
-- XXXX_NN_query_name.sql
-- Brief description of what this query detects
-- Signal: What pattern indicates abuse

WITH step1 AS (
    -- Initial data prep or filtering
    SELECT ...
),

step2 AS (
    -- Aggregation or enrichment
    SELECT ...
),

final_scoring AS (
    -- Apply scoring heuristics
    SELECT ...,
    CASE ... END AS risk_score
)

SELECT 
    key_fields,
    evidence_fields,
    risk_score,
    is_malicious  -- Ground truth for evaluation
FROM final_scoring
WHERE risk_score >= THRESHOLD
ORDER BY risk_score DESC, ...
LIMIT 100;  -- Top N results
```

### DuckDB-Specific Patterns

**Reading Parquet:**
```sql
FROM read_parquet('${DATA}/table_name.parquet')
```

**Parameterization:**
- `${DATA}`: Data directory path (injected by run_queries.py)
- Queries are pure SQL, no embedded Python

**Date Handling:**
```sql
DATE_TRUNC('hour', timestamp)  -- Time bucketing
EXTRACT(DOW FROM timestamp)    -- Day of week (0=Sunday)
EXTRACT(HOUR FROM timestamp)   -- Hour of day
```

**Time Windows:**
```sql
-- Business hours: Mon-Fri, 9am-6pm
WHERE EXTRACT(DOW FROM timestamp) BETWEEN 1 AND 5
  AND EXTRACT(HOUR FROM timestamp) BETWEEN 9 AND 17
```

---

## Data Schema Patterns

### Common Fields Across Cases

**Identity:**
- `account_id`: Unique account identifier
- `user_id`: User within account
- `email`: User email (synthetic)
- `organization_id`: Tenant/org identifier

**Network:**
- `ip_address`: Source IP
- `asn`: Autonomous System Number
- `country_code`: ISO country code
- `hosting_provider`: Hosting/VPN provider name

**Temporal:**
- `timestamp`: Event time (ISO 8601 format)
- `created_at`: Entity creation time
- `updated_at`: Entity last modified time

**Ground Truth:**
- `is_malicious`: Boolean flag for evaluation
- `campaign_id` / `attack_chain_id`: Groups related malicious activity

### Case-Specific Tables

**CASE-0001:**
- posts.parquet: User-generated content
- template_hash: Content similarity indicator
- content_cluster_id: Clustering result

**CASE-0002:**
- identity_events.parquet: Login attempts, MFA changes, OAuth grants
- event_type: 'failed_login', 'successful_login', 'mfa_device_added', etc.

**CASE-0003:**
- dns_events.parquet: DNS queries
- domain, tld, entropy_score, rarity_score
- parent_domain / child_domain: Redirect chains

**CASE-0004:**
- k8s_audit_logs.parquet: K8s API server events
- resource_metrics.parquet: Pod CPU/GPU/memory usage
- network_flows.parquet: Egress connections
- registry_type: 'internal' vs. 'external'

---

## Scoring System

### Deterministic Heuristics

**Philosophy:** Explainable weights over black-box models

Each signal has:
- **Weight:** Importance (0.0 to 1.0)
- **Rationale:** Why this signal matters
- **Threshold:** When to fire the signal

### Scoring Logic (scoring.py)

```python
CASE_XXXX_SIGNALS = {
    "XXXX_01_signal_name": {
        "weight": 0.20,
        "rationale": "Why this matters...",
        "threshold": "score >= 5"
    },
    # ... more signals
}

def score_case_XXXX(findings: dict) -> dict:
    total_score = 0.0
    for signal_name, config in CASE_XXXX_SIGNALS.items():
        if signal_name in findings:
            row_count = len(findings[signal_name])
            normalized = min(1.0, row_count / 10.0)  # Cap at 10 rows
            weighted = normalized * config['weight']
            total_score += weighted
    
    # Risk level assessment
    if total_score >= 0.40:
        risk_level = "CRITICAL"
    elif total_score >= 0.25:
        risk_level = "HIGH"
    # ...
    
    return {"total_score": total_score, "risk_level": risk_level, ...}
```

### Risk Levels

- **CRITICAL:** >= 0.40 (immediate investigation required)
- **HIGH:** >= 0.25 (priority investigation)
- **MEDIUM:** >= 0.15 (review flagged entities)
- **LOW:** < 0.15 (continue monitoring)

### Signal Weight Examples

**Definitive indicators (0.40-0.50):**
- Mining pool connections (CASE-0004)
- Known IOC hits
- Triple signal correlation

**Strong indicators (0.20-0.30):**
- External registry usage
- High resource anomalies
- Rare external IPs

**Supporting indicators (0.10-0.20):**
- Timing anomalies
- Volume spikes
- Namespace violations

---

## Testing & Validation

### Unit Testing

Test individual components:

```bash
# Test data generation
python python/generate_dataset.py --config configs/case0001.yaml --out /tmp/test_data --rows 1000

# Verify row counts
python -c "import pandas as pd; df = pd.read_parquet('/tmp/test_data/accounts.parquet'); print(len(df))"
```

### Integration Testing

Test full pipeline:

```bash
# Generate data
python python/generate_dataset.py --config configs/case0001.yaml --out datasets/test_output

# Run queries
python python/run_queries.py \
  --duckdb artifacts/test.duckdb \
  --data datasets/test_output \
  --sql sql/case0001 \
  --case-dir /tmp/test_case \
  --strict

# Check artifacts
ls /tmp/test_case/artifacts/*.csv
```

### Validation Checks

**Data quality:**
- [ ] Row counts match config
- [ ] Ground truth labels present (`is_malicious`, `attack_chain_id`)
- [ ] No NULL values in key fields
- [ ] Timestamps within configured time window

**Query quality:**
- [ ] All queries execute without errors
- [ ] Results contain expected columns
- [ ] Row counts are reasonable (not 0, not millions)
- [ ] Ground truth labels preserved in results

**Scoring quality:**
- [ ] Total score is between 0.0 and 1.0
- [ ] Risk level assigned correctly
- [ ] All signals have scores

**Report quality:**
- [ ] REPORT.md generated successfully
- [ ] Executive summary present
- [ ] Signal breakdown shows all queries
- [ ] Precision/recall metrics calculated

---

## Conventions & Best Practices

### File Organization

**Gitignored:**
- `datasets/output*/` (synthetic data)
- `artifacts/*.duckdb` (database files)
- `case_studies/*/artifacts/` (CSV artifacts)
- `case_studies/*/findings.json`
- `case_studies/*/scoring.json`
- `case_studies/*/REPORT.md`

**Tracked:**
- All source code (python/, sql/)
- All configs (configs/)
- Case study READMEs (case_studies/*/README.md)
- Documentation (docs/, README.md)

### Naming Conventions

**Python files:**
- `generate_*.py`: Data generators
- `run_queries.py`: Query executor
- `scoring.py`: Signal scoring
- `render_report.py`: Report generation

**SQL files:**
- Pattern: `XXXX_NN_descriptive_name.sql`
- Use underscores, not hyphens
- Keep names concise but clear

**Config files:**
- Pattern: `caseXXXX.yaml`
- No hyphens in case IDs (use case0001, not case-0001)

**Directories:**
- Use hyphens for multi-word names
- Example: `CASE-0001-coordinated-influence`

### Code Style

**Python:**
- Follow PEP 8
- Type hints where helpful
- Docstrings for functions
- Comments explaining "why," not "what"

**SQL:**
- CTEs for readability (WITH clauses)
- Comments at query start explaining purpose
- Consistent indentation (4 spaces)
- Uppercase SQL keywords

---

## Known Issues & Gotchas

### Two-Phase Generation

**Issue:** Some cases require base data before specialized events

**Solution:** Always generate base data first:
```bash
python python/generate_dataset.py --config configs/caseXXXX.yaml --out datasets/output_caseXXXX
python python/generate_XXXX_events.py --config configs/caseXXXX.yaml --data datasets/output_caseXXXX
```

### SQL Path Changes

**Issue:** CASE-0001 queries moved to `sql/case0001/` for consistency

**Solution:** Always specify `--sql` parameter:
```bash
python python/run_queries.py --sql sql/case0001 ...
```

### DuckDB Locking

**Issue:** Multiple processes can't write to same DuckDB file

**Solution:** Use separate DuckDB files per case:
- `artifacts/ai_abuse.duckdb` (CASE-0001)
- `artifacts/ai_abuse_case0002.duckdb` (CASE-0002)
- etc.

### Ground Truth Propagation

**Issue:** Ground truth labels must survive all joins

**Solution:** Always use `MAX(is_malicious)` in GROUP BY queries:
```sql
GROUP BY account_id
HAVING MAX(is_malicious) = true  -- Preserve ground truth
```

### Parquet Type Inference

**Issue:** DuckDB may infer wrong types from Parquet

**Solution:** Cast explicitly when needed:
```sql
CAST(field AS INTEGER)
field::BIGINT
```

---

## Quick Reference

### Common Tasks

**Add a new case study:**
1. Create config: `configs/caseXXXX.yaml`
2. Create generator: `python/generate_XXXX_events.py`
3. Create SQL directory: `sql/caseXXXX/`
4. Create case directory: `case_studies/CASE-XXXX-name/`
5. Add scoring logic to `python/scoring.py`
6. Update main README

**Run a complete investigation:**
```bash
# 1. Generate data
python python/generate_dataset.py --config configs/case0001.yaml

# 2. Run queries
python python/run_queries.py \
  --duckdb artifacts/ai_abuse.duckdb \
  --data datasets/output \
  --sql sql/case0001 \
  --case-dir case_studies/CASE-0001-coordinated-influence \
  --strict

# 3. Score
python python/scoring.py --case-dir case_studies/CASE-0001-coordinated-influence

# 4. Report
python python/render_report.py --case-dir case_studies/CASE-0001-coordinated-influence
```

**Inspect generated data:**
```bash
# Row counts
python -c "import pandas as pd; print(pd.read_parquet('datasets/output/accounts.parquet').shape)"

# Schema
python -c "import pandas as pd; print(pd.read_parquet('datasets/output/accounts.parquet').dtypes)"

# Sample rows
python -c "import pandas as pd; print(pd.read_parquet('datasets/output/accounts.parquet').head())"
```

**Test a single query:**
```bash
duckdb artifacts/ai_abuse.duckdb < sql/case0001/01_first_seen_hosting_asn.sql
```

---

## Future Roadmap

### Planned Case Studies

**CASE-0005: Prompt Injection Detection at Scale**
- Systematic jailbreak attempt detection
- Injection pattern recognition (template matching, obfuscation techniques)
- Success indicator correlation (model outputs sensitive data)
- Volume-based abuse detection (same user, many variations)
- **Rationale:** LLM-specific threat vector, highest relevance to AI companies

**CASE-0006: API Abuse & Rate Limit Evasion**
- Token rotation pattern detection
- Distributed request analysis (same user, many sources)
- Just-under-threshold behavior
- Time-window manipulation
- **Rationale:** Platform economics, resource exhaustion attacks

**CASE-0007: Data Exfiltration via AI Platforms**
- Large document upload anomalies
- Sensitive data pattern detection (PII, credentials, financial)
- Structured data processing requests (SQL dumps, CSV parsing)
- Post-processing export patterns
- **Rationale:** Novel threat vector, liability/regulatory concern

**CASE-0008: Supply Chain Compromise Detection**
- Malicious package/dependency detection
- Poisoned model checkpoint identification
- Training data poisoning indicators
- Dependency confusion attacks
- **Rationale:** Systemic risk, affects entire AI ecosystem

### Enhancement Ideas

**Practitioner-focused improvements:**
- [ ] Parameterized query templates (user fills in their table names)
- [ ] IOC extraction scripts (pull IOCs from investigation results)
- [ ] Report templates (executive summaries, technical appendices)
- [ ] Validation framework (test queries against user's own data)

**Evaluation framework:**
- [ ] Automated precision/recall calculation
- [ ] ROC curve generation
- [ ] Cost-benefit analysis (alert volume vs. detection rate)
- [ ] Baseline drift detection

**Integration & tooling:**
- [ ] SIEM export adapters (QRadar, Splunk, Sentinel)
- [ ] API clients for common platforms
- [ ] Real-time detection mode (vs. batch investigation)

---

## Contributing

### Code Contributions

1. Create a branch: `git checkout -b feature/case-XXXX`
2. Add/modify code with clear, minimal diffs
3. Run full pipeline for affected case(s)
4. Open PR with:
   - What changed
   - How to reproduce
   - Expected outputs

### Style Guidelines

- Keep logic explainable and deterministic
- Favor small, reviewable commits
- Document "why" in comments, not "what"
- Update PROJECT_CONTEXT.md for significant changes

---

## License

MIT License

---

## Contact & Support

- **GitHub:** threat-hunting-lab
- **Repository:** ai-platform-abuse-investigations
- **Issues:** Use GitHub issues for bugs and feature requests

---

## Changelog

**2025-01-21:**
- Added CASE-0004 (K8s resource hijacking)
- Created PROJECT_CONTEXT.md
- Standardized SQL directory structure

**2025-01-12:**
- Added CASE-0003 (DNS triage)
- Improved evaluation framework

**2025-01-08:**
- Added CASE-0002 (Account takeover)
- Two-phase generation pattern established

**2025-01-01:**
- Initial release with CASE-0001 (Coordinated influence)

---

*Last Updated: 2025-01-21*
*Document Version: 1.0*
*Total Lines: ~1150*
