# ai-platform-abuse-investigations

Case-driven **SQL + Python** investigations of coordinated abuse and AI platform misuse — built on **synthetic, privacy-safe telemetry** with **reproducible artifacts** and **intel-style reporting**.

This repo demonstrates an end-to-end workflow:

1. Generate synthetic telemetry (Parquet tables)
2. Load into DuckDB + run an investigation SQL pack
3. Export evidence artifacts (CSVs) + a machine-readable findings summary
4. Score signals deterministically (reviewable heuristics)
5. Render a human-readable report (REPORT.md)

---

## What's inside

### Case Studies

**CASE-0001 — Coordinated Influence (Synthetic)**
- Multi-language coordinated activity across many orgs/tenants
- Shared hosting/VPN provider buckets + synchronized bursts
- Template/content similarity (`template_hash`, `content_cluster_id`)
- Enforcement funnel (warn → throttle → block) at both infra + account levels
- Reproducible SQL queries + exported artifacts + investigation report

**CASE-0002 — Account Takeover & Identity Abuse (Synthetic)**
- Credential stuffing → compromise → persistence → abuse chain detection
- Failed login bursts + success from new ASN correlation
- MFA device manipulation + mailbox rule abuse
- OAuth consent grants to malicious apps
- Temporal attack chain analysis with ~24 compromised accounts per investigation

**CASE-0003 — Suspicious DNS + Redirect Chains (Synthetic)**
- DNS triage with explainable heuristics (suspicious TLD, keyword hit, entropy, rarity)
- Redirect chain analysis via synthetic parent→child domain transitions
- Pre-computed risk scores for SQL-friendly detection
- Empirical evaluation with precision/recall against synthetic ground truth
- Exposed account tracking across suspicious domain lookups

**CASE-OSINT-0001 — CVE-2025-12420 (BodySnatcher / ServiceNow agentic AI auth weakness)**
- OSINT-to-hunting translation: affected/fixed versions, ATT&CK mapping
- Behavior-based detection (user creation + role grants correlated to Virtual Agent sessions)
- Intel report summarizing trust-boundary failure patterns
- No synthetic data - pure OSINT/threat intel case study


### Core Deliverables

- **DuckDB SQL investigation packs** (`sql/`) - Case-specific detection queries (CASE-0001: 11 queries, CASE-0002: 8 queries, CASE-0003: 5 queries)
- **Synthetic telemetry generator** (`python/generate_dataset.py`) - Configurable data generation
- **Report builder** (`python/render_report.py`) - Human-readable investigation reports
- **Deterministic scoring** (`python/scoring.py`) - Explainable signal weights and rationales
- **Methodology docs** (`docs/`) - Confidence rubric and investigation playbooks

---

## Workflow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Investigation Pipeline                          │
└─────────────────────────────────────────────────────────────────────────┘

   1. CONFIGURE                    2. GENERATE DATA
   ┌──────────────┐               ┌──────────────────┐
   │ case0001.yaml│──────────────▶│ Synthetic Parquet│
   │              │               │ (1M rows)        │
   │ • Time window│               │ datasets/output/ │
   │ • Campaign mix│               └────────┬─────────┘
   │ • Infra bias │                        │
   │ • Row counts │                        │
   └──────────────┘                        │
                                           │
   3. LOAD + QUERY                         ▼
   ┌──────────────────────────────────────────────┐
   │     DuckDB + SQL Pack (CASE-0001: 11 queries)│
   │  ┌────────────────────────────────────────┐  │
   │  │ sql/case0001/                          │  │
   │  │ • 01_first_seen_hosting_asn.sql        │  │
   │  │ • 02_pct_hosting_vpn_by_account.sql    │  │
   │  │ • 03_tenant_diversity_by_asn.sql       │  │
   │  │ • 04_device_reuse.sql                  │  │
   │  │ • 05_burst_detection_asn.sql           │  │
   │  │ • 06_sync_org_spikes.sql               │  │
   │  │ • 07_template_reuse.sql                │  │
   │  │ • 08_content_cluster_spread.sql        │  │
   │  │ • 09_policy_funnel_by_provider.sql     │  │
   │  │ • 10_cluster_keys.sql                  │  │
   │  │ • 11_rate_limit_summary.sql            │  │
   │  └────────────────────────────────────────┘  │
   └──────────────┬───────────────────────────────┘
                  │
                  ▼
   4. EXPORT ARTIFACTS            5. SCORE SIGNALS
   ┌──────────────────┐          ┌──────────────────┐
   │ artifacts/*.csv  │─────────▶│ scoring.json     │
   │                  │          │                  │
   │ • Evidence rows  │          │ • Risk score     │
   │ • Per-signal CSVs│          │ • Signal weights │
   │                  │          │ • Rationales     │
   └────────┬─────────┘          └────────┬─────────┘
            │                             │
            │        6. RENDER REPORT     │
            │       ┌─────────────────┐   │
            └──────▶│   REPORT.md     │◀──┘
                    │                 │
                    │ • Executive     │
                    │   summary       │
                    │ • Signal        │
                    │   breakdown     │
                    │ • Evidence      │
                    │   highlights    │
                    └─────────────────┘
```

**Key Features:**
- **Reproducible investigations** from config → findings → report
- **Privacy-safe** synthetic telemetry (no real identifiers)
- **Deterministic scoring** with explainable signal weights
- **Evidence artifacts** for peer review and audit trails
- **Laptop-scale** analysis (1M+ rows in seconds with DuckDB)

---

## Why this exists

Security / Trust & Safety teams at AI platforms often need to:

- Detect coordinated behavior (shared infra, synchronized bursts, cross-tenant patterns)
- Build explainable abuse signals from telemetry at scale
- Produce reports with calibrated confidence language
- Stay robust under partial / noisy telemetry (synthetic-first, reproducible workflows)

---

## Repo layout

```
.
├── configs/
│   ├── case0001.yaml                          # CASE-0001 configuration
│   ├── case0002.yaml                          # CASE-0002 configuration
│   └── case0003.yaml                          # CASE-0003 configuration
├── datasets/
│   ├── output/                                # Generated Parquet tables (gitignored)
│   ├── output_case0002/                       # CASE-0002 datasets (gitignored)
│   ├── output_case0003/                       # CASE-0003 datasets (gitignored)
│   └── schema.md                              # Dataset schema documentation
├── docs/                                      # Methodology and confidence rubric documentation
├── sql/                                       # Investigation queries (DuckDB SQL)
│   ├── case0001/                              # CASE-0001: Coordinated influence (11 queries)
│   │   ├── 01_first_seen_hosting_asn.sql
│   │   ├── 02_pct_hosting_vpn_by_account.sql
│   │   ├── 03_tenant_diversity_by_asn.sql
│   │   ├── 04_device_reuse.sql
│   │   ├── 05_burst_detection_asn.sql
│   │   ├── 06_sync_org_spikes.sql
│   │   ├── 07_template_reuse.sql
│   │   ├── 08_content_cluster_spread.sql
│   │   ├── 09_policy_funnel_by_provider.sql
│   │   ├── 10_cluster_keys.sql
│   │   └── 11_rate_limit_summary.sql
│   ├── case0002/                              # CASE-0002: ATO & identity abuse (8 queries)
│   └── case0003/                              # CASE-0003: DNS triage (5 queries)
│       ├── 0003_01_top_suspicious_domains.sql
│       ├── 0003_02_domain_chain_clusters.sql
│       ├── 0003_03_exposed_accounts.sql
│       ├── 0003_04_heuristic_breakdown.sql
│       └── 0003_99_rollup.sql
├── python/
│   ├── generate_dataset.py                    # Synthetic data generator (base tables)
│   ├── generate_identity_events.py            # Identity events generator (CASE-0002)
│   ├── generate_dns_events.py                 # DNS events generator (CASE-0003)
│   ├── run_queries.py                         # Runs SQL pack, exports artifacts, writes findings.json
│   ├── scoring.py                             # Deterministic signal scoring, writes scoring.json
│   └── render_report.py                       # Renders REPORT.md from findings + scoring
├── case_studies/
│   ├── CASE-0001-coordinated-influence/
│   │   ├── README.md                          # Case overview (tracked)
│   │   ├── artifacts/                         # Generated CSVs (gitignored)
│   │   │   ├── 01_first_seen_hosting_asn.csv
│   │   │   ├── 02_pct_hosting_vpn_by_account.csv
│   │   │   └── ... (11 CSV files total)
│   │   ├── findings.json                      # Investigation findings (generated, gitignored)
│   │   ├── scoring.json                       # Signal scores (generated, gitignored)
│   │   └── REPORT.md                          # Human-readable report (generated, gitignored)
│   ├── CASE-0002-ato-identity-abuse/
│   │   ├── README.md                          # Case overview (tracked)
│   │   ├── artifacts/                         # Generated CSVs (8 files, gitignored)
│   │   ├── findings.json                      # Generated, gitignored
│   │   ├── scoring.json                       # Generated, gitignored
│   │   └── REPORT.md                          # Generated, gitignored
│   └── CASE-0003-dns-triage/
│       ├── README.md                          # Case overview (tracked)
│       ├── artifacts/                         # Generated CSVs (5 files, gitignored)
│       ├── findings.json                      # Generated, gitignored
│       ├── scoring.json                       # Generated, gitignored
│       └── REPORT.md                          # Generated, gitignored
├── Makefile                                   # Build automation
├── requirements.txt                           # Python dependencies
└── README.md                                  # This file
```

---

## Install

**Requirements:** Python 3.10+ (tested on Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Or using Make:**
```bash
make install
```

> **Note:** `pandas` + `numpy` are used by the DuckDB → DataFrame export path in `run_queries.py`.

> **SQL Directory Change (2026-01-20):** CASE-0001 queries moved to `sql/case0001/` for consistency with CASE-0002. When running queries, use `--sql sql/case0001` for CASE-0001 or `--sql sql/case0002` for CASE-0002. The `--sql` parameter is now required.

---

## Quickstart (recommended)

> **Windows note:** `make` requires GNU Make (WSL, Git Bash, or MSYS2). If you don't have GNU Make, use the PowerShell commands below (this is the default path).

**Run the complete pipeline with Make (optional):**
```bash
make all
# This runs: gen → queries → score → report (default: 1M rows)
```

**Or run steps individually with PowerShell (recommended for Windows):**

> **Note:** Only `generate_dataset.py` supports `--config`. The other scripts (`run_queries.py`, `scoring.py`, `render_report.py`) use explicit CLI arguments.

```powershell
# Set variables first
$CASEDIR = ".\case_studies\CASE-0001-coordinated-influence"
$SQLDIR  = ".\sql\case0001"
$DATA    = ".\datasets\output"
$DUCKDB  = ".\ai_abuse.duckdb"

# Run pipeline
python .\python\generate_dataset.py --config .\configs\case0001.yaml

python .\python\run_queries.py --duckdb $DUCKDB --data $DATA --sql $SQLDIR --case-dir $CASEDIR --strict

python .\python\scoring.py --case-dir $CASEDIR

python .\python\render_report.py --case-dir $CASEDIR
```

**Expected outputs:**
- `ai_abuse.duckdb` (DuckDB database; generated, gitignored)
- `case_studies/CASE-0001-coordinated-influence/artifacts/*.csv` (11 CSV files; generated, gitignored)
- `case_studies/CASE-0001-coordinated-influence/findings.json` (generated, gitignored)
- `case_studies/CASE-0001-coordinated-influence/scoring.json` (generated, gitignored)
- `case_studies/CASE-0001-coordinated-influence/REPORT.md` (generated, gitignored)

**Sanity check (verify outputs were created):**
```powershell
Test-Path ".\ai_abuse.duckdb"
Test-Path "$CASEDIR\findings.json"
Test-Path "$CASEDIR\scoring.json"
Test-Path "$CASEDIR\REPORT.md"
```

---

**Individual step details:**

### 1) Generate synthetic dataset

```powershell
python .\python\generate_dataset.py --config .\configs\case0001.yaml
# Or with custom row count:
python .\python\generate_dataset.py --config .\configs\case0001.yaml --out .\datasets\output --rows 100000
```

### 2) Run SQL investigation pack

```powershell
python .\python\run_queries.py --duckdb $DUCKDB --data $DATA --sql $SQLDIR --case-dir $CASEDIR --strict
```

### 3) Score signals

```powershell
python .\python\scoring.py --case-dir $CASEDIR
```

### 4) Render report

```powershell
python .\python\render_report.py --case-dir $CASEDIR
```

---

### CASE-0002 Quickstart

**Generate dataset + identity events:**
```powershell
# Use helper script for two-phase generation
.\scripts\gen_case.ps1 -Config "configs\case0002.yaml" -OutDir "datasets\output_case0002" -Clean
```

**Run ATO detection pipeline:**
```powershell
# Set variables
$CASEDIR = ".\case_studies\CASE-0002-ato-identity-abuse"
$SQLDIR  = ".\sql\case0002"
$DATA    = ".\datasets\output_case0002"
$DUCKDB  = ".\ai_abuse_case0002.duckdb"

# Run queries
python .\python\run_queries.py --duckdb $DUCKDB --data $DATA --sql $SQLDIR --case-dir $CASEDIR --strict

# Score and report
python .\python\scoring.py --case-dir $CASEDIR
python .\python\render_report.py --case-dir $CASEDIR
```

**Expected outputs:**
- `ai_abuse_case0002.duckdb` (DuckDB database)
- `datasets/output_case0002/identity_events.parquet` (ATO attack chains)
- `case_studies/CASE-0002-ato-identity-abuse/artifacts/*.csv` (8 CSV files)
- `case_studies/CASE-0002-ato-identity-abuse/findings.json`
- `case_studies/CASE-0002-ato-identity-abuse/scoring.json`
- `case_studies/CASE-0002-ato-identity-abuse/REPORT.md`

---

### CASE-0003 Quickstart

**Generate dataset + DNS events:**
```powershell
# Step 1: Generate base dataset (accounts, orgs, devices, enrichment_ip)
python .\python\generate_dataset.py --config .\configs\case0003.yaml --out .\datasets\output_case0003

# Step 2: Generate DNS events (requires base dataset from Step 1)
python .\python\generate_dns_events.py --config .\configs\case0003.yaml --data .\datasets\output_case0003
```

**Run DNS triage detection pipeline:**
```powershell
# Create artifacts directory
mkdir .\artifacts -Force | Out-Null

# Set variables
$CASEDIR = ".\case_studies\CASE-0003-dns-triage"
$SQLDIR  = ".\sql\case0003"
$DATA    = ".\datasets\output_case0003"
$DUCKDB  = ".\artifacts\ai_abuse_case0003.duckdb"

# Run queries
python .\python\run_queries.py --duckdb $DUCKDB --data $DATA --sql $SQLDIR --case-dir $CASEDIR --strict

# Score and report
python .\python\scoring.py --case-dir $CASEDIR
python .\python\render_report.py --case-dir $CASEDIR
```

**Expected outputs:**
- `artifacts/ai_abuse_case0003.duckdb` (DuckDB database)
- `datasets/output_case0003/dns_events.parquet` (~2-3M DNS events)
- `case_studies/CASE-0003-dns-triage/artifacts/*.csv` (5 CSV files)
- `case_studies/CASE-0003-dns-triage/findings.json`
- `case_studies/CASE-0003-dns-triage/scoring.json`
- `case_studies/CASE-0003-dns-triage/REPORT.md`

---

### Makefile Shortcuts

Run the entire pipeline in one command:
```bash
make all              # Run gen → queries → score → report (default: 1M rows)
```

Override variables (examples for future cases):
```bash
make all ROWS=100000                                            # Custom row count
make gen CONFIG=configs/case0002.yaml                           # Different config (when CASE-0002 exists)
make queries CASE_DIR=case_studies/CASE-0002-ato-identity-abuse # Different case (when CASE-0002 exists)
make queries SQL_DIR=sql/case0002                               # Different SQL directory (if case-specific queries exist)
```

Clean up generated files:
```bash
make clean         # Remove all outputs (dataset + duckdb + case artifacts)
make clean_db      # Remove only DuckDB file
make clean_case    # Remove only case study outputs
```

View all available targets:
```bash
make help
```

---

## What to look for in CASE-0001 (Coordinated Influence)

Indicators of coordination that should emerge when multiple signals align:

- **Cross-tenant diversity on shared infrastructure**
- **Hosting/VPN provider concentration**
- **Synchronized bursts** (narrow time-window spikes)
- **Similarity** (template reuse + content cluster alignment)
- **Policy funnel concentration** (warn → throttle → block around the same infra/similarity clusters)

---

## What to look for in CASE-0002 (Account Takeover)

Attack chain indicators that emerge when ATO succeeds:

- **Failed login bursts** (6+ failures in 10-minute windows from credential stuffing/spraying)
- **New ASN success** (successful authentication from new infrastructure immediately after failures)
- **MFA manipulation** (device enrollment immediately after compromise)
- **Persistence actions** (mailbox rules for data exfiltration, OAuth grants to malicious apps)
- **Temporal correlation** (full attack chain completing within 24-48 hours)
- **Compromised account concentration** (~24 accounts with complete ATO chains in the investigation)

---

## What to look for in CASE-0003 (DNS Triage)

Malicious DNS patterns that emerge from heuristic analysis:

- **High-risk domains** (score ≥ 5: multiple heuristics triggered simultaneously)
- **Redirect chains** (parent domain → child domain transitions with escalating risk scores)
- **Account exposure** (accounts touching 5+ distinct suspicious domains)
- **Empirical metrics** (precision/recall against synthetic ground truth for detection quality validation)
- **Heuristic breakdown** (which detection rules fire most often, score distribution analysis)

---

## Design Decisions

### Why synthetic-first?

**Privacy compliance by default**
- No real user data, organization names, or platform identifiers
- Safe to share in interviews, portfolios, and public repositories
- Eliminates GDPR/CCPA/data handling concerns

**Reproducible ground truth for validation**
- Config defines exactly what patterns exist (your "dial")
- Enables testing detection logic against known coordination campaigns
- Supports retrospective analysis: "Did our queries catch what we planted?"
- Makes debugging false negatives tractable

**Operational robustness testing**
- Tune signal-to-noise ratios in config
- Test partial telemetry scenarios (e.g., 50% missing data)
- Simulate different abuse patterns without waiting for real incidents

### Why deterministic scoring before ML?

**Reviewable heuristics build trust**
- Each signal has explicit weight, rationale, and evidence trail
- Analysts can audit why a score changed
- Easier to explain to policy/legal teams than black-box models

**Faster iteration on detection logic**
- Change SQL query → re-run scoring → see impact immediately
- No training data collection or model retraining cycles
- SQL is more accessible to security analysts than ML pipelines

**Model-in-the-loop comes after signal quality is proven**
- Use LLMs for summarization, not primary detection
- Embeddings for content clustering (already referenced in template reuse)
- But only after failure modes are characterized with synthetic ground truth

### Why DuckDB + Parquet?

**Scales to laptop-sized investigations**
- Handles 1M–10M+ row datasets in seconds
- No Spark cluster or cloud warehouse required
- Fast iteration during threat hunting research

**Portable and reproducible**
- Single `.duckdb` file contains entire investigation state
- Parquet files are columnar, compressed, and widely supported
- Easy to version control the investigation logic (SQL + config)

### Why artifact-first export strategy?

**Enables peer review and handoffs**
- Every signal exports a CSV with top evidence rows
- Analysts can review raw data without re-running queries
- Case files are self-contained (artifacts + findings + report)

**Supports iterative refinement**
- Export artifacts → review manually → tune scoring weights
- No need to re-query database for every scoring change
- Artifacts become regression test suite for future query changes

### Why YAML configs over hardcoded values?

**Scenarios as code**
- Each case is a documented hypothesis about abuse patterns
- Config serves as "threat model specification"
- Easy to create case variants (CASE-0002, CASE-0003) for comparison

**Interview-friendly demonstrations**
- Modify config → re-run pipeline → show detection impact
- Explains your thought process: "Here's what I expected to find"
- Makes the "planted ground truth" concept tangible

---

## Extending the repo

To add a new case:

1. Create a new YAML config in `configs/` (e.g., `case0003.yaml`)
2. Run `python\generate_dataset.py` with your config to generate data to `datasets/output/`
3. Add/modify SQL queries in `sql/` for new detection patterns
4. Add scoring rules in `python/scoring.py` for the new signals
5. Create a case directory in `case_studies/` (e.g., `CASE-0003-...`)
6. Re-run pipeline to generate `REPORT.md`

**Implemented Cases:**
- **CASE-0001**: Coordinated influence campaigns (synthetic)
- **CASE-0002**: Account takeover & identity abuse (synthetic)
- **CASE-0003**: DNS triage + redirect chains (synthetic)
- **CASE-OSINT-0001**: CVE threat intelligence (ServiceNow)

**Future Case Ideas:**
- Cross-platform campaign tracking
- API abuse & rate limit evasion
- Synthetic media manipulation campaigns
- Supply chain compromise detection
- DNS exposure → ATO correlation (CASE-0003 + CASE-0002 integration)

Each case demonstrates different abuse patterns and detection methodologies.

---

## Safety / OPSEC

- ✅ All telemetry is **synthetic** (no real orgs, users, platforms, or identifiers)
- ✅ Outputs are **reproducible** from config + code
- ✅ Generated artifacts and datasets are **gitignored** by default

---

## License

MIT

## Contributing

Thanks for your interest.

**Scope:**
- Additive changes are preferred (new cases, new SQL packs, new configs)
- Avoid breaking existing cases; keep pipelines reproducible

**How to contribute:**
1. Create a branch
2. Add/modify code with clear, minimal diffs
3. Run the full pipeline for the affected case(s)
4. Open a PR with:
   - what changed
   - how to reproduce
   - expected outputs

**Style:**
- Keep logic explainable and deterministic
- Favor small, reviewable commits
