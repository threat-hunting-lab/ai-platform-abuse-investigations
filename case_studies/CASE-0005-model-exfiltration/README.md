# CASE-0005: Model Weight Exfiltration via Insider Access

## Threat Model

An AI company's most valuable intellectual property is its model weights, training configurations, and research findings. Unlike traditional IP theft (source code, customer data), model weight exfiltration has unique characteristics:

- **File sizes are massive** — frontier model weights can be hundreds of GBs, making exfiltration noisy if you know what to look for
- **Access is legitimate** — researchers and engineers *need* access to model repos, so simple access controls alone are insufficient
- **Motivation is high** — competitors, nation-states, and departing employees have strong incentives to acquire model weights
- **Detection window is narrow** — once weights leave the network, the damage is done

This case study models three independent insider threat campaigns where employees with legitimate access systematically exfiltrate proprietary AI assets prior to departure.

## Attack Campaigns

### Campaign Alpha — Senior Frontier Researcher
A senior researcher on the frontier model team has accepted a position at a competing AI lab. Over 3 weeks, they systematically:
1. **Recon (Nov 5–11):** Browse repos outside their normal scope, exploring training configs and safety evals
2. **Escalation (Nov 12–17):** Begin downloading model weight shards during off-hours
3. **Staging (Nov 18–24):** Upload model weights and configs to personal Google Drive/Dropbox
4. **Final exfil (Nov 25):** Bulk download of remaining model artifacts before last day
5. **Departure (Nov 27)**

### Campaign Beta — Applied ML Engineer
An applied ML engineer copies fine-tuning recipes, evaluation datasets, and applied model artifacts.
- Shorter recon phase, focused on configs and eval data rather than raw weights
- Uses personal cloud storage for staging
- Departure Nov 28

### Campaign Gamma — Safety Team Member
A safety team member exfiltrates alignment research, RLHF configurations, and safety evaluation benchmarks.
- Slower, more methodical approach
- Focuses on research notebooks and alignment-specific data
- Departure Nov 30

## Detection Approach

### Signal 1: First-Time Access to Sensitive Repos (`0005_01`)
Track when employees access high/critical sensitivity repositories for the first time. A sudden spike in new-repo access correlates with the reconnaissance phase.

### Signal 2: Off-Hours Model Access (`0005_02`)
Monitor the ratio of off-hours to business-hours access for sensitive repos. Insiders often shift to off-hours activity to avoid observation.

### Signal 3: Download Volume Anomaly (`0005_03`)
Establish per-employee download volume baselines and detect spikes using z-score analysis. A researcher who normally downloads <1 GB/day suddenly pulling 50+ GB is a strong signal.

### Signal 4: Repository Breadth Anomaly (`0005_04`)
Track the number of distinct repos each employee accesses per week vs. their baseline. A sudden broadening of access scope indicates "shopping" behavior.

### Signal 5: Personal Cloud Staging (`0005_05`)
Detect uploads to personal cloud storage (Google Drive, Dropbox, OneDrive, etc.), with special attention to model weight file extensions (.safetensors, .pt, .ckpt, .bin).

### Signal 6: Correlated Exfiltration Chain (`0005_06`)
Combine all five signals into a composite risk score. Employees who trigger multiple independent signals simultaneously represent high-confidence insider threat detections.

### Rollup: Attack Chain Summary (`0005_99`)
Reconstruct the full timeline of each confirmed exfiltration campaign with evidence inventory.

## Evaluation

This case includes ground truth labels for all telemetry:
- `is_malicious` flag on all events
- `campaign_id` groups related malicious activity

**Expected outcomes:**
- **Precision:** >90% for correlated signal query (0005_06) at `critical` risk level
- **Recall:** >95% for all three campaigns detected by at least one signal
- **Time to detection:** Anomalies detectable within 48 hours of escalation phase start

**Evaluation questions:**
1. Does the correlated query (0005_06) catch all 3 campaigns?
2. Which individual signal has the highest standalone precision?
3. What is the false positive rate for volume anomaly (0005_03) in isolation?
4. Does personal cloud staging (0005_05) have near-perfect precision?
5. How early in the campaign timeline can we detect with ≥ medium confidence?

## Relevance to AI Platform Security

This case study directly addresses the insider threat detection challenges facing AI companies:

1. **Model weights are the crown jewels** — unlike source code, model weights represent billions of dollars in compute investment and are the primary competitive advantage
2. **Legitimate access is required** — researchers need these repos, so detection must focus on behavioral anomalies rather than simple access controls
3. **The attack surface is novel** — traditional DLP tools don't understand .safetensors or model sharding; custom detections are required
4. **Cross-functional response is essential** — investigations require coordination with HR (departure timelines), Legal (IP protection), and Security (evidence preservation)
5. **AI can detect AI theft** — the same ML techniques used to build models can be applied to detect anomalous access patterns to those models

## Synthetic Data

All telemetry is generated from `configs/case0005.yaml`:

| Table | Rows | Description |
|-------|------|-------------|
| `model_repo_access.parquet` | ~150K | Repository access events (clone, pull, download, browse) |
| `file_transfers.parquet` | ~80K | File download/upload events with sizes and destinations |
| `auth_sessions.parquet` | ~50K | Authentication sessions with timing and location |

## Usage

```bash
# Generate synthetic data
python python/generate_model_exfil.py --config configs/case0005.yaml --out datasets/output_case0005

# Run detection queries
python python/run_queries.py \
  --duckdb artifacts/ai_abuse_case0005.duckdb \
  --data datasets/output_case0005 \
  --sql sql/case0005 \
  --case-dir case_studies/CASE-0005-model-exfiltration \
  --strict

# Score and report
python python/scoring.py --case-dir case_studies/CASE-0005-model-exfiltration
python python/render_report.py --case-dir case_studies/CASE-0005-model-exfiltration
```

## Production Telemetry Mapping

The synthetic tables in this case study are abstractions of real cloud-native log sources. In a production AWS/K8s environment:

| Synthetic Table | Production Log Sources | Key Fields |
|----------------|----------------------|------------|
| `model_repo_access.parquet` | K8s Audit Logs (API server) + eBPF runtime telemetry (Falco/Tetragon) | `objectRef.resource`, `user.username`, `sourceIPs`, `verb`, `proc.name` |
| `file_transfers.parquet` | AWS CloudTrail `PutObject`/`GetObject` data events + VPC Flow Logs (byte counts + destination IPs) | `userIdentity`, `requestParameters.bucketName`, `bytes`, `dstaddr` |
| `auth_sessions.parquet` | Identity Provider logs (Okta/Entra ID) + Teleport session recordings | `actor.displayName`, `eventType`, `client.ipAddress`, `authenticationContext` |

**Why this matters:** Standard user-space EDR can be disabled by a root-level insider. eBPF-based tools (Tetragon, Falco) operate at the Linux kernel layer, providing immutable syscall visibility even when the insider has root access — critical for monitoring researchers on training nodes. CloudTrail data events provide an authoritative ledger of every S3 API call, while VPC Flow Logs quantify exact egress volumes leaving the training subnet.

The detection logic in `0005_06_correlated_exfil_chain.sql` would translate to a **stateful detection rule** in production: Event A (first-time sensitive repo access) transitions to a watched state; if Event B (volume anomaly) and Event C (personal cloud upload to a non-corporate AWS Account ID) occur within a 72-hour window on the same `user_id`, the rule fires at Critical severity.

## Future Extensions

- **Temporal correlation with HR signals** — Integrate resignation dates, PIP notifications, and performance review timelines as contextual enrichment
- **Network flow analysis** — Detect large egress transfers to non-corporate destinations at the network layer
- **Endpoint detection** — USB device connections, screen capture tools, print events
- **Behavioral biometrics** — Keystroke/mouse pattern changes indicating account sharing or stress
- **Model fingerprinting** — Detect if exfiltrated weights appear in competitor products (post-incident)
