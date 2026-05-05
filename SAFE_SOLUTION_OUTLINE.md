# SurrKarr Safe Solution Outline

## Scope

SurrKarr should be positioned as a **defensive vulnerability management platform** for **authorized assets only**. It can safely support:

- Active and passive discovery for approved targets
- Ingestion of results from tools such as Nmap, Nessus, OpenVAS, Nikto, and Nuclei
- Normalized vulnerability reporting with CVE, CVSS, EPSS, affected component, and evidence
- Threat-intelligence enrichment from authoritative sources
- Risk-path analysis that explains how findings combine into business risk
- Natural-language querying for remediation, prioritization, and report interpretation

It should **not** generate exploit instructions, attack commands, or operate as an unrestricted offensive assistant.

## Recommended Architecture

### 1. Frontend

- Keep the current Streamlit prototype for the MVP dashboard
- Long term, move to a React frontend if you need richer multi-user workflows
- Core views:
  - Target registration and scan authorization
  - Scan orchestration and live job status
  - Findings explorer with filters and evidence
  - Risk-path graph and remediation queue
  - Chat interface with citations

### 2. Backend Services

- `API layer`: FastAPI for authentication, scan jobs, findings, chat, and reporting
- `Worker layer`: background jobs for scanner execution, parsing, enrichment, and report generation
- `Storage`:
  - PostgreSQL for users, assets, scans, findings, remediations, audit logs
  - Object storage for raw scan artifacts
  - Vector store for RAG documents and finding summaries
- `Realtime`: WebSocket or SSE updates for scan progress and chat status

### 3. Scanner Integration

Use an adapter pattern:

- `NmapAdapter`
- `NessusAdapter`
- `OpenVASAdapter`
- `NiktoAdapter`
- `NucleiAdapter`

Each adapter should implement:

- `start_scan(target, profile)`
- `poll_status(job_id)`
- `fetch_artifact(job_id)`
- `parse_artifact(artifact_path)`

For scanners that are usually managed externally, prefer API or file-ingestion mode over tightly coupling the platform to local CLI execution.

## Normalized Data Model

Each finding should map into one schema:

- `finding_id`
- `asset_id`
- `scan_id`
- `source_tool`
- `host`
- `port`
- `protocol`
- `service`
- `url`
- `title`
- `description`
- `evidence`
- `cve_ids[]`
- `cvss_base`
- `cvss_vector`
- `epss_score`
- `severity`
- `affected_component`
- `references[]`
- `first_seen`
- `last_seen`
- `status`

Supporting entities:

- `Asset`
- `ScanJob`
- `Finding`
- `ThreatIntel`
- `RemediationTask`
- `User`
- `AuditLog`

## Threat Intelligence Enrichment

Enrich findings with:

- NVD for canonical CVE descriptions and CVSS details
- CISA KEV for known-exploited prioritization
- EPSS for exploitation likelihood
- Rapid7/vendor advisories for remediation context
- ExploitDB as a reference pointer only, not as an instruction source

Cache enrichment results and revalidate periodically to avoid repeated external lookups.

## Risk-Path Analysis

Instead of exploit-step generation, build a **risk-path engine** that models:

- Internet exposure
- Weak authentication boundaries
- Missing patches
- Privilege boundaries
- Lateral movement opportunities
- Asset criticality

Example output:

- "Public web server with critical RCE exposure could lead to application-tier compromise"
- "Application-tier compromise plus overly permissive service account could increase database exposure risk"

This gives defenders a chain-aware explanation without producing offensive instructions.

## RAG Chatbot

The chatbot should answer:

- What are the highest-risk findings for asset X?
- Why is CVE-YYYY-NNNN important here?
- Which findings are externally exposed?
- What should we remediate first this week?
- Which sources support this recommendation?

Recommended retrieval sources:

- Internal findings database
- Stored scan reports
- NVD/CISA/vendor advisories
- Internal remediation playbooks

Recommended response format:

- Summary
- Evidence from finding data
- Risk reasoning
- Remediation guidance
- References/citations

## Evaluation

Measure the system by component:

- Parser accuracy: precision/recall of normalized fields from scanner artifacts
- CVE enrichment quality: correct mapping rate and missing-field rate
- Risk-path quality: analyst-validated relevance, precision, and agreement
- Chat quality:
  - retrieval precision
  - grounded-answer rate
  - citation coverage
  - answer usefulness score
- ML metrics when applicable:
  - accuracy
  - precision
  - recall
  - F1
- For summarization and report text:
  - ROUGE/BLEU only as secondary metrics

## How This Maps To The Current Repo

Good starting points already exist:

- [app.py](C:\Users\User\Desktop\SurrKarr\app.py)
- [core/scanner/live_scanner.py](C:\Users\User\Desktop\SurrKarr\core\scanner\live_scanner.py)
- [core/normalization/enrichment.py](C:\Users\User\Desktop\SurrKarr\core\normalization\enrichment.py)
- [core/ai_query/query_executor.py](C:\Users\User\Desktop\SurrKarr\core\ai_query\query_executor.py)

Main gaps to address next:

1. Replace the current SQLite schema and model mismatches with a single consistent schema.
2. Convert direct scanner execution into a job-based adapter layer with authorization checks and safer error handling.
3. Replace `attack_path_generator` outputs with defensive risk-path explanations.
4. Upgrade the AI query flow into a grounded RAG pipeline with citations and remediation-first answers.
5. Add authentication, RBAC, audit logging, and per-user scan ownership before calling it multi-user ready.

## Suggested Delivery Plan

### Phase 1

- Finish ingestion and normalization for uploaded scan files
- Add scan-job tracking and dashboard summaries
- Stabilize the storage schema and tests

### Phase 2

- Add enrichment, deduplication, prioritization, and risk-path analysis
- Generate executive and technical reports

### Phase 3

- Add RAG chat with citations and remediation playbooks
- Add multi-user auth, audit logs, and team workflows

## Immediate Next Engineering Tasks

1. Fix model/database/test inconsistencies so the current backend can run reliably.
2. Refactor scanner adapters and parsers behind a common interface.
3. Rename and redesign attack-path logic as remediation-focused risk-path analysis.
4. Add a grounded chat response format with citations from finding data and threat-intel sources.
