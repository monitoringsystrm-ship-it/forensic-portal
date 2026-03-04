# Forensic-Ready CI/CD Security Framework – New Features & Implementation Guide

Tech stack target: **Jenkins + GitHub + Node.js/React + Docker**

---

## 1. Table of New Features

| # | Component | Feature | Current Portal | New Requirement | Status |
|---|-----------|---------|----------------|-----------------|--------|
| **Component 1: Forensic-Ready Jenkins CI/CD Agents** |
| 1.1 | CI/CD Agents | **Tech stack** | HDFS/Hadoop log–based agents | Jenkins + Node.js/React + Docker | **Change** |
| 1.2 | CI/CD Agents | **Inputs: GitHub** | None | GitHub webhooks (push, PR, branch/tag), commit SHA, author, timestamp | **Implement** |
| 1.3 | CI/CD Agents | **Inputs: Jenkins** | None | Jenkinsfile, pipeline stages (build/test/dockerize), Node/npm/yarn config | **Implement** |
| 1.4 | CI/CD Agents | **Inputs: Build env** | None | Docker daemon logs, Node env vars, npm/yarn cache, package.json/lock snapshots | **Implement** |
| 1.5 | CI/CD Agents | **Inputs: Runtime** | Console/log text | Jenkins console output, shell command sequences, Docker build commands, npm install/build | **Extend** |
| 1.6 | CI/CD Agents | **Inputs: Docker** | None | Dockerfile, build args, layer logs, image metadata | **Implement** |
| 1.7 | CI/CD Agents | **Outputs: Evidence** | Generic evidence list | Timestamped build logs (JSON), Docker context snapshots (tar.gz), env dumps (redacted), command traces | **Implement** |
| 1.8 | CI/CD Agents | **Outputs: Docker** | None | Built images + tags, layer manifests, image metadata, registry provenance tags | **Implement** |
| 1.9 | CI/CD Agents | **Outputs: GitHub** | None | Commit→build mapping (SHA→Build #), build status to GitHub, artifact URLs | **Implement** |
| 1.10 | CI/CD Agents | **Chain of custody** | Basic evidence | SHA-256 hashes, build UUID, timestamp authority signatures | **Extend** |
| 1.11 | **ML: Command sequence** | **Model** | HDFS/Hadoop log anomaly (TF-IDF + classifier) | LSTM/Transformer command sequence classifier (benign/suspicious/malicious) | **Implement** |
| 1.12 | **ML: Command sequence** | **Input** | Log lines | Tokenized command sequences, e.g. `["npm","install"], ["curl","-o","/tmp/script.sh", "http://..."]` | **Implement** |
| 1.13 | **ML: Command sequence** | **Output** | Anomaly labels | Benign/Suspicious/Malicious + confidence; per-command anomaly score; alert JSON with build_id, command, confidence, risk_level | **Implement** |
| 1.14 | **ML: Command sequence** | **Explainability** | None | Which command triggered alert and why | **Implement** |
| **Component 2: SBOM & Malware Detection** |
| 2.1 | SBOM | **Scope** | Manual SBOM hash input | Pipeline-stage SBOM (per stage: env, tools, inputs, outputs, deps) | **Implement** |
| 2.2 | SBOM | **Format** | Generic JSON hash | Extended CycloneDX/SPDX with `pipelineStage`, `buildEnvironment`, `inputArtifacts`, `outputArtifacts`, Merkle proof refs | **Implement** |
| 2.3 | SBOM | **Orchestrator** | None | `PipelineSBOMOrchestrator`: capture_stage_context(), capture_environment(), capture_tools_used(), capture_inputs/outputs(), generate_dependency_sbom() | **Implement** |
| 2.4 | SBOM | **Merkle integration** | Merkle root from list of hashes | Pipeline Merkle tree: add_stage(stage_sbom), finalize_pipeline(), verify_stage(); leaf = stage_name, index, sbom_hash, timestamp | **Implement** |
| 2.5 | SBOM | **CI integration** | None | Jenkins shared library: `sbomCapture('stageName') { ... }`, `publishPipelineSBOM()` | **Implement** |
| 2.6 | SBOM | **Verification service** | None | verify_pipeline_integrity(pipeline_id), query_vulnerable_builds(cve_id), trace_artifact_provenance(artifact_hash) | **Implement** |
| 2.7 | Malware | **Detection** | Microsoft Malware classifier (PE) | Keep + extend: SBOM hash lookup (e.g. XMRig), malware family classification; integrate with Node/npm context | **Extend** |
| **Component 3: Automated Forensic Incident Analysis** |
| 3.1 | Incident analysis | **GitHub commits** | Commit pattern analyzer (NSL-KDD/UNSW-style features) | Full commit history (6–12 months), metadata, diffs, contributor behavior, code review data | **Extend** |
| 3.2 | Incident analysis | **Contributor behavior** | Implicit in features | Commit frequency, time patterns, account age, code review participation | **Implement** |
| 3.3 | Incident analysis | **Dependency history** | Dependency anomaly detector | package.json changelog (git diff), version bumps, new deps, lockfile integrity | **Extend** |
| 3.4 | Incident analysis | **Jenkins patterns** | None | Build frequency/duration, success/failure, resource use, Docker image size trends | **Implement** |
| 3.5 | Incident analysis | **Threat intel** | None | CVE DB (Node/React), npm advisories, GitHub advisories, compromised package lists | **Implement** |
| 3.6 | **ML: Commit anomaly** | **Model** | Commit pattern (existing) | Isolation Forest + Autoencoder; commit + author behavioral features; anomaly_type, reasons, recommendation | **Extend** |
| 3.7 | **ML: Dependency anomaly** | **Model** | Dependency anomaly (existing) | GNN + clustering (e.g. DBSCAN); typosquatting, Levenshtein, namespace similarity; BLOCK_INSTALL recommendation | **Extend** |
| 3.8 | **Outputs** | **Reports** | Anomaly lists | Commit anomaly report JSON; dependency risk assessment JSON; incident timeline (commit→build→deploy); trend analysis | **Implement** |
| **Component 4: Chain of Custody & Integration** |
| 4.1 | Integration | **Flow** | Separate tabs (agents, anomaly, integrity, reporting) | Single flow: GitHub push → Component 1 (capture + command ML) → Component 2 (SBOM + malware) → Component 3 (commit/dep analysis) → Component 4 (block/alert) | **Implement** |
| 4.2 | UI | **Views** | Per-component UIs | Incident timeline visualization; pipeline integrity verification UI; forensic query (CVE, artifact provenance); Merkle tree visualization (e.g. D3.js) | **Implement** |

---

## 2. What Is Going to Change

### 2.1 CI/CD Agents (Component 1)

| Area | Current | Change |
|------|---------|--------|
| **Data source** | Static HDFS/Hadoop log files under `ml_models/cicd_agents/` | Live Jenkins pipelines + GitHub webhooks + Docker build context |
| **Evidence types** | Git diffs, build logs, env vars, artifacts, pipeline config (conceptual) | Same categories but **populated from Jenkins**: timestamped JSON logs, Docker context tar.gz, redacted env dumps, command execution traces |
| **ML model** | HDFS log anomaly (TF-IDF + classifier), Hadoop log failure classifier | **New**: Command sequence classifier (LSTM/Transformer) on tokenized shell/Docker/npm command sequences; output: benign/suspicious/malicious + alerts with risk_level and explainability |
| **Outputs** | Evidence list + HDFS/Hadoop inference | Forensic evidence packages, Docker artifact metadata, GitHub commit↔build mapping, chain-of-custody (SHA-256, build UUID, timestamp signatures) |

### 2.2 Integrity Verification & SBOM (Component 2)

| Area | Current | Change |
|------|---------|--------|
| **SBOM** | User pastes JSON; backend hashes it and returns SHA-256 | **Pipeline-stage SBOM**: orchestrator captures per-stage context (env, tools, inputs, outputs, deps); extended schema with `pipelineStage`, `buildEnvironment`, `inputArtifacts`, `outputArtifacts` |
| **Merkle** | User supplies list of hashes; backend returns root | **Pipeline Merkle tree**: one leaf per stage SBOM; add_stage(), finalize_pipeline(), verify_stage(); store proof chain; verification service for full pipeline integrity |
| **Malware** | Microsoft Malware classifier (PE files) | Keep; add SBOM-based hash lookup and Node/npm artifact context where applicable |
| **CI integration** | None | Jenkins shared library: `sbomCapture('stageName') { steps }`, `publishPipelineSBOM()`; optional GitLab/GitHub Actions equivalent |

### 2.3 Anomaly Detection (Component 3)

| Area | Current | Change |
|------|---------|--------|
| **Commit pattern** | CommitPatternAnalyzer on synthetic/NSL-KDD-style data | **Extend**: real GitHub commit history (6–12 months), author behavior, commit time patterns; Isolation Forest + Autoencoder; output: anomaly_type, reasons, recommendation (e.g. MANUAL_REVIEW) |
| **Dependency anomaly** | DependencyAnomalyDetector on synthetic dependency features | **Extend**: real package.json/lockfile history; GNN + clustering; typosquatting/Levenshtein; output: BLOCK_INSTALL, similar_package, detection_method |
| **Pipeline tampering** | PipelineTamperingDetector (script tampering) | Keep; align with Jenkins pipeline scripts and stage definitions |
| **New inputs** | — | Jenkins build patterns (frequency, duration, success rate, resources, image size); external threat intel (CVE, npm advisories, GitHub advisories, compromised packages) |
| **New outputs** | Anomaly list + timeline reconstruction | Structured commit anomaly report, dependency risk assessment, incident reconstruction (commit→build→deploy), trend analysis |

### 2.4 Reporting Portal & UI

| Area | Current | Change |
|------|---------|--------|
| **Reporting** | Forensic data, custody, correlate, attack/breach classifiers | Add: incident timeline from Component 3, pipeline integrity status, CVE-affected builds, artifact provenance |
| **Integrity UI** | SBOM hash, Merkle root, hashes, signatures, Microsoft Malware | Add: pipeline integrity verification, forensic query (by CVE, by artifact hash), Merkle tree visualization (e.g. D3.js) |
| **Navigation** | Tabs: CI/CD Agents, Anomaly Detection, Integrity Verification, Reporting Portal | Optional: integrated “Pipeline view” showing full flow (GitHub → Jenkins → SBOM → ML alerts) and incident timeline |

---

## 3. What Needs to Be Implemented

### 3.1 Backend (Flask / Python)

| Priority | Item | Description |
|----------|------|-------------|
| **P1** | **Jenkins/GitHub evidence ingestion** | APIs or webhooks to receive: GitHub events (push, PR), Jenkins build metadata, console snippets, Docker context references. Store in `data/` or DB with build UUID and timestamps. |
| **P1** | **Command sequence ML model** | New module: tokenize Jenkins console output into command sequences; train LSTM or Transformer for benign/suspicious/malicious; expose infer API; return confidence, risk_level, and explainability (which command, why). |
| **P1** | **Extended SBOM schema** | Define and validate JSON schema for pipeline-stage SBOM (pipelineStage, buildEnvironment, inputArtifacts, outputArtifacts, components). |
| **P1** | **Pipeline SBOM orchestrator** | `PipelineSBOMOrchestrator` (or equivalent): capture_stage_context(), capture_environment(), capture_tools_used(), capture_inputs(), capture_outputs(), generate_dependency_sbom(). Can be called from API or from Jenkins shared library. |
| **P1** | **Pipeline Merkle tree** | `PipelineMerkleTree`: add_stage(stage_sbom), finalize_pipeline() → root + proof chain, verify_stage(). Persist proof chain per pipeline_id. |
| **P2** | **Forensic verification service** | `ForensicVerificationService`: verify_pipeline_integrity(pipeline_id), query_vulnerable_builds(cve_id), trace_artifact_provenance(artifact_hash). REST endpoints for each. |
| **P2** | **Commit pattern extension** | Feed real GitHub commit history; add author/time features; train Isolation Forest + Autoencoder; return anomaly_type, reasons, recommendation. |
| **P2** | **Dependency anomaly extension** | Feed real package.json/lockfile history; add typosquatting/Levenshtein features; GNN + DBSCAN or similar; return BLOCK_INSTALL, similar_package. |
| **P2** | **Threat intel integration** | Integrate CVE (Node/React), npm advisories, GitHub advisories, compromised package list into dependency and build risk scoring. |
| **P2** | **Jenkins build metrics** | Ingest and store build frequency, duration, success/failure, resource usage, Docker image size; use in Component 3 trend analysis. |

### 3.2 CI/CD Integration

| Priority | Item | Description |
|----------|------|-------------|
| **P1** | **Jenkins shared library** | Groovy library: `sbomCapture('stageName') { ... }` wraps stage steps; collects metadata; calls backend to submit stage SBOM; `publishPipelineSBOM()` finalizes Merkle tree and uploads proof. |
| **P2** | **GitHub webhook receiver** | Endpoint to receive push/PR events; map commit SHA to build; optionally post build status back to GitHub. |
| **P2** | **Docker context capture** | In Jenkins pipeline: capture Dockerfile, build args, layer logs, image metadata; send to backend as part of evidence package. |

### 3.3 Frontend (React)

| Priority | Item | Description |
|----------|------|-------------|
| **P1** | **Command sequence alerts** | New section under CI/CD Agents: list alerts from command ML (build_id, command, confidence, risk_level); link to evidence. |
| **P1** | **Pipeline SBOM / Merkle UI** | View pipeline stages, per-stage SBOM summary, Merkle root and proof chain; “Verify pipeline” button calling verification API. |
| **P2** | **Forensic query UI** | Query by CVE (list affected builds); query by artifact hash (provenance chain + verification status). |
| **P2** | **Merkle tree visualization** | D3.js (or similar) tree of pipeline stages and hashes. |
| **P2** | **Incident timeline** | Timeline view: commit → build → deployment with anomaly and alert annotations (from Component 3). |
| **P2** | **Commit & dependency anomaly reports** | Display commit anomaly report (reasons, recommendation) and dependency risk (typosquatting, BLOCK_INSTALL, similar_package). |

### 3.4 Data & Storage

| Priority | Item | Description |
|----------|------|-------------|
| **P1** | **Pipeline/SBOM storage** | Store pipeline_id, stage SBOMs, Merkle root and proof chain (DB or file under `data/`). |
| **P2** | **Evidence package storage** | Store or reference Jenkins evidence packages (logs, Docker context tar.gz); link to build UUID. |
| **P2** | **Index for CVE/artifact queries** | Index SBOMs/components by CVE and by artifact hash for fast forensic queries. |

### 3.5 Reuse (Minimal or No Change)

| Item | Action |
|------|--------|
| HDFS/Hadoop CI agents | Keep as optional legacy agents or repurpose for “log-only” mode; new default is Jenkins+Node+Docker. |
| Microsoft Malware classifier | Keep; add SBOM/hash lookup and Node context if needed. |
| Hash/HMAC/Ed25519 APIs | Keep as-is for chain-of-custody and signing. |
| Merkle root from hashes | Keep; extend with Pipeline Merkle layer and verification. |
| Evidence correlator, attack/breach classifiers | Keep; feed with new alerts and incident timeline. |
| Commit/dependency/pipeline anomaly models | Extend with new features and outputs; add new command sequence model. |

---

## 4. Summary

- **Component 1**: Shift from HDFS/Hadoop logs to **Jenkins + GitHub + Node.js/React + Docker**; add **command sequence ML** and structured evidence packages and chain-of-custody.
- **Component 2**: Move from manual SBOM hash to **pipeline-stage SBOM** and **Merkle-based pipeline integrity**; add **orchestrator**, **verification service**, and **Jenkins integration**.
- **Component 3**: Evolve commit and dependency models to **real GitHub and npm data**; add **incident timeline**, **threat intel**, and **Jenkins build patterns**; output structured **anomaly and risk reports**.
- **Component 4**: Implement **end-to-end flow** and **forensic query UI** (CVE, artifact provenance, Merkle tree visualization, incident timeline).

Use the table in Section 1 for tracking; use Sections 2 and 3 to plan changes and implementation order (P1 first, then P2).
