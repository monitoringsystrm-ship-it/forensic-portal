## Forensic Portal – VPS Deployment & Project Overview

This document is for future setup on a VPS and for any AI assistant to quickly understand how the system works.

---

### 1. High-Level Architecture

- **Frontend**: React (Create React App) in `src/`, served on port `3000` in dev, static build for prod.
- **Backend**: Flask API in `backend/api/ml_api.py`, running on port `5000`.
- **ML Models**:
  - `backend/ml_models/cicd_agents/*` – CI/CD agents (HDFS/Hadoop, command sequence classifier).
  - `backend/ml_models/anomaly_detection/*` – commit, dependency, pipeline-tampering anomaly models.
  - `backend/ml_models/integrity_verification/*` – integrity, Microsoft malware classifier.
  - `backend/ml_models/reporting_portal/*` – reporting portal classifiers.
- **Data / State (JSON files)**:
  - CI/CD agent state: `backend/data/cicd_state.json` (agents, evidence, config, mappings).
  - Pipeline SBOM + Merkle tree store: `backend/data/pipeline_sbom_store.json`.
  - Incident analysis state: `backend/data/incident_analysis_state.json`.
- **Integration Flow (Component 4)**: Aggregates Components 1–3, returns a single decision:
  - `ALLOW` / `ALERT` / `BLOCK_DEPLOYMENT`.

Main components:

1. **Component 1 – Forensic-Ready Jenkins CI/CD Agents**
   - Endpoints under `/api/ml/cicd-agents/*`.
   - Collects Jenkins build logs, env vars (redacted), Docker context, command traces.
   - Command sequence classifier marks commands as BENIGN/SUSPICIOUS/MALICIOUS.

2. **Component 2 – SBOM & Malware Detection**
   - Endpoints under `/api/ml/integrity-verification/*`.
   - Stage-level SBOMs with extended metadata + pipeline Merkle tree.
   - Malware classifier + hash lookup for known bad hashes.

3. **Component 3 – Automated Forensic Incident Analysis**
   - Endpoints under `/api/ml/anomaly-detection/incident/*`.
   - Ingests:
     - GitHub commits
     - Dependency history
     - Jenkins build metrics
     - Threat intelligence (CVE/advisories/compromised packages)
   - Produces commit anomaly reports, dependency risk assessments, build anomalies, and a timeline.

4. **Component 4 – Chain of Custody & Integration**
   - Endpoints under `/api/ml/integration/flow/*`.
   - Combines Components 1–3 + pipeline integrity into a single “deploy or block” decision.

---

### 2. Minimal VPS Setup

If the provider only lets you choose **one thing** at creation time:

- Choose **Ubuntu 22.04 LTS** (or Debian 12) as the OS.
- After first SSH login, install Docker manually:

```bash
sudo apt update && sudo apt install -y docker.io
sudo systemctl enable docker && sudo systemctl start docker
```

Optional but recommended features in the VPS dashboard (if available later):

- **Malware scanner**: enable (free).
- **Docker manager**: enable (makes running containers easier).
- **Daily auto-backups**: enable if budget allows; useful for easy restore.

---

### 3. Running the App on the VPS (simplest path)

Assumes:

- Backend runs on port `5000`.
- Frontend serves static build on port `80` (via Nginx) or on `3000` (via Node server).

Steps (non-Docker, similar to dev but on VPS):

1. **Upload project** to `/opt/forensic-portal-41` (for example).
2. **Backend**:
   - Create venv and install requirements:
     - `cd /opt/forensic-portal-41/backend`
     - `python3 -m venv venv`
     - `source venv/bin/activate`
     - `pip install -r requirements.txt`
   - Run backend (basic, not production-grade):
     - `PORT=5000 python api/ml_api.py`
   - For production, use Gunicorn or similar with a supervisor/service file.

3. **Frontend**:
   - Install Node/npm (Node 18+ / 20).
   - `cd /opt/forensic-portal-41`
   - `npm install`
   - Build:
     - `npm run build`
   - Serve the `build/` directory via Nginx (recommended) or a Node static server.

4. **Reverse proxy (optional but recommended)**:
   - Use Nginx or Nginx Proxy Manager.
   - Route:
     - `https://forensic.yourdomain.com` → React build (port 80/3000).
     - Proxy `/api/ml/*` to `http://127.0.0.1:5000`.

---

### 4. Key Backend Endpoints (for CI/CD and analysis)

#### Component 1 – CI/CD Agents & Command ML

- Health: `GET /api/ml/health`
- CI/CD status: `GET /api/ml/cicd-agents/status`
- Evidence list: `GET /api/ml/cicd-agents/evidence?limit=200`
- Collect (from models): `POST /api/ml/cicd-agents/collect`
- Register agent: `POST /api/ml/cicd-agents/register`
- Config get/save/reset:
  - `GET /api/ml/cicd-agents/config`
  - `POST /api/ml/cicd-agents/config`
  - `POST /api/ml/cicd-agents/config/reset`
- GitHub webhook ingest:
  - `POST /api/ml/cicd-agents/github/webhook`
- Jenkins build ingest (main CI entry):
  - `POST /api/ml/cicd-agents/jenkins/build`
- Command sequence classifier:
  - `GET /api/ml/cicd-agents/command-sequence/status`
  - `GET /api/ml/cicd-agents/command-sequence/latest`
  - `POST /api/ml/cicd-agents/command-sequence/train`
  - `POST /api/ml/cicd-agents/command-sequence/infer`
- Commit→build mapping:
  - `GET /api/ml/cicd-agents/mappings/commit-build?commit_sha=...`

**Important fields for `POST /api/ml/cicd-agents/jenkins/build` payload:**

- `build_id`, `build_number`, `pipeline_name`, `stage_name`, `stage_index`
- `commit_sha`, `branch`, `tags[]`
- `commands[]` **or** `console_output` string
- `env` – dictionary of env vars; backend redacts secrets
- `docker` – `{ dockerfile, image, tags[], build_args{}, image_size_mb }`
- Optional performance metrics:
  - `duration_sec`, `success`, `cpu_percent`, `memory_mb`

These fields are used by:

- Component 1: evidence, command alerts, agent status.
- Component 3: Jenkins pattern analysis + commit analysis.

#### Component 2 – SBOM, Merkle Integrity, Malware

- Hash arbitrary content:
  - `POST /api/ml/integrity-verification/hash`
  - `POST /api/ml/integrity-verification/hash/verify`
- SBOM hash:
  - `POST /api/ml/integrity-verification/sbom/hash`
- Pipeline-stage SBOM capture/finalize/verify:
  - `POST /api/ml/integrity-verification/pipeline-sbom/capture`
  - `POST /api/ml/integrity-verification/pipeline-sbom/finalize`
  - `POST /api/ml/integrity-verification/pipeline-sbom/verify-stage`
  - `GET /api/ml/integrity-verification/pipeline-sbom/pipeline/<pipeline_id>`
  - `GET /api/ml/integrity-verification/pipeline-sbom/pipelines`
  - `GET /api/ml/integrity-verification/verification/verify-pipeline/<pipeline_id>`
- Forensic queries:
  - `GET /api/ml/integrity-verification/verification/query-vulnerable-builds?cve_id=...`
  - `GET /api/ml/integrity-verification/verification/trace-artifact?artifact_hash=...`
- Malware:
  - Status/train/infer under `/api/ml/integrity-verification/microsoft-malware/*`
  - Hash lookup: `POST /api/ml/integrity-verification/malware/hash-lookup`

The pipeline SBOM capture endpoint automatically feeds dependency history into Component 3.

#### Component 3 – Incident Analysis

- Ingest GitHub commits:
  - `POST /api/ml/anomaly-detection/incident/ingest/github-commits`
- Ingest dependency history:
  - `POST /api/ml/anomaly-detection/incident/ingest/dependency-history`
- Ingest Jenkins build patterns:
  - `POST /api/ml/anomaly-detection/incident/ingest/jenkins-patterns`
- Ingest threat intel (CVE/advisories/compromised packages):
  - `POST /api/ml/anomaly-detection/incident/ingest/threat-intel`
- Run analysis (window in months, typically 6–12):
  - `POST /api/ml/anomaly-detection/incident/analyze`
- Get latest analysis:
  - `GET /api/ml/anomaly-detection/incident/latest`

Outputs include:

- `commit_anomalies[]` – each has `commit_sha`, `author`, `anomaly_score` (0–1), `reasons[]`, `recommendation`.
- `dependency_risks[]` – each has `package`, `anomaly_score` (0–1), `similar_package`, `recommendation` (e.g. `BLOCK_INSTALL`).
- `build_anomalies[]` – Jenkins build anomalies.
- `timeline[]` – ordered sequence of anomaly events (commit/dependency/build).
- `trends` – commit counts, top contributors, dependency churn, build failure rate, avg durations/image sizes.

#### Component 4 – Integration + Decision

- Integration flow status:
  - `GET /api/ml/integration/flow/status?pipeline_id=optional`
- Decision endpoint (use in deploy stage):
  - `POST /api/ml/integration/flow/decision` with body `{ "pipeline_id": "<id>" }`

Response includes:

- `decision`: `"ALLOW"`, `"ALERT"`, or `"BLOCK_DEPLOYMENT"`
- `reasons[]`: human-readable reasons
- `component_steps[]`: summary for Components 1–4
- `pipeline_verification`: integrity verification result
- `timeline`: combined incident events

---

### 5. Frontend Tabs / Where to See Things

In `src/App.js` tabs:

- `Integrated Flow` – new unified view for Component 1–4 status and decision.
- `CI/CD Agents` – configuration, evidence list, command sequence classification, legacy HDFS/Hadoop ML.
- `Anomaly Detection` – commit/dependency anomalies, timeline reconstruction, training reports, incident analysis panel.
- `Integrity Verification` – SBOM hash, Merkle root, signatures, Microsoft Malware, pipeline SBOM controls, forensic queries.
- `Reporting Portal` – forensic evidence visualization, chain-of-custody logs, legal-style reports, reporting ML models.

---

### 6. Jenkins / GitHub / CI Notes

#### GitHub Webhook

- Configure webhook on your repo:
  - URL: `https://<your-host>/api/ml/cicd-agents/github/webhook`
  - Events: `push`, `pull_request`.

This populates GitHub commit evidence and also feeds commits into Component 3.

#### Jenkins Shared Library (Component 2 SBOM)

Files under `jenkins/shared-library/vars`:

- `sbomCapture.groovy` – wrapper for each stage to capture SBOM metadata.
- `publishPipelineSBOM.groovy` – finalizes the pipeline Merkle tree and verifies integrity.

Example Jenkinsfile: `jenkins/Jenkinsfile.component2.example` shows:

- How to wrap `Checkout`, `Build`, `Dockerize` stages with `sbomCapture('stageName') { ... }`.
- How to call `publishPipelineSBOM()` in `post { always { ... } }`.

**Required Jenkins configuration:**

- Install plugins:
  - HTTP Request
  - Pipeline Utility Steps
- Set environment variable:
  - `FORENSIC_API_BASE` (e.g. `http://<your-host>:5000` or via HTTPS with domain).

#### Deploy-Time Gate (Component 4)

In your Jenkins deploy stage, call the decision endpoint:

- `POST /api/ml/integration/flow/decision` with `pipeline_id` set to job name or some consistent pipeline identifier.

Then implement logic:

- If `decision == "BLOCK_DEPLOYMENT"` → **fail build / abort deploy**.
- If `decision == "ALERT"` → **pause for manual approval**.
- If `decision == "ALLOW"` → **continue deploy**.

---

### 7. What To Check First When You Reconnect From VPS

1. **Backend health**:
   - `curl http://localhost:5000/api/ml/health`
2. **Frontend reachable**:
   - Open the app URL (e.g. `http://<vps-ip>:3000` or domain) and check Integrated Flow tab.
3. **CI/CD agents status**:
   - `GET /api/ml/cicd-agents/status`
4. **Integration flow**:
   - `GET /api/ml/integration/flow/status`
   - Confirm decision and that pipelines / mapping counts are non-zero after first Jenkins/GitHub runs.

This file should give enough context for any future AI session to understand and operate the system on the VPS.

