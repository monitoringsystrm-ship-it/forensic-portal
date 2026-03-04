const API_BASE = process.env.REACT_APP_ML_API_BASE || "";

async function requestJson(path, options) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(options && options.headers ? options.headers : {}),
    },
    ...options,
  });

  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }

  if (!res.ok) {
    const msg = json && json.error ? json.error : `Request failed (${res.status})`;
    throw new Error(msg);
  }

  return json;
}

export async function getMlHealth() {
  return requestJson("/api/ml/health");
}

export async function getAnomalyStatus() {
  return requestJson("/api/ml/anomaly-detection/status");
}

export async function trainAnomalyModels(models, limit) {
  return requestJson("/api/ml/anomaly-detection/train", {
    method: "POST",
    body: JSON.stringify({ models, limit }),
  });
}

export async function inferAnomalies(model, limit) {
  return requestJson("/api/ml/anomaly-detection/infer", {
    method: "POST",
    body: JSON.stringify({ model, limit }),
  });
}

export async function inferAnomalySample(model, sample, store) {
  return requestJson("/api/ml/anomaly-detection/infer-sample", {
    method: "POST",
    body: JSON.stringify({ model, sample, store }),
  });
}

export async function ingestIncidentGithubCommits(commits) {
  return requestJson("/api/ml/anomaly-detection/incident/ingest/github-commits", {
    method: "POST",
    body: JSON.stringify({ commits }),
  });
}

export async function ingestIncidentDependencyHistory(changes) {
  return requestJson("/api/ml/anomaly-detection/incident/ingest/dependency-history", {
    method: "POST",
    body: JSON.stringify({ changes }),
  });
}

export async function ingestIncidentJenkinsPatterns(builds) {
  return requestJson("/api/ml/anomaly-detection/incident/ingest/jenkins-patterns", {
    method: "POST",
    body: JSON.stringify({ builds }),
  });
}

export async function ingestIncidentThreatIntel(payload) {
  return requestJson("/api/ml/anomaly-detection/incident/ingest/threat-intel", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function analyzeIncidents(months) {
  return requestJson("/api/ml/anomaly-detection/incident/analyze", {
    method: "POST",
    body: JSON.stringify({ months }),
  });
}

export async function getLatestIncidentAnalysis() {
  return requestJson("/api/ml/anomaly-detection/incident/latest");
}

export async function getLatestAnomalies(model) {
  const qp = model ? `?model=${encodeURIComponent(model)}` : "";
  return requestJson(`/api/ml/anomaly-detection/latest${qp}`);
}

export function getAnomalyReportUrl(filename) {
  return `${API_BASE}/api/ml/anomaly-detection/reports/${filename}`;
}

export async function getCicdHdfsStatus() {
  return requestJson("/api/ml/cicd-agents/hdfs/status");
}

export async function trainCicdHdfsModel(limit) {
  return requestJson("/api/ml/cicd-agents/hdfs/train", {
    method: "POST",
    body: JSON.stringify({ limit }),
  });
}

export async function inferCicdHdfsDataset(limit, store) {
  return requestJson("/api/ml/cicd-agents/hdfs/infer-dataset", {
    method: "POST",
    body: JSON.stringify({ limit, store }),
  });
}

export async function getCicdHdfsLatest() {
  return requestJson("/api/ml/cicd-agents/hdfs/latest");
}

export function getCicdHdfsReportUrl(filename) {
  return `${API_BASE}/api/ml/cicd-agents/hdfs/reports/${filename}`;
}

export async function getCicdHadoopStatus() {
  return requestJson("/api/ml/cicd-agents/hadoop/status");
}

export async function trainCicdHadoopModel(limitApps) {
  return requestJson("/api/ml/cicd-agents/hadoop/train", {
    method: "POST",
    body: JSON.stringify({ limit_apps: limitApps }),
  });
}

export async function inferCicdHadoopDataset(limitApps, store) {
  return requestJson("/api/ml/cicd-agents/hadoop/infer-dataset", {
    method: "POST",
    body: JSON.stringify({ limit_apps: limitApps, store }),
  });
}

export async function getCicdHadoopLatest() {
  return requestJson("/api/ml/cicd-agents/hadoop/latest");
}

export function getCicdHadoopReportUrl(filename) {
  return `${API_BASE}/api/ml/cicd-agents/hadoop/reports/${filename}`;
}

export async function getCicdAgentsStatus() {
  return requestJson("/api/ml/cicd-agents/status");
}

export async function getCicdEvidence(limit) {
  const qp = typeof limit === "number" ? `?limit=${encodeURIComponent(String(limit))}` : "";
  return requestJson(`/api/ml/cicd-agents/evidence${qp}`);
}

export async function collectCicdEvidence(mode) {
  return requestJson("/api/ml/cicd-agents/collect", {
    method: "POST",
    body: JSON.stringify({ mode }),
  });
}

export async function getCicdConfig() {
  return requestJson("/api/ml/cicd-agents/config");
}

export async function saveCicdConfig(config) {
  return requestJson("/api/ml/cicd-agents/config", {
    method: "POST",
    body: JSON.stringify({ config }),
  });
}

export async function resetCicdConfig() {
  return requestJson("/api/ml/cicd-agents/config/reset", { method: "POST" });
}

export async function registerCicdAgent(agent) {
  return requestJson("/api/ml/cicd-agents/register", {
    method: "POST",
    body: JSON.stringify({ agent }),
  });
}

export async function getCicdCommandSequenceStatus() {
  return requestJson("/api/ml/cicd-agents/command-sequence/status");
}

export async function getCicdCommandSequenceLatest() {
  return requestJson("/api/ml/cicd-agents/command-sequence/latest");
}

export async function trainCicdCommandSequence(benign_sequences, malicious_sequences) {
  return requestJson("/api/ml/cicd-agents/command-sequence/train", {
    method: "POST",
    body: JSON.stringify({ benign_sequences, malicious_sequences }),
  });
}

export async function inferCicdCommandSequence(build_id, commands, console_output) {
  return requestJson("/api/ml/cicd-agents/command-sequence/infer", {
    method: "POST",
    body: JSON.stringify({ build_id, commands, console_output }),
  });
}

export async function ingestGithubWebhook(payload) {
  return requestJson("/api/ml/cicd-agents/github/webhook", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function ingestJenkinsBuild(build) {
  return requestJson("/api/ml/cicd-agents/jenkins/build", {
    method: "POST",
    body: JSON.stringify(build),
  });
}

export async function getCommitBuildMapping(commit_sha) {
  const qp = commit_sha ? `?commit_sha=${encodeURIComponent(commit_sha)}` : "";
  return requestJson(`/api/ml/cicd-agents/mappings/commit-build${qp}`);
}

export async function getMicrosoftMalwareStatus() {
  return requestJson("/api/ml/integrity-verification/microsoft-malware/status");
}

export async function trainMicrosoftMalwareModel(limit) {
  return requestJson("/api/ml/integrity-verification/microsoft-malware/train", {
    method: "POST",
    body: JSON.stringify({ limit }),
  });
}

export async function inferMicrosoftMalwareDataset(limit, store) {
  return requestJson("/api/ml/integrity-verification/microsoft-malware/infer-dataset", {
    method: "POST",
    body: JSON.stringify({ limit, store }),
  });
}

export async function getMicrosoftMalwareLatest() {
  return requestJson("/api/ml/integrity-verification/microsoft-malware/latest");
}

export async function computeIntegrityHash(content) {
  return requestJson("/api/ml/integrity-verification/hash", {
    method: "POST",
    body: JSON.stringify({ content }),
  });
}

export async function verifyIntegrityHash(content, expected_hash) {
  return requestJson("/api/ml/integrity-verification/hash/verify", {
    method: "POST",
    body: JSON.stringify({ content, expected_hash }),
  });
}

export async function hashSbom(sbom_json) {
  return requestJson("/api/ml/integrity-verification/sbom/hash", {
    method: "POST",
    body: JSON.stringify({ sbom_json }),
  });
}

export async function capturePipelineStageSbom(payload) {
  return requestJson("/api/ml/integrity-verification/pipeline-sbom/capture", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function finalizePipelineSbom(pipeline_id) {
  return requestJson("/api/ml/integrity-verification/pipeline-sbom/finalize", {
    method: "POST",
    body: JSON.stringify({ pipeline_id }),
  });
}

export async function verifyPipelineStageSbom(pipeline_id, stage_index) {
  return requestJson("/api/ml/integrity-verification/pipeline-sbom/verify-stage", {
    method: "POST",
    body: JSON.stringify({ pipeline_id, stage_index }),
  });
}

export async function getPipelineSbom(pipeline_id) {
  return requestJson(`/api/ml/integrity-verification/pipeline-sbom/pipeline/${encodeURIComponent(pipeline_id)}`);
}

export async function listPipelineSboms() {
  return requestJson("/api/ml/integrity-verification/pipeline-sbom/pipelines");
}

export async function verifyPipelineIntegrity(pipeline_id) {
  return requestJson(`/api/ml/integrity-verification/verification/verify-pipeline/${encodeURIComponent(pipeline_id)}`);
}

export async function queryVulnerableBuilds(cve_id) {
  return requestJson(
    `/api/ml/integrity-verification/verification/query-vulnerable-builds?cve_id=${encodeURIComponent(cve_id)}`
  );
}

export async function traceArtifactProvenance(artifact_hash) {
  return requestJson(
    `/api/ml/integrity-verification/verification/trace-artifact?artifact_hash=${encodeURIComponent(artifact_hash)}`
  );
}

export async function getIntegrationFlowStatus(pipeline_id) {
  const qp = pipeline_id ? `?pipeline_id=${encodeURIComponent(pipeline_id)}` : "";
  return requestJson(`/api/ml/integration/flow/status${qp}`);
}

export async function evaluateIntegrationDecision(pipeline_id) {
  return requestJson("/api/ml/integration/flow/decision", {
    method: "POST",
    body: JSON.stringify({ pipeline_id }),
  });
}

export async function lookupMalwareHash(hash, packageName, version, source) {
  return requestJson("/api/ml/integrity-verification/malware/hash-lookup", {
    method: "POST",
    body: JSON.stringify({ hash, package: packageName, version, source }),
  });
}

export async function computeMerkleRoot(hashes) {
  return requestJson("/api/ml/integrity-verification/merkle/root", {
    method: "POST",
    body: JSON.stringify({ hashes }),
  });
}

export async function signHmac(payload, secret) {
  return requestJson("/api/ml/integrity-verification/sign/hmac", {
    method: "POST",
    body: JSON.stringify({ payload, secret }),
  });
}

export async function verifyHmac(payload, secret, signature) {
  return requestJson("/api/ml/integrity-verification/verify/hmac", {
    method: "POST",
    body: JSON.stringify({ payload, secret, signature }),
  });
}

export async function generateEd25519Keypair() {
  return requestJson("/api/ml/integrity-verification/keys/ed25519", { method: "POST" });
}

export async function signEd25519(payload, private_key_pem) {
  return requestJson("/api/ml/integrity-verification/sign/ed25519", {
    method: "POST",
    body: JSON.stringify({ payload, private_key_pem }),
  });
}

export async function verifyEd25519(payload, public_key_pem, signature_b64) {
  return requestJson("/api/ml/integrity-verification/verify/ed25519", {
    method: "POST",
    body: JSON.stringify({ payload, public_key_pem, signature_b64 }),
  });
}

export async function getReportingPortalStatus() {
  return requestJson("/api/ml/reporting-portal/status");
}

export async function trainReportingPortalModels(models, limit_attack, limit_breaches) {
  return requestJson("/api/ml/reporting-portal/train", {
    method: "POST",
    body: JSON.stringify({ models, limit_attack, limit_breaches }),
  });
}

export async function inferReportingPortalSample(model, record) {
  return requestJson("/api/ml/reporting-portal/infer-sample", {
    method: "POST",
    body: JSON.stringify({ model, record }),
  });
}

export async function inferReportingPortalDataset(model, limit, store) {
  return requestJson("/api/ml/reporting-portal/infer-dataset", {
    method: "POST",
    body: JSON.stringify({ model, limit, store }),
  });
}

export async function getReportingPortalLatest(model) {
  const qp = model ? `?model=${encodeURIComponent(model)}` : "";
  return requestJson(`/api/ml/reporting-portal/latest${qp}`);
}

export function getReportingPortalReportUrl(model, filename) {
  return `${API_BASE}/api/ml/reporting-portal/reports/${encodeURIComponent(model)}/${encodeURIComponent(filename)}`;
}

export async function getReportingPortalForensicData() {
  return requestJson("/api/ml/reporting-portal/forensic-data");
}

export async function getReportingPortalCustody() {
  return requestJson("/api/ml/reporting-portal/custody");
}

export async function generateReportingPortalReport(config) {
  return requestJson("/api/ml/reporting-portal/report/generate", {
    method: "POST",
    body: JSON.stringify({ config }),
  });
}
