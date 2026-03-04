import React, { useEffect, useState } from "react";
import {
  getReportingPortalStatus,
  trainReportingPortalModels,
  inferReportingPortalDataset,
  inferReportingPortalSample,
  getReportingPortalLatest,
  getReportingPortalReportUrl,
} from "../../api/mlApi";

function ReportingPortalModels() {
  const [status, setStatus] = useState(null);
  const [activeModel, setActiveModel] = useState("attack_type");
  const [isTraining, setIsTraining] = useState(false);
  const [isInferring, setIsInferring] = useState(false);
  const [latest, setLatest] = useState(null);
  const [recordJson, setRecordJson] = useState("{\n  \"Title\": \"Authentication Bypass via SQL Injection\",\n  \"Scenario Description\": \"A login form fails to sanitize input\"\n}");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const loadStatus = async () => {
    const s = await getReportingPortalStatus();
    setStatus(s);
  };

  const loadLatest = async () => {
    const r = await getReportingPortalLatest(activeModel);
    setLatest(r);
  };

  useEffect(() => {
    loadStatus().catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    loadLatest().catch(() => {});
  }, [activeModel]);

  const onTrain = async () => {
    setIsTraining(true);
    setError(null);
    try {
      const res = await trainReportingPortalModels([activeModel], activeModel === "attack_type" ? 6000 : null, null);
      setResult(res);
      await loadStatus();
    } catch (e) {
      setError(e.message);
    } finally {
      setIsTraining(false);
    }
  };

  const onInferDataset = async () => {
    setIsInferring(true);
    setError(null);
    try {
      const res = await inferReportingPortalDataset(activeModel, 200, true);
      setResult(res);
      await loadLatest();
    } catch (e) {
      setError(e.message);
    } finally {
      setIsInferring(false);
    }
  };

  const onInferSample = async () => {
    setIsInferring(true);
    setError(null);
    try {
      const obj = JSON.parse(recordJson);
      const res = await inferReportingPortalSample(activeModel, obj);
      setResult(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsInferring(false);
    }
  };

  const modelState = status?.training_state?.[activeModel];
  const reports = modelState?.reports || [];

  return (
    <div className="reporting-ml-card">
      <div className="generator-header">
        <h3>Reporting Portal ML Models</h3>
        <p className="generator-subtitle">Train and infer using the real datasets in backend</p>
      </div>

      <div className="config-grid">
        <div className="config-item">
          <label>
            Model:
            <select
              className="config-select"
              value={activeModel}
              onChange={(e) => setActiveModel(e.target.value)}
            >
              <option value="attack_type">Attack Type Classifier (Attack_Dataset.csv)</option>
              <option value="breach_type">Breach Type Classifier (Cyber Security Breaches.csv)</option>
            </select>
          </label>
        </div>
      </div>

      <div className="config-actions">
        <button className="generate-button" onClick={onTrain} disabled={isTraining}>
          {isTraining ? "Training..." : "Train Model"}
        </button>
        <button className="generate-button" onClick={onInferDataset} disabled={isInferring}>
          {isInferring ? "Running..." : "Infer Dataset"}
        </button>
      </div>

      <div className="report-config-section">
        <h4>Infer Single Record (JSON)</h4>
        <textarea
          className="config-select"
          style={{ width: "100%", minHeight: 140 }}
          value={recordJson}
          onChange={(e) => setRecordJson(e.target.value)}
        />
        <div className="config-actions">
          <button className="generate-button" onClick={onInferSample} disabled={isInferring}>
            {isInferring ? "Running..." : "Infer Sample"}
          </button>
        </div>
      </div>

      {error && <p className="no-data">{error}</p>}

      {modelState?.metrics && (
        <div className="report-info">
          <div className="report-info-item">
            <span>Accuracy:</span>
            <span>{(modelState.metrics.accuracy * 100).toFixed(2)}%</span>
          </div>
          <div className="report-info-item">
            <span>F1 (macro):</span>
            <span>{(modelState.metrics.f1_macro * 100).toFixed(2)}%</span>
          </div>
          <div className="report-info-item">
            <span>Recall (macro):</span>
            <span>{(modelState.metrics.recall_macro * 100).toFixed(2)}%</span>
          </div>
        </div>
      )}

      {latest?.predictions && (
        <div className="report-info">
          <div className="report-info-item">
            <span>Latest stored predictions:</span>
            <span>{latest.predictions.length}</span>
          </div>
          <div className="report-info-item">
            <span>Timestamp:</span>
            <span>{latest.timestamp || "N/A"}</span>
          </div>
        </div>
      )}

      {reports.length > 0 && (
        <div className="generated-report-section">
          <h4>Training Reports</h4>
          <div className="preview-sections">
            {reports.map((f) => (
              <div key={f} className="preview-section">
                <strong>{f}</strong>
                {f.endsWith(".png") ? (
                  <div style={{ marginTop: 10 }}>
                    <img
                      alt={f}
                      src={getReportingPortalReportUrl(activeModel, f)}
                      style={{ width: "100%", maxWidth: 900 }}
                    />
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        </div>
      )}

      {result && (
        <div className="generated-report-section">
          <h4>Last Result</h4>
          <pre style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}

export default ReportingPortalModels;


