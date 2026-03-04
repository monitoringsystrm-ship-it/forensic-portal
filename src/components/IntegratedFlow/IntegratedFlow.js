import React, { useEffect, useState } from "react";
import { evaluateIntegrationDecision, getIntegrationFlowStatus } from "../../api/mlApi";
import "./IntegratedFlow.css";

function IntegratedFlow() {
  const [flow, setFlow] = useState(null);
  const [error, setError] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [pipelineId, setPipelineId] = useState("");

  const loadFlow = async (pid) => {
    setIsRefreshing(true);
    try {
      const res = await getIntegrationFlowStatus(pid || undefined);
      setFlow(res.flow || null);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadFlow("");
  }, []);

  const runDecision = async () => {
    setIsRefreshing(true);
    try {
      const res = await evaluateIntegrationDecision(pipelineId || undefined);
      setFlow(res.flow || null);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsRefreshing(false);
    }
  };

  const getStatusClass = (s) => {
    if (s === "critical") return "status-critical";
    if (s === "warning") return "status-warning";
    return "status-ok";
  };

  return (
    <div className="integrated-flow">
      <div className="flow-header">
        <h2>Integrated Chain of Custody Flow</h2>
        <p className="flow-subtitle">
          GitHub Push -> Component 1 -> Component 2 -> Component 3 -> Component 4 (decision)
        </p>
      </div>

      <div className="flow-controls">
        <input
          value={pipelineId}
          onChange={(e) => setPipelineId(e.target.value)}
          placeholder="Pipeline ID (optional)"
          className="flow-input"
        />
        <button className="flow-button" onClick={() => loadFlow(pipelineId)} disabled={isRefreshing}>
          {isRefreshing ? "Loading..." : "Refresh Flow"}
        </button>
        <button className="flow-button" onClick={runDecision} disabled={isRefreshing}>
          Evaluate Decision
        </button>
      </div>

      {error && <div className="flow-error">{error}</div>}

      {flow ? (
        <>
          <div className="decision-card">
            <div className="decision-row">
              <span>Decision</span>
              <span className={`decision-value ${flow.decision === "BLOCK_DEPLOYMENT" ? "decision-block" : flow.decision === "ALERT" ? "decision-alert" : "decision-allow"}`}>
                {flow.decision}
              </span>
            </div>
            <div className="decision-row">
              <span>Pipeline</span>
              <span>{flow.pipeline_id || "N/A"}</span>
            </div>
            <div className="decision-row">
              <span>Generated</span>
              <span>{flow.generated_at ? new Date(flow.generated_at).toLocaleString() : "N/A"}</span>
            </div>
          </div>

          <div className="flow-steps">
            {(flow.component_steps || []).map((step) => (
              <div key={step.component} className="flow-step">
                <div className="flow-step-top">
                  <span className="flow-step-id">{step.component}</span>
                  <span className={`flow-step-status ${getStatusClass(step.status)}`}>{step.status}</span>
                </div>
                <div className="flow-step-title">{step.title}</div>
                <pre className="flow-step-summary">{JSON.stringify(step.summary || {}, null, 2)}</pre>
              </div>
            ))}
          </div>

          <div className="flow-grid">
            <div className="flow-panel">
              <h3>Pipeline Integrity Verification</h3>
              <pre>{JSON.stringify(flow.pipeline_verification || {}, null, 2)}</pre>
            </div>
            <div className="flow-panel">
              <h3>Forensic Queries</h3>
              <pre>{JSON.stringify(flow.queries || {}, null, 2)}</pre>
            </div>
          </div>

          <div className="timeline-panel">
            <h3>Incident Timeline</h3>
            {Array.isArray(flow.timeline) && flow.timeline.length > 0 ? (
              <div className="timeline-list">
                {flow.timeline.map((event, idx) => (
                  <div key={`${event.type}-${idx}`} className="timeline-item">
                    <div className="timeline-item-top">
                      <span>{event.type}</span>
                      <span>{event.timestamp ? new Date(event.timestamp).toLocaleString() : "N/A"}</span>
                    </div>
                    <div className="timeline-title">{event.title}</div>
                    <pre>{JSON.stringify(event.details || {}, null, 2)}</pre>
                  </div>
                ))}
              </div>
            ) : (
              <div className="timeline-empty">No timeline events.</div>
            )}
          </div>

          <div className="reason-panel">
            <h3>Decision Reasons</h3>
            {Array.isArray(flow.reasons) && flow.reasons.length > 0 ? (
              <ul>
                {flow.reasons.map((r, i) => (
                  <li key={`${r}-${i}`}>{r}</li>
                ))}
              </ul>
            ) : (
              <div>No blocking reason. Flow is currently acceptable.</div>
            )}
          </div>
        </>
      ) : (
        <div className="timeline-empty">No integration flow data yet.</div>
      )}
    </div>
  );
}

export default IntegratedFlow;
