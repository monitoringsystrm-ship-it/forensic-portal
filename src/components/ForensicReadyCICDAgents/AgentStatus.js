import React from "react";

function AgentStatus({ agents, metrics }) {
  const getStatusColor = (status) => {
    switch (status) {
      case "active":
        return "#4caf50";
      case "inactive":
        return "#f44336";
      case "warning":
        return "#ff9800";
      default:
        return "#9e9e9e";
    }
  };

  return (
    <div className="agent-status-card">
      <h3>Agent Status</h3>
      <div className="status-overview">
        {metrics && (
          <div className="metric-item">
            <span className="metric-label">Total Agents:</span>
            <span className="metric-value">{agents.length}</span>
          </div>
        )}
        {metrics && (
          <div className="metric-item">
            <span className="metric-label">Active Agents:</span>
            <span className="metric-value">
              {typeof metrics.activeAgents === "number" ? metrics.activeAgents : "N/A"}
            </span>
          </div>
        )}
        {metrics && (
          <div className="metric-item">
            <span className="metric-label">Performance Overhead:</span>
            <span className="metric-value">
              {typeof metrics.performanceOverhead === "number" ? `${metrics.performanceOverhead}%` : "N/A"}
            </span>
          </div>
        )}
        {metrics && (
          <div className="metric-item">
            <span className="metric-label">Evidence Items:</span>
            <span className="metric-value">
              {typeof metrics.totalEvidenceItems === "number" ? metrics.totalEvidenceItems : "N/A"}
            </span>
          </div>
        )}
        {metrics && (
          <div className="metric-item">
            <span className="metric-label">Command Alerts:</span>
            <span className="metric-value">
              {typeof metrics.commandAlerts === "number" ? metrics.commandAlerts : "N/A"}
            </span>
          </div>
        )}
      </div>

      <div className="agents-list">
        {agents.length === 0 ? (
          <div className="no-evidence">No agents connected</div>
        ) : null}
        {agents.map((agent) => (
          <div key={agent.id} className="agent-item">
            <div className="agent-header">
              <span className="agent-id">{agent.id}</span>
              <span
                className="status-badge"
                style={{ backgroundColor: getStatusColor(agent.status) }}
              >
                {agent.status}
              </span>
            </div>
            <div className="agent-details">
              <div className="detail-row">
                <span>Type:</span>
                <span>{agent.type || "N/A"}</span>
              </div>
              <div className="detail-row">
                <span>Builds Captured:</span>
                <span>{typeof agent.buildsCaptured === "number" ? agent.buildsCaptured : "N/A"}</span>
              </div>
              <div className="detail-row">
                <span>Evidence Items:</span>
                <span>{typeof agent.evidenceItems === "number" ? agent.evidenceItems : "N/A"}</span>
              </div>
              <div className="detail-row">
                <span>Last Seen:</span>
                <span>{agent.lastSeen ? new Date(agent.lastSeen).toLocaleString() : "N/A"}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default AgentStatus;

