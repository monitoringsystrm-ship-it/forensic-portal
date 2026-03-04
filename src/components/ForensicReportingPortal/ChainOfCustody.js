import React, { useState } from "react";

function ChainOfCustody({ custodyLogs }) {
  const [selectedLog, setSelectedLog] = useState(null);
  const [filterStatus, setFilterStatus] = useState("all");

  const statuses = ["all", "collected", "analyzed", "archived", "exported"];

  const filteredLogs =
    filterStatus === "all"
      ? custodyLogs
      : custodyLogs.filter((log) => log.status === filterStatus);

  const getStatusColor = (status) => {
    switch (status) {
      case "collected":
        return "#2196f3";
      case "analyzed":
        return "#ff9800";
      case "archived":
        return "#4caf50";
      case "exported":
        return "#9c27b0";
      default:
        return "#757575";
    }
  };

  return (
    <div className="chain-of-custody-card">
      <div className="custody-header">
        <h3>Chain of Custody Logs</h3>
        <p className="custody-subtitle">
          Legal-grade evidence tracking for admissibility in investigations
        </p>
      </div>

      <div className="custody-filters">
        <label>Filter by Status:</label>
        <div className="status-filters">
          {statuses.map((status) => (
            <button
              key={status}
              className={`status-filter-button ${
                filterStatus === status ? "active" : ""
              }`}
              onClick={() => setFilterStatus(status)}
              style={{
                borderColor:
                  filterStatus === status && status !== "all"
                    ? getStatusColor(status)
                    : "#e0e0e0",
              }}
            >
              {status === "all" ? "All" : status.charAt(0).toUpperCase() + status.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <div className="custody-stats">
        <div className="custody-stat">
          <span className="stat-label">Total Evidence Items</span>
          <span className="stat-value">{custodyLogs.length}</span>
        </div>
        <div className="custody-stat">
          <span className="stat-label">In Custody</span>
          <span className="stat-value">
            {custodyLogs.filter((l) => l.status !== "exported").length}
          </span>
        </div>
        <div className="custody-stat">
          <span className="stat-label">Exported</span>
          <span className="stat-value">
            {custodyLogs.filter((l) => l.status === "exported").length}
          </span>
        </div>
      </div>

      <div className="custody-logs">
        {filteredLogs.length === 0 ? (
          <p className="no-logs">No custody logs found</p>
        ) : (
          filteredLogs.map((log, index) => (
            <div
              key={log.id}
              className={`custody-log-item ${
                selectedLog === log.id ? "selected" : ""
              }`}
              onClick={() => setSelectedLog(log.id === selectedLog ? null : log.id)}
            >
              <div className="log-header">
                <div className="log-id-section">
                  <span className="log-id">{log.evidenceId}</span>
                  <span
                    className="log-status-badge"
                    style={{ backgroundColor: getStatusColor(log.status) }}
                  >
                    {log.status}
                  </span>
                </div>
                <span className="log-timestamp">
                  {new Date(log.timestamp).toLocaleString()}
                </span>
              </div>

              <div className="log-details">
                <div className="log-detail-row">
                  <span className="detail-label">Evidence Type:</span>
                  <span className="detail-value">{log.evidenceType}</span>
                </div>
                <div className="log-detail-row">
                  <span className="detail-label">Custodian:</span>
                  <span className="detail-value">{log.custodian}</span>
                </div>
                <div className="log-detail-row">
                  <span className="detail-label">Location:</span>
                  <span className="detail-value">{log.location}</span>
                </div>
                {log.previousCustodian && (
                  <div className="log-detail-row">
                    <span className="detail-label">Previous Custodian:</span>
                    <span className="detail-value">{log.previousCustodian}</span>
                  </div>
                )}
                {log.transferReason && (
                  <div className="log-detail-row">
                    <span className="detail-label">Transfer Reason:</span>
                    <span className="detail-value">{log.transferReason}</span>
                  </div>
                )}
              </div>

              {selectedLog === log.id && (
                <div className="log-expanded-details">
                  <div className="expanded-section">
                    <h4>Chain of Custody History</h4>
                    {log.history && log.history.length > 0 ? (
                      <div className="custody-history">
                        {log.history.map((entry, idx) => (
                          <div key={idx} className="history-entry">
                            <div className="history-timestamp">
                              {new Date(entry.timestamp).toLocaleString()}
                            </div>
                            <div className="history-action">{entry.action}</div>
                            <div className="history-custodian">
                              Custodian: {entry.custodian}
                            </div>
                            {entry.notes && (
                              <div className="history-notes">Notes: {entry.notes}</div>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p>No history available</p>
                    )}
                  </div>
                  {log.checksum && (
                    <div className="expanded-section">
                      <h4>Integrity Verification</h4>
                      <div className="checksum-info">
                        <span>Checksum:</span>
                        <span className="checksum-value">{log.checksum}</span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default ChainOfCustody;

