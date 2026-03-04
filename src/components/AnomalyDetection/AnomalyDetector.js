import React, { useState } from "react";

function AnomalyDetector({ anomalies, stats, isDetecting, onDetect }) {
  const [selectedCategory, setSelectedCategory] = useState("all");
  const [selectedSeverity, setSelectedSeverity] = useState("all");

  const categories = [
    { id: "commit-patterns", label: "Unusual Commit Patterns", count: 0 },
    { id: "pipeline-tampering", label: "Pipeline Script Tampering", count: 0 },
    { id: "dependency-anomalies", label: "Dependency Anomalies", count: 0 },
    { id: "all", label: "All Anomalies", count: 0 },
  ];

  const severities = ["critical", "high", "medium", "low"];

  const getCategoryCount = (categoryId) => {
    if (categoryId === "all") return anomalies.length;
    return anomalies.filter((a) => a.category === categoryId).length;
  };

  const getSeverityCount = (severity) => {
    return anomalies.filter((a) => a.severity === severity).length;
  };

  const filteredAnomalies = anomalies.filter((anomaly) => {
    const categoryMatch =
      selectedCategory === "all" || anomaly.category === selectedCategory;
    const severityMatch =
      selectedSeverity === "all" || anomaly.severity === selectedSeverity;
    return categoryMatch && severityMatch;
  });

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "critical":
        return "#d32f2f";
      case "high":
        return "#f57c00";
      case "medium":
        return "#fbc02d";
      case "low":
        return "#388e3c";
      default:
        return "#757575";
    }
  };

  return (
    <div className="anomaly-detector-card">
      <div className="detector-header">
        <h3>Anomaly Detection</h3>
        <button
          className="detect-button"
          onClick={onDetect}
          disabled={isDetecting}
        >
          {isDetecting ? "Detecting..." : "Run Detection"}
        </button>
      </div>

      {stats && (
        <div className="detection-stats">
          <div className="stat-item">
            <span className="stat-label">Total Anomalies:</span>
            <span className="stat-value">{stats.totalAnomalies}</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">ML Detections:</span>
            <span className="stat-value">{stats.mlDetections}</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Rule-Based:</span>
            <span className="stat-value">{stats.ruleBasedDetections}</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Accuracy:</span>
            <span className="stat-value">{stats.accuracy}</span>
          </div>
        </div>
      )}

      <div className="filter-section">
        <div className="filter-group">
          <label>Category:</label>
          <div className="category-filters">
            {categories.map((cat) => (
              <button
                key={cat.id}
                className={`filter-button ${
                  selectedCategory === cat.id ? "active" : ""
                }`}
                onClick={() => setSelectedCategory(cat.id)}
              >
                {cat.label} ({getCategoryCount(cat.id)})
              </button>
            ))}
          </div>
        </div>

        <div className="filter-group">
          <label>Severity:</label>
          <div className="severity-filters">
            <button
              className={`filter-button ${
                selectedSeverity === "all" ? "active" : ""
              }`}
              onClick={() => setSelectedSeverity("all")}
            >
              All ({anomalies.length})
            </button>
            {severities.map((sev) => (
              <button
                key={sev}
                className={`filter-button severity-${sev} ${
                  selectedSeverity === sev ? "active" : ""
                }`}
                onClick={() => setSelectedSeverity(sev)}
                style={{
                  borderColor:
                    selectedSeverity === sev ? getSeverityColor(sev) : "#e0e0e0",
                }}
              >
                {sev.toUpperCase()} ({getSeverityCount(sev)})
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="anomalies-list">
        {filteredAnomalies.length === 0 ? (
          <p className="no-anomalies">No anomalies detected</p>
        ) : (
          filteredAnomalies.map((anomaly, index) => (
            <div key={index} className="anomaly-item">
              <div className="anomaly-header">
                <div className="anomaly-title-section">
                  <span
                    className="severity-badge"
                    style={{ backgroundColor: getSeverityColor(anomaly.severity) }}
                  >
                    {anomaly.severity}
                  </span>
                  <span className="anomaly-title">{anomaly.title}</span>
                </div>
                <span className="anomaly-timestamp">
                  {new Date(anomaly.timestamp).toLocaleString()}
                </span>
              </div>
              <div className="anomaly-content">
                <p className="anomaly-description">{anomaly.description}</p>
                <div className="anomaly-details">
                  <div className="detail-item">
                    <span className="detail-label">Category:</span>
                    <span className="detail-value">{anomaly.category}</span>
                  </div>
                  <div className="detail-item">
                    <span className="detail-label">Detection Method:</span>
                    <span className="detail-value">{anomaly.detectionMethod}</span>
                  </div>
                  {anomaly.confidence && (
                    <div className="detail-item">
                      <span className="detail-label">Confidence:</span>
                      <span className="detail-value">{anomaly.confidence}</span>
                    </div>
                  )}
                </div>
                {anomaly.evidence && (
                  <div className="anomaly-evidence">
                    <strong>Evidence:</strong>
                    <pre>{JSON.stringify(anomaly.evidence, null, 2)}</pre>
                  </div>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default AnomalyDetector;

