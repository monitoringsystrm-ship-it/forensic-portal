import React, { useState } from "react";

function EvidenceCollector({ evidence, isCollecting, onStartCollection }) {
  const [selectedType, setSelectedType] = useState("all");

  const evidenceTypes = [
    { id: "github-event", label: "GitHub Events", count: 0 },
    { id: "build-logs", label: "Jenkins Build Logs", count: 0 },
    { id: "docker-build", label: "Docker Build Context", count: 0 },
    { id: "command-alert", label: "Command Alerts", count: 0 },
    { id: "env-vars", label: "Environment Variables", count: 0 },
    { id: "secrets-access", label: "Secrets Access Events", count: 0 },
    { id: "artifacts", label: "Build Artifacts", count: 0 },
    { id: "pipeline-config", label: "Pipeline Config Files", count: 0 },
  ];

  const filteredEvidence =
    selectedType === "all"
      ? evidence
      : evidence.filter((item) => item.type === selectedType);

  const getTypeCount = (typeId) => {
    return evidence.filter((item) => item.type === typeId).length;
  };

  return (
    <div className="evidence-collector-card">
      <div className="collector-header">
        <h3>Evidence Collection</h3>
        <button
          className="collect-button"
          onClick={onStartCollection}
          disabled={isCollecting}
        >
          {isCollecting ? "Collecting..." : "Start Collection"}
        </button>
      </div>

      <div className="evidence-types">
        {evidenceTypes.map((type) => (
          <div
            key={type.id}
            className={`evidence-type-item ${
              selectedType === type.id ? "active" : ""
            }`}
            onClick={() => setSelectedType(type.id)}
          >
            <span className="type-label">{type.label}</span>
            <span className="type-count">{getTypeCount(type.id)}</span>
          </div>
        ))}
        <div
          className={`evidence-type-item ${
            selectedType === "all" ? "active" : ""
          }`}
          onClick={() => setSelectedType("all")}
        >
          <span className="type-label">All Evidence</span>
          <span className="type-count">{evidence.length}</span>
        </div>
      </div>

      <div className="evidence-list">
        {filteredEvidence.length === 0 ? (
          <p className="no-evidence">No evidence collected yet</p>
        ) : (
          filteredEvidence.map((item, index) => (
            <div key={index} className="evidence-item">
              <div className="evidence-header">
                <span className="evidence-type">{item.type}</span>
                <span className="evidence-timestamp">
                  {new Date(item.timestamp).toLocaleString()}
                </span>
              </div>
              <div className="evidence-content">
                <p>{item.description}</p>
                {item.metadata && (
                  <div className="evidence-metadata">
                    {Object.entries(item.metadata).map(([key, value]) => (
                      <div key={key} className="metadata-item">
                        <span className="metadata-key">{key}:</span>
                        <span className="metadata-value">{String(value)}</span>
                      </div>
                    ))}
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

export default EvidenceCollector;

