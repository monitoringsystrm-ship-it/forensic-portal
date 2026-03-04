import React, { useState } from "react";

function EvidenceVisualization({ forensicData }) {
  const [selectedTimeframe, setSelectedTimeframe] = useState("all");
  const [selectedType, setSelectedType] = useState("all");

  if (!forensicData) {
    return <div className="loading">Loading forensic data...</div>;
  }

  const timeframes = ["all", "24h", "7d", "30d", "custom"];
  const evidenceTypes = [
    "all",
    "commits",
    "builds",
    "artifacts",
    "dependencies",
  ];

  const filterData = () => {
    let filtered = [...forensicData.timeline];

    if (selectedType !== "all") {
      filtered = filtered.filter((item) => item.type === selectedType);
    }

    if (selectedTimeframe !== "all") {
      const now = new Date();
      let cutoff;
      switch (selectedTimeframe) {
        case "24h":
          cutoff = new Date(now - 24 * 60 * 60 * 1000);
          break;
        case "7d":
          cutoff = new Date(now - 7 * 24 * 60 * 60 * 1000);
          break;
        case "30d":
          cutoff = new Date(now - 30 * 24 * 60 * 60 * 1000);
          break;
        default:
          cutoff = null;
      }
      if (cutoff) {
        filtered = filtered.filter((item) => new Date(item.timestamp) >= cutoff);
      }
    }

    return filtered;
  };

  const filteredTimeline = filterData();

  const getTypeColor = (type) => {
    switch (type) {
      case "commit":
        return "#2196f3";
      case "build":
        return "#4caf50";
      case "artifact":
        return "#ff9800";
      case "dependency":
        return "#9c27b0";
      default:
        return "#757575";
    }
  };

  return (
    <div className="evidence-visualization-card">
      <div className="viz-header">
        <h3>Evidence Timeline Visualization</h3>
        <div className="viz-filters">
          <select
            value={selectedTimeframe}
            onChange={(e) => setSelectedTimeframe(e.target.value)}
            className="filter-select"
          >
            {timeframes.map((tf) => (
              <option key={tf} value={tf}>
                {tf === "all" ? "All Time" : tf.toUpperCase()}
              </option>
            ))}
          </select>
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="filter-select"
          >
            {evidenceTypes.map((type) => (
              <option key={type} value={type}>
                {type === "all" ? "All Types" : type.charAt(0).toUpperCase() + type.slice(1)}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="timeline-stats">
        <div className="stat-box">
          <span className="stat-label">Total Events</span>
          <span className="stat-value">{filteredTimeline.length}</span>
        </div>
        <div className="stat-box">
          <span className="stat-label">Commits</span>
          <span className="stat-value">
            {filteredTimeline.filter((e) => e.type === "commit").length}
          </span>
        </div>
        <div className="stat-box">
          <span className="stat-label">Builds</span>
          <span className="stat-value">
            {filteredTimeline.filter((e) => e.type === "build").length}
          </span>
        </div>
        <div className="stat-box">
          <span className="stat-label">Artifacts</span>
          <span className="stat-value">
            {filteredTimeline.filter((e) => e.type === "artifact").length}
          </span>
        </div>
      </div>

      <div className="timeline-view">
        {filteredTimeline.length === 0 ? (
          <p className="no-data">No evidence found for selected filters</p>
        ) : (
          filteredTimeline.map((event, index) => (
            <div key={index} className="timeline-event-item">
              <div className="event-marker-container">
                <div
                  className="event-marker-dot"
                  style={{ backgroundColor: getTypeColor(event.type) }}
                ></div>
                {index < filteredTimeline.length - 1 && (
                  <div className="event-connector-line"></div>
                )}
              </div>
              <div className="event-details">
                <div className="event-header-row">
                  <span
                    className="event-type-badge"
                    style={{ backgroundColor: getTypeColor(event.type) }}
                  >
                    {event.type}
                  </span>
                  <span className="event-timestamp">
                    {new Date(event.timestamp).toLocaleString()}
                  </span>
                </div>
                <h4 className="event-title">{event.title}</h4>
                <p className="event-description">{event.description}</p>
                {event.metadata && (
                  <div className="event-metadata">
                    {Object.entries(event.metadata).map(([key, value]) => (
                      <div key={key} className="metadata-entry">
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

export default EvidenceVisualization;

