import React, { useState, useEffect } from "react";

function TimelineReconstruction({ timeline, anomalies, onTimelineUpdate }) {
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [reconstructedTimelines, setReconstructedTimelines] = useState([]);

  useEffect(() => {
    if (anomalies.length > 0) {
      reconstructTimelines();
    }
  }, [anomalies]);

  const reconstructTimelines = () => {
    const incidents = groupAnomaliesByIncident(anomalies);
    const timelines = incidents.map((incident) =>
      buildTimeline(incident.anomalies)
    );
    setReconstructedTimelines(timelines);
    if (timelines.length > 0) {
      setSelectedIncident(timelines[0].id);
    }
  };

  const groupAnomaliesByIncident = (anomalies) => {
    const groups = {};
    anomalies.forEach((anomaly) => {
      const incidentId = anomaly.incidentId || "incident-1";
      if (!groups[incidentId]) {
        groups[incidentId] = {
          id: incidentId,
          anomalies: [],
        };
      }
      groups[incidentId].anomalies.push(anomaly);
    });
    return Object.values(groups);
  };

  const buildTimeline = (incidentAnomalies) => {
    const sorted = [...incidentAnomalies].sort(
      (a, b) => new Date(a.timestamp) - new Date(b.timestamp)
    );

    const timelineEvents = sorted.map((anomaly, index) => ({
      id: `event-${index}`,
      type: getEventType(anomaly),
      timestamp: anomaly.timestamp,
      title: anomaly.title,
      description: anomaly.description,
      anomaly: anomaly,
      links: getLinks(anomaly, sorted, index),
    }));

    return {
      id: incidentAnomalies[0]?.incidentId || "incident-1",
      events: timelineEvents,
      startTime: timelineEvents[0]?.timestamp,
      endTime: timelineEvents[timelineEvents.length - 1]?.timestamp,
      totalEvents: timelineEvents.length,
    };
  };

  const getEventType = (anomaly) => {
    if (anomaly.category === "commit-patterns") return "commit";
    if (anomaly.category === "pipeline-tampering") return "pipeline";
    if (anomaly.category === "dependency-anomalies") return "dependency";
    return "unknown";
  };

  const getLinks = (anomaly, allAnomalies, currentIndex) => {
    const links = [];
    if (anomaly.commitHash) {
      links.push({
        type: "commit",
        target: anomaly.commitHash,
      });
    }
    if (anomaly.buildId) {
      links.push({
        type: "build",
        target: anomaly.buildId,
      });
    }
    if (anomaly.artifactId) {
      links.push({
        type: "artifact",
        target: anomaly.artifactId,
      });
    }
    return links;
  };

  const selectedTimeline =
    reconstructedTimelines.find((t) => t.id === selectedIncident) ||
    reconstructedTimelines[0];

  return (
    <div className="timeline-reconstruction-card">
      <div className="timeline-header">
        <h3>Timeline Reconstruction</h3>
        <button
          className="reconstruct-button"
          onClick={reconstructTimelines}
        >
          Reconstruct Timelines
        </button>
      </div>

      {reconstructedTimelines.length > 0 && (
        <div className="incidents-list">
          {reconstructedTimelines.map((timeline) => (
            <button
              key={timeline.id}
              className={`incident-button ${
                selectedIncident === timeline.id ? "active" : ""
              }`}
              onClick={() => setSelectedIncident(timeline.id)}
            >
              {timeline.id} ({timeline.totalEvents} events)
            </button>
          ))}
        </div>
      )}

      {selectedTimeline ? (
        <div className="timeline-view">
          <div className="timeline-info">
            <div className="info-item">
              <span>Incident ID:</span>
              <span>{selectedTimeline.id}</span>
            </div>
            <div className="info-item">
              <span>Total Events:</span>
              <span>{selectedTimeline.totalEvents}</span>
            </div>
            <div className="info-item">
              <span>Start Time:</span>
              <span>{new Date(selectedTimeline.startTime).toLocaleString()}</span>
            </div>
            <div className="info-item">
              <span>End Time:</span>
              <span>{new Date(selectedTimeline.endTime).toLocaleString()}</span>
            </div>
          </div>

          <div className="timeline-events">
            {selectedTimeline.events.map((event, index) => (
              <div key={event.id} className="timeline-event">
                <div className="event-marker">
                  <div className={`marker-dot marker-${event.type}`}></div>
                  {index < selectedTimeline.events.length - 1 && (
                    <div className="timeline-line"></div>
                  )}
                </div>
                <div className="event-content">
                  <div className="event-header">
                    <span className="event-type">{event.type}</span>
                    <span className="event-time">
                      {new Date(event.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <h4 className="event-title">{event.title}</h4>
                  <p className="event-description">{event.description}</p>
                  {event.links && event.links.length > 0 && (
                    <div className="event-links">
                      {event.links.map((link, linkIndex) => (
                        <span key={linkIndex} className="event-link">
                          {link.type}: {link.target}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <p className="no-timeline">
          No timeline data available. Run anomaly detection first.
        </p>
      )}
    </div>
  );
}

export default TimelineReconstruction;

