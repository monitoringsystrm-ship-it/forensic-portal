import React, { useState, useEffect } from "react";
import AnomalyDetector from "./AnomalyDetector";
import TimelineReconstruction from "./TimelineReconstruction";
import TrainingReports from "./TrainingReports";
import IncidentAnalysis from "./IncidentAnalysis";
import { getAnomalyStatus, getLatestAnomalies, inferAnomalies, trainAnomalyModels } from "../../api/mlApi";
import "./AnomalyDetection.css";

function AnomalyDetection() {
  const [anomalies, setAnomalies] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [stats, setStats] = useState(null);
  const [isDetecting, setIsDetecting] = useState(false);
  const [activeTab, setActiveTab] = useState("detector");
  const [selectedModel, setSelectedModel] = useState("commit_pattern");
  const [status, setStatus] = useState(null);
  const [trainResult, setTrainResult] = useState(null);
  const [error, setError] = useState(null);
  const [isTraining, setIsTraining] = useState(false);

  useEffect(() => {
    loadStatus();
  }, []);

  const loadStatus = async () => {
    try {
      const s = await getAnomalyStatus();
      setStatus(s);
      setError(null);
    } catch (e) {
      setError(e.message);
    }
  };

  const handleDetectAnomalies = async () => {
    setIsDetecting(true);
    try {
      const res = await inferAnomalies(selectedModel, 500);
      const mapped = (res.anomalies || []).map((a) => {
        const rawConfidence = Number(a.confidence || 0);
        const confidence = rawConfidence > 1 ? rawConfidence / 100 : rawConfidence;
        const severity =
          confidence >= 0.9 ? "critical" : confidence >= 0.8 ? "high" : confidence >= 0.7 ? "medium" : "low";
        return {
          id: a.id,
          title:
            a.category === "commit-patterns"
              ? "Commit anomaly detected"
              : a.category === "dependency-anomalies"
                ? "Dependency anomaly detected"
                : "Anomaly detected",
          description: "",
          category: a.category,
          severity: severity,
          timestamp: new Date().toISOString(),
          detectionMethod: "ML Model",
          confidence: Number(confidence.toFixed ? confidence.toFixed(4) : confidence),
          incidentId: `${selectedModel}-dataset`,
          evidence: a.details || null,
        };
      });
      setAnomalies(mapped);
      setStats({
        totalAnomalies: mapped.length,
        mlDetections: mapped.length,
        ruleBasedDetections: 0,
        accuracy:
          trainResult &&
          trainResult.summary &&
          trainResult.summary[selectedModel === "commit_pattern" ? "commit_pattern" : "dependency_anomaly"] &&
          trainResult.summary[selectedModel === "commit_pattern" ? "commit_pattern" : "dependency_anomaly"].accuracy
            ? (
                trainResult.summary[
                  selectedModel === "commit_pattern" ? "commit_pattern" : "dependency_anomaly"
                ].accuracy
              ).toFixed(4)
            : "N/A",
      });
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsDetecting(false);
    }
  };

  const refreshFromServer = async () => {
    try {
      const [res, statusData] = await Promise.all([
        getLatestAnomalies(selectedModel),
        getAnomalyStatus(),
      ]);
      const mapped = (res.anomalies || []).map((a) => {
        const rawConfidence = Number(a.confidence || 0);
        const confidence = rawConfidence > 1 ? rawConfidence / 100 : rawConfidence;
        const severity =
          confidence >= 0.9 ? "critical" : confidence >= 0.8 ? "high" : confidence >= 0.7 ? "medium" : "low";
        return {
          id: a.id,
          title:
            a.category === "commit-patterns"
              ? "Commit anomaly detected"
              : a.category === "dependency-anomalies"
                ? "Dependency anomaly detected"
                : "Anomaly detected",
          description: "",
          category: a.category,
          severity: severity,
          timestamp: res.timestamp || new Date().toISOString(),
          detectionMethod: "ML Model",
          confidence: Number(confidence.toFixed ? confidence.toFixed(4) : confidence),
          incidentId: `${selectedModel}-latest`,
          evidence: a.details || null,
        };
      });
      setAnomalies(mapped);
      
      const modelKey = selectedModel === "commit_pattern" ? "commit_pattern" : "dependency_anomaly";
      const metrics = statusData?.training_state?.[modelKey]?.metrics;
      const accuracy = metrics?.accuracy 
        ? metrics.accuracy.toFixed(4)
        : "N/A";
      
      setStats({
        totalAnomalies: mapped.length,
        mlDetections: mapped.length,
        ruleBasedDetections: 0,
        accuracy: accuracy,
      });
      setStatus(statusData);
      setError(null);
    } catch (e) {
      setError(e.message);
    }
  };

  const handleTimelineUpdate = (newTimeline) => {
    setTimeline(newTimeline);
  };

  const handleTrain = async () => {
    try {
      setError(null);
      setIsTraining(true);
      const res = await trainAnomalyModels(["commit_pattern", "dependency_anomaly"], 2000);
      setTrainResult(res);
      await loadStatus();
      setActiveTab("reports");
    } catch (e) {
      setError(e.message);
    } finally {
      setIsTraining(false);
    }
  };

  return (
    <div className="anomaly-detection">
      <div className="detection-header">
        <h2>Automated Forensic Anomaly Detection Engine</h2>
        <p className="subtitle">
          ML and rule-based detection for commits, pipelines, and dependencies
        </p>
      </div>

      <div className="detection-tabs">
        <button
          className={`tab-button ${activeTab === "detector" ? "active" : ""}`}
          onClick={() => setActiveTab("detector")}
        >
          Anomaly Detector
        </button>
        <button
          className={`tab-button ${activeTab === "timeline" ? "active" : ""}`}
          onClick={() => setActiveTab("timeline")}
        >
          Timeline Reconstruction
        </button>
        <button
          className={`tab-button ${activeTab === "incident-analysis" ? "active" : ""}`}
          onClick={() => setActiveTab("incident-analysis")}
        >
          Incident Analysis
        </button>
        <button
          className={`tab-button ${activeTab === "reports" ? "active" : ""}`}
          onClick={() => setActiveTab("reports")}
        >
          Training Reports
        </button>
      </div>

      <div className="detection-content">
        {activeTab === "detector" && (
          <div>
            <div className="filter-section" style={{ marginBottom: 20 }}>
              <div className="filter-group">
                <label>Model:</label>
                <div className="category-filters">
                  <button
                    className={`filter-button ${selectedModel === "commit_pattern" ? "active" : ""}`}
                    onClick={() => setSelectedModel("commit_pattern")}
                  >
                    Commit Patterns
                  </button>
                  <button
                    className={`filter-button ${selectedModel === "dependency_anomaly" ? "active" : ""}`}
                    onClick={() => setSelectedModel("dependency_anomaly")}
                  >
                    Dependency Anomalies
                  </button>
                </div>
              </div>
              <div className="filter-group">
                <label>Actions:</label>
                <div className="category-filters">
                  <button className="filter-button" onClick={handleTrain}>
                    {isTraining ? "Training..." : "Train Models"}
                  </button>
                  <button className="filter-button" onClick={refreshFromServer}>
                    Refresh Results
                  </button>
                </div>
              </div>
            </div>

            {error && <p className="no-anomalies">{error}</p>}

            <AnomalyDetector
              anomalies={anomalies}
              stats={stats}
              isDetecting={isDetecting}
              onDetect={handleDetectAnomalies}
            />
          </div>
        )}
        {activeTab === "timeline" && (
          <TimelineReconstruction
            timeline={timeline}
            anomalies={anomalies}
            onTimelineUpdate={handleTimelineUpdate}
          />
        )}
        {activeTab === "reports" && (
          <TrainingReports status={status} lastTrainSummary={trainResult} error={error} />
        )}
        {activeTab === "incident-analysis" && <IncidentAnalysis />}
      </div>
    </div>
  );
}

export default AnomalyDetection;

