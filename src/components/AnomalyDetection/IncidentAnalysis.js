import React, { useState } from "react";
import {
  ingestIncidentGithubCommits,
  ingestIncidentDependencyHistory,
  ingestIncidentJenkinsPatterns,
  ingestIncidentThreatIntel,
  analyzeIncidents,
  getLatestIncidentAnalysis,
} from "../../api/mlApi";

function IncidentAnalysis() {
  const [error, setError] = useState(null);
  const [isWorking, setIsWorking] = useState(false);
  const [months, setMonths] = useState(12);
  const [result, setResult] = useState(null);

  const seedData = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const now = new Date().toISOString();
      await ingestIncidentGithubCommits([
        {
          sha: "abc123",
          author: "new-contributor",
          timestamp: now,
          message: "fix",
          files_changed: 45,
          lines_added: 2500,
          lines_deleted: 900,
          diff: "eval(atob('ZXZpbA==')) https://suspicious.example",
          build_id: "jenkins-456",
        },
      ]);
      await ingestIncidentDependencyHistory([
        {
          id: "dep-1",
          timestamp: now,
          name: "reacct",
          version: "18.2.0",
          previous_version: "",
          build_id: "jenkins-456",
          maintainer_count: 1,
          github_stars: 1,
          download_count: 80,
        },
      ]);
      await ingestIncidentJenkinsPatterns([
        {
          build_id: "jenkins-456",
          pipeline_name: "forensic-portal",
          timestamp: now,
          duration_sec: 2800,
          success: false,
          cpu_percent: 95,
          memory_mb: 7800,
          image_size_mb: 2200,
        },
      ]);
      await ingestIncidentThreatIntel({
        compromised_packages: ["reacct"],
        npm_advisories: [{ package: "reacct", severity: "high", id: "npm-adv-1" }],
        cves: [{ id: "CVE-2024-0001", package: "reacct", severity: "high" }],
        github_advisories: [{ package: "reacct", advisory: "GHSA-test" }],
      });
      const analyzed = await analyzeIncidents(months);
      setResult(analyzed.analysis || null);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  const runAnalysis = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const analyzed = await analyzeIncidents(months);
      setResult(analyzed.analysis || null);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  const loadLatest = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const latest = await getLatestIncidentAnalysis();
      setResult(latest.latest_analysis || null);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  return (
    <div className="detection-rules-card">
      <div className="rules-header">
        <h3>Incident Analysis</h3>
      </div>
      {error && <p className="no-anomalies">{error}</p>}
      <div className="filter-section">
        <div className="filter-group">
          <label>Analysis Window (months):</label>
          <input
            type="number"
            min="1"
            max="12"
            value={months}
            onChange={(e) => setMonths(Number(e.target.value || 12))}
            style={{ width: 120, padding: 8, border: "1px solid #ddd", borderRadius: 4 }}
          />
        </div>
        <div className="category-filters">
          <button className="filter-button" onClick={seedData} disabled={isWorking}>
            {isWorking ? "Working..." : "Seed Demo + Analyze"}
          </button>
          <button className="filter-button" onClick={runAnalysis} disabled={isWorking}>
            Run Analysis
          </button>
          <button className="filter-button" onClick={loadLatest} disabled={isWorking}>
            Load Latest
          </button>
        </div>
      </div>

      {result ? (
        <div className="rules-section">
          <h4>Outputs</h4>
          <div className="model-details" style={{ flexWrap: "wrap" }}>
            <div className="model-detail-item">
              <span>Commit Anomalies:</span>
              <span>{Array.isArray(result.commit_anomalies) ? result.commit_anomalies.length : 0}</span>
            </div>
            <div className="model-detail-item">
              <span>Dependency Risks:</span>
              <span>{Array.isArray(result.dependency_risks) ? result.dependency_risks.length : 0}</span>
            </div>
            <div className="model-detail-item">
              <span>Build Anomalies:</span>
              <span>{Array.isArray(result.build_anomalies) ? result.build_anomalies.length : 0}</span>
            </div>
            <div className="model-detail-item">
              <span>Timeline Events:</span>
              <span>{Array.isArray(result.timeline) ? result.timeline.length : 0}</span>
            </div>
          </div>

          <div className="rules-list" style={{ marginTop: 12 }}>
            <div className="rule-item">
              <div className="rule-header">
                <div className="rule-title-section">
                  <span className="rule-name">Top Commit Anomaly</span>
                </div>
              </div>
              <pre>{JSON.stringify((result.commit_anomalies || [])[0] || {}, null, 2)}</pre>
            </div>
            <div className="rule-item">
              <div className="rule-header">
                <div className="rule-title-section">
                  <span className="rule-name">Top Dependency Risk</span>
                </div>
              </div>
              <pre>{JSON.stringify((result.dependency_risks || [])[0] || {}, null, 2)}</pre>
            </div>
            <div className="rule-item">
              <div className="rule-header">
                <div className="rule-title-section">
                  <span className="rule-name">Top Build Anomaly</span>
                </div>
              </div>
              <pre>{JSON.stringify((result.build_anomalies || [])[0] || {}, null, 2)}</pre>
            </div>
            <div className="rule-item">
              <div className="rule-header">
                <div className="rule-title-section">
                  <span className="rule-name">Trend Snapshot</span>
                </div>
              </div>
              <pre>{JSON.stringify(result.trends || {}, null, 2)}</pre>
            </div>
          </div>
        </div>
      ) : (
        <p className="no-anomalies">No incident analysis report yet.</p>
      )}
    </div>
  );
}

export default IncidentAnalysis;
