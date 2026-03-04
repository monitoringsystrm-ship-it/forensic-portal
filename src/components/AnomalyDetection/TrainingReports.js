import React from "react";
import { getAnomalyReportUrl } from "../../api/mlApi";

function TrainingReports({ status, lastTrainSummary, error }) {
  const metrics =
    (lastTrainSummary && lastTrainSummary.summary) || undefined;

  return (
    <div className="detection-rules-card">
      <div className="rules-header">
        <h3>Training Reports</h3>
      </div>

      {error && <p className="no-anomalies">{error}</p>}

      {status && (
        <div className="models-list">
          <div className="model-item">
            <div className="model-header">
              <div className="model-title-section">
                <span className="model-name">Commit Pattern</span>
              </div>
              <span
                className={`model-status status-${
                  status.models.commit_pattern.is_trained ? "trained" : "training"
                }`}
              >
                {status.models.commit_pattern.is_trained ? "trained" : "not trained"}
              </span>
            </div>
          </div>
          <div className="model-item">
            <div className="model-header">
              <div className="model-title-section">
                <span className="model-name">Dependency Anomaly</span>
              </div>
              <span
                className={`model-status status-${
                  status.models.dependency_anomaly.is_trained ? "trained" : "training"
                }`}
              >
                {status.models.dependency_anomaly.is_trained ? "trained" : "not trained"}
              </span>
            </div>
          </div>
        </div>
      )}

      {metrics && (
        <div className="rules-section">
          <h4>Metrics</h4>
          <div className="rules-list">
            {Object.entries(metrics).map(([modelName, m]) => (
              <div key={modelName} className="rule-item">
                <div className="rule-header">
                  <div className="rule-title-section">
                    <span className="rule-name">{modelName}</span>
                  </div>
                </div>
                <div className="model-details">
                  {"accuracy" in m && (
                    <div className="model-detail-item">
                      <span>Accuracy:</span>
                      <span>{m.accuracy.toFixed(4)}</span>
                    </div>
                  )}
                  {"precision" in m && (
                    <div className="model-detail-item">
                      <span>Precision:</span>
                      <span>{m.precision.toFixed(4)}</span>
                    </div>
                  )}
                  {"recall" in m && (
                    <div className="model-detail-item">
                      <span>Recall:</span>
                      <span>{m.recall.toFixed(4)}</span>
                    </div>
                  )}
                  {"f1" in m && (
                    <div className="model-detail-item">
                      <span>F1:</span>
                      <span>{m.f1.toFixed(4)}</span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="rules-section">
        <h4>Visualizations</h4>
        <div className="rules-list">
          <div className="rule-item">
            <p className="rule-description">Confusion Matrix (Commit)</p>
            <img
              src={getAnomalyReportUrl("commit_confusion_matrix.png")}
              alt="commit confusion matrix"
              style={{ maxWidth: "100%" }}
              onError={(e) => {
                e.currentTarget.style.display = "none";
              }}
            />
          </div>
          <div className="rule-item">
            <p className="rule-description">Feature Correlation (Commit)</p>
            <img
              src={getAnomalyReportUrl("commit_feature_correlation.png")}
              alt="commit correlation"
              style={{ maxWidth: "100%" }}
              onError={(e) => {
                e.currentTarget.style.display = "none";
              }}
            />
          </div>
          <div className="rule-item">
            <p className="rule-description">Label Distribution (Commit)</p>
            <img
              src={getAnomalyReportUrl("commit_label_distribution.png")}
              alt="commit label distribution"
              style={{ maxWidth: "100%" }}
              onError={(e) => {
                e.currentTarget.style.display = "none";
              }}
            />
          </div>
          <div className="rule-item">
            <p className="rule-description">Confusion Matrix (Dependency)</p>
            <img
              src={getAnomalyReportUrl("dependency_confusion_matrix.png")}
              alt="dependency confusion matrix"
              style={{ maxWidth: "100%" }}
              onError={(e) => {
                e.currentTarget.style.display = "none";
              }}
            />
          </div>
          <div className="rule-item">
            <p className="rule-description">Feature Correlation (Dependency)</p>
            <img
              src={getAnomalyReportUrl("dependency_feature_correlation.png")}
              alt="dependency correlation"
              style={{ maxWidth: "100%" }}
              onError={(e) => {
                e.currentTarget.style.display = "none";
              }}
            />
          </div>
          <div className="rule-item">
            <p className="rule-description">Label Distribution (Dependency)</p>
            <img
              src={getAnomalyReportUrl("dependency_label_distribution.png")}
              alt="dependency label distribution"
              style={{ maxWidth: "100%" }}
              onError={(e) => {
                e.currentTarget.style.display = "none";
              }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

export default TrainingReports;
