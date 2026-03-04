import React, { useState } from "react";
import { generateReportingPortalReport } from "../../api/mlApi";

function ReportGenerator({ forensicData, custodyLogs }) {
  const [reportConfig, setReportConfig] = useState({
    standard: "ISO/IEC 27037",
    format: "PDF",
    includeTimeline: true,
    includeIntegrityProofs: true,
    includeCustodyLogs: true,
    includeEvidence: true,
    dateRange: "all",
  });
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedReport, setGeneratedReport] = useState(null);

  const standards = ["ISO/IEC 27037", "NIST SP 800-86", "Both"];
  const formats = ["PDF", "JSON", "XML"];

  const handleConfigChange = (field, value) => {
    setReportConfig((prev) => ({
      ...prev,
      [field]: value,
    }));
  };

  const handleGenerateReport = async () => {
    setIsGenerating(true);
    try {
      const res = await generateReportingPortalReport(reportConfig);
      setGeneratedReport(res.report);
    } catch (error) {
      console.error("Error generating report:", error);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleExportReport = async (format) => {
    if (!generatedReport) return;
    try {
      const blob = new Blob([JSON.stringify(generatedReport, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `forensic-report-${generatedReport.id}.${String(format).toLowerCase()}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Error exporting report:", error);
      alert("Error exporting report");
    }
  };

  return (
    <div className="report-generator-card">
      <div className="generator-header">
        <h3>Forensic Report Generator</h3>
        <p className="generator-subtitle">
          Generate legal-grade reports aligned with ISO/IEC 27037 and NIST SP 800-86
        </p>
      </div>

      <div className="report-config-section">
        <h4>Report Configuration</h4>
        <div className="config-grid">
          <div className="config-item">
            <label>
              Standard:
              <select
                value={reportConfig.standard}
                onChange={(e) => handleConfigChange("standard", e.target.value)}
                className="config-select"
              >
                {standards.map((std) => (
                  <option key={std} value={std}>
                    {std}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className="config-item">
            <label>
              Export Format:
              <select
                value={reportConfig.format}
                onChange={(e) => handleConfigChange("format", e.target.value)}
                className="config-select"
              >
                {formats.map((fmt) => (
                  <option key={fmt} value={fmt}>
                    {fmt}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className="config-item">
            <label>
              Date Range:
              <select
                value={reportConfig.dateRange}
                onChange={(e) => handleConfigChange("dateRange", e.target.value)}
                className="config-select"
              >
                <option value="all">All Time</option>
                <option value="24h">Last 24 Hours</option>
                <option value="7d">Last 7 Days</option>
                <option value="30d">Last 30 Days</option>
                <option value="custom">Custom Range</option>
              </select>
            </label>
          </div>
        </div>

        <div className="config-checkboxes">
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={reportConfig.includeTimeline}
              onChange={(e) =>
                handleConfigChange("includeTimeline", e.target.checked)
              }
            />
            Include Evidence Timeline
          </label>
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={reportConfig.includeIntegrityProofs}
              onChange={(e) =>
                handleConfigChange("includeIntegrityProofs", e.target.checked)
              }
            />
            Include Integrity Proofs
          </label>
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={reportConfig.includeCustodyLogs}
              onChange={(e) =>
                handleConfigChange("includeCustodyLogs", e.target.checked)
              }
            />
            Include Chain of Custody Logs
          </label>
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={reportConfig.includeEvidence}
              onChange={(e) =>
                handleConfigChange("includeEvidence", e.target.checked)
              }
            />
            Include Evidence Details
          </label>
        </div>

        <div className="config-actions">
          <button
            className="generate-button"
            onClick={handleGenerateReport}
            disabled={isGenerating}
          >
            {isGenerating ? "Generating..." : "Generate Report"}
          </button>
        </div>
      </div>

      {generatedReport && (
        <div className="generated-report-section">
          <h4>Generated Report</h4>
          <div className="report-info">
            <div className="report-info-item">
              <span>Report ID:</span>
              <span>{generatedReport.id}</span>
            </div>
            <div className="report-info-item">
              <span>Standard:</span>
              <span>{generatedReport.standard}</span>
            </div>
            <div className="report-info-item">
              <span>Generated:</span>
              <span>{new Date(generatedReport.generatedAt).toLocaleString()}</span>
            </div>
            <div className="report-info-item">
              <span>Evidence Items:</span>
              <span>{generatedReport.evidenceCount}</span>
            </div>
            <div className="report-info-item">
              <span>Pages:</span>
              <span>{generatedReport.pages}</span>
            </div>
          </div>

          <div className="report-preview">
            <h5>Report Preview</h5>
            <div className="preview-content">
              <div className="preview-section">
                <strong>Executive Summary</strong>
                <p>{generatedReport.summary}</p>
              </div>
              {generatedReport.sections && (
                <div className="preview-sections">
                  {generatedReport.sections.map((section, idx) => (
                    <div key={idx} className="preview-section">
                      <strong>{section.title}</strong>
                      <p>{section.content.substring(0, 200)}...</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="export-actions">
            <h5>Export Report</h5>
            <div className="export-buttons">
              <button
                className="export-button"
                onClick={() => handleExportReport("PDF")}
              >
                Export as PDF
              </button>
              <button
                className="export-button"
                onClick={() => handleExportReport("JSON")}
              >
                Export as JSON
              </button>
              <button
                className="export-button"
                onClick={() => handleExportReport("XML")}
              >
                Export as XML
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default ReportGenerator;

