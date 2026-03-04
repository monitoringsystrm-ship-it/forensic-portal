import React, { useState, useEffect } from "react";
import EvidenceVisualization from "./EvidenceVisualization";
import IntegrityProofs from "./IntegrityProofs";
import ChainOfCustody from "./ChainOfCustody";
import ReportGenerator from "./ReportGenerator";
import ReportingPortalModels from "./ReportingPortalModels";
import { getReportingPortalForensicData, getReportingPortalCustody } from "../../api/mlApi";
import "./ForensicReportingPortal.css";

function ForensicReportingPortal() {
  const [activeTab, setActiveTab] = useState("visualization");
  const [forensicData, setForensicData] = useState(null);
  const [custodyLogs, setCustodyLogs] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    refreshAll();
    const interval = setInterval(() => {
      refreshAll();
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const refreshAll = async () => {
    try {
      const [fd, cl] = await Promise.all([getReportingPortalForensicData(), getReportingPortalCustody()]);
      setForensicData(fd);
      setCustodyLogs(cl.custodyLogs || []);
      setError(null);
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div className="forensic-reporting-portal">
      <div className="portal-header">
        <h2>Forensic Chain-of-Custody & Reporting Portal</h2>
        <p className="subtitle">
          Legal-grade reporting aligned with ISO/IEC 27037 and NIST SP 800-86
        </p>
      </div>

      <div className="portal-tabs">
        <button
          className={`portal-tab-button ${
            activeTab === "visualization" ? "active" : ""
          }`}
          onClick={() => setActiveTab("visualization")}
        >
          Evidence Visualization
        </button>
        <button
          className={`portal-tab-button ${
            activeTab === "integrity" ? "active" : ""
          }`}
          onClick={() => setActiveTab("integrity")}
        >
          Integrity Proofs
        </button>
        <button
          className={`portal-tab-button ${
            activeTab === "custody" ? "active" : ""
          }`}
          onClick={() => setActiveTab("custody")}
        >
          Chain of Custody
        </button>
        <button
          className={`portal-tab-button ${
            activeTab === "reports" ? "active" : ""
          }`}
          onClick={() => setActiveTab("reports")}
        >
          Report Generator
        </button>
        <button
          className={`portal-tab-button ${
            activeTab === "ml" ? "active" : ""
          }`}
          onClick={() => setActiveTab("ml")}
        >
          ML Models
        </button>
      </div>

      <div className="portal-content">
        {error && <div className="loading">{error}</div>}
        {activeTab === "visualization" && (
          <EvidenceVisualization forensicData={forensicData} />
        )}
        {activeTab === "integrity" && (
          <IntegrityProofs forensicData={forensicData} />
        )}
        {activeTab === "custody" && <ChainOfCustody custodyLogs={custodyLogs} />}
        {activeTab === "reports" && (
          <ReportGenerator forensicData={forensicData} custodyLogs={custodyLogs} />
        )}
        {activeTab === "ml" && <ReportingPortalModels />}
      </div>
    </div>
  );
}

export default ForensicReportingPortal;

