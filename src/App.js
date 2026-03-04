import React, { useEffect, useState } from "react";
import ForensicReadyCICDAgents from "./components/ForensicReadyCICDAgents/ForensicReadyCICDAgents";
import AnomalyDetection from "./components/AnomalyDetection/AnomalyDetection";
import ForensicReportingPortal from "./components/ForensicReportingPortal/ForensicReportingPortal";
import IntegrityVerification from "./components/IntegrityVerification/IntegrityVerification";
import IntegratedFlow from "./components/IntegratedFlow/IntegratedFlow";
import { getMlHealth } from "./api/mlApi";
import "./App.css";

function App() {
  const [activeTab, setActiveTab] = useState("integrated-flow");
  const [mlHealth, setMlHealth] = useState(null);

  useEffect(() => {
    getMlHealth()
      .then((h) => setMlHealth(h))
      .catch(() => setMlHealth(null));
  }, []);

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h1>Forensic Monitoring System</h1>
        <p style={styles.status}>
          Status: {mlHealth && mlHealth.success ? "Connected" : "Disconnected"}
        </p>
      </div>

      <div style={styles.tabs}>
        <button
          style={{
            ...styles.tab,
            ...(activeTab === "integrated-flow" ? styles.tabActive : {}),
          }}
          onClick={() => setActiveTab("integrated-flow")}
        >
          Integrated Flow
        </button>
        <button
          style={{
            ...styles.tab,
            ...(activeTab === "cicd-agents" ? styles.tabActive : {}),
          }}
          onClick={() => setActiveTab("cicd-agents")}
        >
          CI/CD Agents
        </button>
        <button
          style={{
            ...styles.tab,
            ...(activeTab === "anomaly-detection" ? styles.tabActive : {}),
          }}
          onClick={() => setActiveTab("anomaly-detection")}
        >
          Anomaly Detection
        </button>
        <button
          style={{
            ...styles.tab,
            ...(activeTab === "integrity-verification" ? styles.tabActive : {}),
          }}
          onClick={() => setActiveTab("integrity-verification")}
        >
          Integrity Verification
        </button>
        <button
          style={{
            ...styles.tab,
            ...(activeTab === "reporting-portal" ? styles.tabActive : {}),
          }}
          onClick={() => setActiveTab("reporting-portal")}
        >
          Reporting Portal
        </button>
      </div>

      <div style={styles.content}>
        {activeTab === "integrated-flow" && <IntegratedFlow />}
        {activeTab === "cicd-agents" && <ForensicReadyCICDAgents />}
        {activeTab === "anomaly-detection" && <AnomalyDetection />}
        {activeTab === "integrity-verification" && <IntegrityVerification />}
        {activeTab === "reporting-portal" && <ForensicReportingPortal />}
      </div>
    </div>
  );
}

const styles = {
  container: {
    fontFamily: "Arial, sans-serif",
    padding: "20px 40px",
    minHeight: "100vh",
    background: "#f5f5f5",
  },
  header: {
    marginBottom: "30px",
  },
  status: {
    color: "#666",
    margin: "5px 0 0 0",
    fontSize: "14px",
  },
  tabs: {
    display: "flex",
    gap: "10px",
    marginBottom: "20px",
    borderBottom: "2px solid #e0e0e0",
  },
  tab: {
    padding: "12px 24px",
    border: "none",
    background: "transparent",
    color: "#666",
    fontSize: "14px",
    fontWeight: "500",
    cursor: "pointer",
    borderBottom: "3px solid transparent",
    transition: "all 0.3s",
    marginBottom: "-2px",
  },
  tabActive: {
    color: "#2196f3",
    borderBottomColor: "#2196f3",
    fontWeight: "600",
  },
  content: {
    background: "transparent",
  },
};

export default App;
