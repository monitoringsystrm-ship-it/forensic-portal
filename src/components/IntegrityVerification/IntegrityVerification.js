import React, { useState, useEffect } from "react";
import SBOMGenerator from "./SBOMGenerator";
import HashVerification from "./HashVerification";
import DigitalSignatures from "./DigitalSignatures";
import MerkleTree from "./MerkleTree";
import MicrosoftMalware from "./MicrosoftMalware";
import "./IntegrityVerification.css";

function IntegrityVerification() {
  const [activeTab, setActiveTab] = useState("sbom");

  return (
    <div className="integrity-verification">
      <div className="verification-header">
        <h2>Cryptographic Integrity Verification with SBOM</h2>
        <p className="subtitle">
          Tamper-evident verification using SBOMs, hashing, digital signatures, and Merkle trees
        </p>
      </div>

      <div className="verification-tabs">
        <button
          className={`verification-tab-button ${
            activeTab === "sbom" ? "active" : ""
          }`}
          onClick={() => setActiveTab("sbom")}
        >
          SBOM Generator
        </button>
        <button
          className={`verification-tab-button ${
            activeTab === "hash" ? "active" : ""
          }`}
          onClick={() => setActiveTab("hash")}
        >
          Hash Verification
        </button>
        <button
          className={`verification-tab-button ${
            activeTab === "signatures" ? "active" : ""
          }`}
          onClick={() => setActiveTab("signatures")}
        >
          Digital Signatures
        </button>
        <button
          className={`verification-tab-button ${
            activeTab === "merkle" ? "active" : ""
          }`}
          onClick={() => setActiveTab("merkle")}
        >
          Merkle Tree
        </button>
        <button
          className={`verification-tab-button ${
            activeTab === "malware" ? "active" : ""
          }`}
          onClick={() => setActiveTab("malware")}
        >
          Malware Classification
        </button>
      </div>

      <div className="verification-content">
        {activeTab === "sbom" && <SBOMGenerator />}
        {activeTab === "hash" && <HashVerification />}
        {activeTab === "signatures" && <DigitalSignatures />}
        {activeTab === "merkle" && <MerkleTree />}
        {activeTab === "malware" && <MicrosoftMalware />}
      </div>
    </div>
  );
}

export default IntegrityVerification;

