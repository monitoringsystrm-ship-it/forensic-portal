import React, { useState } from "react";
import { verifyIntegrityHash } from "../../api/mlApi";

function IntegrityProofs({ forensicData }) {
  const [selectedProof, setSelectedProof] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);

  if (!forensicData) {
    return <div className="loading">Loading integrity proofs...</div>;
  }

  const integrityProofs = forensicData.integrityProofs || [];

  const handleVerify = async (proof) => {
    setSelectedProof(proof);
    try {
      const payload = typeof proof.payload === "string" ? proof.payload : "";
      const expected = typeof proof.hash === "string" ? proof.hash : "";
      const res = await verifyIntegrityHash(payload, expected);
      setVerificationResult({
        proofId: proof.id,
        isValid: !!res.valid,
        timestamp: new Date().toISOString(),
        verifiedBy: "backend",
      });
    } catch (e) {
      setVerificationResult({
        proofId: proof.id,
        isValid: false,
        timestamp: new Date().toISOString(),
        verifiedBy: "backend",
      });
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case "verified":
        return "#4caf50";
      case "failed":
        return "#f44336";
      case "pending":
        return "#ff9800";
      default:
        return "#757575";
    }
  };

  return (
    <div className="integrity-proofs-card">
      <div className="proofs-header">
        <h3>Cryptographic Integrity Proofs</h3>
        <p className="proofs-subtitle">
          SHA-256 checksums, digital signatures, and Merkle tree verification
        </p>
      </div>

      <div className="proofs-stats">
        <div className="proof-stat">
          <span className="stat-label">Total Proofs</span>
          <span className="stat-value">{integrityProofs.length}</span>
        </div>
        <div className="proof-stat">
          <span className="stat-label">Verified</span>
          <span className="stat-value verified">
            {integrityProofs.filter((p) => p.status === "verified").length}
          </span>
        </div>
        <div className="proof-stat">
          <span className="stat-label">Failed</span>
          <span className="stat-value failed">
            {integrityProofs.filter((p) => p.status === "failed").length}
          </span>
        </div>
      </div>

      <div className="proofs-list">
        {integrityProofs.length === 0 ? (
          <p className="no-proofs">No integrity proofs available</p>
        ) : (
          integrityProofs.map((proof) => (
            <div key={proof.id} className="proof-item">
              <div className="proof-header">
                <div className="proof-title-section">
                  <span className="proof-id">{proof.artifactName}</span>
                  <span
                    className="proof-status"
                    style={{ backgroundColor: getStatusColor(proof.status) }}
                  >
                    {proof.status}
                  </span>
                </div>
                <button
                  className="verify-button"
                  onClick={() => handleVerify(proof)}
                >
                  Verify
                </button>
              </div>

              <div className="proof-details">
                <div className="proof-detail-row">
                  <span className="detail-label">Proof ID:</span>
                  <span className="detail-value">{proof.id}</span>
                </div>
                <div className="proof-detail-row">
                  <span className="detail-label">Algorithm:</span>
                  <span className="detail-value">{proof.algorithm}</span>
                </div>
                <div className="proof-detail-row">
                  <span className="detail-label">Hash:</span>
                  <span className="detail-value hash-value">{proof.hash}</span>
                </div>
                {proof.signature && (
                  <div className="proof-detail-row">
                    <span className="detail-label">Digital Signature:</span>
                    <span className="detail-value signature-value">
                      {proof.signature.substring(0, 50)}...
                    </span>
                  </div>
                )}
                {proof.merkleRoot && (
                  <div className="proof-detail-row">
                    <span className="detail-label">Merkle Root:</span>
                    <span className="detail-value hash-value">
                      {proof.merkleRoot}
                    </span>
                  </div>
                )}
                <div className="proof-detail-row">
                  <span className="detail-label">Created:</span>
                  <span className="detail-value">
                    {new Date(proof.createdAt).toLocaleString()}
                  </span>
                </div>
                {proof.verifiedAt && (
                  <div className="proof-detail-row">
                    <span className="detail-label">Verified:</span>
                    <span className="detail-value">
                      {new Date(proof.verifiedAt).toLocaleString()}
                    </span>
                  </div>
                )}
              </div>

              {verificationResult &&
                verificationResult.proofId === proof.id && (
                  <div
                    className={`verification-result ${
                      verificationResult.isValid ? "valid" : "invalid"
                    }`}
                  >
                    <strong>
                      Verification {verificationResult.isValid ? "PASSED" : "FAILED"}
                    </strong>
                    <p>
                      Verified at: {new Date(verificationResult.timestamp).toLocaleString()}
                    </p>
                    <p>Verified by: {verificationResult.verifiedBy}</p>
                  </div>
                )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default IntegrityProofs;

