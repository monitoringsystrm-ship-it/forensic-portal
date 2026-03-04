import React, { useState } from "react";
import { computeIntegrityHash, verifyIntegrityHash } from "../../api/mlApi";

function HashVerification() {
  const [content, setContent] = useState("");
  const [expectedHash, setExpectedHash] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [isWorking, setIsWorking] = useState(false);

  const handleCompute = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const res = await computeIntegrityHash(content);
      setResult({ mode: "compute", ...res });
    } catch (e) {
      setResult(null);
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  const handleVerify = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const res = await verifyIntegrityHash(content, expectedHash);
      setResult({ mode: "verify", ...res });
    } catch (e) {
      setResult(null);
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  return (
    <div className="hash-verification-card">
      <div className="hash-header">
        <div>
          <h3>SHA-256 Hash Verification</h3>
          <p className="hash-subtitle">Compute and verify SHA-256 for provided content</p>
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button className="verify-hash-button" onClick={handleCompute} disabled={isWorking || !content}>
            {isWorking ? "Working..." : "Compute Hash"}
          </button>
          <button
            className="verify-hash-button"
            onClick={handleVerify}
            disabled={isWorking || !content || !expectedHash}
          >
            {isWorking ? "Working..." : "Verify Hash"}
          </button>
        </div>
      </div>

      {error && <div className="no-evidence">{error}</div>}

      <textarea
        style={{ width: "100%", minHeight: 140, border: "1px solid #e0e0e0", borderRadius: 6, padding: 10 }}
        value={content}
        onChange={(e) => setContent(e.target.value)}
        placeholder="Paste artifact/log/SBOM content here"
      />

      <input
        style={{ width: "100%", marginTop: 10, border: "1px solid #e0e0e0", borderRadius: 6, padding: 10 }}
        value={expectedHash}
        onChange={(e) => setExpectedHash(e.target.value)}
        placeholder="Expected SHA-256 (for verify)"
      />

      {result ? (
        <div className="verification-result valid" style={{ marginTop: 12 }}>
          <strong>Result</strong>
          <div className="verification-details">
            {"sha256" in result ? (
              <div className="verification-row">
                <span>SHA-256:</span>
                <span className="hash-value">{result.sha256}</span>
              </div>
            ) : null}
            {"actual_hash" in result ? (
              <div className="verification-row">
                <span>Actual:</span>
                <span className="hash-value">{result.actual_hash}</span>
              </div>
            ) : null}
            {"match" in result ? (
              <div className="verification-row">
                <span>Match:</span>
                <span>{result.match ? "true" : "false"}</span>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default HashVerification;

