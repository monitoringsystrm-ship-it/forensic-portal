import React, { useState } from "react";
import { computeMerkleRoot } from "../../api/mlApi";

function MerkleTree() {
  const [hashesText, setHashesText] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [isWorking, setIsWorking] = useState(false);

  const handleCompute = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const hashes = hashesText
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);
      const res = await computeMerkleRoot(hashes);
      setResult(res);
    } catch (e) {
      setResult(null);
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  return (
    <div className="merkle-tree-card">
      <div className="merkle-header">
        <div>
          <h3>Merkle Root</h3>
          <p className="merkle-subtitle">Compute a Merkle root from SHA-256 leaf hashes</p>
        </div>
        <button className="generate-sbom-button" onClick={handleCompute} disabled={isWorking || !hashesText}>
          {isWorking ? "Computing..." : "Compute Root"}
        </button>
      </div>

      {error && <div className="no-evidence">{error}</div>}

      <textarea
        style={{ width: "100%", minHeight: 140, border: "1px solid #e0e0e0", borderRadius: 6, padding: 10 }}
        value={hashesText}
        onChange={(e) => setHashesText(e.target.value)}
        placeholder="One SHA-256 hash per line"
      />

      {result && result.root ? (
        <div className="sbom-section" style={{ marginTop: 16 }}>
          <h5>Result</h5>
          <div className="integrity-info">
            <div className="integrity-item">
              <span>Root:</span>
              <span className="hash-value">{result.root}</span>
            </div>
            <div className="integrity-item">
              <span>Leaves:</span>
              <span>{String(result.count)}</span>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default MerkleTree;

