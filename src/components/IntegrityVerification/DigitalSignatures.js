import React, { useState } from "react";
import { generateEd25519Keypair, signEd25519, verifyEd25519 } from "../../api/mlApi";

function DigitalSignatures() {
  const [payload, setPayload] = useState("");
  const [privateKeyPem, setPrivateKeyPem] = useState("");
  const [publicKeyPem, setPublicKeyPem] = useState("");
  const [signatureB64, setSignatureB64] = useState("");
  const [verifyResult, setVerifyResult] = useState(null);
  const [error, setError] = useState(null);
  const [isWorking, setIsWorking] = useState(false);

  const handleGenerate = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const res = await generateEd25519Keypair();
      setPrivateKeyPem(res.private_key_pem || "");
      setPublicKeyPem(res.public_key_pem || "");
      setSignatureB64("");
      setVerifyResult(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  const handleSign = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const res = await signEd25519(payload, privateKeyPem);
      setSignatureB64(res.signature_b64 || "");
      setVerifyResult(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  const handleVerify = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const res = await verifyEd25519(payload, publicKeyPem, signatureB64);
      setVerifyResult(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  return (
    <div className="digital-signatures-card">
      <div className="signatures-header">
        <div>
          <h3>Signature (Ed25519)</h3>
          <p className="signatures-subtitle">Generate a keypair, sign a payload, and verify using the public key</p>
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button className="verify-signature-button" onClick={handleGenerate} disabled={isWorking}>
            {isWorking ? "Working..." : "Generate Keypair"}
          </button>
          <button
            className="verify-signature-button"
            onClick={handleSign}
            disabled={isWorking || !payload || !privateKeyPem}
          >
            {isWorking ? "Working..." : "Sign"}
          </button>
          <button
            className="verify-signature-button"
            onClick={handleVerify}
            disabled={isWorking || !payload || !publicKeyPem || !signatureB64}
          >
            {isWorking ? "Working..." : "Verify"}
          </button>
        </div>
      </div>

      {error && <div className="no-evidence">{error}</div>}

      <textarea
        style={{ width: "100%", minHeight: 120, border: "1px solid #e0e0e0", borderRadius: 6, padding: 10 }}
        value={payload}
        onChange={(e) => setPayload(e.target.value)}
        placeholder="Payload to sign"
      />

      <textarea
        style={{ width: "100%", marginTop: 10, minHeight: 120, border: "1px solid #e0e0e0", borderRadius: 6, padding: 10 }}
        value={privateKeyPem}
        onChange={(e) => setPrivateKeyPem(e.target.value)}
        placeholder="Private key (PEM)"
      />

      <textarea
        style={{ width: "100%", marginTop: 10, minHeight: 90, border: "1px solid #e0e0e0", borderRadius: 6, padding: 10 }}
        value={publicKeyPem}
        onChange={(e) => setPublicKeyPem(e.target.value)}
        placeholder="Public key (PEM)"
      />

      <input
        style={{ width: "100%", marginTop: 10, border: "1px solid #e0e0e0", borderRadius: 6, padding: 10 }}
        value={signatureB64}
        onChange={(e) => setSignatureB64(e.target.value)}
        placeholder="Signature (base64)"
      />

      {verifyResult ? (
        <div className={`verification-result ${verifyResult.valid ? "valid" : "invalid"}`} style={{ marginTop: 12 }}>
          <strong>Verification {verifyResult.valid ? "PASSED" : "FAILED"}</strong>
          <div className="verification-details">
            <div className="verification-row">
              <span>Valid:</span>
              <span>{verifyResult.valid ? "true" : "false"}</span>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default DigitalSignatures;

