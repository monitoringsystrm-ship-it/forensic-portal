import React, { useState } from "react";
import {
  hashSbom,
  capturePipelineStageSbom,
  finalizePipelineSbom,
  verifyPipelineIntegrity,
  listPipelineSboms,
  verifyPipelineStageSbom,
  queryVulnerableBuilds,
  traceArtifactProvenance,
} from "../../api/mlApi";

function SBOMGenerator() {
  const [sbomJson, setSbomJson] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [isWorking, setIsWorking] = useState(false);
  const [pipelineId, setPipelineId] = useState("pipeline-001");
  const [stageName, setStageName] = useState("build");
  const [stageIndex, setStageIndex] = useState(1);
  const [dependenciesText, setDependenciesText] = useState("react@19.2.1\nreact-dom@19.2.1");
  const [artifactsIn, setArtifactsIn] = useState("source.tar.gz|sha256:sourcehash");
  const [artifactsOut, setArtifactsOut] = useState("app-image.tar|sha256:imagehash");
  const [captureResult, setCaptureResult] = useState(null);
  const [finalizeResult, setFinalizeResult] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [pipelinesResult, setPipelinesResult] = useState(null);
  const [verifyStageIndex, setVerifyStageIndex] = useState(1);
  const [cveId, setCveId] = useState("CVE-2024-0001");
  const [cveQueryResult, setCveQueryResult] = useState(null);
  const [artifactHash, setArtifactHash] = useState("sha256:imagehash");
  const [artifactTraceResult, setArtifactTraceResult] = useState(null);

  const handleHash = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const res = await hashSbom(sbomJson);
      setResult(res);
    } catch (e) {
      setResult(null);
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  const parseDependencies = () => {
    return dependenciesText
      .split("\n")
      .map((x) => x.trim())
      .filter(Boolean)
      .map((line) => {
        const at = line.lastIndexOf("@");
        if (at > 0) {
          return { name: line.slice(0, at), version: line.slice(at + 1) };
        }
        return { name: line, version: "" };
      });
  };

  const parseArtifacts = (text) => {
    return text
      .split("\n")
      .map((x) => x.trim())
      .filter(Boolean)
      .map((line) => {
        const parts = line.split("|");
        return {
          name: parts[0] || "",
          hash: parts[1] || "",
          path: parts[2] || "",
        };
      });
  };

  const handleCaptureStage = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const payload = {
        pipeline_id: pipelineId,
        project_name: "forensic-portal",
        stage_name: stageName,
        stage_index: Number(stageIndex),
        stage_type: stageName,
        executor: "jenkins-agent",
        environment: {
          os: "linux",
          runtime: "node",
          node_version: "20",
          build_tool: "npm",
          env_vars: {
            NODE_ENV: "production",
            SAMPLE_TOKEN: "token-value",
          },
        },
        tools: {
          node: "20",
          npm: "10",
          docker: "25",
          jenkins: "2.x",
        },
        dependencies: parseDependencies(),
        inputs: parseArtifacts(artifactsIn),
        outputs: parseArtifacts(artifactsOut),
      };
      const res = await capturePipelineStageSbom(payload);
      setCaptureResult(res);
      setFinalizeResult(null);
      setVerifyResult(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  const handleFinalizePipeline = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const res = await finalizePipelineSbom(pipelineId);
      setFinalizeResult(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  const handleVerifyPipeline = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const res = await verifyPipelineIntegrity(pipelineId);
      setVerifyResult(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  const handleListPipelines = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const res = await listPipelineSboms();
      setPipelinesResult(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  const handleVerifyStage = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const res = await verifyPipelineStageSbom(pipelineId, Number(verifyStageIndex));
      setVerifyResult(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  const handleQueryCve = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const res = await queryVulnerableBuilds(cveId);
      setCveQueryResult(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  const handleTraceArtifact = async () => {
    setIsWorking(true);
    try {
      setError(null);
      const res = await traceArtifactProvenance(artifactHash);
      setArtifactTraceResult(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setIsWorking(false);
    }
  };

  return (
    <div className="sbom-generator-card">
      <div className="sbom-header">
        <div>
          <h3>Software Bill of Materials (SBOM)</h3>
          <p className="sbom-subtitle">Paste an SBOM JSON and compute its SHA-256</p>
        </div>
        <button className="generate-sbom-button" onClick={handleHash} disabled={isWorking || !sbomJson}>
          {isWorking ? "Computing..." : "Compute Hash"}
        </button>
      </div>

      {error && <div className="no-evidence">{error}</div>}

      <textarea
        style={{ width: "100%", minHeight: 160, border: "1px solid #e0e0e0", borderRadius: 6, padding: 10 }}
        value={sbomJson}
        onChange={(e) => setSbomJson(e.target.value)}
        placeholder='Paste SBOM JSON here'
      />

      {result && result.sha256 ? (
        <div className="sbom-section" style={{ marginTop: 16 }}>
          <h5>Result</h5>
          <div className="integrity-info">
            <div className="integrity-item">
              <span>SHA-256 Hash:</span>
              <span className="hash-value">{result.sha256}</span>
            </div>
            {typeof result.dependency_count === "number" ? (
              <div className="integrity-item">
                <span>Dependency Count:</span>
                <span>{String(result.dependency_count)}</span>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}

      <div className="sbom-section" style={{ marginTop: 16 }}>
        <h5>Pipeline Stage SBOM Capture</h5>
        <div className="metadata-grid" style={{ marginBottom: 12 }}>
          <input value={pipelineId} onChange={(e) => setPipelineId(e.target.value)} placeholder="Pipeline ID" />
          <input value={stageName} onChange={(e) => setStageName(e.target.value)} placeholder="Stage Name" />
          <input
            value={stageIndex}
            onChange={(e) => setStageIndex(Number(e.target.value || 0))}
            type="number"
            placeholder="Stage Index"
          />
          <input
            value={verifyStageIndex}
            onChange={(e) => setVerifyStageIndex(Number(e.target.value || 0))}
            type="number"
            placeholder="Verify Stage Index"
          />
        </div>
        <div style={{ display: "grid", gap: 10 }}>
          <textarea
            style={{ width: "100%", minHeight: 90, border: "1px solid #e0e0e0", borderRadius: 6, padding: 10 }}
            value={dependenciesText}
            onChange={(e) => setDependenciesText(e.target.value)}
            placeholder={"Dependencies, one per line: package@version"}
          />
          <textarea
            style={{ width: "100%", minHeight: 80, border: "1px solid #e0e0e0", borderRadius: 6, padding: 10 }}
            value={artifactsIn}
            onChange={(e) => setArtifactsIn(e.target.value)}
            placeholder={"Input artifacts: name|hash|path"}
          />
          <textarea
            style={{ width: "100%", minHeight: 80, border: "1px solid #e0e0e0", borderRadius: 6, padding: 10 }}
            value={artifactsOut}
            onChange={(e) => setArtifactsOut(e.target.value)}
            placeholder={"Output artifacts: name|hash|path"}
          />
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 10 }}>
          <button className="generate-sbom-button" onClick={handleCaptureStage} disabled={isWorking}>
            Capture Stage SBOM
          </button>
          <button className="generate-sbom-button" onClick={handleFinalizePipeline} disabled={isWorking}>
            Finalize Pipeline
          </button>
          <button className="generate-sbom-button" onClick={handleVerifyPipeline} disabled={isWorking}>
            Verify Pipeline
          </button>
          <button className="generate-sbom-button" onClick={handleVerifyStage} disabled={isWorking}>
            Verify Stage
          </button>
          <button className="generate-sbom-button" onClick={handleListPipelines} disabled={isWorking}>
            List Pipelines
          </button>
        </div>
      </div>

      <div className="sbom-section" style={{ marginTop: 16 }}>
        <h5>Forensic Queries</h5>
        <div className="metadata-grid">
          <input value={cveId} onChange={(e) => setCveId(e.target.value)} placeholder="CVE ID" />
          <button className="generate-sbom-button" onClick={handleQueryCve} disabled={isWorking}>
            Query Vulnerable Builds
          </button>
          <input value={artifactHash} onChange={(e) => setArtifactHash(e.target.value)} placeholder="Artifact Hash" />
          <button className="generate-sbom-button" onClick={handleTraceArtifact} disabled={isWorking}>
            Trace Artifact
          </button>
        </div>
      </div>

      {captureResult ? (
        <div className="sbom-section" style={{ marginTop: 16 }}>
          <h5>Capture Result</h5>
          <div className="integrity-item">
            <span>Stage Hash:</span>
            <span className="hash-value">{captureResult.sbom_hash}</span>
          </div>
        </div>
      ) : null}

      {finalizeResult && finalizeResult.merkle ? (
        <div className="sbom-section" style={{ marginTop: 16 }}>
          <h5>Pipeline Merkle</h5>
          <div className="integrity-item">
            <span>Root Hash:</span>
            <span className="hash-value">{finalizeResult.merkle.root_hash}</span>
          </div>
          <div className="integrity-item">
            <span>Stage Count:</span>
            <span>{Array.isArray(finalizeResult.merkle.stages) ? finalizeResult.merkle.stages.length : 0}</span>
          </div>
        </div>
      ) : null}

      {verifyResult ? (
        <div className="sbom-section" style={{ marginTop: 16 }}>
          <h5>Verification Result</h5>
          <div className="integrity-item">
            <span>Verified:</span>
            <span>{String(!!verifyResult.verified)}</span>
          </div>
          {"stored_root_hash" in verifyResult ? (
            <div className="integrity-item">
              <span>Stored Root:</span>
              <span className="hash-value">{verifyResult.stored_root_hash}</span>
            </div>
          ) : null}
          {"rebuilt_root_hash" in verifyResult ? (
            <div className="integrity-item">
              <span>Rebuilt Root:</span>
              <span className="hash-value">{verifyResult.rebuilt_root_hash}</span>
            </div>
          ) : null}
        </div>
      ) : null}

      {pipelinesResult && Array.isArray(pipelinesResult.pipelines) ? (
        <div className="sbom-section" style={{ marginTop: 16 }}>
          <h5>Pipelines</h5>
          <div className="evidence-list">
            {pipelinesResult.pipelines.map((p) => (
              <div key={p.pipeline_id} className="evidence-item">
                <div className="detail-row">
                  <span>ID</span>
                  <span>{p.pipeline_id}</span>
                </div>
                <div className="detail-row">
                  <span>Stages</span>
                  <span>{p.stage_count}</span>
                </div>
                <div className="detail-row">
                  <span>Root</span>
                  <span className="hash-value">{p.root_hash}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {cveQueryResult ? (
        <div className="sbom-section" style={{ marginTop: 16 }}>
          <h5>CVE Query Result</h5>
          <div className="integrity-item">
            <span>Affected:</span>
            <span>
              {Array.isArray(cveQueryResult.affected_pipelines) ? cveQueryResult.affected_pipelines.length : 0}
            </span>
          </div>
        </div>
      ) : null}

      {artifactTraceResult ? (
        <div className="sbom-section" style={{ marginTop: 16 }}>
          <h5>Artifact Trace Result</h5>
          <div className="integrity-item">
            <span>Traces:</span>
            <span>{Array.isArray(artifactTraceResult.traces) ? artifactTraceResult.traces.length : 0}</span>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default SBOMGenerator;

