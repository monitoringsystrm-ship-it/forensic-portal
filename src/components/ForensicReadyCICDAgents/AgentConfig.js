import React, { useEffect, useState } from "react";

function AgentConfig({ config, onSave, onReset }) {
  const [localConfig, setLocalConfig] = useState(config || null);

  useEffect(() => {
    setLocalConfig(config || null);
  }, [config]);

  const handleConfigChange = (key, value) => {
    setLocalConfig((prev) => (prev ? { ...prev, [key]: value } : prev));
  };

  return (
    <div className="agent-config-card">
      <h3>Agent Configuration</h3>
      {!localConfig ? (
        <div className="no-evidence">No configuration loaded</div>
      ) : null}
      <div className="config-section">
        <h4>Evidence Collection Settings</h4>
        <div className="config-grid">
          <div className="config-item">
            <label>
              <input
                type="checkbox"
                checked={!!(localConfig && localConfig.captureGitDiffs)}
                onChange={(e) =>
                  handleConfigChange("captureGitDiffs", e.target.checked)
                }
                disabled={!localConfig}
              />
              Capture Git Commit Diffs & Contributor Metadata
            </label>
          </div>
          <div className="config-item">
            <label>
              <input
                type="checkbox"
                checked={!!(localConfig && localConfig.captureBuildLogs)}
                onChange={(e) =>
                  handleConfigChange("captureBuildLogs", e.target.checked)
                }
                disabled={!localConfig}
              />
              Capture Build Logs & Pipeline Configuration Files
            </label>
          </div>
          <div className="config-item">
            <label>
              <input
                type="checkbox"
                checked={!!(localConfig && localConfig.captureEnvVars)}
                onChange={(e) =>
                  handleConfigChange("captureEnvVars", e.target.checked)
                }
                disabled={!localConfig}
              />
              Capture Environment Variables
            </label>
          </div>
          <div className="config-item">
            <label>
              <input
                type="checkbox"
                checked={!!(localConfig && localConfig.captureSecretsAccess)}
                onChange={(e) =>
                  handleConfigChange("captureSecretsAccess", e.target.checked)
                }
                disabled={!localConfig}
              />
              Capture Secrets Access Events
            </label>
          </div>
          <div className="config-item">
            <label>
              <input
                type="checkbox"
                checked={!!(localConfig && localConfig.captureArtifacts)}
                onChange={(e) =>
                  handleConfigChange("captureArtifacts", e.target.checked)
                }
                disabled={!localConfig}
              />
              Capture Temporary Build Artifacts and Scripts
            </label>
          </div>
          <div className="config-item">
            <label>
              <input
                type="checkbox"
                checked={!!(localConfig && localConfig.capturePipelineConfig)}
                onChange={(e) =>
                  handleConfigChange("capturePipelineConfig", e.target.checked)
                }
                disabled={!localConfig}
              />
              Capture Pipeline Configuration Files
            </label>
          </div>
          <div className="config-item">
            <label>
              <input
                type="checkbox"
                checked={!!(localConfig && localConfig.captureDockerContext)}
                onChange={(e) =>
                  handleConfigChange("captureDockerContext", e.target.checked)
                }
                disabled={!localConfig}
              />
              Capture Docker Build Context and Metadata
            </label>
          </div>
          <div className="config-item">
            <label>
              <input
                type="checkbox"
                checked={!!(localConfig && localConfig.captureCommandTraces)}
                onChange={(e) =>
                  handleConfigChange("captureCommandTraces", e.target.checked)
                }
                disabled={!localConfig}
              />
              Capture Command Execution Traces
            </label>
          </div>
          <div className="config-item">
            <label>
              <input
                type="checkbox"
                checked={!!(localConfig && localConfig.captureImageMetadata)}
                onChange={(e) =>
                  handleConfigChange("captureImageMetadata", e.target.checked)
                }
                disabled={!localConfig}
              />
              Capture Docker Image Metadata
            </label>
          </div>
          <div className="config-item">
            <label>
              <input
                type="checkbox"
                checked={!!(localConfig && localConfig.captureGithubEvents)}
                onChange={(e) =>
                  handleConfigChange("captureGithubEvents", e.target.checked)
                }
                disabled={!localConfig}
              />
              Capture GitHub Webhook Events
            </label>
          </div>
        </div>
      </div>

      <div className="config-section">
        <h4>Collection Behavior</h4>
        <div className="config-grid">
          <div className="config-item">
            <label>
              <input
                type="checkbox"
                checked={!!(localConfig && localConfig.autoCollection)}
                onChange={(e) =>
                  handleConfigChange("autoCollection", e.target.checked)
                }
                disabled={!localConfig}
              />
              Enable Automatic Collection
            </label>
          </div>
          <div className="config-item">
            <label>
              Collection Interval (seconds):
              <input
                type="number"
                value={localConfig ? localConfig.collectionInterval : ""}
                onChange={(e) =>
                  handleConfigChange(
                    "collectionInterval",
                    parseInt(e.target.value)
                  )
                }
                min="10"
                max="300"
                disabled={!localConfig}
              />
            </label>
          </div>
          <div className="config-item">
            <label>
              Max Evidence Size (MB):
              <input
                type="number"
                value={localConfig ? localConfig.maxEvidenceSize : ""}
                onChange={(e) =>
                  handleConfigChange(
                    "maxEvidenceSize",
                    parseInt(e.target.value)
                  )
                }
                min="10"
                max="1000"
                disabled={!localConfig}
              />
            </label>
          </div>
          <div className="config-item">
            <label>
              <input
                type="checkbox"
                checked={!!(localConfig && localConfig.encryptionEnabled)}
                onChange={(e) =>
                  handleConfigChange("encryptionEnabled", e.target.checked)
                }
                disabled={!localConfig}
              />
              Enable Encryption for Stored Evidence
            </label>
          </div>
        </div>
      </div>

      <div className="config-actions">
        <button
          className="save-config-button"
          onClick={() => (localConfig ? onSave(localConfig) : null)}
          disabled={!localConfig}
        >
          Save Configuration
        </button>
        <button className="reset-config-button" onClick={onReset} disabled={!localConfig}>
          Reset to Defaults
        </button>
      </div>
    </div>
  );
}

export default AgentConfig;

