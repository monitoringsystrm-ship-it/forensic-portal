import json
import os
import platform
from datetime import datetime


class PipelineSBOMOrchestrator:
    def __init__(self, backend_root):
        self.backend_root = backend_root

    def capture_stage_context(self, payload):
        stage_name = str(payload.get("stage_name") or "unknown-stage")
        stage_index = int(payload.get("stage_index", 0) or 0)
        stage_type = str(payload.get("stage_type") or "build")
        executor = str(payload.get("executor") or "unknown-executor")
        start_time = str(payload.get("start_time") or self._utc_now())
        end_time = str(payload.get("end_time") or self._utc_now())
        exit_code = int(payload.get("exit_code", 0) or 0)
        pipeline_id = str(payload.get("pipeline_id") or "unknown-pipeline")
        project_name = str(payload.get("project_name") or "node-react-app")
        build_environment = self.capture_environment(payload.get("environment", {}))
        tools = self.capture_tools_used(payload.get("tools", {}))
        inputs = self.capture_inputs(payload.get("inputs", []))
        outputs = self.capture_outputs(payload.get("outputs", []))
        dependencies = self.generate_dependency_sbom(payload.get("dependencies", []))
        vulnerabilities = payload.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            vulnerabilities = []

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "serialNumber": f"urn:uuid:{pipeline_id}-{stage_index}",
            "metadata": {
                "timestamp": self._utc_now(),
                "component": {"type": "application", "name": project_name},
                "pipelineStage": {
                    "pipelineId": pipeline_id,
                    "stageName": stage_name,
                    "stageIndex": stage_index,
                    "stageType": stage_type,
                    "executor": executor,
                    "startTime": start_time,
                    "endTime": end_time,
                    "exitCode": exit_code,
                },
                "buildEnvironment": build_environment,
                "tools": tools,
                "inputArtifacts": inputs,
                "outputArtifacts": outputs,
            },
            "components": dependencies,
            "vulnerabilities": vulnerabilities,
        }
        return sbom

    def capture_environment(self, environment):
        if not isinstance(environment, dict):
            environment = {}
        env_vars = environment.get("env_vars", {})
        if not isinstance(env_vars, dict):
            env_vars = {}
        redacted = {}
        for k, v in env_vars.items():
            ku = str(k).upper()
            if any(x in ku for x in ["TOKEN", "SECRET", "PASSWORD", "KEY", "PRIVATE", "CREDENTIAL"]):
                redacted[str(k)] = "[REDACTED]"
            else:
                redacted[str(k)] = str(v)
        return {
            "os": str(environment.get("os") or platform.system()),
            "osVersion": str(environment.get("os_version") or platform.version()),
            "runtime": str(environment.get("runtime") or f"Python {platform.python_version()}"),
            "nodeVersion": str(environment.get("node_version") or ""),
            "buildTool": str(environment.get("build_tool") or ""),
            "envVars": redacted,
        }

    def capture_tools_used(self, tools):
        if not isinstance(tools, dict):
            tools = {}
        return {
            "node": str(tools.get("node") or ""),
            "npm": str(tools.get("npm") or ""),
            "yarn": str(tools.get("yarn") or ""),
            "docker": str(tools.get("docker") or ""),
            "jenkins": str(tools.get("jenkins") or ""),
            "plugins": tools.get("plugins", []) if isinstance(tools.get("plugins"), list) else [],
        }

    def capture_inputs(self, artifacts):
        return self._normalize_artifacts(artifacts, "input")

    def capture_outputs(self, artifacts):
        return self._normalize_artifacts(artifacts, "output")

    def generate_dependency_sbom(self, dependencies):
        if isinstance(dependencies, dict):
            dependencies = [{"name": k, "version": v} for k, v in dependencies.items()]
        if not isinstance(dependencies, list):
            dependencies = []
        components = []
        for i, dep in enumerate(dependencies):
            if isinstance(dep, str):
                name = dep
                version = ""
                purl = ""
                dep_type = "library"
            else:
                d = dep if isinstance(dep, dict) else {}
                name = str(d.get("name") or f"dep-{i}")
                version = str(d.get("version") or "")
                purl = str(d.get("purl") or "")
                dep_type = str(d.get("type") or "library")
            components.append(
                {
                    "type": dep_type,
                    "name": name,
                    "version": version,
                    "purl": purl,
                }
            )
        if not components:
            package_json = os.path.join(os.path.dirname(self.backend_root), "package.json")
            lock_json = os.path.join(os.path.dirname(self.backend_root), "package-lock.json")
            components.extend(self._read_npm_dependencies(package_json, lock_json))
        return components

    def _read_npm_dependencies(self, package_json_path, lock_json_path):
        components = []
        if os.path.exists(package_json_path):
            try:
                with open(package_json_path, "r", encoding="utf-8") as f:
                    pkg = json.load(f)
                deps = pkg.get("dependencies", {})
                if isinstance(deps, dict):
                    for k, v in deps.items():
                        components.append({"type": "library", "name": str(k), "version": str(v), "purl": ""})
            except Exception:
                pass
        if components:
            return components
        if os.path.exists(lock_json_path):
            try:
                with open(lock_json_path, "r", encoding="utf-8") as f:
                    lock = json.load(f)
                pkgs = lock.get("packages", {})
                if isinstance(pkgs, dict):
                    for key, obj in list(pkgs.items())[:500]:
                        if key and isinstance(obj, dict):
                            name = key.split("node_modules/")[-1]
                            version = str(obj.get("version") or "")
                            if name:
                                components.append({"type": "library", "name": name, "version": version, "purl": ""})
            except Exception:
                pass
        return components

    def _normalize_artifacts(self, artifacts, artifact_type):
        if not isinstance(artifacts, list):
            artifacts = []
        out = []
        for i, a in enumerate(artifacts):
            item = a if isinstance(a, dict) else {}
            out.append(
                {
                    "artifactType": artifact_type,
                    "name": str(item.get("name") or f"{artifact_type}-artifact-{i}"),
                    "hash": str(item.get("hash") or ""),
                    "path": str(item.get("path") or ""),
                    "sizeBytes": int(item.get("size_bytes", 0) or 0),
                    "merkleProofRef": str(item.get("merkle_proof_ref") or ""),
                }
            )
        return out

    def _utc_now(self):
        return datetime.utcnow().isoformat() + "Z"
