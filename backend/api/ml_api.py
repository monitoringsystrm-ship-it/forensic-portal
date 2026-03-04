from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sys
import os
import json
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import hashlib
import hmac
import base64
from datetime import datetime
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.pipeline_sbom_orchestrator import PipelineSBOMOrchestrator
from utils.forensic_verification_service import ForensicVerificationService
from utils.incident_analysis_service import IncidentAnalysisService

from ml_models.cicd_agents.evidence_pattern_detector import EvidencePatternDetector
from ml_models.cicd_agents.hdfs_log_anomaly_detector import HdfsLogAnomalyDetector
from ml_models.cicd_agents.hadoop_log_failure_classifier import HadoopLogFailureClassifier
from ml_models.cicd_agents.command_sequence_classifier import CommandSequenceClassifier
from ml_models.anomaly_detection.commit_pattern_analyzer import CommitPatternAnalyzer
from ml_models.anomaly_detection.pipeline_tampering_detector import PipelineTamperingDetector
from ml_models.anomaly_detection.dependency_anomaly_detector import DependencyAnomalyDetector
from ml_models.integrity_verification.tampering_detector import TamperingDetector
from ml_models.integrity_verification.microsoft_malware_classifier import MicrosoftMalwareClassifier
from ml_models.reporting_portal.evidence_correlator import EvidenceCorrelator
from ml_models.reporting_portal.attack_type_classifier import AttackTypeClassifier
from ml_models.reporting_portal.breach_type_classifier import BreachTypeClassifier
from ml_models.reporting_portal.train_reporting_portal_models import (
    train_attack_type_model,
    train_breach_type_model,
)
from ml_models.anomaly_detection.dataset_service import (
    load_nsl_kdd,
    build_commit_samples,
    load_unsw_nb15,
    build_dependency_samples,
    evaluate_binary,
    save_summary,
    get_reports_dir,
    plot_confusion_matrix,
    plot_correlation,
    plot_label_distribution,
)

app = Flask(__name__)
CORS(app)

backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
anomaly_dir = os.path.join(backend_root, "ml_models", "anomaly_detection")
commit_model_path = os.path.join(anomaly_dir, "commit_pattern_model.pkl")
dependency_model_path = os.path.join(anomaly_dir, "dependency_anomaly_model.pkl")
pipeline_model_path = os.path.join(anomaly_dir, "pipeline_tampering_model.pkl")

cicd_dir = os.path.join(backend_root, "ml_models", "cicd_agents")
hdfs_model_path = os.path.join(cicd_dir, "hdfs_log_anomaly_model.pkl")
hdfs_reports_dir = os.path.join(cicd_dir, "reports", "hdfs_log_anomaly")
hdfs_log_path = os.path.join(cicd_dir, "HDFS Log Anomaly Detection", "hdfs_log", "hdfs.log", "sorted.log")

hadoop_dir = os.path.join(cicd_dir, "HDFS Log Anomaly Detection", "Hadoop_log", "Hadoop_log")
hadoop_label_path = os.path.join(hadoop_dir, "abnormal_label.txt")
hadoop_model_path = os.path.join(cicd_dir, "hadoop_log_failure_model.pkl")
hadoop_reports_dir = os.path.join(cicd_dir, "reports", "hadoop_log_failure")

cicd_state_path = os.path.join(backend_root, "data", "cicd_state.json")

integrity_dir = os.path.join(backend_root, "ml_models", "integrity_verification")
microsoft_malware_data_path = os.path.join(
    integrity_dir, "Microsoft Malware Classification Challenge", "data.csv"
)
microsoft_malware_model_path = os.path.join(integrity_dir, "microsoft_malware_model.pkl")
microsoft_malware_reports_dir = os.path.join(integrity_dir, "reports", "microsoft_malware")

reporting_dir = os.path.join(backend_root, "ml_models", "reporting_portal")
reporting_attack_csv_path = os.path.join(reporting_dir, "Attack_Dataset.csv")
reporting_breaches_csv_path = os.path.join(reporting_dir, "Cyber Security Breaches.csv")
reporting_attack_model_path = os.path.join(reporting_dir, "attack_type_model.pkl")
reporting_breach_model_path = os.path.join(reporting_dir, "breach_type_model.pkl")
pipeline_sbom_store_path = os.path.join(backend_root, "data", "pipeline_sbom_store.json")
pipeline_sbom_orchestrator = PipelineSBOMOrchestrator(backend_root)
forensic_verification_service = ForensicVerificationService(pipeline_sbom_store_path)
incident_analysis_store_path = os.path.join(backend_root, "data", "incident_analysis_state.json")
incident_analysis_service = IncidentAnalysisService(incident_analysis_store_path)
known_malware_hashes = {
    "sha256:d5ce4f63b42eb61f7f6d7f8ad86cb6f7f90fca4f67f6bca3de91ef6b4f4f7f31": {
        "family": "XMRig",
        "risk": "HIGH",
        "source": "threat-intel-lab",
    },
    "sha256:8d01db62126b0ea3aeb154d4f0b8f2b8d4f5f9d17bde5fa9f2c59c4f2d508a5d": {
        "family": "AgentTesla",
        "risk": "HIGH",
        "source": "threat-intel-lab",
    },
}

models = {
    'evidence_pattern': EvidencePatternDetector(),
    'hdfs_log_anomaly': HdfsLogAnomalyDetector(),
    'hadoop_log_failure': HadoopLogFailureClassifier(),
    'command_sequence': CommandSequenceClassifier(),
    'commit_pattern': CommitPatternAnalyzer(),
    'pipeline_tampering': PipelineTamperingDetector(),
    'dependency_anomaly': DependencyAnomalyDetector(),
    'tampering_detector': TamperingDetector(),
    'microsoft_malware': MicrosoftMalwareClassifier(),
    'evidence_correlator': EvidenceCorrelator(),
    'reporting_attack_type': AttackTypeClassifier(),
    'reporting_breach_type': BreachTypeClassifier(),
}

training_state = {
    "commit_pattern": {"trained": False, "metrics": None},
    "dependency_anomaly": {"trained": False, "metrics": None},
    "pipeline_tampering": {"trained": False, "metrics": None},
}

latest_results = {
    "commit_pattern": {"timestamp": None, "anomalies": []},
    "dependency_anomaly": {"timestamp": None, "anomalies": []},
    "pipeline_tampering": {"timestamp": None, "anomalies": []},
}

integrity_training_state = {
    "microsoft_malware": {"trained": False, "metrics": None},
}

integrity_latest_results = {
    "microsoft_malware": {"timestamp": None, "predictions": []},
}

ci_training_state = {
    "hdfs_log_anomaly": {"trained": False, "metrics": None, "reports": []},
    "hadoop_log_failure": {"trained": False, "metrics": None, "reports": []},
    "command_sequence": {"trained": True, "metrics": None, "reports": []},
}

ci_latest_results = {
    "hdfs_log_anomaly": {"timestamp": None, "anomalies": []},
    "hadoop_log_failure": {"timestamp": None, "anomalies": []},
    "command_sequence": {"timestamp": None, "alerts": [], "last_result": None},
}

reporting_training_state = {
    "attack_type": {"trained": False, "metrics": None, "reports": []},
    "breach_type": {"trained": False, "metrics": None, "reports": []},
}

reporting_latest_results = {
    "attack_type": {"timestamp": None, "predictions": []},
    "breach_type": {"timestamp": None, "predictions": []},
}

def try_load_models():
    loaded = []
    try:
        if os.path.exists(commit_model_path):
            models["commit_pattern"].load_model(commit_model_path)
            training_state["commit_pattern"]["trained"] = bool(models["commit_pattern"].is_trained)
            loaded.append("commit_pattern")
        if os.path.exists(dependency_model_path):
            models["dependency_anomaly"].load_model(dependency_model_path)
            training_state["dependency_anomaly"]["trained"] = bool(models["dependency_anomaly"].is_trained)
            loaded.append("dependency_anomaly")
        if os.path.exists(pipeline_model_path):
            models["pipeline_tampering"].load_model(pipeline_model_path)
            training_state["pipeline_tampering"]["trained"] = bool(models["pipeline_tampering"].is_trained)
            loaded.append("pipeline_tampering")
        if os.path.exists(hdfs_model_path):
            models["hdfs_log_anomaly"].load_model(hdfs_model_path)
            ci_training_state["hdfs_log_anomaly"]["trained"] = bool(models["hdfs_log_anomaly"].is_trained)
            loaded.append("hdfs_log_anomaly")
        if os.path.exists(hadoop_model_path):
            models["hadoop_log_failure"].load_model(hadoop_model_path)
            ci_training_state["hadoop_log_failure"]["trained"] = bool(models["hadoop_log_failure"].is_trained)
            loaded.append("hadoop_log_failure")
        if os.path.exists(microsoft_malware_model_path):
            models["microsoft_malware"].load_model(microsoft_malware_model_path)
            integrity_training_state["microsoft_malware"]["trained"] = bool(models["microsoft_malware"].is_trained)
            loaded.append("microsoft_malware")
        if os.path.exists(reporting_attack_model_path):
            models["reporting_attack_type"].load_model(reporting_attack_model_path)
            reporting_training_state["attack_type"]["trained"] = bool(models["reporting_attack_type"].is_trained)
            loaded.append("reporting_attack_type")
        if os.path.exists(reporting_breach_model_path):
            models["reporting_breach_type"].load_model(reporting_breach_model_path)
            reporting_training_state["breach_type"]["trained"] = bool(models["reporting_breach_type"].is_trained)
            loaded.append("reporting_breach_type")
    except Exception:
        pass
    return loaded

try_load_models()

def cicd_default_config():
    return {
        "captureGitDiffs": True,
        "captureBuildLogs": True,
        "captureEnvVars": True,
        "captureSecretsAccess": True,
        "captureArtifacts": True,
        "capturePipelineConfig": True,
        "captureDockerContext": True,
        "captureCommandTraces": True,
        "captureImageMetadata": True,
        "captureGithubEvents": True,
        "autoCollection": False,
        "collectionInterval": 30,
        "maxEvidenceSize": 100,
        "encryptionEnabled": True,
    }


def load_cicd_state():
    os.makedirs(os.path.dirname(cicd_state_path), exist_ok=True)
    if not os.path.exists(cicd_state_path):
        return {"agents": [], "evidence": [], "config": cicd_default_config(), "mappings": {"commit_to_build": {}}}
    try:
        with open(cicd_state_path, "r") as f:
            s = json.load(f)
        if "agents" not in s:
            s["agents"] = []
        if "evidence" not in s:
            s["evidence"] = []
        if "config" not in s or not isinstance(s["config"], dict):
            s["config"] = cicd_default_config()
        if "mappings" not in s or not isinstance(s["mappings"], dict):
            s["mappings"] = {"commit_to_build": {}}
        if "commit_to_build" not in s["mappings"] or not isinstance(s["mappings"].get("commit_to_build"), dict):
            s["mappings"]["commit_to_build"] = {}
        return s
    except Exception:
        return {"agents": [], "evidence": [], "config": cicd_default_config(), "mappings": {"commit_to_build": {}}}


def save_cicd_state(state):
    os.makedirs(os.path.dirname(cicd_state_path), exist_ok=True)
    with open(cicd_state_path, "w") as f:
        json.dump(state, f)


def compute_cicd_metrics(state):
    agents = state.get("agents", [])
    active = 0
    for a in agents:
        if a.get("status") == "active":
            active += 1
    evidence = state.get("evidence", [])
    command_alerts = 0
    for item in evidence[-500:]:
        if item.get("type") == "command-alert":
            command_alerts += 1
    return {
        "activeAgents": active,
        "performanceOverhead": None,
        "totalEvidenceItems": len(evidence),
        "commandAlerts": command_alerts,
    }


def upsert_agent(state, agent):
    agent_id = agent.get("id")
    if not agent_id:
        return state
    agents = state.get("agents", [])
    now = __import__("datetime").datetime.utcnow().isoformat() + "Z"
    found = False
    for a in agents:
        if a.get("id") == agent_id:
            for k in ["type", "status", "buildsCaptured", "evidenceItems"]:
                if k in agent:
                    a[k] = agent.get(k)
            a["lastSeen"] = agent.get("lastSeen", now)
            found = True
            break
    if not found:
        agents.append(
            {
                "id": agent_id,
                "type": agent.get("type"),
                "status": agent.get("status", "inactive"),
                "buildsCaptured": agent.get("buildsCaptured"),
                "evidenceItems": agent.get("evidenceItems"),
                "lastSeen": agent.get("lastSeen", now),
            }
        )
    state["agents"] = agents
    return state


def utc_now_iso():
    return datetime.utcnow().isoformat() + "Z"


def redact_env_vars(env_vars):
    if not isinstance(env_vars, dict):
        return {}
    redacted = {}
    for k, v in env_vars.items():
        key = str(k)
        val = str(v)
        ku = key.upper()
        if any(x in ku for x in ["SECRET", "TOKEN", "PASSWORD", "KEY", "PRIVATE", "CREDENTIAL"]):
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = val
    return redacted


def normalize_commands(commands=None, console_output=None):
    out = []
    if isinstance(commands, list):
        for c in commands:
            s = str(c or "").strip()
            if s:
                out.append(s)
    if isinstance(console_output, str):
        for line in console_output.splitlines():
            s = line.strip()
            if s:
                out.append(s)
    return out


def append_cicd_evidence_items(state, new_items, max_items=5000):
    evidence = state.get("evidence", [])
    evidence.extend(new_items)
    if len(evidence) > max_items:
        evidence = evidence[-max_items:]
    state["evidence"] = evidence
    return state


def build_integration_flow_snapshot(pipeline_id=None):
    cicd_state = load_cicd_state()
    evidence = cicd_state.get("evidence", [])
    commit_map = cicd_state.get("mappings", {}).get("commit_to_build", {})
    latest_command = ci_latest_results.get("command_sequence", {})
    command_alerts = latest_command.get("alerts", []) if isinstance(latest_command, dict) else []
    command_high = [a for a in command_alerts if str(a.get("risk_level", "")).upper() == "HIGH"]

    pipeline_list = forensic_verification_service.list_pipelines()
    pipelines = pipeline_list.get("pipelines", []) if isinstance(pipeline_list, dict) else []
    selected_pipeline = pipeline_id
    if not selected_pipeline and pipelines:
        selected_pipeline = pipelines[0].get("pipeline_id")
    pipeline_info = None
    pipeline_verification = None
    if selected_pipeline:
        pipeline_info = forensic_verification_service.get_pipeline(selected_pipeline)
        pipeline_verification = forensic_verification_service.verify_pipeline_integrity(selected_pipeline)

    incident_latest = incident_analysis_service.latest()
    analysis = incident_latest.get("latest_analysis") if isinstance(incident_latest, dict) else None
    commit_anomalies = analysis.get("commit_anomalies", []) if isinstance(analysis, dict) else []
    dep_risks = analysis.get("dependency_risks", []) if isinstance(analysis, dict) else []
    build_anomalies = analysis.get("build_anomalies", []) if isinstance(analysis, dict) else []
    timeline = analysis.get("timeline", []) if isinstance(analysis, dict) else []

    top_commit = commit_anomalies[0] if commit_anomalies else None
    top_dep = dep_risks[0] if dep_risks else None
    top_build = build_anomalies[0] if build_anomalies else None

    decision = "ALLOW"
    reasons = []
    if command_high:
        decision = "BLOCK_DEPLOYMENT"
        reasons.append("High-risk command sequence detected in CI/CD execution")
    if top_dep and str(top_dep.get("recommendation", "")).upper() == "BLOCK_INSTALL":
        decision = "BLOCK_DEPLOYMENT"
        reasons.append("Dependency anomaly requires BLOCK_INSTALL")
    if top_commit and float(top_commit.get("anomaly_score", 0) or 0) >= 0.85:
        decision = "BLOCK_DEPLOYMENT"
        reasons.append("Critical commit anomaly score exceeded threshold")
    if pipeline_verification and pipeline_verification.get("success") and not bool(pipeline_verification.get("verified")):
        decision = "BLOCK_DEPLOYMENT"
        reasons.append("Pipeline integrity verification failed")

    if decision == "ALLOW":
        if command_alerts or (top_commit and float(top_commit.get("anomaly_score", 0) or 0) >= 0.45):
            decision = "ALERT"
            reasons.append("Suspicious activity detected; manual review required")

    component_steps = [
        {
            "component": "Component 1",
            "title": "Jenkins Forensic Agent + Command ML",
            "status": "ok" if not command_high else "critical",
            "summary": {
                "agents": len(cicd_state.get("agents", [])),
                "evidence_items": len(evidence),
                "command_alerts": len(command_alerts),
            },
        },
        {
            "component": "Component 2",
            "title": "SBOM + Merkle Integrity + Malware Lookup",
            "status": "ok"
            if not pipeline_verification or bool(pipeline_verification.get("verified"))
            else "critical",
            "summary": {
                "pipeline_id": selected_pipeline,
                "pipeline_verified": pipeline_verification.get("verified") if pipeline_verification else None,
                "root_hash": pipeline_verification.get("stored_root_hash") if pipeline_verification else None,
            },
        },
        {
            "component": "Component 3",
            "title": "Commit + Dependency + Build Incident Analysis",
            "status": "critical"
            if top_dep and str(top_dep.get("recommendation", "")).upper() == "BLOCK_INSTALL"
            else ("warning" if top_commit and float(top_commit.get("anomaly_score", 0) or 0) >= 0.45 else "ok"),
            "summary": {
                "top_commit_score": top_commit.get("anomaly_score") if top_commit else None,
                "top_dependency_score": top_dep.get("anomaly_score") if top_dep else None,
                "top_build_score": top_build.get("anomaly_score") if top_build else None,
                "timeline_events": len(timeline),
            },
        },
        {
            "component": "Component 4",
            "title": "Chain of Custody + Integration Decision",
            "status": "critical" if decision == "BLOCK_DEPLOYMENT" else ("warning" if decision == "ALERT" else "ok"),
            "summary": {
                "decision": decision,
                "reasons": reasons,
                "commit_build_mappings": len(commit_map),
            },
        },
    ]

    return {
        "generated_at": utc_now_iso(),
        "pipeline_id": selected_pipeline,
        "decision": decision,
        "reasons": reasons,
        "component_steps": component_steps,
        "timeline": timeline,
        "pipeline_verification": pipeline_verification,
        "pipeline_data": pipeline_info.get("pipeline") if pipeline_info and pipeline_info.get("success") else None,
        "queries": {
            "available_pipelines": pipelines,
            "commit_build_mapping_count": len(commit_map),
        },
    }


def ensure_microsoft_malware_reports_dir():
    os.makedirs(microsoft_malware_reports_dir, exist_ok=True)
    return microsoft_malware_reports_dir

def read_hdfs_lines(limit=None, offset=0):
    lines = []
    if not os.path.exists(hdfs_log_path):
        return lines
    with open(hdfs_log_path, "r", errors="ignore") as f:
        for i, line in enumerate(f):
            if offset and i < offset:
                continue
            s = line.strip()
            if s:
                lines.append(s)
            if limit and len(lines) >= int(limit):
                break
    return lines


def ensure_hdfs_reports_dir():
    os.makedirs(hdfs_reports_dir, exist_ok=True)
    return hdfs_reports_dir


def build_hdfs_reports(lines, results):
    ensure_hdfs_reports_dir()
    sample_lines = lines[: min(len(lines), 5000)]
    if not sample_lines:
        return []
    X = models["hdfs_log_anomaly"].vectorizer.transform(sample_lines)
    feats = models["hdfs_log_anomaly"].vectorizer.get_feature_names_out()
    mean = np.asarray(X.mean(axis=0)).ravel()
    top_idx = np.argsort(mean)[::-1][:30]
    top_tokens = [feats[i] for i in top_idx]
    top_vals = mean[top_idx]

    plt.figure(figsize=(10, 5))
    sns.barplot(x=top_vals, y=top_tokens)
    plt.tight_layout()
    plt.savefig(os.path.join(hdfs_reports_dir, "hdfs_word_map.png"))
    plt.close()

    m = X[:50, :50].toarray()
    plt.figure(figsize=(10, 6))
    sns.heatmap(m, cmap="mako")
    plt.tight_layout()
    plt.savefig(os.path.join(hdfs_reports_dir, "hdfs_dataset_matrix.png"))
    plt.close()

    scores = [r.get("anomaly_score") for r in results if r.get("anomaly_score") is not None]
    if scores:
        plt.figure(figsize=(8, 4))
        sns.histplot(scores, bins=40, kde=True)
        plt.tight_layout()
        plt.savefig(os.path.join(hdfs_reports_dir, "hdfs_score_distribution.png"))
        plt.close()

    return [
        "hdfs_word_map.png",
        "hdfs_dataset_matrix.png",
        "hdfs_score_distribution.png",
    ]


def ensure_hadoop_reports_dir():
    os.makedirs(hadoop_reports_dir, exist_ok=True)
    return hadoop_reports_dir


def parse_hadoop_labels():
    if not os.path.exists(hadoop_label_path):
        return {}
    labels = {}
    mode = None
    with open(hadoop_label_path, "r", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.endswith(":"):
                if line.lower().startswith("normal"):
                    mode = "normal"
                else:
                    mode = "abnormal"
                continue
            if line.startswith("+"):
                app = line.lstrip("+").strip()
                if app.startswith("application_"):
                    labels[app] = 0 if mode == "normal" else 1
    return labels


def read_hadoop_app_text(app_id, max_lines_per_file=2000, max_total_lines=12000):
    app_dir = os.path.join(hadoop_dir, app_id)
    if not os.path.isdir(app_dir):
        return ""
    parts = []
    total = 0
    for name in sorted(os.listdir(app_dir)):
        if not name.endswith(".log"):
            continue
        p = os.path.join(app_dir, name)
        try:
            with open(p, "r", errors="ignore") as f:
                for i, raw in enumerate(f):
                    if i >= int(max_lines_per_file):
                        break
                    s = raw.strip()
                    if s:
                        parts.append(s)
                        total += 1
                    if total >= int(max_total_lines):
                        break
        except Exception:
            continue
        if total >= int(max_total_lines):
            break
    return "\n".join(parts)


def build_hadoop_reports(texts, y_true, y_pred, proba, metrics):
    ensure_hadoop_reports_dir()

    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["normal", "abnormal"], yticklabels=["normal", "abnormal"])
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.tight_layout()
    plt.savefig(os.path.join(hadoop_reports_dir, "hadoop_confusion_matrix.png"))
    plt.close()

    plt.figure(figsize=(6, 3.5))
    vals = [metrics["accuracy"], metrics["precision"], metrics["recall"], metrics["f1"]]
    sns.barplot(x=["accuracy", "precision", "recall", "f1"], y=vals)
    plt.ylim(0, 1)
    plt.tight_layout()
    plt.savefig(os.path.join(hadoop_reports_dir, "hadoop_metrics.png"))
    plt.close()

    scores = list(proba)
    if scores:
        plt.figure(figsize=(8, 4))
        sns.histplot(scores, bins=20, kde=True)
        plt.tight_layout()
        plt.savefig(os.path.join(hadoop_reports_dir, "hadoop_probability_distribution.png"))
        plt.close()

    X = models["hadoop_log_failure"].vectorizer.transform(texts)
    feats = models["hadoop_log_failure"].vectorizer.get_feature_names_out()
    mean = np.asarray(X.mean(axis=0)).ravel()
    top_idx = np.argsort(mean)[::-1][:30]
    top_tokens = [feats[i] for i in top_idx]
    top_vals = mean[top_idx]
    plt.figure(figsize=(10, 5))
    sns.barplot(x=top_vals, y=top_tokens)
    plt.tight_layout()
    plt.savefig(os.path.join(hadoop_reports_dir, "hadoop_word_map.png"))
    plt.close()

    m = X[:50, :50].toarray()
    plt.figure(figsize=(10, 6))
    sns.heatmap(m, cmap="mako")
    plt.tight_layout()
    plt.savefig(os.path.join(hadoop_reports_dir, "hadoop_dataset_matrix.png"))
    plt.close()

    return [
        "hadoop_confusion_matrix.png",
        "hadoop_metrics.png",
        "hadoop_probability_distribution.png",
        "hadoop_word_map.png",
        "hadoop_dataset_matrix.png",
    ]


@app.route('/api/ml/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'models_loaded': len(models)})

@app.route('/api/ml/anomaly-detection/status', methods=['GET'])
def anomaly_detection_status():
    return jsonify(
        {
            "success": True,
            "models": {
                "commit_pattern": {"is_trained": bool(models["commit_pattern"].is_trained)},
                "dependency_anomaly": {"is_trained": bool(models["dependency_anomaly"].is_trained)},
                "pipeline_tampering": {"is_trained": bool(models["pipeline_tampering"].is_trained)},
            },
            "model_files": {
                "commit_pattern": {"path": commit_model_path, "exists": os.path.exists(commit_model_path)},
                "dependency_anomaly": {"path": dependency_model_path, "exists": os.path.exists(dependency_model_path)},
                "pipeline_tampering": {"path": pipeline_model_path, "exists": os.path.exists(pipeline_model_path)},
            },
            "training_state": training_state,
        }
    )

@app.route('/api/ml/anomaly-detection/reports/<path:filename>', methods=['GET'])
def anomaly_reports(filename):
    reports_dir = get_reports_dir()
    return send_from_directory(reports_dir, filename, as_attachment=False)


@app.route('/api/ml/anomaly-detection/incident/ingest/github-commits', methods=['POST'])
def incident_ingest_github_commits():
    try:
        data = request.json or {}
        commits = data.get("commits", [])
        result = incident_analysis_service.ingest_github_commits(commits)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/anomaly-detection/incident/ingest/dependency-history', methods=['POST'])
def incident_ingest_dependency_history():
    try:
        data = request.json or {}
        changes = data.get("changes", [])
        result = incident_analysis_service.ingest_dependency_history(changes)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/anomaly-detection/incident/ingest/jenkins-patterns', methods=['POST'])
def incident_ingest_jenkins_patterns():
    try:
        data = request.json or {}
        builds = data.get("builds", [])
        result = incident_analysis_service.ingest_jenkins_patterns(builds)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/anomaly-detection/incident/ingest/threat-intel', methods=['POST'])
def incident_ingest_threat_intel():
    try:
        data = request.json or {}
        result = incident_analysis_service.ingest_threat_intel(data)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/anomaly-detection/incident/analyze', methods=['POST'])
def incident_analyze():
    try:
        data = request.json or {}
        months = data.get("months", 12)
        result = incident_analysis_service.analyze(months=months)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/anomaly-detection/incident/latest', methods=['GET'])
def incident_latest():
    try:
        return jsonify(incident_analysis_service.latest())
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/ml/anomaly-detection/train', methods=['POST'])
def anomaly_detection_train():
    try:
        data = request.json or {}
        model_names = data.get("models", ["commit_pattern", "dependency_anomaly"])
        limit = data.get("limit", None)
        summary = {}

        if "commit_pattern" in model_names:
            train_df, test_df = load_nsl_kdd()
            train_samples = build_commit_samples(train_df, limit=limit)
            test_samples = build_commit_samples(test_df, limit=limit)
            y_train = train_df["target"].head(len(train_samples)).values
            y_test = test_df["target"].head(len(test_samples)).values

            train_metrics = models["commit_pattern"].train(train_samples, y_train)

            X_test = models["commit_pattern"].extract_features(test_samples)
            X_test_scaled = models["commit_pattern"].scaler.transform(X_test)
            y_pred = models["commit_pattern"].model.predict(X_test_scaled)

            metrics = evaluate_binary(y_test, y_pred)
            metrics["train_accuracy_internal"] = float(train_metrics["train_accuracy"])
            metrics["test_accuracy_internal"] = float(train_metrics["test_accuracy"])
            metrics["classification_report"] = classification_report(y_test, y_pred, zero_division=0)
            plot_confusion_matrix(
                np.array(metrics["confusion_matrix"]),
                "commit_confusion_matrix.png",
                title="Commit Pattern Confusion Matrix",
                cmap="Blues",
            )
            plot_correlation(train_df, "commit_feature_correlation.png")
            plot_label_distribution(train_df["target"], "commit_label_distribution.png")

            os.makedirs(anomaly_dir, exist_ok=True)
            models["commit_pattern"].save_model(commit_model_path)
            training_state["commit_pattern"] = {"trained": True, "metrics": metrics}
            summary["commit_pattern"] = metrics

        if "dependency_anomaly" in model_names:
            train_df, test_df = load_unsw_nb15()
            train_samples = build_dependency_samples(train_df, limit=limit)
            test_samples = build_dependency_samples(test_df, limit=limit)
            y_test = test_df["target"].head(len(test_samples)).values

            models["dependency_anomaly"].train(train_samples)

            X_test = models["dependency_anomaly"].extract_features(test_samples)
            X_test_scaled = models["dependency_anomaly"].scaler.transform(X_test)
            preds = models["dependency_anomaly"].model.predict(X_test_scaled)
            y_pred = np.where(preds == -1, 1, 0)

            metrics = evaluate_binary(y_test, y_pred)
            plot_confusion_matrix(
                np.array(metrics["confusion_matrix"]),
                "dependency_confusion_matrix.png",
                title="Dependency Anomaly Confusion Matrix",
                cmap="Greens",
            )
            plot_correlation(train_df, "dependency_feature_correlation.png")
            plot_label_distribution(train_df["target"], "dependency_label_distribution.png")
            os.makedirs(anomaly_dir, exist_ok=True)
            models["dependency_anomaly"].save_model(dependency_model_path)
            training_state["dependency_anomaly"] = {"trained": True, "metrics": metrics}
            summary["dependency_anomaly"] = metrics

        summary_path = save_summary(summary)

        return jsonify({"success": True, "summary": summary, "summary_path": summary_path})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ml/anomaly-detection/infer', methods=['POST'])
def anomaly_detection_infer():
    try:
        data = request.json or {}
        model_name = data.get("model", "commit_pattern")
        limit = data.get("limit", 200)
        store = bool(data.get("store", False))

        if model_name == "commit_pattern":
            if not models["commit_pattern"].is_trained:
                return jsonify({"success": False, "error": "commit_pattern model not trained"}), 400
            _, test_df = load_nsl_kdd()
            test_samples = build_commit_samples(test_df, limit=limit)
            X = models["commit_pattern"].extract_features(test_samples)
            Xs = models["commit_pattern"].scaler.transform(X)
            probs = models["commit_pattern"].model.predict_proba(Xs)[:, 1]
            preds = models["commit_pattern"].model.predict(Xs)
            results = []
            for i, s in enumerate(test_samples):
                if int(preds[i]) == 1:
                    results.append(
                        {
                            "id": s["id"],
                            "category": "commit-patterns",
                            "confidence": float(probs[i] * 100),
                            "details": s,
                        }
                    )
            if store:
                latest_results["commit_pattern"] = {
                    "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                    "anomalies": results,
                }
            return jsonify({"success": True, "model": model_name, "anomalies": results})

        if model_name == "dependency_anomaly":
            if not models["dependency_anomaly"].is_trained:
                return jsonify({"success": False, "error": "dependency_anomaly model not trained"}), 400
            _, test_df = load_unsw_nb15()
            test_samples = build_dependency_samples(test_df, limit=limit)
            X = models["dependency_anomaly"].extract_features(test_samples)
            Xs = models["dependency_anomaly"].scaler.transform(X)
            preds = models["dependency_anomaly"].model.predict(Xs)
            scores = models["dependency_anomaly"].model.score_samples(Xs)
            results = []
            for i, s in enumerate(test_samples):
                if int(preds[i]) == -1:
                    results.append(
                        {
                            "id": s["id"],
                            "category": "dependency-anomalies",
                            "confidence": float(abs(scores[i]) * 100),
                            "details": s,
                        }
                    )
            if store:
                latest_results["dependency_anomaly"] = {
                    "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                    "anomalies": results,
                }
            return jsonify({"success": True, "model": model_name, "anomalies": results})

        return jsonify({"success": False, "error": "Unknown model"}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ml/anomaly-detection/infer-sample', methods=['POST'])
def anomaly_detection_infer_sample():
    try:
        data = request.json or {}
        model_name = data.get("model", "commit_pattern")
        sample = data.get("sample", None)
        store = bool(data.get("store", False))

        if sample is None:
            return jsonify({"success": False, "error": "Missing sample"}), 400

        if model_name == "commit_pattern":
            if not models["commit_pattern"].is_trained:
                return jsonify({"success": False, "error": "commit_pattern model not trained"}), 400
            X = models["commit_pattern"].extract_features([sample])
            Xs = models["commit_pattern"].scaler.transform(X)
            prob = float(models["commit_pattern"].model.predict_proba(Xs)[0, 1] * 100)
            pred = int(models["commit_pattern"].model.predict(Xs)[0])
            result = {
                "id": sample.get("id", "sample"),
                "category": "commit-patterns",
                "confidence": prob,
                "is_anomaly": bool(pred == 1),
                "details": sample,
            }
            if store and result["is_anomaly"]:
                latest_results["commit_pattern"] = {
                    "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                    "anomalies": [result],
                }
            return jsonify({"success": True, "model": model_name, "result": result})

        if model_name == "dependency_anomaly":
            if not models["dependency_anomaly"].is_trained:
                return jsonify({"success": False, "error": "dependency_anomaly model not trained"}), 400
            r = models["dependency_anomaly"].predict([sample])[0]
            result = {
                "id": sample.get("id", r.get("dependency_id", "sample")),
                "category": "dependency-anomalies",
                "confidence": float(r.get("confidence", 0)),
                "is_anomaly": bool(r.get("is_anomaly", False)),
                "details": sample,
            }
            if store and result["is_anomaly"]:
                latest_results["dependency_anomaly"] = {
                    "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                    "anomalies": [result],
                }
            return jsonify({"success": True, "model": model_name, "result": result})

        return jsonify({"success": False, "error": "Unknown model"}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ml/anomaly-detection/latest', methods=['GET'])
def anomaly_detection_latest():
    model_name = request.args.get("model", "commit_pattern")
    if model_name not in latest_results:
        return jsonify({"success": False, "error": "Unknown model"}), 400
    return jsonify({"success": True, "model": model_name, **latest_results[model_name]})


@app.route('/api/ml/cicd-agents/hdfs/status', methods=['GET'])
def cicd_hdfs_status():
    return jsonify(
        {
            "success": True,
            "model": {"is_trained": bool(models["hdfs_log_anomaly"].is_trained)},
            "model_file": {"path": hdfs_model_path, "exists": os.path.exists(hdfs_model_path)},
            "dataset": {"path": hdfs_log_path, "exists": os.path.exists(hdfs_log_path)},
            "training_state": ci_training_state["hdfs_log_anomaly"],
            "latest": ci_latest_results["hdfs_log_anomaly"],
        }
    )


@app.route('/api/ml/cicd-agents/hdfs/reports/<path:filename>', methods=['GET'])
def cicd_hdfs_reports(filename):
    ensure_hdfs_reports_dir()
    return send_from_directory(hdfs_reports_dir, filename, as_attachment=False)


@app.route('/api/ml/cicd-agents/hdfs/train', methods=['POST'])
def cicd_hdfs_train():
    try:
        data = request.json or {}
        limit = data.get("limit", 50000)
        lines = read_hdfs_lines(limit=limit)
        if not lines:
            return jsonify({"success": False, "error": "HDFS dataset not found or empty"}), 400
        ci_training_state["hdfs_log_anomaly"] = {"trained": False, "metrics": None, "reports": []}

        models["hdfs_log_anomaly"].train(lines)
        os.makedirs(cicd_dir, exist_ok=True)
        models["hdfs_log_anomaly"].save_model(hdfs_model_path)

        eval_lines = lines[: min(len(lines), 5000)]
        preds = models["hdfs_log_anomaly"].predict(eval_lines)
        anomaly_count = sum(1 for r in preds if r.get("is_anomaly"))
        total = len(preds) if preds else 0
        anomaly_rate = float(anomaly_count / total) if total else 0.0

        reports = build_hdfs_reports(eval_lines, preds)
        metrics = {
            "train_lines": int(len(lines)),
            "eval_lines": int(total),
            "eval_anomaly_count": int(anomaly_count),
            "eval_anomaly_rate": float(anomaly_rate),
        }

        summary_path = os.path.join(hdfs_reports_dir, "hdfs_training_summary.json")
        with open(summary_path, "w") as f:
            json.dump(metrics, f, indent=4)

        ci_training_state["hdfs_log_anomaly"] = {"trained": True, "metrics": metrics, "reports": reports}
        return jsonify({"success": True, "metrics": metrics, "reports": reports, "model_path": hdfs_model_path})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/cicd-agents/hdfs/infer', methods=['POST'])
def cicd_hdfs_infer():
    try:
        if not models["hdfs_log_anomaly"].is_trained:
            return jsonify({"success": False, "error": "hdfs_log_anomaly model not trained"}), 400
        data = request.json or {}
        lines = data.get("lines", [])
        store = bool(data.get("store", False))
        results = models["hdfs_log_anomaly"].predict(lines)
        anomalies = [
            {
                "id": r.get("id"),
                "category": "hdfs-log-anomaly",
                "confidence": float(r.get("confidence", 0)),
                "details": {"line": r.get("line"), "score": r.get("anomaly_score")},
            }
            for r in results
            if r.get("is_anomaly")
        ]
        if store:
            ci_latest_results["hdfs_log_anomaly"] = {
                "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                "anomalies": anomalies,
            }
        return jsonify({"success": True, "anomalies": anomalies})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/cicd-agents/hdfs/infer-dataset', methods=['POST'])
def cicd_hdfs_infer_dataset():
    try:
        if not models["hdfs_log_anomaly"].is_trained:
            return jsonify({"success": False, "error": "hdfs_log_anomaly model not trained"}), 400
        data = request.json or {}
        limit = data.get("limit", 2000)
        store = bool(data.get("store", False))
        lines = read_hdfs_lines(limit=limit)
        results = models["hdfs_log_anomaly"].predict(lines)
        anomalies = [
            {
                "id": r.get("id"),
                "category": "hdfs-log-anomaly",
                "confidence": float(r.get("confidence", 0)),
                "details": {"line": r.get("line"), "score": r.get("anomaly_score")},
            }
            for r in results
            if r.get("is_anomaly")
        ]
        if store:
            ci_latest_results["hdfs_log_anomaly"] = {
                "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                "anomalies": anomalies,
            }
        return jsonify({"success": True, "anomalies": anomalies})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/cicd-agents/hdfs/latest', methods=['GET'])
def cicd_hdfs_latest():
    return jsonify({"success": True, **ci_latest_results["hdfs_log_anomaly"]})


@app.route('/api/ml/cicd-agents/hadoop/status', methods=['GET'])
def cicd_hadoop_status():
    return jsonify(
        {
            "success": True,
            "model": {"is_trained": bool(models["hadoop_log_failure"].is_trained)},
            "model_file": {"path": hadoop_model_path, "exists": os.path.exists(hadoop_model_path)},
            "dataset": {"dir": hadoop_dir, "labels": {"path": hadoop_label_path, "exists": os.path.exists(hadoop_label_path)}},
            "training_state": ci_training_state["hadoop_log_failure"],
            "latest": ci_latest_results["hadoop_log_failure"],
        }
    )


@app.route('/api/ml/cicd-agents/hadoop/reports/<path:filename>', methods=['GET'])
def cicd_hadoop_reports(filename):
    ensure_hadoop_reports_dir()
    return send_from_directory(hadoop_reports_dir, filename, as_attachment=False)


@app.route('/api/ml/cicd-agents/hadoop/train', methods=['POST'])
def cicd_hadoop_train():
    try:
        data = request.json or {}
        limit = data.get("limit", None)
        labels = parse_hadoop_labels()
        if not labels:
            return jsonify({"success": False, "error": "Hadoop labels not found or empty"}), 400
        app_ids = sorted(labels.keys())
        if limit:
            app_ids = app_ids[: int(limit)]

        texts = []
        y = []
        kept_ids = []
        for app_id in app_ids:
            txt = read_hadoop_app_text(app_id)
            if txt:
                texts.append(txt)
                y.append(int(labels[app_id]))
                kept_ids.append(app_id)

        if len(texts) < 10:
            return jsonify({"success": False, "error": "Not enough Hadoop log samples"}), 400

        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, precision_recall_fscore_support

        X_train, X_test, y_train, y_test, id_train, id_test = train_test_split(
            texts, y, kept_ids, test_size=0.3, random_state=42, stratify=y
        )

        ci_training_state["hadoop_log_failure"] = {"trained": False, "metrics": None, "reports": []}
        models["hadoop_log_failure"].train(X_train, y_train)
        os.makedirs(cicd_dir, exist_ok=True)
        models["hadoop_log_failure"].save_model(hadoop_model_path)

        Xv = models["hadoop_log_failure"].vectorizer.transform(X_test)
        proba = models["hadoop_log_failure"].model.predict_proba(Xv)[:, 1]
        y_pred = (proba >= 0.5).astype(int)
        acc = float(accuracy_score(y_test, y_pred))
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)

        metrics = {
            "train_samples": int(len(X_train)),
            "test_samples": int(len(X_test)),
            "accuracy": float(acc),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
        }

        ensure_hadoop_reports_dir()
        with open(os.path.join(hadoop_reports_dir, "hadoop_training_summary.json"), "w") as f:
            json.dump(metrics, f, indent=4)

        reports = build_hadoop_reports(X_test, y_test, y_pred, proba, metrics)
        ci_training_state["hadoop_log_failure"] = {"trained": True, "metrics": metrics, "reports": reports}
        return jsonify({"success": True, "metrics": metrics, "reports": reports, "model_path": hadoop_model_path})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/cicd-agents/hadoop/infer-dataset', methods=['POST'])
def cicd_hadoop_infer_dataset():
    try:
        if not models["hadoop_log_failure"].is_trained:
            return jsonify({"success": False, "error": "hadoop_log_failure model not trained"}), 400
        data = request.json or {}
        limit = data.get("limit", 20)
        store = bool(data.get("store", False))

        labels = parse_hadoop_labels()
        app_ids = sorted(labels.keys())[: int(limit)]
        items = []
        for app_id in app_ids:
            txt = read_hadoop_app_text(app_id)
            if txt:
                items.append((app_id, txt, int(labels[app_id])))

        if not items:
            return jsonify({"success": False, "error": "No Hadoop samples found"}), 400

        ids = [x[0] for x in items]
        texts = [x[1] for x in items]
        y_true = [x[2] for x in items]

        Xv = models["hadoop_log_failure"].vectorizer.transform(texts)
        proba = models["hadoop_log_failure"].model.predict_proba(Xv)[:, 1]
        y_pred = (proba >= 0.5).astype(int)

        anomalies = []
        for i, app_id in enumerate(ids):
            if int(y_pred[i]) == 1:
                anomalies.append(
                    {
                        "id": app_id,
                        "category": "hadoop-log-failure",
                        "confidence": float(proba[i] * 100.0),
                        "details": {"app_id": app_id, "label": int(y_true[i])},
                    }
                )

        if store:
            ci_latest_results["hadoop_log_failure"] = {
                "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                "anomalies": anomalies,
            }

        return jsonify({"success": True, "anomalies": anomalies})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/cicd-agents/hadoop/latest', methods=['GET'])
def cicd_hadoop_latest():
    return jsonify({"success": True, **ci_latest_results["hadoop_log_failure"]})


@app.route('/api/ml/cicd-agents/status', methods=['GET'])
def cicd_agents_status():
    state = load_cicd_state()
    metrics = compute_cicd_metrics(state)
    commit_map = state.get("mappings", {}).get("commit_to_build", {})
    return jsonify(
        {
            "success": True,
            "agents": state.get("agents", []),
            "metrics": metrics,
            "mappings": {"commit_to_build_count": len(commit_map)},
            "command_sequence": {
                "trained": bool(ci_training_state["command_sequence"].get("trained")),
                "latest_timestamp": ci_latest_results["command_sequence"].get("timestamp"),
                "latest_alerts": len(ci_latest_results["command_sequence"].get("alerts", [])),
            },
        }
    )


@app.route('/api/ml/cicd-agents/evidence', methods=['GET'])
def cicd_agents_evidence():
    state = load_cicd_state()
    limit = request.args.get("limit", None)
    items = state.get("evidence", [])
    items = list(reversed(items))
    if limit is not None:
        try:
            items = items[: int(limit)]
        except Exception:
            pass
    return jsonify({"success": True, "evidence": items})


@app.route('/api/ml/cicd-agents/register', methods=['POST'])
def cicd_agents_register():
    data = request.json or {}
    agent = data.get("agent", {}) or {}
    state = load_cicd_state()
    state = upsert_agent(state, agent)
    save_cicd_state(state)
    metrics = compute_cicd_metrics(state)
    return jsonify({"success": True, "agents": state.get("agents", []), "metrics": metrics})


@app.route('/api/ml/cicd-agents/config', methods=['GET'])
def cicd_agents_get_config():
    state = load_cicd_state()
    return jsonify({"success": True, "config": state.get("config", cicd_default_config())})


@app.route('/api/ml/cicd-agents/config', methods=['POST'])
def cicd_agents_save_config():
    data = request.json or {}
    cfg = data.get("config", None)
    if not isinstance(cfg, dict):
        return jsonify({"success": False, "error": "Invalid config"}), 400
    state = load_cicd_state()
    state["config"] = cfg
    save_cicd_state(state)
    return jsonify({"success": True, "config": state.get("config")})


@app.route('/api/ml/cicd-agents/config/reset', methods=['POST'])
def cicd_agents_reset_config():
    state = load_cicd_state()
    state["config"] = cicd_default_config()
    save_cicd_state(state)
    return jsonify({"success": True, "config": state.get("config")})


@app.route('/api/ml/cicd-agents/collect', methods=['POST'])
def cicd_agents_collect():
    data = request.json or {}
    mode = data.get("mode", "dataset")
    state = load_cicd_state()
    now = __import__("datetime").datetime.utcnow().isoformat() + "Z"
    new_items = []

    if mode == "dataset":
        if models["hdfs_log_anomaly"].is_trained:
            lines = read_hdfs_lines(limit=2000)
            res = models["hdfs_log_anomaly"].predict(lines)
            for r in res:
                if r.get("is_anomaly"):
                    new_items.append(
                        {
                            "timestamp": now,
                            "type": "build-logs",
                            "description": "HDFS log anomaly detected",
                            "metadata": {"line": r.get("line"), "confidence": r.get("confidence")},
                        }
                    )
        if models["hadoop_log_failure"].is_trained:
            labels_map = parse_hadoop_labels()
            app_ids = sorted(labels_map.keys())[:55]
            texts = []
            labels = []
            ids = []
            for app_id in app_ids:
                txt = read_hadoop_app_text(app_id)
                if txt:
                    texts.append(txt)
                    labels.append(int(labels_map[app_id]))
                    ids.append(app_id)
            if texts:
                Xv = models["hadoop_log_failure"].vectorizer.transform(texts)
                proba = models["hadoop_log_failure"].model.predict_proba(Xv)[:, 1]
                for i in range(len(ids)):
                    if float(proba[i]) >= 0.5:
                        new_items.append(
                            {
                                "timestamp": now,
                                "type": "build-logs",
                                "description": "Hadoop job failure predicted",
                                "metadata": {
                                    "app_id": ids[i],
                                    "confidence": float(proba[i] * 100.0),
                                    "label": int(labels[i]),
                                },
                            }
                        )

    state = append_cicd_evidence_items(state, new_items, max_items=5000)
    state_evidence = state.get("evidence", [])

    for a in state.get("agents", []):
        a["evidenceItems"] = len(state_evidence)
        if not a.get("lastSeen"):
            a["lastSeen"] = now
    save_cicd_state(state)
    return jsonify({"success": True, "added": len(new_items)})


@app.route('/api/ml/cicd-agents/command-sequence/status', methods=['GET'])
def cicd_command_sequence_status():
    return jsonify(
        {
            "success": True,
            "training_state": ci_training_state["command_sequence"],
            "latest": ci_latest_results["command_sequence"],
        }
    )


@app.route('/api/ml/cicd-agents/command-sequence/latest', methods=['GET'])
def cicd_command_sequence_latest():
    return jsonify({"success": True, **ci_latest_results["command_sequence"]})


@app.route('/api/ml/cicd-agents/command-sequence/train', methods=['POST'])
def cicd_command_sequence_train():
    try:
        data = request.json or {}
        benign_sequences = data.get("benign_sequences", [])
        malicious_sequences = data.get("malicious_sequences", [])
        train_result = models["command_sequence"].train(benign_sequences, malicious_sequences)
        ci_training_state["command_sequence"] = {
            "trained": bool(train_result.get("trained")),
            "metrics": {
                "benign_samples": int(train_result.get("benign_samples", 0)),
                "malicious_samples": int(train_result.get("malicious_samples", 0)),
            },
            "reports": [],
        }
        return jsonify({"success": True, "training_state": ci_training_state["command_sequence"]})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/cicd-agents/command-sequence/infer', methods=['POST'])
def cicd_command_sequence_infer():
    try:
        data = request.json or {}
        build_id = str(data.get("build_id") or f"build-{uuid4().hex[:10]}")
        commands = normalize_commands(data.get("commands"), data.get("console_output"))
        if not commands:
            return jsonify({"success": False, "error": "No commands provided"}), 400
        result = models["command_sequence"].classify_commands(build_id, commands)
        now = utc_now_iso()
        ci_latest_results["command_sequence"] = {
            "timestamp": now,
            "alerts": result.get("alerts", []),
            "last_result": result,
        }

        state = load_cicd_state()
        new_items = []
        for alert in result.get("alerts", []):
            new_items.append(
                {
                    "timestamp": now,
                    "type": "command-alert",
                    "description": alert.get("alert", "Suspicious command detected"),
                    "metadata": {
                        "build_id": alert.get("build_id"),
                        "risk_level": alert.get("risk_level"),
                        "confidence": alert.get("confidence"),
                        "command": alert.get("command"),
                        "why": ", ".join(alert.get("why", [])),
                    },
                }
            )
        state = append_cicd_evidence_items(state, new_items, max_items=5000)
        save_cicd_state(state)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/cicd-agents/github/webhook', methods=['POST'])
def cicd_github_webhook():
    try:
        payload = request.json or {}
        event_name = request.headers.get("X-GitHub-Event", "unknown")
        delivery = request.headers.get("X-GitHub-Delivery", "")
        repo = ((payload.get("repository") or {}).get("full_name")) or ""
        ref = payload.get("ref")
        action = payload.get("action")
        before_sha = payload.get("before")
        after_sha = payload.get("after")
        commits = payload.get("commits", []) if isinstance(payload.get("commits"), list) else []
        p = payload.get("pull_request") or {}
        pr_number = p.get("number")
        pr_state = p.get("state")
        author = None
        ts = None
        if commits:
            last_commit = commits[-1]
            after_sha = after_sha or last_commit.get("id")
            c_author = (last_commit.get("author") or {})
            author = c_author.get("name") or c_author.get("username")
            ts = c_author.get("timestamp")
        if not author:
            sender = payload.get("sender") or {}
            author = sender.get("login")
        if not ts:
            ts = payload.get("head_commit", {}).get("timestamp")

        state = load_cicd_state()
        now = utc_now_iso()
        evidence_item = {
            "timestamp": now,
            "type": "github-event",
            "description": f"GitHub event {event_name}",
            "metadata": {
                "event": event_name,
                "delivery": delivery,
                "repo": repo,
                "ref": ref,
                "action": action,
                "before_sha": before_sha,
                "after_sha": after_sha,
                "author": author,
                "author_timestamp": ts,
                "pr_number": pr_number,
                "pr_state": pr_state,
                "commit_count": len(commits),
            },
        }
        state = append_cicd_evidence_items(state, [evidence_item], max_items=5000)
        save_cicd_state(state)
        incident_commits = []
        for c in commits:
            if isinstance(c, dict):
                author_obj = c.get("author") if isinstance(c.get("author"), dict) else {}
                incident_commits.append(
                    {
                        "sha": c.get("id") or after_sha,
                        "author": author_obj.get("name") or author_obj.get("username") or author,
                        "timestamp": c.get("timestamp") or ts or now,
                        "message": c.get("message") or "",
                        "files_changed": int(c.get("added", []) and len(c.get("added", [])) or 0)
                        + int(c.get("removed", []) and len(c.get("removed", [])) or 0)
                        + int(c.get("modified", []) and len(c.get("modified", [])) or 0),
                        "lines_added": int(c.get("lines_added", 0) or 0),
                        "lines_deleted": int(c.get("lines_deleted", 0) or 0),
                        "diff": str(c.get("diff") or ""),
                        "build_id": None,
                    }
                )
        if incident_commits:
            incident_analysis_service.ingest_github_commits(incident_commits)
        return jsonify({"success": True, "event": event_name, "delivery": delivery})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/cicd-agents/jenkins/build', methods=['POST'])
def cicd_jenkins_build():
    try:
        data = request.json or {}
        build_id = str(data.get("build_id") or f"jenkins-{uuid4().hex[:10]}")
        build_number = data.get("build_number")
        pipeline_name = str(data.get("pipeline_name") or "unknown-pipeline")
        stage_name = str(data.get("stage_name") or "unknown-stage")
        stage_index = data.get("stage_index")
        commit_sha = str(data.get("commit_sha") or "")
        branch = str(data.get("branch") or "")
        tags = data.get("tags", [])
        if not isinstance(tags, list):
            tags = []
        commands = normalize_commands(data.get("commands"), data.get("console_output"))
        env_dump = redact_env_vars(data.get("env", {}))
        docker_context = data.get("docker", {}) if isinstance(data.get("docker"), dict) else {}

        now = utc_now_iso()
        command_result = None
        if commands:
            command_result = models["command_sequence"].classify_commands(build_id, commands)
            ci_latest_results["command_sequence"] = {
                "timestamp": now,
                "alerts": command_result.get("alerts", []),
                "last_result": command_result,
            }

        state = load_cicd_state()
        agent_id = f"jenkins-{pipeline_name}"
        state = upsert_agent(
            state,
            {
                "id": agent_id,
                "type": "jenkins",
                "status": "active",
                "buildsCaptured": int(data.get("builds_captured", 0) or 0),
            },
        )
        if commit_sha:
            state.setdefault("mappings", {}).setdefault("commit_to_build", {})[commit_sha] = {
                "build_id": build_id,
                "build_number": build_number,
                "pipeline_name": pipeline_name,
                "timestamp": now,
            }

        new_items = [
            {
                "timestamp": now,
                "type": "build-logs",
                "description": "Jenkins stage execution captured",
                "metadata": {
                    "build_id": build_id,
                    "build_number": build_number,
                    "pipeline_name": pipeline_name,
                    "stage_name": stage_name,
                    "stage_index": stage_index,
                    "commit_sha": commit_sha,
                    "branch": branch,
                    "tags": ",".join(tags),
                    "command_count": len(commands),
                },
            },
            {
                "timestamp": now,
                "type": "env-vars",
                "description": "Build environment variables captured",
                "metadata": {
                    "build_id": build_id,
                    "env_count": len(env_dump),
                    "sample_keys": ",".join(list(env_dump.keys())[:10]),
                },
            },
            {
                "timestamp": now,
                "type": "docker-build",
                "description": "Docker build context captured",
                "metadata": {
                    "build_id": build_id,
                    "dockerfile": str(docker_context.get("dockerfile") or ""),
                    "image": str(docker_context.get("image") or ""),
                    "tags": ",".join(docker_context.get("tags", []) if isinstance(docker_context.get("tags"), list) else []),
                    "build_args_count": len(docker_context.get("build_args", {}) if isinstance(docker_context.get("build_args"), dict) else {}),
                },
            },
        ]
        if command_result:
            for alert in command_result.get("alerts", []):
                new_items.append(
                    {
                        "timestamp": now,
                        "type": "command-alert",
                        "description": alert.get("alert", "Suspicious command detected"),
                        "metadata": {
                            "build_id": alert.get("build_id"),
                            "risk_level": alert.get("risk_level"),
                            "confidence": alert.get("confidence"),
                            "command": alert.get("command"),
                            "why": ", ".join(alert.get("why", [])),
                        },
                    }
                )

        state = append_cicd_evidence_items(state, new_items, max_items=5000)
        for a in state.get("agents", []):
            if a.get("id") == agent_id:
                a["evidenceItems"] = len(state.get("evidence", []))
                a["lastSeen"] = now
                a["buildsCaptured"] = int(a.get("buildsCaptured", 0) or 0) + 1
        save_cicd_state(state)

        incident_analysis_service.ingest_jenkins_patterns(
            [
                {
                    "build_id": build_id,
                    "pipeline_name": pipeline_name,
                    "timestamp": now,
                    "duration_sec": float(data.get("duration_sec", 0) or 0),
                    "success": bool(data.get("success", True)),
                    "cpu_percent": float(data.get("cpu_percent", 0) or 0),
                    "memory_mb": float(data.get("memory_mb", 0) or 0),
                    "image_size_mb": float(docker_context.get("image_size_mb", 0) or 0),
                }
            ]
        )
        if commit_sha:
            incident_analysis_service.ingest_github_commits(
                [
                    {
                        "sha": commit_sha,
                        "author": str(data.get("author") or "unknown"),
                        "timestamp": str(data.get("timestamp") or now),
                        "message": str(data.get("commit_message") or ""),
                        "files_changed": int(data.get("files_changed", 0) or 0),
                        "lines_added": int(data.get("lines_added", 0) or 0),
                        "lines_deleted": int(data.get("lines_deleted", 0) or 0),
                        "diff": str(data.get("diff") or ""),
                        "build_id": build_id,
                    }
                ]
            )

        return jsonify(
            {
                "success": True,
                "build_id": build_id,
                "captured_evidence": len(new_items),
                "command_sequence": command_result,
            }
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/cicd-agents/mappings/commit-build', methods=['GET'])
def cicd_commit_build_mapping():
    state = load_cicd_state()
    commit_sha = str(request.args.get("commit_sha", "")).strip()
    mapping = state.get("mappings", {}).get("commit_to_build", {})
    if commit_sha:
        return jsonify({"success": True, "mapping": mapping.get(commit_sha)})
    return jsonify({"success": True, "mapping": mapping})

@app.route('/api/ml/cicd-agents/detect', methods=['POST'])
def detect_evidence_patterns():
    try:
        data = request.json
        evidence_data = data.get('evidence', [])
        
        results = models['evidence_pattern'].predict(evidence_data)
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ml/anomaly-detection/commit-patterns', methods=['POST'])
def detect_commit_anomalies():
    try:
        data = request.json
        commit_data = data.get('commits', [])
        
        results = models['commit_pattern'].predict(commit_data)
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ml/anomaly-detection/pipeline-tampering', methods=['POST'])
def detect_pipeline_tampering():
    try:
        data = request.json
        pipeline_scripts = data.get('scripts', [])
        
        results = models['pipeline_tampering'].predict(pipeline_scripts)
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ml/anomaly-detection/dependency-anomalies', methods=['POST'])
def detect_dependency_anomalies():
    try:
        data = request.json
        dependency_data = data.get('dependencies', [])
        
        results = models['dependency_anomaly'].predict(dependency_data)
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ml/integrity-verification/detect-tampering', methods=['POST'])
def detect_tampering():
    try:
        data = request.json
        artifact_data = data.get('artifacts', [])
        
        results = models['tampering_detector'].predict(artifact_data)
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ml/integrity-verification/microsoft-malware/status', methods=['GET'])
def microsoft_malware_status():
    return jsonify(
        {
            "success": True,
            "model": {"is_trained": bool(models["microsoft_malware"].is_trained)},
            "model_file": {"path": microsoft_malware_model_path, "exists": os.path.exists(microsoft_malware_model_path)},
            "dataset": {"path": microsoft_malware_data_path, "exists": os.path.exists(microsoft_malware_data_path)},
            "training_state": integrity_training_state["microsoft_malware"],
            "latest": integrity_latest_results["microsoft_malware"],
        }
    )


@app.route('/api/ml/integrity-verification/microsoft-malware/reports/<path:filename>', methods=['GET'])
def microsoft_malware_reports(filename):
    ensure_microsoft_malware_reports_dir()
    return send_from_directory(microsoft_malware_reports_dir, filename, as_attachment=False)


@app.route('/api/ml/integrity-verification/microsoft-malware/train', methods=['POST'])
def microsoft_malware_train():
    try:
        data = request.json or {}
        limit = data.get("limit", None)
        if not os.path.exists(microsoft_malware_data_path):
            return jsonify({"success": False, "error": "Dataset not found"}), 400

        df = pd.read_csv(microsoft_malware_data_path)
        if limit:
            df = df.head(int(limit))
        if "Class" not in df.columns:
            return jsonify({"success": False, "error": "Dataset missing Class column"}), 400

        y = df["Class"].astype(int).values
        X = df.drop(columns=["Class"])

        from sklearn.model_selection import train_test_split, StratifiedKFold, learning_curve
        from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y
        )

        integrity_training_state["microsoft_malware"] = {"trained": False, "metrics": None}
        models["microsoft_malware"].train(X_train, y_train)
        models["microsoft_malware"].save_model(microsoft_malware_model_path)

        pred, conf, _ = models["microsoft_malware"].predict_df(X_test.assign(Class=y_test))
        acc = accuracy_score(y_test, pred)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, pred, average="weighted", zero_division=0
        )
        cm = confusion_matrix(y_test, pred)

        ensure_microsoft_malware_reports_dir()
        plt.figure(figsize=(7, 6))
        sns.heatmap(cm, annot=False, cmap="Blues")
        plt.xlabel("Predicted")
        plt.ylabel("True")
        plt.tight_layout()
        plt.savefig(os.path.join(microsoft_malware_reports_dir, "microsoft_malware_confusion_matrix.png"))
        plt.close()

        plt.figure(figsize=(6, 3.5))
        vals = [acc, precision, recall, f1]
        sns.barplot(x=["accuracy", "precision", "recall", "f1"], y=vals)
        plt.ylim(0, 1)
        plt.tight_layout()
        plt.savefig(os.path.join(microsoft_malware_reports_dir, "microsoft_malware_metrics.png"))
        plt.close()

        from sklearn.ensemble import RandomForestClassifier

        X_all = X.copy()
        for c in X_all.columns:
            X_all[c] = pd.to_numeric(X_all[c], errors="coerce")
        X_all = X_all.fillna(0)

        curve_model = RandomForestClassifier(
            n_estimators=80,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced_subsample",
        )
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
        train_sizes = np.linspace(0.1, 1.0, 10)
        sizes_abs, train_scores, test_scores = learning_curve(
            curve_model,
            X_all.values,
            y,
            train_sizes=train_sizes,
            cv=cv,
            scoring="accuracy",
            n_jobs=-1,
            shuffle=True,
            random_state=42,
        )

        train_mean = np.mean(train_scores, axis=1)
        train_std = np.std(train_scores, axis=1)
        test_mean = np.mean(test_scores, axis=1)
        test_std = np.std(test_scores, axis=1)

        plt.figure(figsize=(8, 4.5))
        plt.plot(sizes_abs, train_mean, marker="o", label="train")
        plt.plot(sizes_abs, test_mean, marker="o", label="test")
        plt.fill_between(sizes_abs, train_mean - train_std, train_mean + train_std, alpha=0.15)
        plt.fill_between(sizes_abs, test_mean - test_std, test_mean + test_std, alpha=0.15)
        plt.ylim(0, 1)
        plt.xlabel("Train samples")
        plt.ylabel("Accuracy")
        plt.legend(loc="lower right")
        plt.tight_layout()
        plt.savefig(os.path.join(microsoft_malware_reports_dir, "microsoft_malware_accuracy_curve.png"))
        plt.close()

        metrics = {
            "train_samples": int(len(X_train)),
            "test_samples": int(len(X_test)),
            "accuracy": float(acc),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
        }
        with open(os.path.join(microsoft_malware_reports_dir, "microsoft_malware_training_summary.json"), "w") as f:
            json.dump(metrics, f, indent=4)

        integrity_training_state["microsoft_malware"] = {"trained": True, "metrics": metrics}
        return jsonify({"success": True, "metrics": metrics})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/integrity-verification/microsoft-malware/infer-dataset', methods=['POST'])
def microsoft_malware_infer_dataset():
    try:
        if not models["microsoft_malware"].is_trained:
            return jsonify({"success": False, "error": "Model not trained"}), 400
        data = request.json or {}
        limit = int(data.get("limit", 200))
        store = bool(data.get("store", False))
        if not os.path.exists(microsoft_malware_data_path):
            return jsonify({"success": False, "error": "Dataset not found"}), 400
        df = pd.read_csv(microsoft_malware_data_path, nrows=limit)
        if "Class" not in df.columns:
            return jsonify({"success": False, "error": "Dataset missing Class column"}), 400
        y_true = df["Class"].astype(int).values
        X = df.drop(columns=["Class"])

        pred, conf, _ = models["microsoft_malware"].predict_df(X.assign(Class=y_true))
        preds = []
        for i in range(len(pred)):
            preds.append(
                {
                    "id": f"row_{i}",
                    "true_class": int(y_true[i]),
                    "predicted_class": int(pred[i]),
                    "confidence": float(conf[i] * 100.0),
                }
            )
        if store:
            integrity_latest_results["microsoft_malware"] = {
                "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                "predictions": preds,
            }
        return jsonify({"success": True, "predictions": preds})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/integrity-verification/microsoft-malware/infer', methods=['POST'])
def microsoft_malware_infer():
    try:
        if not models["microsoft_malware"].is_trained:
            return jsonify({"success": False, "error": "Model not trained"}), 400
        data = request.json or {}
        samples = data.get("samples", [])
        store = bool(data.get("store", False))
        pred, conf, _ = models["microsoft_malware"].predict_samples(samples)
        preds = []
        for i in range(len(pred)):
            preds.append(
                {
                    "id": samples[i].get("id", f"sample_{i}") if isinstance(samples[i], dict) else f"sample_{i}",
                    "predicted_class": int(pred[i]),
                    "confidence": float(conf[i] * 100.0),
                }
            )
        if store:
            integrity_latest_results["microsoft_malware"] = {
                "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                "predictions": preds,
            }
        return jsonify({"success": True, "predictions": preds})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/integrity-verification/microsoft-malware/latest', methods=['GET'])
def microsoft_malware_latest():
    return jsonify({"success": True, **integrity_latest_results["microsoft_malware"]})


@app.route('/api/ml/integrity-verification/malware/hash-lookup', methods=['POST'])
def integrity_malware_hash_lookup():
    data = request.json or {}
    artifact_hash = str(data.get("hash") or "").strip().lower()
    if not artifact_hash:
        return jsonify({"success": False, "error": "hash is required"}), 400
    normalized = artifact_hash if artifact_hash.startswith("sha256:") else f"sha256:{artifact_hash}"
    match = known_malware_hashes.get(normalized)
    return jsonify(
        {
            "success": True,
            "hash": normalized,
            "matched": bool(match),
            "match": match,
            "context": {
                "package": str(data.get("package") or ""),
                "version": str(data.get("version") or ""),
                "source": str(data.get("source") or "npm"),
            },
        }
    )


@app.route('/api/ml/integrity-verification/hash', methods=['POST'])
def integrity_hash():
    data = request.json or {}
    content = data.get("content", "")
    if not isinstance(content, (str, bytes)):
        return jsonify({"success": False, "error": "Invalid content"}), 400
    raw = content.encode("utf-8") if isinstance(content, str) else content
    digest = hashlib.sha256(raw).hexdigest()
    return jsonify({"success": True, "sha256": digest})


@app.route('/api/ml/integrity-verification/hash/verify', methods=['POST'])
def integrity_hash_verify():
    data = request.json or {}
    content = data.get("content", "")
    expected = data.get("expected_hash", "")
    if not isinstance(content, (str, bytes)) or not isinstance(expected, str):
        return jsonify({"success": False, "error": "Invalid input"}), 400
    raw = content.encode("utf-8") if isinstance(content, str) else content
    actual = hashlib.sha256(raw).hexdigest()
    return jsonify({"success": True, "expected_hash": expected, "actual_hash": actual, "match": bool(actual == expected)})


@app.route('/api/ml/integrity-verification/sbom/hash', methods=['POST'])
def integrity_sbom_hash():
    data = request.json or {}
    sbom_json = data.get("sbom_json", "")
    if not isinstance(sbom_json, str):
        return jsonify({"success": False, "error": "Invalid sbom_json"}), 400
    try:
        parsed = json.loads(sbom_json)
    except Exception:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400
    normalized = json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(normalized).hexdigest()
    dep_count = None
    if isinstance(parsed, dict):
        if isinstance(parsed.get("dependencies"), list):
            dep_count = len(parsed.get("dependencies"))
        elif isinstance(parsed.get("components"), list):
            dep_count = len(parsed.get("components"))
    return jsonify({"success": True, "sha256": digest, "dependency_count": dep_count})


@app.route('/api/ml/integrity-verification/pipeline-sbom/capture', methods=['POST'])
def integrity_pipeline_sbom_capture():
    try:
        data = request.json or {}
        pipeline_id = str(data.get("pipeline_id") or "").strip()
        if not pipeline_id:
            return jsonify({"success": False, "error": "pipeline_id is required"}), 400
        stage_sbom = pipeline_sbom_orchestrator.capture_stage_context(data)
        upsert = forensic_verification_service.upsert_stage_sbom(pipeline_id, stage_sbom)
        deps = []
        for c in stage_sbom.get("components", []):
            if isinstance(c, dict):
                deps.append(
                    {
                        "id": f"{pipeline_id}:{stage_sbom.get('metadata', {}).get('pipelineStage', {}).get('stageIndex', 0)}:{c.get('name')}",
                        "timestamp": stage_sbom.get("metadata", {}).get("timestamp"),
                        "name": c.get("name"),
                        "version": c.get("version"),
                        "previous_version": "",
                        "build_id": pipeline_id,
                        "maintainer_count": c.get("maintainer_count", 1),
                        "github_stars": c.get("github_stars", 0),
                        "download_count": c.get("download_count", 0),
                    }
                )
        if deps:
            incident_analysis_service.ingest_dependency_history(deps)
        return jsonify({"success": True, "pipeline_id": pipeline_id, "stage_sbom": stage_sbom, **upsert})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/integrity-verification/pipeline-sbom/finalize', methods=['POST'])
def integrity_pipeline_sbom_finalize():
    try:
        data = request.json or {}
        pipeline_id = str(data.get("pipeline_id") or "").strip()
        if not pipeline_id:
            return jsonify({"success": False, "error": "pipeline_id is required"}), 400
        result = forensic_verification_service.finalize_pipeline(pipeline_id)
        code = 200 if result.get("success") else 400
        return jsonify(result), code
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/integrity-verification/pipeline-sbom/verify-stage', methods=['POST'])
def integrity_pipeline_sbom_verify_stage():
    try:
        data = request.json or {}
        pipeline_id = str(data.get("pipeline_id") or "").strip()
        stage_index = data.get("stage_index", None)
        if not pipeline_id or stage_index is None:
            return jsonify({"success": False, "error": "pipeline_id and stage_index are required"}), 400
        result = forensic_verification_service.verify_stage(pipeline_id, int(stage_index))
        code = 200 if result.get("success") else 400
        return jsonify(result), code
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/integrity-verification/pipeline-sbom/pipeline/<pipeline_id>', methods=['GET'])
def integrity_pipeline_sbom_get_pipeline(pipeline_id):
    result = forensic_verification_service.get_pipeline(str(pipeline_id))
    code = 200 if result.get("success") else 404
    return jsonify(result), code


@app.route('/api/ml/integrity-verification/pipeline-sbom/pipelines', methods=['GET'])
def integrity_pipeline_sbom_list():
    return jsonify(forensic_verification_service.list_pipelines())


@app.route('/api/ml/integrity-verification/verification/verify-pipeline/<pipeline_id>', methods=['GET'])
def integrity_verify_pipeline(pipeline_id):
    result = forensic_verification_service.verify_pipeline_integrity(str(pipeline_id))
    code = 200 if result.get("success") else 404
    return jsonify(result), code


@app.route('/api/ml/integrity-verification/verification/query-vulnerable-builds', methods=['GET'])
def integrity_query_vulnerable_builds():
    cve_id = request.args.get("cve_id", "")
    result = forensic_verification_service.query_vulnerable_builds(cve_id)
    code = 200 if result.get("success") else 400
    return jsonify(result), code


@app.route('/api/ml/integrity-verification/verification/trace-artifact', methods=['GET'])
def integrity_trace_artifact():
    artifact_hash = request.args.get("artifact_hash", "")
    result = forensic_verification_service.trace_artifact_provenance(artifact_hash)
    code = 200 if result.get("success") else 400
    return jsonify(result), code


@app.route('/api/ml/integration/flow/status', methods=['GET'])
def integration_flow_status():
    try:
        pipeline_id = str(request.args.get("pipeline_id", "")).strip() or None
        return jsonify({"success": True, "flow": build_integration_flow_snapshot(pipeline_id)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ml/integration/flow/decision', methods=['POST'])
def integration_flow_decision():
    try:
        data = request.json or {}
        pipeline_id = str(data.get("pipeline_id", "")).strip() or None
        flow = build_integration_flow_snapshot(pipeline_id)
        return jsonify({"success": True, "decision": flow.get("decision"), "reasons": flow.get("reasons", []), "flow": flow})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


def merkle_root_sha256(hex_hashes):
    level = [bytes.fromhex(h) for h in hex_hashes]
    if not level:
        return None
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hashlib.sha256(left + right).digest())
        level = nxt
    return level[0].hex()


@app.route('/api/ml/integrity-verification/merkle/root', methods=['POST'])
def integrity_merkle_root():
    data = request.json or {}
    hashes = data.get("hashes", [])
    if not isinstance(hashes, list) or any((not isinstance(h, str)) for h in hashes):
        return jsonify({"success": False, "error": "Invalid hashes"}), 400
    cleaned = [h.strip().lower() for h in hashes if h and isinstance(h, str)]
    for h in cleaned:
        if len(h) != 64:
            return jsonify({"success": False, "error": "All hashes must be 64 hex chars (sha256)"}), 400
        try:
            bytes.fromhex(h)
        except Exception:
            return jsonify({"success": False, "error": "Invalid hex hash"}), 400
    root = merkle_root_sha256(cleaned)
    return jsonify({"success": True, "root": root, "count": len(cleaned)})


@app.route('/api/ml/integrity-verification/sign/hmac', methods=['POST'])
def integrity_sign_hmac():
    data = request.json or {}
    payload = data.get("payload", "")
    secret = data.get("secret", "")
    if not isinstance(payload, str) or not isinstance(secret, str) or not secret:
        return jsonify({"success": False, "error": "Invalid payload/secret"}), 400
    sig = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return jsonify({"success": True, "signature": sig})


@app.route('/api/ml/integrity-verification/verify/hmac', methods=['POST'])
def integrity_verify_hmac():
    data = request.json or {}
    payload = data.get("payload", "")
    secret = data.get("secret", "")
    signature = data.get("signature", "")
    if not isinstance(payload, str) or not isinstance(secret, str) or not isinstance(signature, str) or not secret:
        return jsonify({"success": False, "error": "Invalid input"}), 400
    expected = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return jsonify({"success": True, "valid": bool(hmac.compare_digest(expected, signature)), "expected": expected})


@app.route('/api/ml/integrity-verification/keys/ed25519', methods=['POST'])
def integrity_keys_ed25519():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return jsonify({"success": True, "private_key_pem": priv_pem, "public_key_pem": pub_pem})


@app.route('/api/ml/integrity-verification/sign/ed25519', methods=['POST'])
def integrity_sign_ed25519():
    data = request.json or {}
    payload = data.get("payload", "")
    private_key_pem = data.get("private_key_pem", "")
    if not isinstance(payload, str) or not isinstance(private_key_pem, str) or not private_key_pem:
        return jsonify({"success": False, "error": "Invalid payload/private_key_pem"}), 400
    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    except Exception:
        return jsonify({"success": False, "error": "Invalid private_key_pem"}), 400
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        return jsonify({"success": False, "error": "Private key must be Ed25519"}), 400
    sig = private_key.sign(payload.encode("utf-8"))
    return jsonify({"success": True, "signature_b64": base64.b64encode(sig).decode("utf-8")})


@app.route('/api/ml/integrity-verification/verify/ed25519', methods=['POST'])
def integrity_verify_ed25519():
    data = request.json or {}
    payload = data.get("payload", "")
    public_key_pem = data.get("public_key_pem", "")
    signature_b64 = data.get("signature_b64", "")
    if not isinstance(payload, str) or not isinstance(public_key_pem, str) or not isinstance(signature_b64, str):
        return jsonify({"success": False, "error": "Invalid input"}), 400
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception:
        return jsonify({"success": False, "error": "Invalid public_key_pem"}), 400
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        return jsonify({"success": False, "error": "Public key must be Ed25519"}), 400
    try:
        sig = base64.b64decode(signature_b64.encode("utf-8"))
    except Exception:
        return jsonify({"success": False, "error": "Invalid signature_b64"}), 400
    try:
        public_key.verify(sig, payload.encode("utf-8"))
        return jsonify({"success": True, "valid": True})
    except Exception:
        return jsonify({"success": True, "valid": False})

@app.route('/api/ml/reporting-portal/correlate', methods=['POST'])
def correlate_evidence():
    try:
        data = request.json
        evidence_data = data.get('evidence', [])
        
        correlation_results = models['evidence_correlator'].correlate(evidence_data)
        timeline = models['evidence_correlator'].build_timeline(evidence_data, correlation_results)
        
        return jsonify({
            'success': True,
            'correlations': correlation_results,
            'timeline': timeline
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route("/api/ml/reporting-portal/status", methods=["GET"])
def reporting_portal_status():
    return jsonify(
        {
            "success": True,
            "datasets": {
                "attack_dataset_present": os.path.exists(reporting_attack_csv_path),
                "breaches_dataset_present": os.path.exists(reporting_breaches_csv_path),
            },
            "training_state": reporting_training_state,
        }
    )


@app.route("/api/ml/reporting-portal/train", methods=["POST"])
def reporting_portal_train():
    data = request.json or {}
    models_req = data.get("models", ["attack_type", "breach_type"])
    limit_attack = data.get("limit_attack")
    limit_breaches = data.get("limit_breaches")
    if not isinstance(models_req, list):
        return jsonify({"success": False, "error": "models must be a list"}), 400
    out = {"success": True, "summary": {}}
    try:
        if "attack_type" in models_req:
            if not os.path.exists(reporting_attack_csv_path):
                return jsonify({"success": False, "error": "Attack_Dataset.csv not found"}), 400
            model, summary = train_attack_type_model(
                reporting_attack_csv_path, reporting_attack_model_path, limit=limit_attack
            )
            models["reporting_attack_type"] = model
            reporting_training_state["attack_type"]["trained"] = True
            reporting_training_state["attack_type"]["metrics"] = summary.get("metrics")
            reporting_training_state["attack_type"]["reports"] = summary.get("reports", [])
            out["summary"]["attack_type"] = summary
        if "breach_type" in models_req:
            if not os.path.exists(reporting_breaches_csv_path):
                return jsonify({"success": False, "error": "Cyber Security Breaches.csv not found"}), 400
            model, summary = train_breach_type_model(
                reporting_breaches_csv_path, reporting_breach_model_path, limit=limit_breaches
            )
            models["reporting_breach_type"] = model
            reporting_training_state["breach_type"]["trained"] = True
            reporting_training_state["breach_type"]["metrics"] = summary.get("metrics")
            reporting_training_state["breach_type"]["reports"] = summary.get("reports", [])
            out["summary"]["breach_type"] = summary
        return jsonify(out)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/ml/reporting-portal/infer-sample", methods=["POST"])
def reporting_portal_infer_sample():
    data = request.json or {}
    model = data.get("model")
    record = data.get("record")
    if model not in ["attack_type", "breach_type"]:
        return jsonify({"success": False, "error": "model must be attack_type or breach_type"}), 400
    if not isinstance(record, dict):
        return jsonify({"success": False, "error": "record must be an object"}), 400
    try:
        if model == "attack_type":
            pred = models["reporting_attack_type"].predict(record)
        else:
            pred = models["reporting_breach_type"].predict(record)
        return jsonify({"success": True, "model": model, "prediction": pred})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/ml/reporting-portal/infer-dataset", methods=["POST"])
def reporting_portal_infer_dataset():
    data = request.json or {}
    model = data.get("model")
    limit = data.get("limit", 200)
    store = bool(data.get("store", True))
    if model not in ["attack_type", "breach_type"]:
        return jsonify({"success": False, "error": "model must be attack_type or breach_type"}), 400
    try:
        limit = int(limit)
        if limit <= 0:
            limit = 200
    except Exception:
        limit = 200
    try:
        preds = []
        if model == "attack_type":
            df = pd.read_csv(reporting_attack_csv_path).head(limit)
            for _, row in df.iterrows():
                rec = row.to_dict()
                p = models["reporting_attack_type"].predict(rec)
                preds.append(
                    {
                        "id": str(rec.get("ID", "")),
                        "title": rec.get("Title", ""),
                        "true": rec.get("Attack Type", None),
                        "predicted": p.get("predicted"),
                        "classes": p.get("classes"),
                        "proba": p.get("proba"),
                    }
                )
        else:
            df = pd.read_csv(reporting_breaches_csv_path).head(limit)
            for _, row in df.iterrows():
                rec = row.to_dict()
                p = models["reporting_breach_type"].predict(rec)
                preds.append(
                    {
                        "id": str(rec.get("Number", "")),
                        "entity": rec.get("Name_of_Covered_Entity", ""),
                        "true": rec.get("Type_of_Breach", None),
                        "predicted": p.get("predicted"),
                        "classes": p.get("classes"),
                        "proba": p.get("proba"),
                    }
                )
        ts = __import__("datetime").datetime.utcnow().isoformat() + "Z"
        if store:
            reporting_latest_results[model]["timestamp"] = ts
            reporting_latest_results[model]["predictions"] = preds
        return jsonify({"success": True, "model": model, "timestamp": ts, "predictions": preds})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/ml/reporting-portal/latest", methods=["GET"])
def reporting_portal_latest():
    model = request.args.get("model")
    if model and model not in ["attack_type", "breach_type"]:
        return jsonify({"success": False, "error": "model must be attack_type or breach_type"}), 400
    if not model:
        return jsonify({"success": True, "latest": reporting_latest_results})
    return jsonify(
        {
            "success": True,
            "model": model,
            "timestamp": reporting_latest_results[model]["timestamp"],
            "predictions": reporting_latest_results[model]["predictions"],
        }
    )


@app.route("/api/ml/reporting-portal/reports/<model>/<filename>", methods=["GET"])
def reporting_portal_reports(model, filename):
    if model not in ["attack_type", "breach_type"]:
        return jsonify({"success": False, "error": "model must be attack_type or breach_type"}), 400
    reports_dir = os.path.join(reporting_dir, "reports", model)
    if not os.path.exists(os.path.join(reports_dir, filename)):
        return jsonify({"success": False, "error": "Report not found"}), 404
    return send_from_directory(reports_dir, filename)


@app.route("/api/ml/reporting-portal/forensic-data", methods=["GET"])
def reporting_portal_forensic_data():
    state = load_cicd_state()
    evidence_items = list(reversed(state.get("evidence", [])))
    timeline = []
    for i, ev in enumerate(evidence_items[:1000]):
        ts = ev.get("timestamp")
        et = ev.get("type", "")
        mapped_type = "build" if "build" in et or "log" in et else "artifact" if "artifact" in et else "commit" if "commit" in et or "git" in et else "dependency" if "depend" in et else "build"
        timeline.append(
            {
                "id": f"evidence-{i}",
                "type": mapped_type,
                "timestamp": ts,
                "title": ev.get("description", "Evidence captured"),
                "description": ev.get("description", ""),
                "metadata": ev.get("metadata", {}),
            }
        )

    for m in ["commit_pattern", "dependency_anomaly", "pipeline_tampering"]:
        lr = latest_results.get(m, {})
        for a in (lr.get("anomalies") or [])[:200]:
            cat = a.get("category", "")
            mapped_type = "commit" if "commit" in cat else "dependency" if "dependency" in cat else "build"
            timeline.append(
                {
                    "id": a.get("id", f"{m}-anomaly"),
                    "type": mapped_type,
                    "timestamp": lr.get("timestamp"),
                    "title": "Anomaly detected",
                    "description": cat,
                    "metadata": a.get("details", {}),
                }
            )

    integrity_proofs = []
    for t in timeline[:200]:
        payload = json.dumps({"id": t.get("id"), "type": t.get("type"), "timestamp": t.get("timestamp"), "metadata": t.get("metadata")}, sort_keys=True)
        h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        integrity_proofs.append(
            {
                "id": f"proof-{t.get('id')}",
                "artifactName": str(t.get("id")),
                "algorithm": "SHA-256",
                "hash": h,
                "payload": payload,
                "signature": None,
                "merkleRoot": None,
                "status": "verified" if h else "pending",
                "createdAt": t.get("timestamp"),
                "verifiedAt": t.get("timestamp") if h else None,
            }
        )

    last_updated = __import__("datetime").datetime.utcnow().isoformat() + "Z"
    return jsonify(
        {
            "success": True,
            "timeline": timeline,
            "integrityProofs": integrity_proofs,
            "evidenceCount": len(timeline),
            "lastUpdated": last_updated,
        }
    )


@app.route("/api/ml/reporting-portal/custody", methods=["GET"])
def reporting_portal_custody():
    state = load_cicd_state()
    evidence_items = list(reversed(state.get("evidence", [])))
    logs = []
    for i, ev in enumerate(evidence_items[:500]):
        ts = ev.get("timestamp")
        et = ev.get("type", "evidence")
        evidence_id = f"EVIDENCE-{str(i).zfill(4)}"
        custodian = "system"
        md = ev.get("metadata", {}) or {}
        if isinstance(md, dict):
            if md.get("app_id"):
                custodian = str(md.get("app_id"))
        logs.append(
            {
                "id": f"log-{i}",
                "evidenceId": evidence_id,
                "evidenceType": et,
                "status": "collected",
                "custodian": custodian,
                "location": f"/var/www/forensic-portal/backend/data/evidence/{evidence_id}.json",
                "timestamp": ts,
                "previousCustodian": None,
                "transferReason": None,
                "checksum": hashlib.sha256(json.dumps(ev, sort_keys=True).encode("utf-8")).hexdigest(),
                "history": [
                    {
                        "timestamp": ts,
                        "action": "collected",
                        "custodian": custodian,
                        "notes": "Evidence collected",
                    }
                ],
            }
        )
    return jsonify({"success": True, "custodyLogs": logs})


@app.route("/api/ml/reporting-portal/report/generate", methods=["POST"])
def reporting_portal_generate_report():
    data = request.json or {}
    config = data.get("config", {}) or {}
    fd = reporting_portal_forensic_data().get_json() or {}
    timeline = fd.get("timeline", [])
    custody = reporting_portal_custody().get_json() or {}
    custody_logs = custody.get("custodyLogs", [])
    payload = json.dumps({"config": config, "timeline": timeline[:500], "custody": custody_logs[:500]}, sort_keys=True)
    report_id = "REPORT-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    now = __import__("datetime").datetime.utcnow().isoformat() + "Z"
    evidence_count = len(timeline)
    include_timeline = bool(config.get("includeTimeline", True))
    include_integrity = bool(config.get("includeIntegrityProofs", True))
    include_custody = bool(config.get("includeCustodyLogs", True))
    sections = []
    sections.append(
        {
            "title": "Executive Summary",
            "content": f"This report contains {evidence_count} evidence items captured from CI/CD monitoring and analytics.",
        }
    )
    sections.append(
        {
            "title": "Evidence Timeline",
            "content": "Included" if include_timeline else "Excluded",
        }
    )
    sections.append(
        {
            "title": "Integrity Verification",
            "content": "Included" if include_integrity else "Excluded",
        }
    )
    sections.append(
        {
            "title": "Chain of Custody",
            "content": "Included" if include_custody else "Excluded",
        }
    )
    report = {
        "id": report_id,
        "standard": str(config.get("standard", "ISO/IEC 27037")),
        "format": str(config.get("format", "JSON")),
        "generatedAt": now,
        "generatedBy": "forensic-ml-api",
        "evidenceCount": evidence_count,
        "pages": max(1, int((evidence_count / 10) + 5)),
        "summary": f"Forensic report generated with {evidence_count} evidence items.",
        "sections": sections,
        "config": config,
        "forensicData": {"timeline": timeline if include_timeline else [], "integrityProofs": fd.get("integrityProofs", []) if include_integrity else []},
        "custodyLogs": custody_logs if include_custody else [],
    }
    return jsonify({"success": True, "report": report})

@app.route('/api/ml/train/<model_name>', methods=['POST'])
def train_model(model_name):
    try:
        if model_name not in models:
            return jsonify({'success': False, 'error': 'Model not found'}), 404
        
        data = request.json
        training_data = data.get('data', [])
        labels = data.get('labels', None)
        
        if model_name == 'evidence_pattern':
            results = models[model_name].train(training_data, labels)
        elif model_name == 'commit_pattern':
            if labels is None:
                return jsonify({'success': False, 'error': 'Labels required'}), 400
            results = models[model_name].train(training_data, labels)
        elif model_name == 'pipeline_tampering':
            if labels is None:
                return jsonify({'success': False, 'error': 'Labels required'}), 400
            results = models[model_name].train(training_data, labels)
        elif model_name == 'dependency_anomaly':
            results = models[model_name].train(training_data, labels)
        elif model_name == 'tampering_detector':
            if labels is None:
                return jsonify({'success': False, 'error': 'Labels required'}), 400
            results = models[model_name].train(training_data, labels)
        elif model_name == 'evidence_correlator':
            results = models[model_name].train(training_data)
        
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", "5000"))
    app.run(debug=False, use_reloader=False, host='0.0.0.0', port=port)


