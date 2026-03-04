import json
import os
from datetime import datetime

from utils.pipeline_merkle_tree import PipelineMerkleTree


class ForensicVerificationService:
    def __init__(self, store_path):
        self.store_path = store_path
        os.makedirs(os.path.dirname(self.store_path), exist_ok=True)

    def upsert_stage_sbom(self, pipeline_id, stage_sbom):
        store = self._load_store()
        pipelines = store.setdefault("pipelines", {})
        pipeline = pipelines.setdefault(
            pipeline_id,
            {
                "pipeline_id": pipeline_id,
                "created_at": self._utc_now(),
                "updated_at": self._utc_now(),
                "stages": [],
                "merkle": {"root_hash": None, "proof_chain": {}, "leaf_hashes": [], "stages": []},
            },
        )
        stage_meta = (stage_sbom.get("metadata") or {}).get("pipelineStage") or {}
        stage_index = int(stage_meta.get("stageIndex", len(pipeline["stages"])) or 0)
        stage_hash = PipelineMerkleTree().hash_sbom(stage_sbom)
        entry = {
            "stage_index": stage_index,
            "stage_name": stage_meta.get("stageName"),
            "timestamp": stage_meta.get("startTime"),
            "sbom_hash": stage_hash,
            "sbom": stage_sbom,
        }
        replaced = False
        for i, e in enumerate(pipeline["stages"]):
            if int(e.get("stage_index", -1)) == stage_index:
                pipeline["stages"][i] = entry
                replaced = True
                break
        if not replaced:
            pipeline["stages"].append(entry)
        pipeline["stages"] = sorted(pipeline["stages"], key=lambda x: int(x.get("stage_index", 0)))
        pipeline["updated_at"] = self._utc_now()
        pipelines[pipeline_id] = pipeline
        store["pipelines"] = pipelines
        self._save_store(store)
        return {"pipeline_id": pipeline_id, "stage_index": stage_index, "sbom_hash": stage_hash}

    def finalize_pipeline(self, pipeline_id):
        store = self._load_store()
        pipeline = (store.get("pipelines") or {}).get(pipeline_id)
        if not pipeline:
            return {"success": False, "error": "Pipeline not found"}
        tree = PipelineMerkleTree()
        for stage in pipeline.get("stages", []):
            tree.add_stage(stage.get("sbom", {}))
        merkle = tree.finalize_pipeline()
        pipeline["merkle"] = merkle
        pipeline["updated_at"] = self._utc_now()
        store["pipelines"][pipeline_id] = pipeline
        self._save_store(store)
        return {"success": True, "pipeline_id": pipeline_id, "merkle": merkle}

    def verify_pipeline_integrity(self, pipeline_id):
        store = self._load_store()
        pipeline = (store.get("pipelines") or {}).get(pipeline_id)
        if not pipeline:
            return {"success": False, "error": "Pipeline not found"}
        current = self._rebuild_merkle(pipeline.get("stages", []))
        stored = (pipeline.get("merkle") or {}).get("root_hash")
        return {
            "success": True,
            "pipeline_id": pipeline_id,
            "stored_root_hash": stored,
            "rebuilt_root_hash": current.get("root_hash"),
            "verified": bool(stored and stored == current.get("root_hash")),
            "stage_count": len(pipeline.get("stages", [])),
        }

    def verify_stage(self, pipeline_id, stage_index):
        store = self._load_store()
        pipeline = (store.get("pipelines") or {}).get(pipeline_id)
        if not pipeline:
            return {"success": False, "error": "Pipeline not found"}
        merkle = pipeline.get("merkle") or {}
        root_hash = merkle.get("root_hash")
        proof_chain = merkle.get("proof_chain") or {}
        stages = pipeline.get("stages", [])
        stage = None
        for s in stages:
            if int(s.get("stage_index", -1)) == int(stage_index):
                stage = s
                break
        if not stage:
            return {"success": False, "error": "Stage not found"}
        proof = proof_chain.get(str(int(stage_index)), [])
        verifier = PipelineMerkleTree()
        valid = verifier.verify_stage(int(stage_index), stage.get("sbom", {}), root_hash, proof) if root_hash else False
        return {
            "success": True,
            "pipeline_id": pipeline_id,
            "stage_index": int(stage_index),
            "verified": bool(valid),
            "root_hash": root_hash,
            "sbom_hash": stage.get("sbom_hash"),
            "proof": proof,
        }

    def query_vulnerable_builds(self, cve_id):
        cve = str(cve_id or "").strip().upper()
        if not cve:
            return {"success": False, "error": "cve_id is required"}
        store = self._load_store()
        affected = []
        for pipeline_id, pipeline in (store.get("pipelines") or {}).items():
            for stage in pipeline.get("stages", []):
                sbom = stage.get("sbom", {})
                components = sbom.get("components", [])
                vulns = sbom.get("vulnerabilities", [])
                found = False
                reasons = []
                for v in vulns if isinstance(vulns, list) else []:
                    vid = str((v or {}).get("id") or "").upper()
                    if vid == cve:
                        found = True
                        reasons.append(f"vulnerability:{vid}")
                for comp in components if isinstance(components, list) else []:
                    cvs = comp.get("vulnerabilities", [])
                    if isinstance(cvs, list):
                        for cv in cvs:
                            if str(cv).upper() == cve:
                                found = True
                                reasons.append(f"component:{comp.get('name')}:{cv}")
                if found:
                    affected.append(
                        {
                            "pipeline_id": pipeline_id,
                            "stage_name": stage.get("stage_name"),
                            "stage_index": stage.get("stage_index"),
                            "timestamp": stage.get("timestamp"),
                            "reasons": reasons,
                        }
                    )
        return {"success": True, "cve_id": cve, "affected_pipelines": affected}

    def trace_artifact_provenance(self, artifact_hash):
        h = str(artifact_hash or "").strip().lower()
        if not h:
            return {"success": False, "error": "artifact_hash is required"}
        store = self._load_store()
        traces = []
        for pipeline_id, pipeline in (store.get("pipelines") or {}).items():
            for stage in pipeline.get("stages", []):
                sbom = stage.get("sbom", {})
                meta = sbom.get("metadata", {})
                inputs = meta.get("inputArtifacts", [])
                outputs = meta.get("outputArtifacts", [])
                for source, items in [("input", inputs), ("output", outputs)]:
                    if not isinstance(items, list):
                        continue
                    for item in items:
                        item_hash = str((item or {}).get("hash") or "").lower()
                        if item_hash == h:
                            traces.append(
                                {
                                    "pipeline_id": pipeline_id,
                                    "stage_name": stage.get("stage_name"),
                                    "stage_index": stage.get("stage_index"),
                                    "timestamp": stage.get("timestamp"),
                                    "source": source,
                                    "artifact": item,
                                }
                            )
        return {"success": True, "artifact_hash": h, "traces": traces}

    def get_pipeline(self, pipeline_id):
        store = self._load_store()
        pipeline = (store.get("pipelines") or {}).get(pipeline_id)
        if not pipeline:
            return {"success": False, "error": "Pipeline not found"}
        return {"success": True, "pipeline": pipeline}

    def list_pipelines(self):
        store = self._load_store()
        pipelines = []
        for pipeline_id, pipeline in (store.get("pipelines") or {}).items():
            pipelines.append(
                {
                    "pipeline_id": pipeline_id,
                    "created_at": pipeline.get("created_at"),
                    "updated_at": pipeline.get("updated_at"),
                    "stage_count": len(pipeline.get("stages", [])),
                    "root_hash": (pipeline.get("merkle") or {}).get("root_hash"),
                }
            )
        pipelines = sorted(pipelines, key=lambda x: str(x.get("updated_at") or ""), reverse=True)
        return {"success": True, "pipelines": pipelines}

    def _rebuild_merkle(self, stages):
        tree = PipelineMerkleTree()
        for stage in stages:
            tree.add_stage(stage.get("sbom", {}))
        return tree.finalize_pipeline()

    def _load_store(self):
        if not os.path.exists(self.store_path):
            return {"pipelines": {}}
        try:
            with open(self.store_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return {"pipelines": {}}
            if "pipelines" not in data or not isinstance(data["pipelines"], dict):
                data["pipelines"] = {}
            return data
        except Exception:
            return {"pipelines": {}}

    def _save_store(self, data):
        with open(self.store_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def _utc_now(self):
        return datetime.utcnow().isoformat() + "Z"
