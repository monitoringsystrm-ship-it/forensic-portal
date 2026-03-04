import hashlib


class PipelineMerkleTree:
    def __init__(self):
        self.stage_entries = []
        self.leaf_hashes = []
        self.levels = []

    def add_stage(self, stage_sbom):
        stage_hash = self.hash_sbom(stage_sbom)
        stage_meta = (stage_sbom.get("metadata") or {}).get("pipelineStage") or {}
        self.stage_entries.append(
            {
                "stage_name": stage_meta.get("stageName"),
                "stage_index": stage_meta.get("stageIndex"),
                "sbom_hash": stage_hash,
                "timestamp": stage_meta.get("startTime"),
            }
        )
        self.leaf_hashes.append(stage_hash)
        return stage_hash

    def hash_sbom(self, stage_sbom):
        encoded = self._normalized_json(stage_sbom).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def finalize_pipeline(self):
        if not self.leaf_hashes:
            return {"root_hash": None, "proof_chain": {}, "stages": self.stage_entries, "leaf_hashes": []}
        self.levels = [self.leaf_hashes[:]]
        level = self.leaf_hashes[:]
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                nxt.append(self._pair_hash(left, right))
            self.levels.append(nxt)
            level = nxt
        root_hash = self.levels[-1][0]
        proof_chain = {}
        for i in range(len(self.leaf_hashes)):
            proof_chain[str(i)] = self.get_proof(i)
        return {
            "root_hash": root_hash,
            "proof_chain": proof_chain,
            "stages": self.stage_entries,
            "leaf_hashes": self.leaf_hashes,
        }

    def get_proof(self, index):
        proof = []
        idx = index
        for level in self.levels[:-1]:
            if idx % 2 == 0:
                sibling_index = idx + 1 if idx + 1 < len(level) else idx
                direction = "right"
            else:
                sibling_index = idx - 1
                direction = "left"
            proof.append({"direction": direction, "hash": level[sibling_index]})
            idx = idx // 2
        return proof

    def verify_stage(self, stage_index, stage_sbom, root_hash, proof):
        current = self.hash_sbom(stage_sbom)
        for step in proof:
            direction = step.get("direction")
            sibling = step.get("hash")
            if direction == "left":
                current = self._pair_hash(sibling, current)
            else:
                current = self._pair_hash(current, sibling)
        return bool(current == root_hash)

    def _pair_hash(self, left_hex, right_hex):
        left = bytes.fromhex(left_hex)
        right = bytes.fromhex(right_hex)
        return hashlib.sha256(left + right).hexdigest()

    def _normalized_json(self, value):
        import json

        return json.dumps(value, sort_keys=True, separators=(",", ":"))
