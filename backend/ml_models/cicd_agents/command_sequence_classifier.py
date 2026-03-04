import re


class CommandSequenceClassifier:
    def __init__(self):
        self.is_trained = True
        self.benign_patterns = [
            re.compile(r"^npm\s+ci(\s|$)", re.IGNORECASE),
            re.compile(r"^npm\s+install(\s|$)", re.IGNORECASE),
            re.compile(r"^npm\s+run\s+build(\s|$)", re.IGNORECASE),
            re.compile(r"^npm\s+test(\s|$)", re.IGNORECASE),
            re.compile(r"^yarn\s+install(\s|$)", re.IGNORECASE),
            re.compile(r"^yarn\s+build(\s|$)", re.IGNORECASE),
            re.compile(r"^docker\s+build(\s|$)", re.IGNORECASE),
            re.compile(r"^docker\s+tag(\s|$)", re.IGNORECASE),
            re.compile(r"^docker\s+push(\s|$)", re.IGNORECASE),
        ]
        self.suspicious_patterns = [
            (re.compile(r"curl\s+.+http", re.IGNORECASE), "external_download"),
            (re.compile(r"wget\s+.+http", re.IGNORECASE), "external_download"),
            (re.compile(r"chmod\s+\+x", re.IGNORECASE), "executable_permission_change"),
            (re.compile(r"^bash\s+.+\.sh", re.IGNORECASE), "remote_script_execution"),
            (re.compile(r"^sh\s+.+\.sh", re.IGNORECASE), "remote_script_execution"),
            (re.compile(r"powershell\s+-enc", re.IGNORECASE), "encoded_command"),
            (re.compile(r"base64\s+-d", re.IGNORECASE), "base64_decode"),
            (re.compile(r"env\s*\|\s*curl", re.IGNORECASE), "env_exfiltration"),
            (re.compile(r"printenv\s*\|\s*curl", re.IGNORECASE), "env_exfiltration"),
            (re.compile(r"curl\s+-x\s+post", re.IGNORECASE), "http_post_outbound"),
            (re.compile(r"nc\s+-e", re.IGNORECASE), "reverse_shell"),
            (re.compile(r"/bin/bash\s+-i", re.IGNORECASE), "interactive_shell"),
            (re.compile(r"miner\.sh|xmrig|cryptominer", re.IGNORECASE), "crypto_miner"),
        ]

    def train(self, benign_sequences=None, malicious_sequences=None):
        self.is_trained = True
        return {
            "success": True,
            "trained": True,
            "benign_samples": len(benign_sequences or []),
            "malicious_samples": len(malicious_sequences or []),
        }

    def classify_commands(self, build_id, commands):
        command_results = []
        suspicious_hits = 0
        malicious_hits = 0

        for i, cmd in enumerate(commands):
            command = str(cmd or "").strip()
            if not command:
                continue
            lower = command.lower()
            score = 0
            reasons = []

            for pattern, reason in self.suspicious_patterns:
                if pattern.search(lower):
                    if reason in ("reverse_shell", "crypto_miner", "env_exfiltration"):
                        score += 55
                        malicious_hits += 1
                    else:
                        score += 25
                        suspicious_hits += 1
                    reasons.append(reason)

            benign_match = False
            for pattern in self.benign_patterns:
                if pattern.search(lower):
                    benign_match = True
                    break

            if benign_match and score == 0:
                label = "BENIGN"
                confidence = 0.92
            elif score >= 55:
                label = "MALICIOUS"
                confidence = min(0.99, 0.65 + (score / 200.0))
            elif score > 0:
                label = "SUSPICIOUS"
                confidence = min(0.98, 0.55 + (score / 250.0))
            else:
                label = "BENIGN"
                confidence = 0.68

            command_results.append(
                {
                    "index": i,
                    "command": command,
                    "classification": label,
                    "confidence": float(round(confidence, 4)),
                    "anomaly_score": int(min(100, score)),
                    "reasons": reasons,
                }
            )

        overall = "BENIGN"
        if any(c["classification"] == "MALICIOUS" for c in command_results):
            overall = "MALICIOUS"
        elif any(c["classification"] == "SUSPICIOUS" for c in command_results):
            overall = "SUSPICIOUS"

        overall_conf = 0.7
        if command_results:
            overall_conf = sum(c["confidence"] for c in command_results) / len(command_results)

        risk_level = "LOW"
        if overall == "SUSPICIOUS":
            risk_level = "MEDIUM"
        if overall == "MALICIOUS":
            risk_level = "HIGH"

        alerts = []
        for c in command_results:
            if c["classification"] in ("SUSPICIOUS", "MALICIOUS"):
                alerts.append(
                    {
                        "build_id": build_id,
                        "alert": "Suspicious command detected",
                        "command": c["command"],
                        "confidence": c["confidence"],
                        "risk_level": "HIGH" if c["classification"] == "MALICIOUS" else "MEDIUM",
                        "why": c["reasons"],
                    }
                )

        return {
            "build_id": build_id,
            "classification": overall,
            "confidence": float(round(overall_conf, 4)),
            "risk_level": risk_level,
            "command_results": command_results,
            "alerts": alerts,
            "stats": {
                "total_commands": len(command_results),
                "suspicious_hits": suspicious_hits,
                "malicious_hits": malicious_hits,
            },
        }
