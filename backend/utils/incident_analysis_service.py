import json
import math
import os
import statistics
from datetime import datetime, timedelta
from difflib import SequenceMatcher


class IncidentAnalysisService:
    def __init__(self, store_path):
        self.store_path = store_path
        os.makedirs(os.path.dirname(self.store_path), exist_ok=True)

    def ingest_github_commits(self, commits):
        state = self._load_state()
        if not isinstance(commits, list):
            commits = []
        for c in commits:
            if isinstance(c, dict):
                state["github_commits"].append(c)
        state["github_commits"] = self._dedupe_by_key(state["github_commits"], "sha")
        state["updated_at"] = self._now()
        self._save_state(state)
        return {"success": True, "count": len(state["github_commits"])}

    def ingest_dependency_history(self, changes):
        state = self._load_state()
        if not isinstance(changes, list):
            changes = []
        for d in changes:
            if isinstance(d, dict):
                state["dependency_changes"].append(d)
        state["dependency_changes"] = self._dedupe_by_key(state["dependency_changes"], "id")
        state["updated_at"] = self._now()
        self._save_state(state)
        return {"success": True, "count": len(state["dependency_changes"])}

    def ingest_jenkins_patterns(self, builds):
        state = self._load_state()
        if not isinstance(builds, list):
            builds = []
        for b in builds:
            if isinstance(b, dict):
                state["jenkins_builds"].append(b)
        state["jenkins_builds"] = self._dedupe_by_key(state["jenkins_builds"], "build_id")
        state["updated_at"] = self._now()
        self._save_state(state)
        return {"success": True, "count": len(state["jenkins_builds"])}

    def ingest_threat_intel(self, intel):
        state = self._load_state()
        payload = intel if isinstance(intel, dict) else {}
        compromised = payload.get("compromised_packages", [])
        advisories = payload.get("npm_advisories", [])
        cves = payload.get("cves", [])
        github_advisories = payload.get("github_advisories", [])
        if isinstance(compromised, list):
            state["threat_intel"]["compromised_packages"] = sorted(set([str(x).lower() for x in compromised]))
        if isinstance(advisories, list):
            state["threat_intel"]["npm_advisories"] = advisories
        if isinstance(cves, list):
            state["threat_intel"]["cves"] = cves
        if isinstance(github_advisories, list):
            state["threat_intel"]["github_advisories"] = github_advisories
        state["updated_at"] = self._now()
        self._save_state(state)
        return {"success": True, "threat_intel": state["threat_intel"]}

    def analyze(self, months=12):
        state = self._load_state()
        cutoff = datetime.utcnow() - timedelta(days=max(30, int(months) * 30))
        commits = self._filter_recent(state["github_commits"], cutoff, "timestamp")
        deps = self._filter_recent(state["dependency_changes"], cutoff, "timestamp")
        builds = self._filter_recent(state["jenkins_builds"], cutoff, "timestamp")
        commit_reports = self._analyze_commits(commits)
        dep_reports = self._analyze_dependencies(deps, state["threat_intel"])
        build_reports = self._analyze_build_patterns(builds)
        timeline = self._build_timeline(commit_reports, dep_reports, build_reports, builds)
        trends = self._build_trends(commits, deps, builds)
        result = {
            "generated_at": self._now(),
            "scope_months": int(months),
            "commit_anomalies": commit_reports,
            "dependency_risks": dep_reports,
            "build_anomalies": build_reports,
            "timeline": timeline,
            "trends": trends,
        }
        state["latest_analysis"] = result
        state["updated_at"] = self._now()
        self._save_state(state)
        return {"success": True, "analysis": result}

    def latest(self):
        state = self._load_state()
        return {"success": True, "latest_analysis": state.get("latest_analysis")}

    def _analyze_commits(self, commits):
        if not commits:
            return []
        by_author = {}
        for c in commits:
            author = str(c.get("author") or "unknown")
            by_author.setdefault(author, []).append(c)
        reports = []
        for author, items in by_author.items():
            items = sorted(items, key=lambda x: str(x.get("timestamp") or ""))
            total = len(items)
            for i, c in enumerate(items):
                score = 0
                reasons = []
                ts = self._parse_time(c.get("timestamp"))
                hour = ts.hour if ts else 12
                if hour < 6 or hour > 22:
                    score += 25
                    reasons.append(f"Unusual commit time ({hour:02d}:00)")
                if i == 0 and total == 1:
                    score += 20
                    reasons.append("First commit from contributor")
                files_changed = int(c.get("files_changed", 0) or 0)
                lines_added = int(c.get("lines_added", 0) or 0)
                lines_deleted = int(c.get("lines_deleted", 0) or 0)
                if files_changed >= 30 or (lines_added + lines_deleted) >= 4000:
                    score += 20
                    reasons.append("Large change set")
                diff_text = str(c.get("diff") or "")
                entropy = self._text_entropy(diff_text) if diff_text else 0.0
                if entropy >= 4.2:
                    score += 15
                    reasons.append("High code entropy")
                if self._contains_obfuscation(diff_text):
                    score += 20
                    reasons.append("Possible obfuscation")
                if "http://" in diff_text or "https://" in diff_text:
                    score += 10
                    reasons.append("External URL added")
                message = str(c.get("message") or "")
                if len(message) <= 6:
                    score += 5
                    reasons.append("Low-information commit message")
                anomaly_score = min(1.0, score / 100.0)
                if anomaly_score >= 0.7:
                    recommendation = "MANUAL_REVIEW"
                elif anomaly_score >= 0.45:
                    recommendation = "ELEVATED_MONITORING"
                else:
                    recommendation = "ALLOW"
                reports.append(
                    {
                        "commit_sha": c.get("sha") or c.get("id"),
                        "author": author,
                        "timestamp": c.get("timestamp"),
                        "anomaly_score": round(anomaly_score, 4),
                        "anomaly_type": "behavioral" if anomaly_score >= 0.45 else "normal",
                        "reasons": reasons,
                        "recommendation": recommendation,
                        "build_id": c.get("build_id"),
                    }
                )
        reports = sorted(reports, key=lambda x: x["anomaly_score"], reverse=True)
        return reports[:500]

    def _analyze_dependencies(self, deps, threat_intel):
        if not deps:
            return []
        popular = set(
            [
                "react",
                "react-dom",
                "next",
                "express",
                "axios",
                "lodash",
                "typescript",
                "webpack",
                "vite",
                "jest",
            ]
        )
        compromised = set([str(x).lower() for x in threat_intel.get("compromised_packages", [])])
        advisories = threat_intel.get("npm_advisories", [])
        reports = []
        for d in deps:
            name = str(d.get("name") or "").lower()
            version = str(d.get("version") or "")
            previous = str(d.get("previous_version") or "")
            score = 0
            reasons = []
            closest, distance = self._closest_package(name, popular)
            if closest and distance == 1 and name != closest:
                score += 45
                reasons.append(f"Possible typosquatting near {closest}")
            elif closest and distance == 2 and name != closest:
                score += 20
                reasons.append(f"Name similarity to {closest}")
            if name in compromised:
                score += 60
                reasons.append("Known compromised package")
            major_bump = self._is_major_bump(previous, version)
            if major_bump:
                score += 15
                reasons.append("Major version bump")
            if int(d.get("maintainer_count", 1) or 1) <= 1:
                score += 10
                reasons.append("Low maintainer count")
            if int(d.get("github_stars", 0) or 0) < 5:
                score += 8
                reasons.append("Low repository trust signal")
            if int(d.get("download_count", 0) or 0) < 500:
                score += 8
                reasons.append("Low package adoption")
            matched_advisories = []
            for a in advisories if isinstance(advisories, list) else []:
                pkg = str((a or {}).get("package") or "").lower()
                if pkg == name:
                    matched_advisories.append(a)
            if matched_advisories:
                score += 30
                reasons.append("Package present in npm advisories")
            anomaly_score = min(1.0, score / 100.0)
            recommendation = "ALLOW"
            if anomaly_score >= 0.8:
                recommendation = "BLOCK_INSTALL"
            elif anomaly_score >= 0.5:
                recommendation = "MANUAL_REVIEW"
            reports.append(
                {
                    "package": f"{name}@{version}",
                    "anomaly_score": round(anomaly_score, 4),
                    "anomaly_type": "typosquatting" if distance == 1 and name != closest else "dependency_risk",
                    "detection_method": "levenshtein_distance",
                    "distance_to_legit": distance if closest else None,
                    "similar_package": closest,
                    "reasons": reasons,
                    "recommendation": recommendation,
                    "build_id": d.get("build_id"),
                }
            )
        reports = sorted(reports, key=lambda x: x["anomaly_score"], reverse=True)
        return reports[:500]

    def _analyze_build_patterns(self, builds):
        if not builds:
            return []
        durations = [float(b.get("duration_sec", 0) or 0) for b in builds]
        image_sizes = [float(b.get("image_size_mb", 0) or 0) for b in builds]
        cpu = [float(b.get("cpu_percent", 0) or 0) for b in builds]
        memory = [float(b.get("memory_mb", 0) or 0) for b in builds]
        d_mean, d_std = self._mean_std(durations)
        s_mean, s_std = self._mean_std(image_sizes)
        c_mean, c_std = self._mean_std(cpu)
        m_mean, m_std = self._mean_std(memory)
        reports = []
        for b in builds:
            score = 0
            reasons = []
            duration = float(b.get("duration_sec", 0) or 0)
            image_size = float(b.get("image_size_mb", 0) or 0)
            cpu_pct = float(b.get("cpu_percent", 0) or 0)
            mem_mb = float(b.get("memory_mb", 0) or 0)
            success = bool(b.get("success", True))
            if not success:
                score += 20
                reasons.append("Build failed")
            if self._is_outlier(duration, d_mean, d_std):
                score += 20
                reasons.append("Build duration deviation")
            if self._is_outlier(image_size, s_mean, s_std):
                score += 20
                reasons.append("Docker image size deviation")
            if self._is_outlier(cpu_pct, c_mean, c_std):
                score += 15
                reasons.append("CPU usage deviation")
            if self._is_outlier(mem_mb, m_mean, m_std):
                score += 15
                reasons.append("Memory usage deviation")
            anomaly_score = min(1.0, score / 100.0)
            reports.append(
                {
                    "build_id": b.get("build_id"),
                    "pipeline_name": b.get("pipeline_name"),
                    "timestamp": b.get("timestamp"),
                    "anomaly_score": round(anomaly_score, 4),
                    "anomaly_type": "jenkins_build_pattern" if anomaly_score >= 0.4 else "normal",
                    "reasons": reasons,
                    "recommendation": "MANUAL_REVIEW" if anomaly_score >= 0.4 else "ALLOW",
                }
            )
        reports = sorted(reports, key=lambda x: x["anomaly_score"], reverse=True)
        return reports[:500]

    def _build_timeline(self, commit_reports, dep_reports, build_reports, builds):
        events = []
        build_map = {}
        for b in builds:
            bid = str(b.get("build_id") or "")
            if bid:
                build_map[bid] = b
        for c in commit_reports[:100]:
            if c["anomaly_score"] >= 0.45:
                events.append(
                    {
                        "type": "commit_anomaly",
                        "timestamp": c.get("timestamp"),
                        "title": f"Commit anomaly {c.get('commit_sha')}",
                        "details": c,
                        "build_id": c.get("build_id"),
                    }
                )
        for d in dep_reports[:100]:
            if d["anomaly_score"] >= 0.5:
                events.append(
                    {
                        "type": "dependency_anomaly",
                        "timestamp": None,
                        "title": f"Dependency anomaly {d.get('package')}",
                        "details": d,
                        "build_id": d.get("build_id"),
                    }
                )
        for b in build_reports[:100]:
            if b["anomaly_score"] >= 0.4:
                events.append(
                    {
                        "type": "build_anomaly",
                        "timestamp": b.get("timestamp"),
                        "title": f"Build anomaly {b.get('build_id')}",
                        "details": b,
                        "build_id": b.get("build_id"),
                    }
                )
        events = sorted(events, key=lambda x: str(x.get("timestamp") or "9999"))
        return events[:300]

    def _build_trends(self, commits, deps, builds):
        contributors = {}
        for c in commits:
            a = str(c.get("author") or "unknown")
            contributors[a] = contributors.get(a, 0) + 1
        commit_count = len(commits)
        dependency_churn = len(deps)
        build_count = len(builds)
        fail_count = len([b for b in builds if not bool(b.get("success", True))])
        durations = [float(b.get("duration_sec", 0) or 0) for b in builds]
        image_sizes = [float(b.get("image_size_mb", 0) or 0) for b in builds]
        return {
            "commit_count": commit_count,
            "top_contributors": sorted(
                [{"author": k, "count": v} for k, v in contributors.items()], key=lambda x: x["count"], reverse=True
            )[:20],
            "dependency_churn": dependency_churn,
            "build_count": build_count,
            "build_failure_rate": round((fail_count / build_count), 4) if build_count else 0.0,
            "avg_build_duration_sec": round(statistics.mean(durations), 2) if durations else 0.0,
            "avg_image_size_mb": round(statistics.mean(image_sizes), 2) if image_sizes else 0.0,
        }

    def _filter_recent(self, items, cutoff, ts_field):
        out = []
        for item in items:
            ts = self._parse_time(item.get(ts_field))
            if ts is None or ts >= cutoff:
                out.append(item)
        return out

    def _closest_package(self, name, pool):
        if not name or not pool:
            return None, None
        best_name = None
        best_distance = 1_000_000
        for p in pool:
            d = self._levenshtein(name, p)
            if d < best_distance:
                best_distance = d
                best_name = p
        return best_name, best_distance

    def _is_major_bump(self, previous, current):
        if not previous or not current:
            return False
        p0 = self._safe_int(previous.split(".")[0])
        c0 = self._safe_int(current.split(".")[0])
        return c0 > p0

    def _safe_int(self, x):
        try:
            return int(str(x).strip())
        except Exception:
            return 0

    def _mean_std(self, values):
        if not values:
            return 0.0, 0.0
        if len(values) == 1:
            return float(values[0]), 0.0
        return float(statistics.mean(values)), float(statistics.pstdev(values))

    def _is_outlier(self, value, mean, std):
        if std <= 0:
            return False
        z = abs((value - mean) / std)
        return z >= 2.0

    def _contains_obfuscation(self, text):
        t = text or ""
        if not t:
            return False
        if "eval(" in t or "fromCharCode(" in t or "atob(" in t:
            return True
        long_tokens = [w for w in t.split() if len(w) >= 60]
        return len(long_tokens) > 3

    def _text_entropy(self, text):
        if not text:
            return 0.0
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(text)
        entropy = 0.0
        for _, c in freq.items():
            p = c / n
            entropy -= p * math.log2(p)
        return entropy

    def _levenshtein(self, a, b):
        if a == b:
            return 0
        if len(a) == 0:
            return len(b)
        if len(b) == 0:
            return len(a)
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            curr = [i]
            for j, cb in enumerate(b, 1):
                ins = curr[j - 1] + 1
                delete = prev[j] + 1
                sub = prev[j - 1] + (0 if ca == cb else 1)
                curr.append(min(ins, delete, sub))
            prev = curr
        return prev[-1]

    def _parse_time(self, ts):
        if not ts:
            return None
        s = str(ts).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is not None:
                return dt.replace(tzinfo=None)
            return dt
        except Exception:
            return None

    def _dedupe_by_key(self, items, key):
        seen = {}
        ordered = []
        for item in items:
            k = str(item.get(key) or "")
            if not k:
                k = f"idx-{len(ordered)}"
            if k in seen:
                continue
            seen[k] = 1
            ordered.append(item)
        return ordered[-5000:]

    def _load_state(self):
        if not os.path.exists(self.store_path):
            return {
                "created_at": self._now(),
                "updated_at": self._now(),
                "github_commits": [],
                "dependency_changes": [],
                "jenkins_builds": [],
                "threat_intel": {
                    "compromised_packages": [],
                    "npm_advisories": [],
                    "cves": [],
                    "github_advisories": [],
                },
                "latest_analysis": None,
            }
        try:
            with open(self.store_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("invalid")
            return data
        except Exception:
            return {
                "created_at": self._now(),
                "updated_at": self._now(),
                "github_commits": [],
                "dependency_changes": [],
                "jenkins_builds": [],
                "threat_intel": {
                    "compromised_packages": [],
                    "npm_advisories": [],
                    "cves": [],
                    "github_advisories": [],
                },
                "latest_analysis": None,
            }

    def _save_state(self, state):
        with open(self.store_path, "w", encoding="utf-8") as f:
            json.dump(state, f)

    def _now(self):
        return datetime.utcnow().isoformat() + "Z"
