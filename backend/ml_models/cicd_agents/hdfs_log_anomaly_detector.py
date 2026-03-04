import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer


class HdfsLogAnomalyDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=5000, token_pattern=r"(?u)\b\w+\b")
        self.model = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=200,
            max_samples=512,
            n_jobs=-1,
        )
        self.is_trained = False

    def train(self, lines):
        X = self.vectorizer.fit_transform(lines)
        self.model.fit(X)
        self.is_trained = True
        return self

    def predict(self, lines):
        if not self.is_trained:
            raise ValueError("Model not trained")
        X = self.vectorizer.transform(lines)
        preds = self.model.predict(X)
        scores = self.model.score_samples(X)
        scores = np.asarray(scores, dtype=float)
        if scores.size == 0:
            return []
        s_min = float(np.min(scores))
        s_max = float(np.max(scores))
        denom = (s_max - s_min) if (s_max - s_min) != 0 else 1.0
        conf = (s_max - scores) / denom * 100.0
        results = []
        for i, line in enumerate(lines):
            is_anomaly = bool(int(preds[i]) == -1)
            results.append(
                {
                    "id": f"hdfs_{i}",
                    "is_anomaly": is_anomaly,
                    "anomaly_score": float(scores[i]),
                    "confidence": float(conf[i]),
                    "line": line,
                }
            )
        return results

    def save_model(self, filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(
            {
                "vectorizer": self.vectorizer,
                "model": self.model,
                "is_trained": self.is_trained,
            },
            filepath,
        )

    def load_model(self, filepath):
        data = joblib.load(filepath)
        self.vectorizer = data["vectorizer"]
        self.model = data["model"]
        self.is_trained = bool(data.get("is_trained", True))
        return self


