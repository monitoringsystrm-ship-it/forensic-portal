import os
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


class HadoopLogFailureClassifier:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=15000, token_pattern=r"(?u)\b\w+\b")
        self.model = LogisticRegression(max_iter=500, n_jobs=-1)
        self.is_trained = False

    def train(self, texts, labels):
        X = self.vectorizer.fit_transform(texts)
        y = np.asarray(labels, dtype=int)
        self.model.fit(X, y)
        self.is_trained = True
        return self

    def predict(self, texts):
        if not self.is_trained:
            raise ValueError("Model not trained")
        X = self.vectorizer.transform(texts)
        proba = self.model.predict_proba(X)[:, 1]
        pred = (proba >= 0.5).astype(int)
        results = []
        for i in range(len(texts)):
            results.append(
                {
                    "id": f"hadoop_app_{i}",
                    "is_anomaly": bool(int(pred[i]) == 1),
                    "confidence": float(proba[i] * 100.0),
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


