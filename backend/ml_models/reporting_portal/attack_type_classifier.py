import os
import joblib
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


class AttackTypeClassifier:
    def __init__(self):
        self.pipeline = None
        self.is_trained = False
        self.label_col = "Attack Type"

    def _load_dataframe(self, csv_path, limit=None):
        df = pd.read_csv(csv_path)
        if limit:
            df = df.head(int(limit))
        return df

    def _build_text(self, df):
        cols = [
            "Title",
            "Category",
            "Scenario Description",
            "Tools Used",
            "Attack Steps ",
            "Target Type",
            "Vulnerability",
            "MITRE Technique",
            "Impact",
            "Detection Method",
            "Solution",
            "Tags",
        ]
        parts = []
        for c in cols:
            if c in df.columns:
                parts.append(df[c].fillna("").astype(str))
        if not parts:
            raise ValueError("No usable text columns found in Attack_Dataset.csv")
        txt = parts[0]
        for p in parts[1:]:
            txt = txt + " " + p
        return txt

    def train(self, csv_path, limit=None):
        df = self._load_dataframe(csv_path, limit=limit)
        if self.label_col not in df.columns:
            raise ValueError("Attack Type column not found in dataset")
        df = df.dropna(subset=[self.label_col]).copy()
        df[self.label_col] = df[self.label_col].astype(str)
        x_text = self._build_text(df)
        y = df[self.label_col].values

        self.pipeline = Pipeline(
            [
                ("tfidf", TfidfVectorizer(max_features=12000, ngram_range=(1, 2))),
                ("clf", LogisticRegression(max_iter=3000, solver="saga", n_jobs=1)),
            ]
        )
        self.pipeline.fit(x_text.astype(str).values, y)
        self.is_trained = True
        return {"labels": sorted(list(set(y))), "rows": int(len(df))}

    def predict(self, record):
        if not self.is_trained or self.pipeline is None:
            raise ValueError("Model not trained")
        if not isinstance(record, dict):
            raise ValueError("record must be an object")
        txt = ""
        for k in [
            "Title",
            "Category",
            "Scenario Description",
            "Tools Used",
            "Attack Steps",
            "Attack Steps ",
            "Target Type",
            "Vulnerability",
            "MITRE Technique",
            "Impact",
            "Detection Method",
            "Solution",
            "Tags",
        ]:
            v = record.get(k, "")
            if isinstance(v, str) and v:
                txt = (txt + " " + v).strip()
        pred = self.pipeline.predict([txt])[0]
        proba = None
        classes = None
        clf = self.pipeline.named_steps.get("clf")
        if clf is not None and hasattr(clf, "predict_proba"):
            proba = self.pipeline.predict_proba([txt])[0].tolist()
            classes = clf.classes_.tolist()
        return {"predicted": pred, "classes": classes, "proba": proba}

    def save_model(self, filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(
            {
                "pipeline": self.pipeline,
                "is_trained": self.is_trained,
                "label_col": self.label_col,
            },
            filepath,
        )

    def load_model(self, filepath):
        data = joblib.load(filepath)
        self.pipeline = data.get("pipeline")
        self.is_trained = bool(data.get("is_trained"))
        self.label_col = data.get("label_col", "Attack Type")
        return self


