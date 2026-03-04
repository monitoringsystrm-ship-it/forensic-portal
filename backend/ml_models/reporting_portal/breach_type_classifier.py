import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import FunctionTransformer


def _ravel_1d(x):
    return x.ravel()


class BreachTypeClassifier:
    def __init__(self):
        self.pipeline = None
        self.is_trained = False
        self.label_col = "Type_of_Breach"

    def _build_pipeline(self, text_col, cat_cols, num_cols):
        flatten = FunctionTransformer(_ravel_1d, validate=False)
        text_pipe = Pipeline(
            [
                ("imputer", SimpleImputer(strategy="constant", fill_value="")),
                ("flatten", flatten),
                ("tfidf", TfidfVectorizer(max_features=8000, ngram_range=(1, 2))),
            ]
        )
        cat_pipe = Pipeline(
            [
                ("imputer", SimpleImputer(strategy="constant", fill_value="")),
                ("onehot", OneHotEncoder(handle_unknown="ignore")),
            ]
        )
        num_pipe = Pipeline(
            [
                ("imputer", SimpleImputer(strategy="median")),
            ]
        )
        pre = ColumnTransformer(
            [
                ("text", text_pipe, [text_col]),
                ("cat", cat_pipe, cat_cols),
                ("num", num_pipe, num_cols),
            ]
        )
        clf = LogisticRegression(max_iter=3000, solver="saga", n_jobs=1)
        return Pipeline([("pre", pre), ("clf", clf)])

    def _load_dataframe(self, csv_path, limit=None):
        df = pd.read_csv(csv_path)
        if limit:
            df = df.head(int(limit))
        for c in ["Individuals_Affected", "year"]:
            if c in df.columns:
                df[c] = pd.to_numeric(df[c], errors="coerce")
        if "breach_start" in df.columns:
            ts = pd.to_datetime(df["breach_start"], errors="coerce")
            df["breach_month"] = ts.dt.month
            df["breach_day"] = ts.dt.day
            df["breach_dow"] = ts.dt.dayofweek
        return df

    def train(self, csv_path, limit=None):
        df = self._load_dataframe(csv_path, limit=limit)
        if self.label_col not in df.columns:
            raise ValueError("Type_of_Breach column not found in dataset")
        df = df.dropna(subset=[self.label_col]).copy()
        df[self.label_col] = df[self.label_col].astype(str)

        text_col = "Summary" if "Summary" in df.columns else None
        if not text_col:
            raise ValueError("Summary column not found in dataset")

        cat_cols = [c for c in ["State", "Location_of_Breached_Information"] if c in df.columns]
        num_cols = [c for c in ["Individuals_Affected", "year", "breach_month", "breach_day", "breach_dow"] if c in df.columns]

        X = df[[text_col] + cat_cols + num_cols].copy()
        y = df[self.label_col].values

        self.pipeline = self._build_pipeline(text_col, cat_cols, num_cols)
        self.pipeline.fit(X, y)
        self.is_trained = True

        return {"labels": sorted(list(set(y))), "rows": int(len(df))}

    def predict(self, record):
        if not self.is_trained or self.pipeline is None:
            raise ValueError("Model not trained")
        if not isinstance(record, dict):
            raise ValueError("record must be an object")
        df = pd.DataFrame([record])
        pred = self.pipeline.predict(df)[0]
        proba = None
        classes = None
        if hasattr(self.pipeline.named_steps["clf"], "predict_proba"):
            proba = self.pipeline.predict_proba(df)[0].tolist()
            classes = self.pipeline.named_steps["clf"].classes_.tolist()
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
        self.label_col = data.get("label_col", "Type_of_Breach")
        return self


