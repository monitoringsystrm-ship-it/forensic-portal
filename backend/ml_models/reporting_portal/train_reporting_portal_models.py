import os
import json
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report
from sklearn.base import clone

from .attack_type_classifier import AttackTypeClassifier
from .breach_type_classifier import BreachTypeClassifier


def _reports_root():
    root = os.path.join(os.path.dirname(__file__), "reports")
    os.makedirs(root, exist_ok=True)
    return root


def _model_dir(name):
    d = os.path.join(_reports_root(), name)
    os.makedirs(d, exist_ok=True)
    return d


def _safe_json_dump(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


def _plot_label_distribution(y, out_path, title):
    vc = pd.Series(y).value_counts().head(20)
    plt.figure(figsize=(10, 4))
    sns.barplot(x=vc.index.astype(str), y=vc.values)
    plt.xticks(rotation=45, ha="right")
    plt.title(title)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def _plot_confusion(cm, labels, out_path, title):
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=False, cmap="Blues", xticklabels=labels, yticklabels=labels)
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.title(title)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def _plot_metrics(metrics, out_path, title):
    keys = ["accuracy", "precision_macro", "recall_macro", "f1_macro"]
    vals = [metrics.get(k, 0.0) for k in keys]
    plt.figure(figsize=(7, 4))
    sns.barplot(x=keys, y=vals)
    plt.ylim(0, 1)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def _plot_holdout_learning_curve(estimator, X_train, y_train, X_test, y_test, out_path, title):
    sizes = np.linspace(0.1, 1.0, 8)
    n = len(y_train)
    train_sizes = [max(2, int(n * s)) for s in sizes]
    train_sizes = sorted(list(dict.fromkeys(train_sizes)))
    train_acc = []
    test_acc = []
    for ts in train_sizes:
        est = clone(estimator)
        est.fit(X_train[:ts], y_train[:ts])
        train_acc.append(float(accuracy_score(y_train[:ts], est.predict(X_train[:ts]))))
        test_acc.append(float(accuracy_score(y_test, est.predict(X_test))))
    plt.figure(figsize=(7, 4))
    plt.plot(train_sizes, train_acc, label="train")
    plt.plot(train_sizes, test_acc, label="test")
    plt.ylim(0, 1)
    plt.title(title)
    plt.xlabel("Training examples")
    plt.ylabel("Accuracy")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def _topk_confusion_labels(y_true, y_pred, k=15):
    vc = pd.Series(y_true).value_counts()
    top = vc.head(k).index.tolist()
    def remap(v):
        return v if v in top else "Other"
    y_t = [remap(v) for v in y_true]
    y_p = [remap(v) for v in y_pred]
    labels = top + (["Other"] if any(v == "Other" for v in y_t) or any(v == "Other" for v in y_p) else [])
    return y_t, y_p, labels


def train_attack_type_model(csv_path, model_path, limit=None):
    out_dir = _model_dir("attack_type")
    clf = AttackTypeClassifier()
    df = pd.read_csv(csv_path)
    if limit:
        df = df.head(int(limit))
    if clf.label_col not in df.columns:
        raise ValueError("Attack Type column not found in Attack_Dataset.csv")
    df = df.dropna(subset=[clf.label_col]).copy()
    df[clf.label_col] = df[clf.label_col].astype(str)
    vc = df[clf.label_col].value_counts()
    keep = vc[vc >= 2].index
    df = df[df[clf.label_col].isin(keep)].copy()
    if df[clf.label_col].nunique() < 2:
        raise ValueError("Not enough labeled classes to train attack_type model")

    x_text = clf._build_text(df).astype(str).values
    y = df[clf.label_col].values
    X_train, X_test, y_train, y_test = train_test_split(
        x_text, y, test_size=0.2, random_state=42, stratify=y
    )

    from sklearn.pipeline import Pipeline
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    clf.pipeline = Pipeline(
        [
            ("tfidf", TfidfVectorizer(max_features=12000, ngram_range=(1, 2))),
            ("clf", LogisticRegression(max_iter=3000, solver="saga", n_jobs=1)),
        ]
    )
    clf.pipeline.fit(X_train, y_train)
    clf.is_trained = True

    y_pred = clf.pipeline.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    p, r, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="macro", zero_division=0)
    report_txt = classification_report(y_test, y_pred, zero_division=0)

    y_t_cm, y_p_cm, labels_cm = _topk_confusion_labels(y_test.tolist(), y_pred.tolist(), k=15)
    cm = confusion_matrix(y_t_cm, y_p_cm, labels=labels_cm)

    metrics = {
        "accuracy": acc,
        "precision_macro": float(p),
        "recall_macro": float(r),
        "f1_macro": float(f1),
        "classes": sorted(df[clf.label_col].unique().tolist()),
        "rows": int(len(df)),
    }

    _plot_confusion(cm, labels_cm, os.path.join(out_dir, "attack_type_confusion_matrix.png"), "Attack Type Confusion Matrix (Top Labels)")
    _plot_metrics(metrics, os.path.join(out_dir, "attack_type_metrics.png"), "Attack Type Metrics")
    _plot_holdout_learning_curve(
        clf.pipeline,
        X_train,
        y_train,
        X_test,
        y_test,
        os.path.join(out_dir, "attack_type_learning_curve.png"),
        "Attack Type Learning Curve",
    )
    _plot_label_distribution(y, os.path.join(out_dir, "attack_type_label_distribution.png"), "Attack Type Label Distribution (Top 20)")

    report_files = [
        "attack_type_confusion_matrix.png",
        "attack_type_metrics.png",
        "attack_type_learning_curve.png",
        "attack_type_label_distribution.png",
    ]

    try:
        vec = clf.pipeline.named_steps["tfidf"]
        model = clf.pipeline.named_steps["clf"]
        feats = np.array(vec.get_feature_names_out())
        coefs = model.coef_
        if coefs.ndim == 2:
            score = np.mean(np.abs(coefs), axis=0)
        else:
            score = np.abs(coefs)
        top_idx = np.argsort(score)[-30:][::-1]
        top_feats = feats[top_idx]
        top_vals = score[top_idx]
        plt.figure(figsize=(10, 4))
        sns.barplot(x=top_feats, y=top_vals)
        plt.xticks(rotation=45, ha="right")
        plt.title("Attack Type Top Tokens")
        plt.tight_layout()
        tokens_path = os.path.join(out_dir, "attack_type_top_tokens.png")
        plt.savefig(tokens_path)
        plt.close()
        report_files.append("attack_type_top_tokens.png")
    except Exception:
        pass

    summary = {
        "model": "attack_type",
        "metrics": metrics,
        "classification_report": report_txt,
        "reports": report_files,
    }
    _safe_json_dump(os.path.join(out_dir, "attack_type_training_summary.json"), summary)

    clf.save_model(model_path)
    return clf, summary


def train_breach_type_model(csv_path, model_path, limit=None):
    out_dir = _model_dir("breach_type")
    clf = BreachTypeClassifier()
    df = pd.read_csv(csv_path)
    if limit:
        df = df.head(int(limit))
    if clf.label_col not in df.columns:
        raise ValueError("Type_of_Breach column not found in Cyber Security Breaches.csv")
    df = df.dropna(subset=[clf.label_col]).copy()
    df[clf.label_col] = df[clf.label_col].astype(str)
    vc = df[clf.label_col].value_counts()
    keep = vc[vc >= 2].index
    df = df[df[clf.label_col].isin(keep)].copy()
    if df[clf.label_col].nunique() < 2:
        raise ValueError("Not enough labeled classes to train breach_type model")

    text_col = "Summary"
    cat_cols = [c for c in ["State", "Location_of_Breached_Information"] if c in df.columns]
    num_cols = [c for c in ["Individuals_Affected", "year"] if c in df.columns]
    for c in num_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")

    X = df[[text_col] + cat_cols + num_cols].copy()
    y = df[clf.label_col].values
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf.pipeline = clf._build_pipeline(text_col, cat_cols, num_cols)
    clf.pipeline.fit(X_train, y_train)
    clf.is_trained = True

    y_pred = clf.pipeline.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    p, r, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="macro", zero_division=0)
    report_txt = classification_report(y_test, y_pred, zero_division=0)

    y_t_cm, y_p_cm, labels_cm = _topk_confusion_labels(y_test.tolist(), y_pred.tolist(), k=15)
    cm = confusion_matrix(y_t_cm, y_p_cm, labels=labels_cm)

    metrics = {
        "accuracy": acc,
        "precision_macro": float(p),
        "recall_macro": float(r),
        "f1_macro": float(f1),
        "classes": sorted(df[clf.label_col].unique().tolist()),
        "rows": int(len(df)),
    }

    _plot_confusion(cm, labels_cm, os.path.join(out_dir, "breach_type_confusion_matrix.png"), "Breach Type Confusion Matrix (Top Labels)")
    _plot_metrics(metrics, os.path.join(out_dir, "breach_type_metrics.png"), "Breach Type Metrics")
    _plot_holdout_learning_curve(
        clf.pipeline,
        X_train,
        y_train,
        X_test,
        y_test,
        os.path.join(out_dir, "breach_type_learning_curve.png"),
        "Breach Type Learning Curve",
    )
    _plot_label_distribution(y, os.path.join(out_dir, "breach_type_label_distribution.png"), "Breach Type Label Distribution (Top 20)")

    summary = {
        "model": "breach_type",
        "metrics": metrics,
        "classification_report": report_txt,
        "reports": [
            "breach_type_confusion_matrix.png",
            "breach_type_metrics.png",
            "breach_type_learning_curve.png",
            "breach_type_label_distribution.png",
        ],
    }
    _safe_json_dump(os.path.join(out_dir, "breach_type_training_summary.json"), summary)

    clf.save_model(model_path)
    return clf, summary


