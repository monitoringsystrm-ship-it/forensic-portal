import os
import json
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns


BASE_DIR = os.path.dirname(__file__)


def ensure_reports_dir():
    reports_dir = os.path.join(BASE_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir


def safe_num(value, default=0.0):
    try:
        if pd.isna(value):
            return default
        v = pd.to_numeric(value, errors="coerce")
        if pd.isna(v):
            return default
        return float(v)
    except Exception:
        return default


def load_nsl_kdd():
    base_dir = os.path.join(BASE_DIR, "NSL‑KDD")
    train_path = os.path.join(base_dir, "KDDTrain+_20Percent.txt")
    test_path = os.path.join(base_dir, "KDDTest+.txt")
    cols = [f"f{i}" for i in range(41)] + ["label", "difficulty"]
    train_df = pd.read_csv(train_path, header=None, names=cols)
    test_df = pd.read_csv(test_path, header=None, names=cols)
    train_df["target"] = (train_df["label"] != "normal").astype(int)
    test_df["target"] = (test_df["label"] != "normal").astype(int)
    return train_df, test_df


def build_commit_samples(df, limit=None):
    if limit:
        df = df.head(limit)
    samples = []
    for idx, row in df.iterrows():
        duration = safe_num(row["f0"], 0)
        src_bytes = safe_num(row["f4"], 0)
        dst_bytes = safe_num(row["f5"], 0)
        f1_val = safe_num(row["f1"], 0)
        f2_val = safe_num(row["f2"], 0)
        f3_val = safe_num(row["f3"], 0)
        hour = int(abs(duration)) % 24
        day_of_week = int(abs(src_bytes)) % 7
        samples.append(
            {
                "id": f"commit_{idx}",
                "timestamp_hour": hour,
                "day_of_week": day_of_week,
                "files_changed": int(abs(src_bytes)) % 200,
                "lines_added": int(abs(dst_bytes)) % 500,
                "lines_removed": int(abs(dst_bytes) // 2) % 300,
                "commit_message_length": int(abs(f1_val)) % 400,
                "is_weekend": 1 if day_of_week in (5, 6) else 0,
                "is_off_hours": 1 if hour < 7 or hour > 20 else 0,
                "author_commit_count": int(abs(f2_val)) % 1000,
                "time_since_last_commit": int(abs(f3_val)) % 10000,
            }
        )
    return samples


def load_unsw_nb15():
    base_dir = os.path.join(BASE_DIR, "UNSW‑NB15")
    train_path = os.path.join(base_dir, "UNSW_NB15_training-set.parquet")
    test_path = os.path.join(base_dir, "UNSW_NB15_testing-set.parquet")
    train_df = pd.read_parquet(train_path)
    test_df = pd.read_parquet(test_path)
    label_col = "label" if "label" in train_df.columns else train_df.columns[-1]
    train_df["target"] = train_df[label_col].astype(int)
    test_df["target"] = test_df[label_col].astype(int)
    return train_df, test_df


def build_dependency_samples(df, limit=None):
    if limit:
        df = df.head(limit)
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    numeric_cols = [c for c in numeric_cols if c != "target"]
    use_cols = numeric_cols[:5]
    samples = []
    for idx, row in df.iterrows():
        nums = [safe_num(row.get(col), 0) for col in use_cols]
        while len(nums) < 5:
            nums.append(0)
        major = int(abs(nums[0])) % 10
        minor = int(abs(nums[1])) % 10
        patch = int(abs(nums[2])) % 10
        version_change_count = int(abs(nums[3])) % 20
        days_since_release = int(abs(nums[4])) % 365
        samples.append(
            {
                "id": f"dep_{idx}",
                "name": f"pkg_{idx}",
                "version": f"{major}.{minor}.{patch}",
                "is_new": int(version_change_count == 0),
                "version_change_count": version_change_count,
                "days_since_release": days_since_release,
            }
        )
    return samples


def evaluate_binary(y_true, y_pred):
    acc = accuracy_score(y_true, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    cm = confusion_matrix(y_true, y_pred).tolist()
    return {
        "accuracy": float(acc),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "confusion_matrix": cm,
    }


def save_metrics(name, metrics):
    reports_dir = ensure_reports_dir()
    path = os.path.join(reports_dir, f"{name}_metrics.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    return path


def save_summary(summary):
    reports_dir = ensure_reports_dir()
    path = os.path.join(reports_dir, "anomaly_detection_summary.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    return path


def get_reports_dir():
    return ensure_reports_dir()


def plot_confusion_matrix(cm, filename, title=None, cmap="Blues"):
    reports_dir = ensure_reports_dir()
    path = os.path.join(reports_dir, filename)
    labels = ["normal", "anomaly"]
    plt.figure(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap=cmap, xticklabels=labels, yticklabels=labels)
    plt.xlabel("Predicted")
    plt.ylabel("True")
    if title:
        plt.title(title)
    plt.tight_layout()
    plt.savefig(path)
    plt.close()
    return path


def plot_correlation(df, filename):
    reports_dir = ensure_reports_dir()
    path = os.path.join(reports_dir, filename)
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if "target" not in numeric_cols and "target" in df.columns:
        numeric_cols.append("target")
    if len(numeric_cols) > 11:
        keep = [c for c in numeric_cols if c != "target"][:10]
        numeric_cols = keep + (["target"] if "target" in df.columns else [])
    corr = df[numeric_cols].corr(numeric_only=True)
    plt.figure(figsize=(9, 7))
    sns.heatmap(corr, cmap="coolwarm", center=0)
    plt.tight_layout()
    plt.savefig(path)
    plt.close()
    return path


def plot_label_distribution(series, filename):
    reports_dir = ensure_reports_dir()
    path = os.path.join(reports_dir, filename)
    counts = series.value_counts().sort_index()
    labels = [str(i) for i in counts.index.tolist()]
    plt.figure(figsize=(5, 3))
    sns.barplot(x=labels, y=counts.values)
    plt.tight_layout()
    plt.savefig(path)
    plt.close()
    return path


