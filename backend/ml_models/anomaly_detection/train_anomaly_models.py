import os
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report
from commit_pattern_analyzer import CommitPatternAnalyzer
from dependency_anomaly_detector import DependencyAnomalyDetector


def ensure_reports_dir():
    reports_dir = os.path.join(os.path.dirname(__file__), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir


def load_nsl_kdd():
    base_dir = os.path.join(os.path.dirname(__file__), "NSL‑KDD")
    train_path = os.path.join(base_dir, "KDDTrain+_20Percent.txt")
    test_path = os.path.join(base_dir, "KDDTest+.txt")
    col_count = 43
    cols = [f"f{i}" for i in range(col_count - 2)] + ["label", "difficulty"]
    train_df = pd.read_csv(train_path, header=None, names=cols)
    test_df = pd.read_csv(test_path, header=None, names=cols)
    label_col = "label"
    train_df["target"] = (train_df[label_col] != "normal").astype(int)
    test_df["target"] = (test_df[label_col] != "normal").astype(int)
    return train_df, test_df


def safe_convert_to_numeric(value, default=0):
    """Safely convert a value to numeric, handling strings and errors."""
    try:
        if pd.isna(value):
            return default
        num_val = pd.to_numeric(value, errors='coerce')
        if pd.isna(num_val):
            return default
        return float(num_val)
    except (ValueError, TypeError):
        return default

def build_commit_data(df, max_rows=None):
    if max_rows:
        df = df.head(max_rows)
    commit_data = []
    for idx, row in df.iterrows():
        duration = safe_convert_to_numeric(row["f0"], 0)
        src_bytes = safe_convert_to_numeric(row["f4"], 0)
        dst_bytes = safe_convert_to_numeric(row["f5"], 0)
        f1_val = safe_convert_to_numeric(row["f1"], 0)
        f2_val = safe_convert_to_numeric(row["f2"], 0)
        f3_val = safe_convert_to_numeric(row["f3"], 0)
        
        hour = int(abs(duration)) % 24
        day_of_week = int(abs(src_bytes)) % 7
        files_changed = int(abs(src_bytes)) % 200
        lines_added = int(abs(dst_bytes)) % 500
        lines_removed = int(abs(dst_bytes) // 2) % 300
        commit_message_length = int(abs(f1_val)) % 400
        is_weekend = 1 if day_of_week in (5, 6) else 0
        is_off_hours = 1 if hour < 7 or hour > 20 else 0
        author_commit_count = int(abs(f2_val)) % 1000
        time_since_last_commit = int(abs(f3_val)) % 10000
        commit = {
            "id": f"commit_{idx}",
            "timestamp_hour": hour,
            "day_of_week": day_of_week,
            "files_changed": files_changed,
            "lines_added": lines_added,
            "lines_removed": lines_removed,
            "commit_message_length": commit_message_length,
            "is_weekend": is_weekend,
            "is_off_hours": is_off_hours,
            "author_commit_count": author_commit_count,
            "time_since_last_commit": time_since_last_commit,
        }
        commit_data.append(commit)
    return commit_data


def train_commit_model():
    reports_dir = ensure_reports_dir()
    train_df, test_df = load_nsl_kdd()
    train_commits = build_commit_data(train_df)
    test_commits = build_commit_data(test_df)
    y_train = train_df["target"].values
    y_test = test_df["target"].values
    analyzer = CommitPatternAnalyzer()
    train_metrics = analyzer.train(train_commits, y_train)
    X_test = analyzer.extract_features(test_commits)
    X_test_scaled = analyzer.scaler.transform(X_test)
    y_pred = analyzer.model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    report_text = classification_report(y_test, y_pred, zero_division=0)
    labels = ["normal", "anomaly"]
    plt.figure(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels)
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.tight_layout()
    plt.savefig(os.path.join(reports_dir, "commit_confusion_matrix.png"))
    plt.close()
    numeric_cols = train_df.select_dtypes(include=[np.number]).columns.tolist()
    if "target" not in numeric_cols:
        numeric_cols.append("target")
    if len(numeric_cols) > 11:
        numeric_cols = numeric_cols[:10] + ["target"]
    corr = train_df[numeric_cols].corr()
    plt.figure(figsize=(8, 6))
    sns.heatmap(corr, cmap="coolwarm", center=0, annot=False, fmt='.2f')
    plt.tight_layout()
    plt.savefig(os.path.join(reports_dir, "commit_feature_correlation.png"))
    plt.close()
    label_counts = train_df["target"].value_counts().sort_index()
    plt.figure(figsize=(4, 3))
    sns.barplot(x=["normal", "anomaly"], y=label_counts.values)
    plt.tight_layout()
    plt.savefig(os.path.join(reports_dir, "commit_label_distribution.png"))
    plt.close()
    metrics = {
        "train_accuracy_internal": float(train_metrics["train_accuracy"]),
        "test_accuracy_internal": float(train_metrics["test_accuracy"]),
        "test_accuracy": float(acc),
        "test_precision": float(precision),
        "test_recall": float(recall),
        "test_f1": float(f1),
        "classification_report": report_text,
    }
    return analyzer, metrics


def load_unsw_nb15():
    base_dir = os.path.join(os.path.dirname(__file__), "UNSW‑NB15")
    train_path = os.path.join(base_dir, "UNSW_NB15_training-set.parquet")
    test_path = os.path.join(base_dir, "UNSW_NB15_testing-set.parquet")
    train_df = pd.read_parquet(train_path)
    test_df = pd.read_parquet(test_path)
    if "label" in train_df.columns:
        label_col = "label"
    else:
        label_col = train_df.columns[-1]
    train_df["target"] = train_df[label_col].astype(int)
    test_df["target"] = test_df[label_col].astype(int)
    return train_df, test_df


def build_dependency_data(df, max_rows=None):
    if max_rows:
        df = df.head(max_rows)
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if len(numeric_cols) < 5:
        numeric_cols = [col for col in df.columns if col != "target" and col != "label"][:10]
    deps = []
    for idx, row in df.iterrows():
        nums = []
        for col in numeric_cols[:5]:
            val = safe_convert_to_numeric(row[col], 0)
            nums.append(val)
        if len(nums) < 4:
            nums.extend([0] * (4 - len(nums)))
        major = int(abs(nums[0])) % 10
        minor = int(abs(nums[1])) % 10
        patch = int(abs(nums[2])) % 10
        version_change_count = int(abs(nums[3])) % 20
        days_since_release = int(abs(nums[4])) % 365 if len(nums) > 4 else 0
        dep = {
            "id": f"dep_{idx}",
            "name": f"pkg_{idx}",
            "version": f"{major}.{minor}.{patch}",
            "is_new": int(version_change_count == 0),
            "version_change_count": version_change_count,
            "days_since_release": days_since_release,
        }
        deps.append(dep)
    return deps


def train_dependency_model():
    reports_dir = ensure_reports_dir()
    train_df, test_df = load_unsw_nb15()
    train_deps = build_dependency_data(train_df)
    test_deps = build_dependency_data(test_df)
    y_test = test_df["target"].head(len(test_deps)).values
    detector = DependencyAnomalyDetector()
    detector.train(train_deps)
    X_test = detector.extract_features(test_deps)
    X_test_scaled = detector.scaler.transform(X_test)
    preds = detector.model.predict(X_test_scaled)
    y_pred = np.where(preds == -1, 1, 0)
    acc = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    labels = ["normal", "anomaly"]
    plt.figure(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Greens", xticklabels=labels, yticklabels=labels)
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.tight_layout()
    plt.savefig(os.path.join(reports_dir, "dependency_confusion_matrix.png"))
    plt.close()
    numeric_cols = train_df.select_dtypes(include=[np.number]).columns[:10].tolist()
    corr = train_df[numeric_cols + ["target"]].corr()
    plt.figure(figsize=(8, 6))
    sns.heatmap(corr, cmap="coolwarm", center=0)
    plt.tight_layout()
    plt.savefig(os.path.join(reports_dir, "dependency_feature_correlation.png"))
    plt.close()
    label_counts = train_df["target"].value_counts().sort_index()
    plt.figure(figsize=(4, 3))
    sns.barplot(x=label_counts.index.astype(str), y=label_counts.values)
    plt.tight_layout()
    plt.savefig(os.path.join(reports_dir, "dependency_label_distribution.png"))
    plt.close()
    metrics = {
        "test_accuracy": float(acc),
        "test_precision": float(precision),
        "test_recall": float(recall),
        "test_f1": float(f1),
    }
    return detector, metrics


def main():
    reports_dir = ensure_reports_dir()
    commit_model, commit_metrics = train_commit_model()
    dependency_model, dependency_metrics = train_dependency_model()
    commit_model.save_model()
    dependency_model.save_model()
    summary = {
        "commit_pattern_analyzer": commit_metrics,
        "dependency_anomaly_detector": dependency_metrics,
    }
    summary_path = os.path.join(reports_dir, "anomaly_models_report.json")
    pd.Series(summary).to_json(summary_path)


if __name__ == "__main__":
    main()


