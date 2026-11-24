from pathlib import Path

import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_curve, roc_curve

from .config import CLASSES, RESULTS


def exported_demo_predictions(directory=RESULTS / "pcap"):
    """Join the four demo CSVs to the test manifest for ground truth."""
    split = pd.read_csv(directory / "split.csv")
    test = split.loc[split.split == "test"].assign(stem=lambda d: d.file.map(lambda p: Path(p).stem))
    frames = []
    for path in sorted((directory / "predictions").glob("*_prediction.csv")):
        rows = test.loc[test.stem == path.stem.removesuffix("_prediction")]
        if len(rows) != 1:
            raise ValueError(f"Không tìm được capture test duy nhất cho {path.name}")
        row = rows.iloc[0]
        frames.append(pd.read_csv(path).assign(file=row.file, label=row.label))
    if not frames:
        raise FileNotFoundError("Thiếu prediction CSV")
    return pd.concat(frames, ignore_index=True)


def evaluate_predictions(rows, score, threshold):
    truth = rows.label != "Normal"
    scores = rows[score]
    if truth.nunique() != 2 or scores.isna().any():
        raise ValueError("Đường cong cần điểm hữu hạn và đủ hai lớp thực")
    positive = scores > threshold if score == "anomaly_score" else scores >= threshold
    fpr, tpr, _ = roc_curve(truth, scores)
    precision, recall, _ = precision_recall_curve(truth, scores)
    return {
        "matrix": confusion_matrix(rows.label, rows.prediction, labels=CLASSES),
        "roc": pd.DataFrame({"FPR": fpr, "TPR": tpr}),
        "pr": pd.DataFrame({"Recall": recall, "Precision": precision}),
        "false_positives": rows.loc[~truth & positive],
        "false_negatives": rows.loc[truth & ~positive],
    }
