import argparse
from pathlib import Path
from time import perf_counter

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

from core.config import FEATURES, MODEL_DIR, RESULTS
from core.model_loader import ModelLoadError, load_model

KEYS = ["file", "window_start_s"]
VALUES = ["prediction", "qae_alert", "confidence", "anomaly_score", "attack_probability"]


def load_test_windows(directory):
    features = pd.read_csv(directory / "features.csv")
    split = pd.read_csv(directory / "split.csv")
    if split.file.duplicated().any():
        raise ValueError("Capture xuất hiện nhiều lần trong split.csv")
    expected = split.loc[split.split == "test", ["file", "label"]]
    test = features.merge(expected, on="file", suffixes=("", "_split"), validate="many_to_one")
    if test.empty or test.file.nunique() != len(expected) or test[KEYS].isna().any().any():
        raise ValueError("Thiếu capture test hoặc mã cửa sổ trong features.csv")
    if test.duplicated(KEYS).any() or not test.label.eq(test.label_split).all():
        raise ValueError("Cửa sổ bị trùng hoặc nhãn capture không khớp split.csv")
    return test.drop(columns="label_split")


def verify(engine, directory):
    test = load_test_windows(directory)
    actual = engine.predict(test, include_probabilities=True)
    indexed = pd.concat([test[KEYS], actual], axis=1).set_index(KEYS)
    references = sorted((directory / "predictions").glob("*_prediction.csv"))
    if not references:
        raise ValueError("Thiếu CSV dự đoán dùng để đối chiếu")
    novel = directory / "evaluation_extra" / "novel_predictions.csv"
    if novel.is_file():
        references.append(novel)
    covered = []
    for path in references:
        saved = pd.read_csv(path)
        if "file" not in saved:
            stem = path.stem.removesuffix("_prediction")
            candidates = [name for name in test.file.unique() if Path(name).stem == stem]
            if len(candidates) != 1:
                raise ValueError(f"{path.name}: không tìm được duy nhất một capture test")
            saved["file"] = candidates[0]
        columns = [*KEYS, *FEATURES]
        joined = saved.merge(test.loc[:, columns], on=KEYS, how="left",
                             suffixes=("_export", ""), validate="one_to_one")
        if not len(joined):
            raise ValueError(f"{path.name}: không có dòng đối chiếu")
        if joined[list(FEATURES)].isna().any().any():
            raise ValueError(f"{path.name}: cửa sổ không có feature test")
        np.testing.assert_allclose(
            joined.loc[:, list(FEATURES)], joined.loc[:, [f"{k}_export" for k in FEATURES]],
            rtol=1e-12, atol=1e-12, err_msg=path.name,
        )
        reference_keys = pd.MultiIndex.from_frame(joined[KEYS])
        predictions = indexed.reindex(reference_keys).reset_index(drop=True)
        covered.extend(reference_keys)
        differences = []
        for key in VALUES:
            if key not in joined:
                if key == "attack_probability" and path == novel:
                    continue
                raise ValueError(f"{path.name}: thiếu cột {key}")
            if key in ("prediction", "qae_alert"):
                np.testing.assert_array_equal(predictions[key], joined[key], err_msg=f"{path.name}: {key}")
            else:
                tolerance = 1e-10 if key == "anomaly_score" else 2e-6
                np.testing.assert_allclose(predictions[key], joined[key], rtol=0, atol=tolerance,
                                           err_msg=f"{path.name}: {key}")
                differences.append(f"{key}={np.max(np.abs(predictions[key] - joined[key])):.3g}")
        print(f"{path.name} | {len(predictions)} windows | max abs: {', '.join(differences)}")
    print(f"Reference rows: {len(covered)}; Colab-covered windows: {len(set(covered))}/{len(test)}")
    print(f"Test split: {len(test)} windows from {test.file.nunique()} captures")
    return test, actual


def verify_test_metrics(test, actual, directory):
    is_attack = test.label.ne("Normal")
    metrics = {
        "accuracy": accuracy_score(test.label, actual.prediction),
        "macro_f1": f1_score(test.label, actual.prediction, average="macro"),
        "binary_f1": f1_score(is_attack, actual.binary_prediction.eq("Attack")),
        "binary_auc": roc_auc_score(is_attack, actual.attack_probability),
    }
    path = directory / "metrics.csv"
    if path.is_file():
        saved = pd.read_csv(path).set_index("model", verify_integrity=True).loc["QAE+QNN"]
        np.testing.assert_allclose(list(metrics.values()), saved[list(metrics)].astype(float),
                                   rtol=0, atol=1e-12, err_msg="metrics.csv: QAE+QNN")
        print("QAE+QNN metrics match the Colab export")
    else:
        print("metrics.csv is unavailable; aggregate metric comparison was skipped")
    print(" | ".join(f"{key}={value:.6f}" for key, value in metrics.items()))


def verify_batches_and_time(engine, test, baseline, repeats):
    probabilities = [f"prob_{label}" for label in engine.config.classes]
    baseline = baseline.drop(columns="inference_ms")
    print(f"CPU threads={torch.get_num_threads()} | each batch size: 2 warm-ups, {repeats} measurements")
    for batch_size in (1, 16, 512):
        for _ in range(2):
            prediction = engine.predict(test, batch_size=batch_size, include_probabilities=True)
        pd.testing.assert_frame_equal(prediction.drop(columns="inference_ms"), baseline, rtol=0, atol=2e-6)
        np.testing.assert_allclose(prediction.anomaly_score, baseline.anomaly_score, rtol=0, atol=1e-10)
        delta = np.abs(prediction[probabilities].to_numpy() - baseline[probabilities].to_numpy()).max()
        wall_ms, inference_ms = [], []
        for _ in range(repeats):
            start = perf_counter()
            prediction = engine.predict(test, batch_size=batch_size, include_probabilities=True)
            wall_ms.append((perf_counter() - start) * 1000)
            inference_ms.append(prediction.inference_ms.sum())
        print(f"batch={batch_size:3} | max abs prob={delta:.3g} | predict() "
              f"p50={np.median(wall_ms):.3f} ms, p95={np.percentile(wall_ms, 95):.3f} ms "
              f"| transform + QAE + QNN + softmax p50={np.median(inference_ms):.3f} ms")


def main():
    parser = argparse.ArgumentParser(description="Đối chiếu inference CPU trên cùng feature test Colab")
    parser.add_argument("--models", type=Path, default=MODEL_DIR)
    parser.add_argument("--results", type=Path, default=RESULTS / "pcap")
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--threads", type=int, default=2, help="Số luồng PyTorch, mặc định theo notebook")
    args = parser.parse_args()
    if args.repeats < 1 or args.threads < 1:
        parser.error("--repeats và --threads phải dương")
    try:
        torch.set_num_threads(args.threads)
        engine = load_model(args.models)
        test, actual = verify(engine, args.results)
        verify_test_metrics(test, actual, args.results)
        verify_batches_and_time(engine, test, actual, args.repeats)
    except (AssertionError, KeyError, ModelLoadError, OSError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
