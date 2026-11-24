import argparse
import hashlib
from pathlib import Path

import numpy as np
import pandas as pd

from core.config import FEATURES, RESULTS, ROOT
from core.evaluation import exported_demo_predictions
from core.model_loader import load_model
from core.pcap_analysis import analyze_pcap


def verify_captures(root, names):
    directory = RESULTS / "pcap"
    predictions = exported_demo_predictions(directory)
    novel = pd.read_csv(directory / "evaluation_extra" / "novel_predictions.csv")
    features = pd.read_csv(directory / "features.csv")
    manifest = pd.read_csv(directory / "manifest.csv").set_index("file", verify_integrity=True)
    engine = load_model()
    if not names:
        names = predictions.file.unique()
    for name in names:
        capture = (root / name).resolve()
        if not capture.is_relative_to(root.resolve()) or name not in manifest.index:
            raise ValueError(f"Capture ngoài manifest hoặc thư mục dữ liệu: {name}")
        with capture.open("rb") as handle:
            if hashlib.file_digest(handle, "sha256").hexdigest() != manifest.at[name, "sha256"]:
                raise ValueError(f"SHA-256 không khớp manifest: {name}")
        analysis = analyze_pcap(capture, engine)
        actual = analysis.results.set_index("window_start_s")
        wanted = features.loc[features.file == name].set_index("window_start_s")
        np.testing.assert_array_equal(actual.index, wanted.index, err_msg=name)
        np.testing.assert_allclose(actual.loc[:, list(FEATURES)], wanted.loc[:, list(FEATURES)],
                                   rtol=1e-10, atol=1e-10, err_msg=name)
        comparisons = []
        for reference in (predictions, novel):
            exported = reference.loc[reference.file == name].set_index("window_start_s")
            actual_predictions = actual.loc[exported.index]
            for key in ("prediction", "qae_alert"):
                np.testing.assert_array_equal(actual_predictions[key], exported[key], err_msg=name)
            for key in ("confidence", "anomaly_score", "attack_probability"):
                if key in exported:
                    np.testing.assert_allclose(actual_predictions[key], exported[key], rtol=0,
                                               atol=1e-10 if key == "anomaly_score" else 2e-6, err_msg=name)
            comparisons.append(len(exported))
        print(f"OK {capture.name} | {analysis.capture.packets:,} packets | {len(actual)} feature rows | "
              f"{comparisons[0]} demo + {comparisons[1]} novel predictions | {analysis.elapsed_s:.2f}s", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Đối chiếu capture theo SHA-256, feature và dự đoán Colab")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--all-test", action="store_true", help="Đối chiếu toàn bộ split test")
    parser.add_argument("captures", nargs="*", help="Đường dẫn tương đối như trong manifest, mặc định bốn file demo")
    args = parser.parse_args()
    try:
        if args.all_test:
            if args.captures:
                parser.error("Chọn --all-test hoặc danh sách capture")
            split = pd.read_csv(RESULTS / "pcap" / "split.csv")
            args.captures = split.loc[split.split == "test", "file"].tolist()
        verify_captures(args.root, args.captures)
    except (AssertionError, OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
