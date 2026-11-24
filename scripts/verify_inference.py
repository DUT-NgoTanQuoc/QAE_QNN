import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from core.config import FEATURES, MODEL_DIR, RESULTS
from core.model_loader import ModelLoadError, load_model

KEYS = ["file", "window_start_s"]
VALUES = ["prediction", "qae_alert", "confidence", "anomaly_score", "attack_probability"]


def verify(engine, directory):
    features = pd.read_csv(directory / "features.csv")
    split = pd.read_csv(directory / "split.csv")
    test = features.merge(split.loc[split.split == "test", ["file"]], on="file", validate="many_to_one")
    references = sorted((directory / "predictions").glob("*_prediction.csv"))
    if not references:
        raise ValueError("Thiếu CSV dự đoán dùng để đối chiếu")
    novel = directory / "evaluation_extra" / "novel_predictions.csv"
    if novel.is_file():
        references.append(novel)
    total = 0
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
        np.testing.assert_allclose(
            joined.loc[:, list(FEATURES)], joined.loc[:, [f"{k}_export" for k in FEATURES]],
            rtol=1e-12, atol=1e-12, err_msg=path.name,
        )
        actual = engine.predict(joined)
        differences = []
        for key in VALUES:
            if key not in joined:
                if key == "attack_probability" and path == novel:
                    continue
                raise ValueError(f"{path.name}: thiếu cột {key}")
            if key in ("prediction", "qae_alert"):
                np.testing.assert_array_equal(actual[key], joined[key], err_msg=f"{path.name}: {key}")
            else:
                tolerance = 1e-10 if key == "anomaly_score" else 2e-6
                np.testing.assert_allclose(actual[key], joined[key], rtol=0, atol=tolerance,
                                           err_msg=f"{path.name}: {key}")
                differences.append(f"{key}={np.max(np.abs(actual[key] - joined[key])):.3g}")
        print(f"{path.name} | {len(actual)} windows | max abs: {', '.join(differences)}")
        total += len(actual)
    print(f"{total} dòng đối chiếu qua {len(references)} CSV (có thể trùng cửa sổ)")


def main():
    parser = argparse.ArgumentParser(description="Đối chiếu inference CPU trên cùng feature test Colab")
    parser.add_argument("--models", type=Path, default=MODEL_DIR)
    parser.add_argument("--results", type=Path, default=RESULTS / "pcap")
    args = parser.parse_args()
    try:
        verify(load_model(args.models), args.results)
    except (AssertionError, ModelLoadError, OSError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
