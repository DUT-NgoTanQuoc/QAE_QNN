import argparse
import hashlib
from pathlib import Path

import numpy as np

from core.config import MODEL_DIR
from core.model_loader import ModelLoadError, load_model


def main():
    parser = argparse.ArgumentParser(description="Kiểm tra khôi phục checkpoint trên CPU")
    parser.add_argument("--models", type=Path, default=MODEL_DIR)
    args = parser.parse_args()
    try:
        checksum_path = args.models / "checksums.sha256"
        if checksum_path.is_file():
            for line in checksum_path.read_text(encoding="ascii").splitlines():
                expected, name = line.split(maxsplit=1)
                actual = hashlib.sha256((args.models / name).read_bytes()).hexdigest()
                if actual != expected:
                    raise ValueError(f"Artifact checksum mismatch: {name}")
        engine = load_model(args.models)
        parameters = {key: (tuple(value.shape), str(value.dtype))
                      for key, value in engine.model.state_dict().items()}
        theta = np.load(args.models / "qae_theta.npy", allow_pickle=False)
        config = engine.config
        print(f"CPU | {parameters}")
        print(f"window={config.window}s | classes={config.classes} | features={config.features}")
        print(f"scaler: clip={engine.scaler.clip}, range={engine.scaler.feature_range}, "
              f"n_samples={engine.scaler.n_samples_seen_}, dtype={engine.scaler.scale_.dtype}")
        print(f"QAE: layers={config.layers} | theta={theta.shape} {theta.dtype} | "
              f"operator={engine.qae.operator.shape} {engine.qae.operator.dtype} | threshold={config.threshold}")
    except (ModelLoadError, OSError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
