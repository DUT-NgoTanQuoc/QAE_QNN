import argparse
from pathlib import Path

from core.config import MODEL_DIR
from core.model_loader import ModelLoadError, load_model


def main():
    parser = argparse.ArgumentParser(description="Kiểm tra khôi phục checkpoint trên CPU")
    parser.add_argument("--models", type=Path, default=MODEL_DIR)
    args = parser.parse_args()
    try:
        engine = load_model(args.models)
        parameters = {key: tuple(value.shape) for key, value in engine.model.state_dict().items()}
        row = engine.predict([[0., 0., 0., 0., 0., 0.]]).iloc[0]
        print(f"CPU | {parameters} | window={engine.config.window}s | classes={engine.config.classes}")
        print(f"Kiểm tra tensor 0 | prediction={row.prediction} | confidence={row.confidence:.6f}")
    except (ModelLoadError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
