import json
import math
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models"
RESULTS = ROOT / "results"
FEATURES = ("f1", "f2", "f3", "f4", "f5", "f6")
CLASSES = ("Normal", "SYN", "HTTP", "UDP")
BINARY_THRESHOLD = .5
ARTIFACTS = ("config.json", "hybrid.pt", "scaler.joblib", "qae_theta.npy")


@dataclass(frozen=True)
class ModelConfig:
    window: int
    layers: int
    threshold: float
    features: tuple[str, ...] = FEATURES
    classes: tuple[str, ...] = CLASSES

    @classmethod
    def read(cls, path: Path):
        data = json.loads(path.read_text(encoding="utf-8"))
        if (
            tuple(data["features"]) != FEATURES
            or tuple(data["classes"]) != CLASSES
            or data["extractor"] != "algorithm2_adapted_nonempty_full_v1"
        ):
            raise ValueError("Config không khớp hợp đồng Train_PCAP_Final")
        window, layers, threshold = (data[key] for key in ("window", "layers", "threshold"))
        if (type(window) is not int or window <= 0 or type(layers) is not int
                or layers <= 0 or type(threshold) not in (int, float)
                or not math.isfinite(threshold) or not 0 <= threshold <= 1):
            raise ValueError("Window, layers hoặc threshold không hợp lệ")
        return cls(window, layers, threshold)
