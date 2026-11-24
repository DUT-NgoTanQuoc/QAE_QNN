from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
import torch
from sklearn.preprocessing import MinMaxScaler
from sklearn.utils.validation import check_is_fitted

from .config import ARTIFACTS, MODEL_DIR, ModelConfig
from .hybrid_model import VQNN
from .inference import InferenceEngine
from .qae import QAE


class ModelLoadError(RuntimeError):
    pass


def load_model(directory=MODEL_DIR):
    directory = Path(directory).resolve()
    try:
        fingerprint = tuple((stat.st_mtime_ns, stat.st_size) for stat in
                            ((directory / name).stat() for name in ARTIFACTS))
        return _load_cached(directory, fingerprint)
    except Exception as exc:
        raise ModelLoadError(f"Không thể phục hồi model từ {directory}: {exc}") from exc


@lru_cache(maxsize=4)
def _load_cached(directory, fingerprint):
    config = ModelConfig.read(directory / "config.json")
    scaler = joblib.load(directory / "scaler.joblib")
    if not isinstance(scaler, MinMaxScaler):
        raise ValueError("Scaler phải là MinMaxScaler")
    check_is_fitted(scaler)
    if scaler.n_features_in_ != len(config.features) or not scaler.clip:
        raise ValueError("Scaler không khớp kích thước feature hoặc clip=True")
    if any(values.shape != (len(config.features),) or not np.isfinite(values).all()
           for values in (scaler.scale_, scaler.min_)):
        raise ValueError("Scaler chứa hệ số sai kích thước hoặc không hữu hạn")
    theta = np.load(directory / "qae_theta.npy", allow_pickle=False)
    if theta.shape != (config.layers * 9,) or not np.isfinite(theta).all():
        raise ValueError("Theta QAE không khớp config")
    state = torch.load(directory / "hybrid.pt", map_location="cpu", weights_only=True)
    if any(tensor.dtype != torch.float32 or not torch.isfinite(tensor).all() for tensor in state.values()):
        raise ValueError("Checkpoint chứa tensor sai dtype hoặc không hữu hạn")
    model = VQNN().to(device="cpu", dtype=torch.float32)
    model.load_state_dict(state, strict=True)
    model.eval().requires_grad_(False)
    return InferenceEngine(config, scaler, QAE(theta, config.layers), model)
