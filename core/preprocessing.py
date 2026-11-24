import numpy as np
import pandas as pd

from .config import FEATURES


def transform(rows, scaler, features=FEATURES):
    if isinstance(rows, pd.DataFrame):
        rows = rows.loc[:, list(features)].to_numpy()
    values = np.asarray(rows, dtype=np.float64)
    if values.ndim != 2 or values.shape[1] != len(features) or not len(values):
        raise ValueError("Cần ma trận feature f1–f6 với ít nhất một dòng")
    if not np.isfinite(values).all() or (values <= -1).any():
        raise ValueError("Feature phải hữu hạn và nằm trong miền log1p")
    return scaler.transform(np.log1p(values))
