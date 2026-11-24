import numpy as np
import pandas as pd

from .config import FEATURES


def transform(rows, scaler, features=FEATURES):
    if isinstance(rows, pd.DataFrame):
        indices = rows.columns.get_indexer_for(features)
        if len(indices) != len(features) or (indices < 0).any():
            raise ValueError("DataFrame phải có đúng một cột cho mỗi feature f1–f6")
        rows = rows.iloc[:, indices].to_numpy()
    raw = np.asarray(rows)
    if np.iscomplexobj(raw):
        raise ValueError("Feature f1–f6 phải là số thực")
    values = raw.astype(np.float64, copy=False)
    if values.ndim != 2 or values.shape[1] != len(features) or not len(values):
        raise ValueError("Cần ma trận feature f1–f6 với ít nhất một dòng")
    if not np.isfinite(values).all() or (values <= -1).any():
        raise ValueError("Feature phải hữu hạn và nằm trong miền log1p")
    scaled = scaler.transform(np.log1p(values))
    if not np.isfinite(scaled).all():
        raise ValueError("Scaler trả về feature không hữu hạn")
    return scaled
