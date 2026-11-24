from dataclasses import dataclass
from numbers import Integral
from time import perf_counter

import numpy as np
import pandas as pd
import torch

from .config import BINARY_THRESHOLD, ModelConfig
from .hybrid_model import VQNN
from .preprocessing import transform
from .qae import QAE


@dataclass(frozen=True)
class InferenceEngine:
    config: ModelConfig
    scaler: object
    qae: QAE
    model: VQNN

    @torch.inference_mode()
    def predict(self, rows, batch_size=512, *, include_probabilities=False):
        """Predict in input order. Optional probability columns follow config.classes."""
        if isinstance(batch_size, bool) or not isinstance(batch_size, Integral) or batch_size < 1:
            raise ValueError("batch_size phải là số nguyên dương")
        if not len(rows):
            raise ValueError("Cần ít nhất một dòng feature")
        batches = []
        classes = np.asarray(self.config.classes)
        for offset in range(0, len(rows), batch_size):
            span = slice(offset, offset + batch_size)
            batch = rows.iloc[span] if isinstance(rows, pd.DataFrame) else rows[span]
            started = perf_counter()
            values = transform(batch, self.scaler, self.config.features)
            quantum = self.qae.features(values)
            inputs = torch.tensor(np.column_stack([values, quantum]), dtype=torch.float32, device="cpu")
            prob = self.model(inputs).softmax(1).numpy()
            elapsed_ms = (perf_counter() - started) * 1000
            if not np.isfinite(prob).all():
                raise ValueError("Mô hình trả về xác suất không hữu hạn")
            attack_probability = 1 - prob[:, 0]
            data = {
                "anomaly_score": quantum[:, 0],
                "qae_alert": quantum[:, 0] > self.config.threshold,
                "prediction": classes[prob.argmax(1)],
                "confidence": prob.max(1),
                "attack_probability": attack_probability,
                "binary_prediction": np.where(attack_probability >= BINARY_THRESHOLD, "Attack", "Benign"),
                "inference_ms": elapsed_ms / len(batch),
            }
            if include_probabilities:
                data.update({f"prob_{label}": column for label, column in zip(classes, prob.T)})
            batches.append(pd.DataFrame(data))
        return pd.concat(batches, ignore_index=True)
