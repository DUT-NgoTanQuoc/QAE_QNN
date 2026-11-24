from dataclasses import dataclass
from time import perf_counter

import numpy as np
import pandas as pd
import torch

from .config import ModelConfig
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
    def predict(self, rows, batch_size=512):
        if batch_size < 1 or not len(rows):
            raise ValueError("Cần ít nhất một dòng và batch_size dương")
        batches = []
        for offset in range(0, len(rows), batch_size):
            batch = rows.iloc[offset:offset + batch_size] if isinstance(rows, pd.DataFrame) else rows[offset:offset + batch_size]
            started = perf_counter()
            values = transform(batch, self.scaler, self.config.features)
            quantum = self.qae.features(values)
            inputs = torch.tensor(np.column_stack([values, quantum]), dtype=torch.float32, device="cpu")
            prob = self.model(inputs).softmax(1).numpy()
            elapsed_ms = (perf_counter() - started) * 1000
            if not np.isfinite(prob).all():
                raise ValueError("Mô hình trả về xác suất không hữu hạn")
            attack_probability = 1 - prob[:, 0]
            batches.append(pd.DataFrame({
                "anomaly_score": quantum[:, 0],
                "qae_alert": quantum[:, 0] > self.config.threshold,
                "prediction": np.asarray(self.config.classes)[prob.argmax(1)],
                "confidence": prob.max(1),
                "attack_probability": attack_probability,
                "binary_prediction": np.where(attack_probability >= .5, "Attack", "Benign"),
                "inference_ms": elapsed_ms / len(batch),
            }))
        return pd.concat(batches, ignore_index=True)
