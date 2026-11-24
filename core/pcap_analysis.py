from time import perf_counter
from dataclasses import dataclass

import pandas as pd

from .feature_extractor import CaptureFeatures, extract_pcap
from .pcap_reader import CaptureError


@dataclass(frozen=True)
class Analysis:
    capture: CaptureFeatures
    results: pd.DataFrame
    elapsed_s: float

    def csv_bytes(self):
        return self.results.to_csv(index=False).encode("utf-8")


def analyze_pcap(source, engine, progress=None):
    started = perf_counter()
    capture = extract_pcap(source, engine.config.window, (lambda x: progress(.9 * x)) if progress else None)
    if capture.windows.empty:
        raise CaptureError("Capture không có cửa sổ đầy đủ và có gói")
    predictions = engine.predict(capture.windows)
    if progress:
        progress(1.)
    return Analysis(capture, pd.concat([capture.windows, predictions], axis=1), perf_counter() - started)
