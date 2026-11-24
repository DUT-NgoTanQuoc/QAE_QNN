from dataclasses import dataclass, field
from math import isfinite
from time import monotonic

import pandas as pd

from .feature_extractor import CaptureFeatures
from .pcap_reader import CaptureError


@dataclass
class Replay:
    capture: CaptureFeatures
    name: str
    state: str = field(default="ready", init=False)
    position_s: float = field(default=0., init=False)
    events: list[pd.DataFrame] = field(default_factory=list, init=False)
    _last_tick: float = field(default=0., init=False)

    def __post_init__(self):
        if self.capture.windows.empty:
            raise CaptureError("Capture không có cửa sổ đầy đủ và có gói")

    def start(self, now=None):
        if self.state in ("running", "paused"):
            raise ValueError("Replay đã bắt đầu")
        self.events.clear()
        self.position_s = 0.
        self.state = "running"
        self._last_tick = monotonic() if now is None else now

    def pause(self):
        if self.state == "running":
            self.state = "paused"

    def resume(self, now=None):
        if self.state == "paused":
            self._last_tick = monotonic() if now is None else now
            self.state = "running"

    def stop(self):
        self.state = "stopped"

    def advance(self, engine, speed, now=None):
        if self.state != "running":
            return
        if not isfinite(speed) or speed <= 0:
            raise ValueError("Tốc độ replay phải dương và hữu hạn")
        now = monotonic() if now is None else now
        self.position_s += max(now - self._last_tick, 0.) * speed
        self._last_tick = now
        windows = self.capture.windows
        # Limit work per refresh to keep controls responsive on large captures.
        for index in range(len(self.events), min(len(windows), len(self.events) + 24)):
            window = windows.iloc[[index]].reset_index(drop=True)
            if window.at[0, "window_end_s"] > self.position_s:
                break
            self.events.append(pd.concat([window, engine.predict(window)], axis=1))
        if len(self.events) == len(windows):
            self.position_s = float(windows["window_end_s"].iloc[-1])
            self.state = "finished"

    def results(self):
        return pd.concat(self.events, ignore_index=True) if self.events else pd.DataFrame()
