import io
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from scapy.all import ARP, Ether, IP, TCP, UDP, PcapNgWriter, wrpcap

from core.config import FEATURES, MODEL_DIR
from core.feature_extractor import extract_pcap
from core.model_loader import ModelLoadError, load_model
from core.pcap_analysis import analyze_pcap
from core.pcap_reader import CaptureError
from core.pcap_replay import Replay
from core.preprocessing import transform


def stamped(packet, timestamp):
    packet[Ether].src = "02:00:00:00:00:01"
    packet[Ether].dst = "02:00:00:00:00:02"
    packet.time = 1000 + timestamp
    return packet


def fixture_packets():
    local = IP(src="192.0.2.1", dst="192.0.2.2")
    peer = IP(src="192.0.2.2", dst="192.0.2.1")
    return [
        stamped(Ether() / local / UDP(), 5),
        stamped(Ether() / local / TCP(flags="S"), 0),
        stamped(Ether() / peer / TCP(flags="SA"), 1),
        stamped(Ether() / local / TCP(flags="PA") / b"GET / HTTP/1.0\r\n\r\n", 2),
        stamped(Ether() / ARP(hwsrc="02:00:00:00:00:01"), 3),
        stamped(Ether() / local / UDP(), 15),
    ]


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = load_model()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.capture = self.directory / "capture.pcap"
        wrpcap(str(self.capture), fixture_packets())

    def test_cpu_model_cached_and_missing(self):
        self.assertIs(self.engine, load_model())
        self.assertFalse(self.engine.model.training)
        self.assertEqual(next(self.engine.model.parameters()).device, torch.device("cpu"))
        (self.directory / "config.json").write_bytes((MODEL_DIR / "config.json").read_bytes())
        with self.assertRaisesRegex(ModelLoadError, "hybrid.pt"):
            load_model(self.directory)
        for name in ("scaler.joblib", "qae_theta.npy"):
            (self.directory / name).write_bytes((MODEL_DIR / name).read_bytes())
        torch.save({"theta": torch.zeros((2, 3))}, self.directory / "hybrid.pt")
        with self.assertRaisesRegex(ModelLoadError, "Missing key"):
            load_model(self.directory)

    def test_features_and_order(self):
        extracted = extract_pcap(self.capture)
        self.assertEqual(extracted.packets, 6)
        self.assertEqual(extracted.duration_s, 15)
        self.assertEqual(extracted.windows.window_id.tolist(), [0, 1])
        self.assertEqual(tuple(extracted.windows.columns[-6:]), FEATURES)
        np.testing.assert_allclose(extracted.windows.loc[:, list(FEATURES)], [
            [4, 1, 2, 1, 1, 0], [1, 0, 1, 0, 0, 1],
        ])

    def test_pcapng_and_stream(self):
        path = self.directory / "capture.pcapng"
        with PcapNgWriter(str(path)) as writer:
            writer.write(fixture_packets())
        with io.BytesIO(path.read_bytes()) as stream:
            expected = extract_pcap(self.capture).windows
            pd.testing.assert_frame_equal(expected, extract_pcap(stream).windows)
            self.assertFalse(stream.closed)
        with self.assertRaises(CaptureError):
            extract_pcap(io.BytesIO(path.read_bytes()[:-1]))

    def test_preprocessing_and_batch(self):
        rows = extract_pcap(self.capture).windows
        reordered = rows.loc[:, list(reversed(FEATURES))].assign(label="not an input")
        np.testing.assert_array_equal(
            transform(reordered, self.engine.scaler),
            self.engine.scaler.transform(np.log1p(rows.loc[:, list(FEATURES)].to_numpy())),
        )
        full = self.engine.predict(rows).drop(columns="inference_ms")
        single = self.engine.predict(reordered, batch_size=1).drop(columns="inference_ms")
        pd.testing.assert_frame_equal(full, single, atol=2e-6, rtol=0)

    def test_invalid_and_empty(self):
        for data in (b"", b"bad magic", self.capture.read_bytes()[:-1],
                     self.capture.read_bytes() + b"x", self.capture.read_bytes()[:24]):
            with self.subTest(size=len(data)), self.assertRaises(CaptureError):
                extract_pcap(io.BytesIO(data))
        path = self.directory / "short.pcap"
        wrpcap(str(path), fixture_packets()[1:3])
        with self.assertRaisesRegex(CaptureError, "cửa sổ"):
            analyze_pcap(path, self.engine)
        for values in ([], [[1]], [[np.nan] * 6], [[np.inf] * 6], [[-1] * 6]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.engine.predict(values)

    def test_csv(self):
        analysis = analyze_pcap(self.capture, self.engine)
        exported = pd.read_csv(io.BytesIO(analysis.csv_bytes()))
        pd.testing.assert_frame_equal(exported, analysis.results, check_dtype=False)

    def test_replay(self):
        replay = Replay(extract_pcap(self.capture), self.capture.name)
        replay.start(now=0)
        replay.advance(self.engine, speed=1, now=4)
        self.assertEqual(len(replay.events), 0)
        replay.pause()
        replay.advance(self.engine, speed=1, now=100)
        self.assertEqual(len(replay.events), 0)
        replay.resume(now=100)
        replay.advance(self.engine, speed=2, now=101)
        self.assertEqual(len(replay.events), 1)
        replay.stop()
        replay.advance(self.engine, speed=1, now=110)
        self.assertEqual(len(replay.events), 1)
        replay.start(now=0)
        replay.advance(self.engine, speed=2, now=5)
        self.assertEqual(replay.state, "finished")
        offline = analyze_pcap(self.capture, self.engine).results
        pd.testing.assert_frame_equal(replay.results().drop(columns="inference_ms"),
                                      offline.drop(columns="inference_ms"), atol=2e-6, rtol=0)


if __name__ == "__main__":
    unittest.main()
