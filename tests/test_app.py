import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from core.config import ROOT
from core.traffic_store import list_runs, load_windows


class StreamlitTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(TemporaryDirectory())
        self.enterContext(patch("core.traffic_store.DB_PATH", Path(directory) / "traffic.sqlite3"))
        self.app = self.open_app()

    def open_app(self):
        return AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()

    def visit(self, page):
        self.app.sidebar.radio[0].set_value(page).run()
        self.assertFalse(self.app.exception)
        rendered = " ".join(item.value for item in self.app.markdown)
        self.assertIn(page, rendered)

    def button(self, label):
        return next(button for button in self.app.button if button.label == label)

    def test_pages(self):
        self.assertIn("Mô hình sẵn sàng", " ".join(item.value for item in self.app.markdown))
        self.assertIn("Chưa có kết quả", " ".join(item.value for item in self.app.markdown))
        for page in ("Phân tích PCAP", "Phát lại PCAP", "Kết quả thực nghiệm", "Đánh giá mô hình", "Giới thiệu"):
            with self.subTest(page=page):
                self.visit(page)
                self.assertFalse(self.app.error)

    def test_demo_analysis_and_dashboard(self):
        demo = ROOT / "data" / "pcap" / "NORMAL_30s_20260729_121618.pcap"
        if not demo.is_file():
            self.skipTest("Chạy scripts.prepare_demo để kiểm thử capture thật")
        self.visit("Phân tích PCAP")
        self.app.radio(key="analysis_mode").set_value("Thư viện demo").run()
        self.app.selectbox(key="analysis_demo").set_value(demo).run()
        self.button("Phân tích lưu lượng").click().run()
        self.assertFalse(self.app.exception)
        self.assertFalse(self.app.error)
        result = self.app.session_state.analysis_display[2]
        self.assertEqual(result.capture.packets, 1276)
        self.assertEqual(result.results["binary_prediction"].tolist(), ["Benign"] * 5)
        self.assertEqual(len(self.app.get("download_button")), 1)
        self.visit("Bảng điều khiển")
        self.assert_dashboard_windows("5")
        self.visit("Phân tích PCAP")
        self.app.radio(key="analysis_mode").set_value("Tải lên").run()
        uploaded_name = "lưu lượng demo.pcap"
        self.app.file_uploader(key="analysis_upload").set_value(
            (uploaded_name, demo.read_bytes(), "application/vnd.tcpdump.pcap")
        ).run()
        self.button("Phân tích lưu lượng").click().run()
        self.assertFalse(self.app.exception)
        self.assertFalse(self.app.error)
        runs = list_runs()
        self.assertEqual([run.name for run in runs], [uploaded_name, demo.name])
        self.assertEqual(load_windows(runs[1].id).to_dict("records"), result.results.to_dict("records"))
        self.app = self.open_app()
        self.assert_dashboard_windows("5")
        self.assertIn(uploaded_name, self.app.caption[0].value)
        self.app.selectbox(key="traffic_history").set_value(runs[1].id).run()
        self.assert_dashboard_windows("5")
        self.assertIn(demo.name, self.app.caption[0].value)

    def assert_dashboard_windows(self, count):
        self.assertFalse(self.app.exception)
        self.assertFalse(self.app.error)
        self.assertEqual(next(metric.value for metric in self.app.metric
                              if metric.label == "Số cửa sổ đã xử lý"), count)

    def test_replay_controls(self):
        demo = ROOT / "data" / "pcap" / "UDP_LOW_30s_20260729_120030.pcap"
        if not demo.is_file():
            self.skipTest("Chạy scripts.prepare_demo để kiểm thử capture thật")
        self.visit("Phát lại PCAP")
        self.app.radio(key="replay_mode").set_value("Thư viện demo").run()
        self.app.selectbox(key="replay_demo").set_value(demo).run()
        clock = self.enterContext(patch("core.pcap_replay.monotonic", return_value=100.))
        self.button("Bắt đầu").click().run()
        self.assertFalse(self.app.exception)
        self.assertEqual(self.app.session_state.replay.state, "running")
        clock.return_value = 106.
        self.button("Tạm dừng").click().run()
        self.assertEqual(self.app.session_state.replay.state, "paused")
        self.button("Tiếp tục").click().run()
        self.assertEqual(self.app.session_state.replay.state, "running")
        clock.return_value = 111.
        self.app.run()
        self.button("Dừng").click().run()
        self.assertEqual(self.app.session_state.replay.state, "stopped")
        self.assertFalse(self.app.exception)
        self.assertFalse(self.app.error)
        run, = list_runs()
        self.assertEqual(run.kind, "replay")
        self.assertEqual(load_windows(run.id).window_start_s.tolist(), [0., 5.])
        self.app = self.open_app()
        self.assert_dashboard_windows("2")
