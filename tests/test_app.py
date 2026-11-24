import unittest

from streamlit.testing.v1 import AppTest

from core.config import ROOT


class StreamlitTests(unittest.TestCase):
    def setUp(self):
        self.app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=45).run()

    def visit(self, page):
        self.app.sidebar.radio[0].set_value(page).run()
        self.assertFalse(self.app.exception)
        self.assertIn(page, [header.value for header in self.app.header])

    def button(self, label):
        return next(button for button in self.app.button if button.label == label)

    def test_pages(self):
        self.assertTrue(self.app.success)
        self.assertTrue(self.app.info)
        for page in ("PCAP Analysis", "PCAP Replay", "Benchmark Research", "Model Evaluation", "About"):
            with self.subTest(page=page):
                self.visit(page)
                self.assertFalse(self.app.error)

    def test_demo_analysis_and_dashboard(self):
        demo = ROOT / "data" / "pcap" / "NORMAL_30s_20260729_121618.pcap"
        if not demo.is_file():
            self.skipTest("Chạy scripts.prepare_demo để kiểm thử capture thật")
        self.visit("PCAP Analysis")
        self.app.selectbox(key="analysis_demo").set_value(demo).run()
        self.button("Analyze Traffic").click().run()
        self.assertFalse(self.app.exception)
        self.assertFalse(self.app.error)
        result = self.app.session_state.analysis_display[2]
        self.assertEqual(result.capture.packets, 1276)
        self.assertEqual(result.results["binary_prediction"].tolist(), ["Benign"] * 5)
        self.assertEqual(len(self.app.get("download_button")), 1)
        self.visit("Dashboard")
        self.assertEqual(next(metric.value for metric in self.app.metric if metric.label == "Cửa sổ"), "5")

    def test_replay_controls(self):
        demo = ROOT / "data" / "pcap" / "UDP_LOW_30s_20260729_120030.pcap"
        if not demo.is_file():
            self.skipTest("Chạy scripts.prepare_demo để kiểm thử capture thật")
        self.visit("PCAP Replay")
        self.app.selectbox(key="replay_demo").set_value(demo).run()
        self.button("Start").click().run()
        self.assertFalse(self.app.exception)
        self.assertEqual(self.app.session_state.replay.state, "running")
        self.button("Pause").click().run()
        self.assertEqual(self.app.session_state.replay.state, "paused")
        self.button("Resume").click().run()
        self.assertEqual(self.app.session_state.replay.state, "running")
        self.button("Stop").click().run()
        self.assertEqual(self.app.session_state.replay.state, "stopped")
        self.assertFalse(self.app.exception)
