from datetime import datetime
from pathlib import Path
from time import perf_counter
from zoneinfo import ZoneInfo

import plotly.express as px
import streamlit as st

from core.config import FEATURES, ROOT
from core.feature_extractor import extract_pcap
from core.pcap_analysis import analyze_pcap
from core.pcap_replay import Replay
from pages.charts import COLORS, PALETTE, events, plot, risk_gauge, timeline
from pages.ui import empty_state, page_header, panel, pills


def model_info(engine, error):
    if engine is None:
        st.error(f"Model unavailable. {error}")
        return
    cfg = engine.config
    pills("MODEL READY", "CPU STATEVECTOR", f"{cfg.window}s WINDOWS", "4 TRAFFIC CLASSES")


def dashboard(engine, error):
    page_header("SOC OVERVIEW", "DDoS Detection Dashboard",
                "Operational view of the latest real PCAP analysis using the validated QAE + QNN pipeline.")
    model_info(engine, error)
    if "latest_traffic" not in st.session_state:
        left, right = st.columns([1.35, 1])
        with left:
            empty_state("No analysis session yet",
                        "Analyze a PCAP or start an offline replay. Detection metrics will appear here from real inference.")
        with right:
            panel("Detection pipeline",
                  "PCAP → 5-second window → f1–f6 → trained scaler → QAE → Hybrid QNN → verdict")
            if engine is not None:
                cfg = engine.config
                st.metric("QAE anomaly threshold", f"{cfg.threshold:.9f}", border=True)
            st.caption("Dashboard values remain empty until a capture is processed.")
        return
    name, packet_count, elapsed, rows = st.session_state.latest_traffic
    attack = int(rows.binary_prediction.eq("Attack").sum())
    benign = len(rows) - attack
    attack_ratio = attack / len(rows)
    st.caption(f"Latest session · {name}")
    metrics = (
        ("Packets inspected", f"{packet_count:,}"),
        ("Analyzed windows", f"{len(rows):,}"),
        ("Benign windows", f"{benign:,}"),
        ("Attack windows", f"{attack:,}"),
        ("Attack ratio", f"{attack_ratio:.1%}"),
        ("Processing time", f"{elapsed:.2f}s"),
    )
    for start in (0, 3):
        for column, (label, value) in zip(st.columns(3), metrics[start:start + 3]):
            column.metric(label, value, border=True)
    counts = rows.binary_prediction.value_counts().rename_axis("label").reset_index(name="windows")
    left, right = st.columns([2.15, 1])
    with left:
        st.subheader("Traffic timeline")
        timeline(rows, "dashboard_timeline")
    with right:
        st.subheader("Session risk")
        risk_gauge(attack_ratio, "dashboard_risk")
    distribution, classification = st.columns(2)
    with distribution:
        st.subheader("Binary distribution")
        plot(px.pie(counts, names="label", values="windows", color="label",
                    color_discrete_map=COLORS, hole=.62), "dashboard_distribution", height=300)
    with classification:
        st.subheader("Predicted attack class")
        classes = rows.prediction.value_counts().rename_axis("class").reset_index(name="windows")
        plot(px.bar(classes, x="class", y="windows", color="class",
                    color_discrete_sequence=PALETTE), "dashboard_classes", height=300)
    st.subheader("Recent detection events")
    events(rows)


def capture_source(prefix):
    source_mode = st.radio("Capture source", ["Upload", "Demo library"], horizontal=True,
                           key=f"{prefix}_mode")
    upload = st.file_uploader("Upload PCAP or PCAPNG", type=["pcap", "pcapng"],
                              key=f"{prefix}_upload") if source_mode == "Upload" else None
    roots = [ROOT / "data" / folder for folder in ("pcap", "demo", "test_pcap")]
    demos = sorted(
        path for directory in roots if directory.is_dir() for path in directory.iterdir()
        if path.is_file() and path.suffix.lower() in (".pcap", ".pcapng")
    )
    if upload is not None:
        source = upload
        identifier = upload.file_id
        size = upload.size
    else:
        source = st.selectbox("Demo capture", demos, index=None, key=f"{prefix}_demo",
                              format_func=lambda path: path.name, placeholder="Select a local capture")
        if source is None:
            return None, None
        stat = source.stat()
        identifier = str(source), stat.st_mtime_ns, stat.st_size
        size = stat.st_size
    st.caption(f"Selected · {source.name} · {size / (1024 * 1024):.2f} MiB")
    return source, identifier


def analysis_page(engine, error):
    page_header("OFFLINE FORENSICS", "PCAP Analysis",
                "Extract real packet-window features and run the validated QAE + QNN model on CPU.")
    if engine is None:
        model_info(engine, error)
    source_panel, action_panel = st.columns([2.2, 1])
    with source_panel:
        source, identifier = capture_source("analysis")
    with action_panel:
        panel("What happens next",
              "Packets are read twice, grouped into full 5-second windows, transformed with the trained scaler and inferred on CPU.")
        analyze = st.button("Analyze Traffic", type="primary", disabled=source is None or engine is None,
                            width="stretch")
    if analyze:
        st.session_state.pop("analysis_display", None)
        progress = st.progress(0., text="Reading packets and running model inference")
        try:
            result = analyze_pcap(source, engine, progress.progress)
        except (OSError, ValueError) as exc:
            st.error(str(exc))
        else:
            st.session_state.analysis_display = identifier, source.name, result
            st.session_state.latest_traffic = source.name, result.capture.packets, result.elapsed_s, result.results
        finally:
            progress.empty()
    previous = st.session_state.get("analysis_display")
    if previous is None or previous[0] != identifier:
        if source is not None:
            st.info("Capture selected. Start analysis to generate real detection results.")
        return
    _, name, analysis = previous
    rows, capture = analysis.results, analysis.capture
    started = datetime.fromtimestamp(capture.start_epoch_s, ZoneInfo("Asia/Bangkok"))
    attack = int(rows.binary_prediction.eq("Attack").sum())
    summary = (
        ("Packets", f"{capture.packets:,}"),
        ("Windows", f"{len(rows):,}"),
        ("Attack", f"{attack:,}"),
        ("Total time", f"{analysis.elapsed_s:.2f}s"),
    )
    for column, (label, value) in zip(st.columns(4), summary):
        column.metric(label, value, border=True)
    st.caption(f"Capture start {started:%d/%m/%Y %H:%M:%S %Z} · duration {capture.duration_s:.3f}s · "
               f"feature extraction {analysis.extraction_s:.3f}s · inference {rows.inference_ms.sum():.3f}ms")
    left, right = st.columns(2)
    choice = left.selectbox("Verdict filter", ["All", "Benign", "Attack"])
    labels = right.multiselect("Class filter", engine.config.classes if engine else rows.prediction.unique())
    filtered = rows
    if choice != "All":
        filtered = filtered.loc[filtered.binary_prediction == choice]
    if labels:
        filtered = filtered.loc[filtered.prediction.isin(labels)]
    if filtered.empty:
        empty_state("No matching windows", "Change the verdict or class filter to inspect other detections.")
    else:
        st.subheader("Detection timeline")
        timeline(filtered, "analysis_timeline")
        st.subheader("Feature telemetry")
        feature = st.selectbox("Feature", FEATURES, format_func=lambda value: value.upper(),
                               label_visibility="collapsed")
        plot(px.line(filtered, x="window_start_s", y=feature, markers=True, color_discrete_sequence=PALETTE,
                     labels={"window_start_s": "Mốc capture (giây)"}), "analysis_features")
        st.subheader("Window detections")
        events(filtered, count=len(filtered))
        with st.expander("Inspect one window"):
            key = st.selectbox("Window ID", filtered.window_id.tolist(), key="analysis_window")
            detail = filtered.loc[filtered.window_id == key].iloc[0].astype(str)
            st.dataframe(detail.to_frame("Giá trị"), width="stretch")
    st.download_button("Export full CSV", analysis.csv_bytes(), f"{Path(name).stem}-results.csv",
                       "text/csv", on_click="ignore")


def replay_page(engine, error):
    page_header("CONTROLLED SIMULATION", "PCAP Replay",
                "Replay completed capture windows through the validated detector. This is offline replay, not live capture.")
    if engine is None:
        model_info(engine, error)
        return
    speed = st.select_slider("Replay speed", options=[.25, .5, 1., 2., 4., 8., 16.], value=1.,
                             format_func=lambda value: f"{value:g}×")
    source, identifier = capture_source("replay")
    replay = st.session_state.get("replay")
    if replay and st.session_state.get("replay_id") != identifier and source is not None:
        replay.stop()
        replay = None
    active = replay is not None and replay.state in ("running", "paused")
    if st.button("Start", type="primary", disabled=source is None or active):
        progress = st.progress(0., text="Đang đọc cửa sổ replay")
        started = perf_counter()
        try:
            replay = Replay(extract_pcap(source, engine.config.window, progress.progress), source.name)
            replay.start()
        except (OSError, ValueError) as exc:
            st.error(str(exc))
        else:
            st.session_state.replay = replay
            st.session_state.replay_id = identifier
            st.session_state.replay_started = started
        finally:
            progress.empty()
    if replay is None:
        if source is None:
            empty_state("Replay is idle", "Choose a PCAP from the demo library or upload a capture to begin.")
        return

    @st.fragment(run_every=.4 if replay.state == "running" else None)
    def replay_controls():
        left, middle, right = st.columns(3)
        pause = left.button("Pause", disabled=replay.state != "running")
        resume = middle.button("Resume", disabled=replay.state != "paused")
        stop = right.button("Stop", disabled=replay.state not in ("running", "paused"))
        original = replay.state
        previous_count = len(replay.events)
        try:
            if stop:
                replay.stop()
            if resume:
                replay.resume()
            replay.advance(engine, speed)
            if pause:
                replay.pause()
        except ValueError as exc:
            replay.stop()
            st.error(str(exc))
            return
        rows = replay.results()
        elapsed = perf_counter() - st.session_state.replay_started
        if len(rows) > previous_count:
            st.session_state.latest_traffic = replay.name, replay.capture.packets, elapsed, rows
        if replay.state != original:
            st.rerun()
        st.progress(len(rows) / len(replay.capture.windows),
                    text=f"{replay.name} · {replay.state} · {replay.position_s:.1f} s · "
                         f"{len(rows)}/{len(replay.capture.windows)} cửa sổ")
        if not rows.empty:
            timeline(rows, "replay_timeline")
            st.subheader("Replay detection events")
            events(rows, count=25)

    replay_controls()
