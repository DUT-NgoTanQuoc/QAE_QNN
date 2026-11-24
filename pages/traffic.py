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
from pages.charts import COLORS, PALETTE, events, plot, timeline


def model_info(engine, error):
    if engine is None:
        st.error(error)
        return
    cfg = engine.config
    st.success("Model sẵn sàng · CPU")
    st.caption(f"QAE + VQNN · 3 qubit mỗi mạch · cửa sổ {cfg.window} giây · "
               f"ngưỡng QAE {cfg.threshold:.9g} · {', '.join(cfg.classes)}")


def dashboard(engine, error):
    st.header("Dashboard")
    model_info(engine, error)
    if "latest_traffic" not in st.session_state:
        st.info("Chưa có phiên phân tích. Mở PCAP Analysis hoặc PCAP Replay để bắt đầu.")
        return
    name, packet_count, elapsed, rows = st.session_state.latest_traffic
    st.subheader(name)
    attack = int(rows.binary_prediction.eq("Attack").sum())
    for labels, values in [
        (("Gói đã đọc", "Cửa sổ", "Tổng thời gian"), (f"{packet_count:,}", len(rows), f"{elapsed:.2f} s")),
        (("Benign", "Attack", "Tỷ lệ Attack"), (len(rows) - attack, attack, f"{attack / len(rows):.1%}")),
    ]:
        for col, label, value in zip(st.columns(3), labels, values):
            col.metric(label, value, border=True)
    counts = rows.binary_prediction.value_counts().rename_axis("label").reset_index(name="windows")
    left, right = st.columns([2, 1])
    with left:
        timeline(rows, "dashboard_timeline")
    with right:
        st.markdown("**Phân bố cửa sổ**")
        plot(px.pie(counts, names="label", values="windows", color="label",
                    color_discrete_map=COLORS, hole=.58), "dashboard_distribution")
    st.subheader("Detection events gần đây")
    events(rows)


def capture_source(prefix):
    upload = st.file_uploader("Tải PCAP hoặc PCAPNG", type=["pcap", "pcapng"], key=f"{prefix}_upload")
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
        source = st.selectbox("Capture demo", demos, index=None, key=f"{prefix}_demo",
                              format_func=lambda path: path.name, placeholder="Chọn capture có sẵn")
        if source is None:
            return None, None
        stat = source.stat()
        identifier = str(source), stat.st_mtime_ns, stat.st_size
        size = stat.st_size
    st.caption(f"{source.name} · {size / (1024 * 1024):.2f} MiB")
    return source, identifier


def analysis_page(engine, error):
    st.header("PCAP Analysis")
    if engine is None:
        model_info(engine, error)
    source, identifier = capture_source("analysis")
    if st.button("Analyze Traffic", type="primary", disabled=source is None or engine is None):
        st.session_state.pop("analysis_display", None)
        progress = st.progress(0., text="Đang đọc capture và suy luận")
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
        return
    _, name, analysis = previous
    rows, capture = analysis.results, analysis.capture
    started = datetime.fromtimestamp(capture.start_epoch_s, ZoneInfo("Asia/Bangkok"))
    st.caption(f"{capture.packets:,} gói đã đọc · {capture.duration_s:.3f} s capture · "
               f"{started:%d/%m/%Y %H:%M:%S %Z} · {len(rows)} cửa sổ")
    st.caption(f"Tổng thời gian {analysis.elapsed_s:.3f} s · inference {rows.inference_ms.sum():.3f} ms · "
               "thời gian từng cửa sổ là trung bình theo batch")
    st.caption("Nhãn multiclass dùng argmax. Attack binary dùng xác suất attack ≥ 0,5.")
    left, right = st.columns(2)
    choice = left.selectbox("Lọc binary", ["Tất cả", "Benign", "Attack"])
    labels = right.multiselect("Lọc nhãn multiclass", engine.config.classes if engine else rows.prediction.unique())
    filtered = rows
    if choice != "Tất cả":
        filtered = filtered.loc[filtered.binary_prediction == choice]
    if labels:
        filtered = filtered.loc[filtered.prediction.isin(labels)]
    if filtered.empty:
        st.info("Không có cửa sổ khớp bộ lọc.")
    else:
        timeline(filtered, "analysis_timeline")
        st.markdown("**Feature theo cửa sổ**")
        feature = st.selectbox("Feature", FEATURES, format_func=lambda value: value.upper())
        plot(px.line(filtered, x="window_start_s", y=feature, markers=True, color_discrete_sequence=PALETTE,
                     labels={"window_start_s": "Mốc capture (giây)"}), "analysis_features")
        st.dataframe(filtered, hide_index=True, width="stretch")
        with st.expander("Chi tiết cửa sổ"):
            key = st.selectbox("Window ID", filtered.window_id.tolist())
            detail = filtered.loc[filtered.window_id == key].iloc[0].astype(str)
            st.dataframe(detail.to_frame("Giá trị"), width="stretch")
    st.download_button("Tải CSV toàn bộ", analysis.csv_bytes(), f"{Path(name).stem}-results.csv",
                       "text/csv", on_click="ignore")


def replay_page(engine, error):
    st.header("PCAP Replay")
    st.caption("Phát lại PCAP đã lưu. Live Network Capture không được sử dụng.")
    if engine is None:
        model_info(engine, error)
        return
    speed = st.select_slider("Tốc độ", options=[.25, .5, 1., 2., 4., 8., 16.], value=1.,
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
            st.subheader("Detection events")
            events(rows, count=25)

    replay_controls()
