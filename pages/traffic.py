import sqlite3
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
from core.traffic_store import list_runs, load_windows, save_windows
from pages.charts import (
    COLORS, FEATURE_LABELS, PALETTE, TRAFFIC_CLASSES, TRAFFIC_COLUMNS, VERDICTS,
    events, feature_chart, plot, risk_gauge, timeline,
)
from pages.ui import empty_state, page_header, panel, pills

LOCAL_TZ = ZoneInfo("Asia/Bangkok")
RUN_KINDS = {"analysis": "Phân tích", "replay": "Phát lại"}
REPLAY_STATES = {"running": "Đang phát", "paused": "Tạm dừng", "stopped": "Đã dừng",
                 "finished": "Hoàn tất"}


def model_info(engine, error):
    if engine is None:
        st.error(f"Không tải được mô hình. {error}")
        return
    cfg = engine.config
    pills("Mô hình sẵn sàng", "Mô phỏng trên CPU", f"Cửa sổ {cfg.window} giây", "4 lớp lưu lượng")


def run_label(run):
    created = datetime.fromisoformat(run.created_at).astimezone(LOCAL_TZ)
    return f"{created:%d/%m/%Y %H:%M:%S} · {RUN_KINDS[run.kind]} · {run.name}"


def dashboard(engine, error):
    page_header("TỔNG QUAN", "Bảng điều khiển phát hiện DDoS",
                "Xem lại các kết quả phát hiện từ mô hình QAE + QNN.")
    model_info(engine, error)
    try:
        runs = {run.id: run for run in list_runs()}
    except (OSError, sqlite3.Error) as exc:
        st.error(f"Không đọc được lịch sử lưu lượng. {exc}")
        return
    if not runs:
        left, right = st.columns([1.35, 1])
        with left:
            empty_state("Chưa có kết quả",
                        "Phân tích hoặc phát lại file PCAP để xem kết quả tại đây.")
        with right:
            panel("Quy trình phát hiện",
                  "PCAP → cửa sổ 5 giây → f1–f6 → chuẩn hóa → QAE → QNN lai → kết luận")
            if engine is not None:
                cfg = engine.config
                st.metric("Ngưỡng bất thường của QAE", f"{cfg.threshold:.9f}", border=True)
        return
    selected = st.selectbox("Lịch sử xử lý PCAP", [0, *runs], key="traffic_history",
                            format_func=lambda key: run_label(runs[key]) if key else "Phiên mới nhất")
    run = runs[selected] if selected else next(iter(runs.values()))
    try:
        rows = load_windows(run.id)
    except (OSError, ValueError, sqlite3.Error) as exc:
        st.error(f"Không đọc được kết quả đã lưu. {exc}")
        return
    attack = int(rows.binary_prediction.eq("Attack").sum())
    benign = len(rows) - attack
    attack_ratio = attack / len(rows)
    st.caption(run_label(run))
    metrics = (
        ("Số gói tin trong file", f"{run.packet_count:,}"),
        ("Số cửa sổ đã xử lý", f"{len(rows):,}"),
        ("Cửa sổ bình thường", f"{benign:,}"),
        ("Cửa sổ tấn công", f"{attack:,}"),
        ("Tỷ lệ tấn công", f"{attack_ratio:.1%}"),
        ("Thời gian xử lý", f"{run.elapsed_s:.2f} giây"),
    )
    for start in (0, 3):
        for column, (label, value) in zip(st.columns(3), metrics[start:start + 3]):
            column.metric(label, value, border=True)
    counts = rows.binary_prediction.replace(VERDICTS).value_counts().rename_axis("label").reset_index(name="windows")
    left, right = st.columns([2.15, 1])
    with left:
        st.subheader("Diễn biến lưu lượng")
        timeline(rows, "dashboard_timeline")
    with right:
        st.subheader("Mức độ rủi ro")
        risk_gauge(attack_ratio, "dashboard_risk")
    distribution, classification = st.columns(2)
    with distribution:
        st.subheader("Phân bố bình thường và tấn công")
        plot(px.pie(counts, names="label", values="windows", color="label",
                    labels={"label": "Kết luận", "windows": "Số cửa sổ"},
                    color_discrete_map=COLORS, hole=.62), "dashboard_distribution", height=300)
    with classification:
        st.subheader("Phân bố lớp dự đoán")
        classes = rows.prediction.replace(TRAFFIC_CLASSES).value_counts().rename_axis("class").reset_index(name="windows")
        figure = px.bar(classes, x="class", y="windows", color="class",
                        labels={"class": "Lớp dự đoán", "windows": "Số cửa sổ"},
                        color_discrete_sequence=PALETTE)
        figure.update_layout(showlegend=False)
        plot(figure, "dashboard_classes", height=300)
    st.subheader("Kết quả theo cửa sổ gần đây")
    events(rows)


def capture_source(prefix):
    source_mode = st.radio("Nguồn file PCAP", ["Tải lên", "Thư viện demo"], horizontal=True,
                           key=f"{prefix}_mode")
    if source_mode == "Tải lên":
        source = st.file_uploader("Chọn hoặc kéo thả file PCAP hay PCAPNG", type=["pcap", "pcapng"],
                                  key=f"{prefix}_upload")
        if source is None:
            return None, None
        identifier, size = source.file_id, source.size
    else:
        roots = [ROOT / "data" / folder for folder in ("pcap", "demo", "test_pcap")]
        demos = sorted(
            path for directory in roots if directory.is_dir() for path in directory.iterdir()
            if path.is_file() and path.suffix.lower() in (".pcap", ".pcapng")
        )
        source = st.selectbox("File PCAP demo", demos, index=None, key=f"{prefix}_demo",
                              format_func=lambda path: path.name, placeholder="Chọn file demo")
        if source is None:
            return None, None
        stat = source.stat()
        identifier = str(source), stat.st_mtime_ns, stat.st_size
        size = stat.st_size
    st.caption(f"Đã chọn · {source.name} · {size / (1024 * 1024):.2f} MiB")
    return source, identifier


def analysis_page(engine, error):
    page_header("PHÂN TÍCH NGOẠI TUYẾN", "Phân tích PCAP",
                "Trích xuất đặc trưng theo cửa sổ và chạy mô hình QAE + QNN trên CPU.")
    if engine is None:
        model_info(engine, error)
    source_panel, action_panel = st.columns([2.2, 1])
    with source_panel:
        source, identifier = capture_source("analysis")
    with action_panel:
        panel("Cách xử lý",
              "Ứng dụng đọc gói tin qua hai lượt, gom theo cửa sổ đủ 5 giây, chuẩn hóa đặc trưng và chạy suy luận trên CPU.")
        analyze = st.button("Phân tích lưu lượng", type="primary", disabled=source is None or engine is None,
                            width="stretch")
    if analyze:
        st.session_state.pop("analysis_display", None)
        progress = st.progress(0., text="Đang đọc gói tin và chạy mô hình")
        try:
            result = analyze_pcap(source, engine, progress.progress)
        except (OSError, ValueError) as exc:
            st.error(str(exc))
        else:
            st.session_state.analysis_display = identifier, source.name, result
            try:
                save_windows(source.name, "analysis", result.capture.packets, result.elapsed_s, result.results)
            except (OSError, ValueError, sqlite3.Error) as exc:
                st.error(f"Không lưu được kết quả vào bảng điều khiển. {exc}")
        finally:
            progress.empty()
    previous = st.session_state.get("analysis_display")
    if previous is None or previous[0] != identifier:
        if source is not None:
            st.info("Bấm Phân tích lưu lượng để xem kết quả.")
        return
    _, name, analysis = previous
    rows, capture = analysis.results, analysis.capture
    started = datetime.fromtimestamp(capture.start_epoch_s, LOCAL_TZ)
    attack = int(rows.binary_prediction.eq("Attack").sum())
    summary = (
        ("Số gói tin", f"{capture.packets:,}"),
        ("Số cửa sổ", f"{len(rows):,}"),
        ("Cửa sổ tấn công", f"{attack:,}"),
        ("Tổng thời gian xử lý", f"{analysis.elapsed_s:.2f} giây"),
    )
    for column, (label, value) in zip(st.columns(4), summary):
        column.metric(label, value, border=True)
    st.caption(f"Bắt đầu ghi gói {started:%d/%m/%Y %H:%M:%S %Z} · thời lượng {capture.duration_s:.3f} giây · "
               f"trích xuất đặc trưng {analysis.extraction_s:.3f} giây · suy luận {rows.inference_ms.sum():.3f} ms")
    left, right = st.columns(2)
    choice = left.selectbox("Lọc theo kết luận", ["All", *VERDICTS],
                            format_func=lambda value: VERDICTS.get(value, "Tất cả"))
    labels = right.multiselect("Lọc theo lớp", engine.config.classes if engine else rows.prediction.unique(),
                               format_func=TRAFFIC_CLASSES.get, placeholder="Chọn lớp")
    filtered = rows
    if choice != "All":
        filtered = filtered.loc[filtered.binary_prediction == choice]
    if labels:
        filtered = filtered.loc[filtered.prediction.isin(labels)]
    if filtered.empty:
        empty_state("Không có cửa sổ phù hợp", "Đổi bộ lọc kết luận hoặc lớp để xem kết quả khác.")
    else:
        st.subheader("Diễn biến phát hiện")
        timeline(filtered, "analysis_timeline")
        st.subheader("Đặc trưng lưu lượng")
        feature = st.selectbox("Đặc trưng", FEATURES,
                               format_func=lambda value: f"{value.upper()} · {FEATURE_LABELS[value]}",
                               label_visibility="collapsed")
        feature_chart(filtered, feature, "analysis_features")
        st.subheader("Kết quả theo cửa sổ")
        events(filtered, count=len(filtered))
        with st.expander("Xem chi tiết một cửa sổ"):
            key = st.selectbox("Mã cửa sổ", filtered.window_id.tolist(), key="analysis_window")
            detail = filtered.loc[filtered.window_id == key].iloc[0].copy()
            detail["binary_prediction"] = VERDICTS[detail["binary_prediction"]]
            detail["prediction"] = TRAFFIC_CLASSES[detail["prediction"]]
            detail["qae_alert"] = "Có" if detail["qae_alert"] else "Không"
            detail = detail.rename(index=TRAFFIC_COLUMNS).astype(str)
            st.dataframe(detail.to_frame("Giá trị"), width="stretch")
    st.download_button("Tải toàn bộ kết quả CSV", analysis.csv_bytes(), f"{Path(name).stem}-results.csv",
                       "text/csv", on_click="ignore")


def replay_page(engine, error):
    page_header("MÔ PHỎNG NGOẠI TUYẾN", "Phát lại PCAP",
                "Chạy mô hình phát hiện theo mốc thời gian của file PCAP đã ghi.")
    if engine is None:
        model_info(engine, error)
        return
    speed = st.select_slider("Tốc độ phát lại", options=[.25, .5, 1., 2., 4., 8., 16.], value=1.,
                             format_func=lambda value: f"{value:g}×")
    source, identifier = capture_source("replay")
    replay = st.session_state.get("replay")
    if replay and st.session_state.get("replay_id") != identifier and source is not None:
        replay.stop()
        replay = None
    active = replay is not None and replay.state in ("running", "paused")
    if st.button("Bắt đầu", type="primary", disabled=source is None or active):
        progress = st.progress(0., text="Đang đọc cửa sổ để phát lại")
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
            st.session_state.replay_saved = None, 0
        finally:
            progress.empty()
    if replay is None:
        if source is None:
            empty_state("Chưa phát lại", "Chọn file PCAP trong thư viện demo hoặc tải file lên để bắt đầu.")
        return

    @st.fragment(run_every=.4 if replay.state == "running" else None)
    def replay_controls():
        left, middle, right = st.columns(3)
        pause = left.button("Tạm dừng", disabled=replay.state != "running")
        resume = middle.button("Tiếp tục", disabled=replay.state != "paused")
        stop = right.button("Dừng", disabled=replay.state not in ("running", "paused"))
        original = replay.state
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
        run_id, saved_count = st.session_state.get("replay_saved", (None, 0))
        if len(rows) > saved_count:
            try:
                run_id = save_windows(replay.name, "replay", replay.capture.packets, elapsed,
                                      rows.iloc[saved_count:], run_id=run_id, offset=saved_count)
            except (OSError, ValueError, sqlite3.Error) as exc:
                st.error(f"Không lưu được cửa sổ phát lại vào bảng điều khiển. {exc}")
            else:
                st.session_state.replay_saved = run_id, len(rows)
        if replay.state != original:
            st.rerun()
        st.progress(len(rows) / len(replay.capture.windows),
                    text=f"{replay.name} · {REPLAY_STATES[replay.state]} · {replay.position_s:.1f} giây · "
                         f"{len(rows)}/{len(replay.capture.windows)} cửa sổ")
        if not rows.empty:
            timeline(rows, "replay_timeline")
            st.subheader("Kết quả theo cửa sổ phát lại")
            events(rows, count=25)

    replay_controls()
