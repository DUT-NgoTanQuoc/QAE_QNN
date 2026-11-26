import json

import pandas as pd
import plotly.express as px
import streamlit as st

from core.config import CLASSES, MODEL_DIR, RESULTS, ModelConfig
from core.evaluation import evaluate_predictions, exported_demo_predictions
from pages.charts import PALETTE, TRAFFIC_CLASSES, TRAFFIC_COLUMNS, plot
from pages.ui import page_header, panel, pills

BENCHMARK = RESULTS / "benchmark"
PCAP = RESULTS / "pcap"
METRICS = {
    "accuracy": "Độ chính xác",
    "macro_precision": "Độ chuẩn xác trung bình theo lớp",
    "macro_recall": "Độ bao phủ trung bình theo lớp",
    "macro_f1": "F1 trung bình theo lớp",
    "auc": "ROC AUC",
    "recall": "Độ bao phủ",
    "fpr": "Tỷ lệ dương tính giả",
    "f1": "F1",
    "seconds": "Thời gian (giây)",
}
TASKS = {"anomaly": "Phát hiện bất thường", "classification": "Phân loại"}
RESEARCH_COLUMNS = {
    **TRAFFIC_COLUMNS, **METRICS,
    "model": "Mô hình", "version": "Phiên bản", "seed": "Hạt giống ngẫu nhiên",
    "fold": "Phần chia", "folds": "Số phần chia", "data_hash": "Mã băm dữ liệu",
    "dataset": "Tập dữ liệu", "variant": "Biến thể", "task": "Tác vụ", "group": "Thành phần",
    "depth": "Độ sâu", "anchor": "Biên độ neo", "threshold": "Ngưỡng", "epoch": "Vòng huấn luyện",
    "balanced_accuracy": "Độ chính xác cân bằng", "weighted_f1": "F1 có trọng số",
    "binary_f1": "F1 nhị phân", "binary_auc": "AUC nhị phân",
    "file": "Tên file", "label": "Nhãn thực",
}


def benchmark_page():
    page_header("NGHIÊN CỨU", "Kết quả thực nghiệm",
                "Xem kết quả đã xuất của V2, V4 và các thí nghiệm loại bỏ thành phần.")
    pills("3 tập dữ liệu", "2 phần chia kiểm thử", "Hạt giống ngẫu nhiên 42")
    source = st.selectbox("Bộ kết quả", ["Tổng hợp cuối", "Bản cơ sở V2", "Bản cải tiến V4"])
    folder = {"Tổng hợp cuối": "final", "Bản cơ sở V2": "baseline", "Bản cải tiến V4": "improved"}[source]
    path = BENCHMARK / folder / "all_metrics.csv"
    try:
        data = pd.read_csv(path)
        paired = pd.read_csv(BENCHMARK / "final" / "paired_comparison.csv")
    except (OSError, ValueError) as exc:
        st.error(f"Không đọc được kết quả thực nghiệm. {exc}")
        return
    if "version" not in data:
        data["version"] = "V2" if folder == "baseline" else "V4"
    controls = st.columns(3)
    dataset = controls[0].selectbox("Tập dữ liệu", sorted(data.dataset.unique()))
    task = controls[1].selectbox("Tác vụ", sorted(data.loc[data.dataset == dataset, "task"].unique()),
                                 format_func=lambda value: TASKS.get(value, value))
    rows = data.loc[(data.dataset == dataset) & (data.task == task)]
    metrics = [key for key in METRICS if key in rows and rows[key].notna().any()]
    preferred = "auc" if task == "anomaly" else "macro_f1"
    metric = controls[2].selectbox("Chỉ số", metrics, index=metrics.index(preferred), format_func=METRICS.get)
    st.caption(f"Nguồn results/benchmark/{folder}/all_metrics.csv · hạt giống ngẫu nhiên 42 · hai phần chia")
    summary = rows.groupby(["model", "version"], as_index=False).agg(
        mean=(metric, "mean"), std=(metric, "std"), folds=(metric, "count"),
    ).dropna(subset=["mean"])
    st.subheader(f"{dataset} · {METRICS[metric]}")
    plot(px.bar(summary, x="model", y="mean", error_y="std", color="version", barmode="group",
                hover_data=["folds"], color_discrete_sequence=PALETTE,
                labels={**RESEARCH_COLUMNS, "mean": METRICS[metric]}),
         "benchmark_models", height=360)
    with st.expander("Kết quả theo phần chia"):
        st.dataframe(rows.loc[:, ["model", "version", "seed", "fold", "data_hash", *metrics]],
                     hide_index=True, width="stretch", column_config=RESEARCH_COLUMNS)
    st.subheader("So sánh V2 và V4 theo cặp")
    st.caption("V4 tinh chỉnh siêu tham số và dùng tập xác thực nội bộ. Thời gian được đo theo quy trình của từng phiên bản.")
    columns = [f"{metric}_v2", f"{metric}_v4"]
    comparison = paired.loc[(paired.dataset == dataset) & (paired.task == task)]
    if all(key in comparison for key in columns):
        keys = ["model", "fold", *columns]
        if f"delta_{metric}" in comparison:
            keys.append(f"delta_{metric}")
        st.dataframe(comparison[keys].dropna(subset=columns), hide_index=True, width="stretch",
                     column_config={**RESEARCH_COLUMNS, columns[0]: "V2", columns[1]: "V4",
                                    f"delta_{metric}": "Chênh lệch"})
    if (PCAP / "metrics.csv").is_file():
        with st.expander("Chỉ số mô hình trên tập PCAP"):
            st.dataframe(pd.read_csv(PCAP / "metrics.csv"), hide_index=True, width="stretch",
                         column_config=RESEARCH_COLUMNS)


def evaluation_page():
    page_header("ĐÁNH GIÁ", "Đánh giá mô hình",
                "Xem ma trận nhầm lẫn, đường cong ROC và PR cùng kết quả loại bỏ thành phần.")
    performance, ablation = st.tabs(["Ma trận nhầm lẫn / ROC / PR", "Loại bỏ thành phần"])
    with performance:
        _performance()
    with ablation:
        _ablation()
    panel("Phạm vi đánh giá",
          "Nhãn được gán theo file PCAP. Thực nghiệm dùng hai phần chia và hạt giống ngẫu nhiên 42. "
          "V2 và V4 có ngân sách tinh chỉnh siêu tham số khác nhau.")


def _performance():
    original = PCAP / "confusion.png"
    if original.is_file():
        with st.expander("Ma trận nhầm lẫn gốc · toàn bộ tập kiểm thử PCAP"):
            st.image(str(original), caption="Kết quả QAE + QNN xuất từ Colab")
    dataset = st.radio("Tập điểm dự đoán", ["Bốn file demo", "Tập mới · 50 cửa sổ"],
                       horizontal=True)
    try:
        if dataset == "Bốn file demo":
            rows = exported_demo_predictions(PCAP)
            score, threshold = "attack_probability", .5
            scope = "QNN lai · ngưỡng phân loại nhị phân 0,5"
        else:
            rows = pd.read_csv(PCAP / "evaluation_extra" / "novel_predictions.csv")
            score = "anomaly_score"
            threshold = ModelConfig.read(MODEL_DIR / "config.json").threshold
            scope = f"QAE · ngưỡng {threshold:.9g}"
        result = evaluate_predictions(rows, score, threshold)
    except (OSError, ValueError, KeyError) as exc:
        st.error(f"Không đọc được kết quả đánh giá. {exc}")
        return
    st.caption(f"{len(rows)} cửa sổ · {rows.file.nunique()} file PCAP · {scope}.")
    left, right = st.columns([1, 2])
    with left:
        st.subheader("Ma trận nhầm lẫn đa lớp")
        class_names = [TRAFFIC_CLASSES[label] for label in CLASSES]
        plot(px.imshow(result["matrix"], x=class_names, y=class_names, text_auto=True,
                       color_continuous_scale=["#101F33", "#23AEC5"],
                       labels={"x": "Dự đoán", "y": "Nhãn thực", "color": "Cửa sổ"}),
             "evaluation_matrix")
    with right:
        roc, pr = st.tabs(["Đường cong ROC", "Đường cong chuẩn xác – bao phủ"])
        with roc:
            plot(px.line(result["roc"], x="FPR", y="TPR", color_discrete_sequence=PALETTE,
                         labels={"FPR": "Tỷ lệ dương tính giả", "TPR": "Tỷ lệ dương tính thật"}),
                 "evaluation_roc")
        with pr:
            plot(px.line(result["pr"], x="Recall", y="Precision", color_discrete_sequence=PALETTE,
                         labels={"Recall": "Độ bao phủ", "Precision": "Độ chuẩn xác"}),
                 "evaluation_pr")
    for name, field in [("Dương tính giả", "false_positives"), ("Âm tính giả", "false_negatives")]:
        errors = result[field]
        with st.expander(f"{name} · {len(errors)}"):
            if errors.empty:
                st.write("Không có cửa sổ thuộc nhóm này trong tập đang chọn.")
            else:
                display = errors[["file", "window_start_s", "label", "prediction", score]].replace(
                    {"label": TRAFFIC_CLASSES, "prediction": TRAFFIC_CLASSES}
                )
                st.dataframe(display, hide_index=True, column_config=RESEARCH_COLUMNS)


def _ablation():
    try:
        ablation = pd.read_csv(BENCHMARK / "final" / "all_ablation.csv")
    except (OSError, ValueError) as exc:
        st.error(f"Không đọc được kết quả loại bỏ thành phần. {exc}")
        return
    groups = {"anchor": "Biên độ neo", "qae_depth": "Độ sâu QAE",
              "fusion": "Kết hợp đặc trưng", "early_stopping": "Dừng sớm"}
    group = st.selectbox("Thành phần", [key for key in groups if key in set(ablation.group)],
                         format_func=groups.get)
    rows = ablation.loc[ablation.group == group]
    metric = "auc" if group in ("anchor", "qae_depth") else "macro_f1"
    summary = rows.groupby(["dataset", "variant"], as_index=False).agg(
        mean=(metric, "mean"), std=(metric, "std"), folds=(metric, "count"),
    )
    plot(px.bar(summary, x="dataset", y="mean", error_y="std", color="variant", barmode="group",
                color_discrete_sequence=PALETTE, hover_data=["folds"],
                labels={**RESEARCH_COLUMNS, "mean": METRICS[metric]}),
         "ablation_chart")
    display = rows.replace({"group": groups, "task": TASKS}).dropna(axis=1, how="all")
    st.dataframe(display, hide_index=True, width="stretch", column_config=RESEARCH_COLUMNS)
    st.caption("Nguồn results/benchmark/final/all_ablation.csv · phân tích khám phá trên tập kiểm thử vòng ngoài.")


def about_page():
    page_header("HỆ THỐNG", "Giới thiệu QAE-QNN IDS",
                "Giao diện nghiên cứu phát hiện DDoS ngoại tuyến bằng mô hình lượng tử kết hợp cổ điển.")
    pills("PCAP ngoại tuyến", "Mô phỏng trên CPU", "QAE + QNN")
    st.markdown("""
QAE-QNN IDS nghiên cứu phát hiện DDoS theo từng cửa sổ của file PCAP.

**Kiến trúc**

PCAP / PCAPNG → cửa sổ 5 giây → f1–f6 → log1p và bộ chuẩn hóa đã huấn luyện → QAE + VQNN → dự đoán.

QAE mã hóa biên độ trên 3 qubit, áp dụng RX, RY, RZ và CX rồi đo xác suất của qubit phụ
và bốn xác suất biên. VQNN mã hóa sáu đặc trưng bằng Ry, dùng hai lớp Ry/CX đã học
và đưa tám xác suất đo cùng năm đặc trưng QAE vào đầu phân loại tuyến tính.
Softmax cho bốn lớp Bình thường, SYN, HTTP và UDP.

Hai mạch chạy bằng mô phỏng statevector trên CPU cổ điển.
""")
    st.subheader("Đặc trưng đầu vào")
    st.table(pd.DataFrame({
        "Đặc trưng": ["f1", "f2", "f3", "f4", "f5", "f6"],
        "Định nghĩa": [
            "Tổng số gói",
            "Số TCP flags = 2 / max(số TCP flags = 18, 1)",
            "Số địa chỉ IPv4 nguồn phân biệt",
            "Số gói TCP chứa GET/POST lớn nhất theo nguồn IPv4",
            "Entropy nguồn IPv4 với mẫu số là tổng số gói",
            "Số gói UDP",
        ],
    }))
    st.subheader("Môi trường thực nghiệm")
    try:
        versions = json.loads((MODEL_DIR / "environment.json").read_text(encoding="utf-8"))
        st.dataframe(pd.DataFrame(versions.items(), columns=["Thư viện", "Phiên bản"]), hide_index=True)
    except (OSError, ValueError) as exc:
        st.warning(f"Không đọc được thông tin môi trường. {exc}")
    st.markdown("""
**Giới hạn**

Dữ liệu PCAP tổng hợp dùng nhãn theo file. Quy tắc cửa sổ bỏ phần đuôi chưa đủ 5 giây
và các cửa sổ trống. Softmax chưa được đánh giá hiệu chuẩn trên mạng thực.
Kết quả thực nghiệm dựa trên hai phần chia và một hạt giống ngẫu nhiên.

**Tài liệu tham khảo**

[Dataset Zenodo](https://zenodo.org/records/21705919) ·
[Qiskit Quantum Information](https://qiskit.qotlabs.org/docs/api/qiskit/quantum_info) ·
[PyTorch](https://pytorch.org/get-started/previous-versions/).
""")
