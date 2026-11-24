import json

import pandas as pd
import plotly.express as px
import streamlit as st

from core.config import CLASSES, MODEL_DIR, RESULTS, ModelConfig
from core.evaluation import evaluate_predictions, exported_demo_predictions
from pages.charts import PALETTE, plot
from pages.ui import page_header, panel, pills

BENCHMARK = RESULTS / "benchmark"
PCAP = RESULTS / "pcap"
METRICS = {
    "accuracy": "Accuracy",
    "macro_precision": "Macro precision",
    "macro_recall": "Macro recall",
    "macro_f1": "Macro F1",
    "auc": "ROC AUC",
    "recall": "Recall",
    "fpr": "FPR",
    "f1": "F1",
    "seconds": "Thời gian nghiên cứu (s)",
}


def benchmark_page():
    page_header("RESEARCH EVIDENCE", "Benchmark Research",
                "Inspect exported V2, V4 and ablation results without retraining or synthetic dashboard values.")
    pills("3 DATASETS", "2 OUTER FOLDS", "SEED 42", "EXPORTED ARTIFACTS")
    source = st.selectbox("Result collection", ["Tổng hợp cuối", "Baseline V2", "Improved V4"])
    folder = {"Tổng hợp cuối": "final", "Baseline V2": "baseline", "Improved V4": "improved"}[source]
    path = BENCHMARK / folder / "all_metrics.csv"
    try:
        data = pd.read_csv(path)
        paired = pd.read_csv(BENCHMARK / "final" / "paired_comparison.csv")
    except (OSError, ValueError) as exc:
        st.error(f"Không đọc được benchmark: {exc}")
        return
    if "version" not in data:
        data["version"] = "V2" if folder == "baseline" else "V4"
    controls = st.columns(3)
    dataset = controls[0].selectbox("Dataset", sorted(data.dataset.unique()))
    task = controls[1].selectbox("Task", sorted(data.loc[data.dataset == dataset, "task"].unique()))
    rows = data.loc[(data.dataset == dataset) & (data.task == task)]
    metrics = [key for key in METRICS if key in rows and rows[key].notna().any()]
    preferred = "auc" if task == "anomaly" else "macro_f1"
    metric = controls[2].selectbox("Metric", metrics, index=metrics.index(preferred), format_func=METRICS.get)
    st.caption(f"Nguồn results/benchmark/{folder}/all_metrics.csv · seed 42 · hai fold")
    summary = rows.groupby(["model", "version"], as_index=False).agg(
        mean=(metric, "mean"), std=(metric, "std"), folds=(metric, "count"),
    ).dropna(subset=["mean"])
    st.subheader(f"{dataset} · {METRICS[metric]}")
    plot(px.bar(summary, x="model", y="mean", error_y="std", color="version", barmode="group",
                hover_data=["folds"], color_discrete_sequence=PALETTE, labels={"mean": METRICS[metric]}),
         "benchmark_models", height=360)
    with st.expander("Fold-level evidence"):
        st.dataframe(rows.loc[:, ["model", "version", "seed", "fold", "data_hash", *metrics]],
                     hide_index=True, width="stretch")
    st.subheader("Paired V2 / V4 comparison")
    st.caption("V4 có thêm tuning và dùng inner validation. Cột seconds đo theo giao thức của từng phiên bản.")
    columns = [f"{metric}_v2", f"{metric}_v4"]
    comparison = paired.loc[(paired.dataset == dataset) & (paired.task == task)]
    if all(key in comparison for key in columns):
        keys = ["model", "fold", *columns]
        if f"delta_{metric}" in comparison:
            keys.append(f"delta_{metric}")
        st.dataframe(comparison[keys].dropna(subset=columns), hide_index=True, width="stretch")
    if (PCAP / "metrics.csv").is_file():
        with st.expander("PCAP model metrics"):
            st.dataframe(pd.read_csv(PCAP / "metrics.csv"), hide_index=True, width="stretch")


def evaluation_page():
    page_header("MODEL ASSURANCE", "Model Evaluation",
                "Review confusion, ranking curves, error cases and ablation results from exported research artifacts.")
    performance, ablation = st.tabs(["Confusion / ROC / PR", "Ablation Study"])
    with performance:
        _performance()
    with ablation:
        _ablation()
    panel("Evaluation scope",
          "PCAP labels are capture-level. Benchmark results use two folds and seed 42. V2 and V4 use different tuning budgets.")


def _performance():
    original = PCAP / "confusion.png"
    if original.is_file():
        with st.expander("Confusion matrix gốc · toàn bộ test PCAP"):
            st.image(str(original), caption="Export Colab của QAE+QNN")
    dataset = st.radio("Exported score set", ["Bốn capture demo", "Novel · 50 cửa sổ"],
                       horizontal=True)
    try:
        if dataset == "Bốn capture demo":
            rows = exported_demo_predictions(PCAP)
            score, threshold = "attack_probability", .5
            scope = "Hybrid QNN · ngưỡng binary 0,5"
        else:
            rows = pd.read_csv(PCAP / "evaluation_extra" / "novel_predictions.csv")
            score = "anomaly_score"
            threshold = ModelConfig.read(MODEL_DIR / "config.json").threshold
            scope = f"QAE · ngưỡng {threshold:.9g}"
        result = evaluate_predictions(rows, score, threshold)
    except (OSError, ValueError, KeyError) as exc:
        st.error(f"Không đọc được kết quả đánh giá: {exc}")
        return
    st.caption(f"{len(rows)} cửa sổ · {rows.file.nunique()} capture · {scope}. "
               "ROC, PR và FP/FN tính từ điểm tương ứng của tập đang chọn.")
    left, right = st.columns([1, 2])
    with left:
        st.subheader("Multiclass confusion")
        plot(px.imshow(result["matrix"], x=CLASSES, y=CLASSES, text_auto=True,
                       color_continuous_scale=["#101F33", "#23AEC5"],
                       labels={"x": "Dự đoán", "y": "Nhãn thực", "color": "Cửa sổ"}),
             "evaluation_matrix")
    with right:
        roc, pr = st.tabs(["ROC Curve", "Precision–Recall Curve"])
        with roc:
            plot(px.line(result["roc"], x="FPR", y="TPR", color_discrete_sequence=PALETTE),
                 "evaluation_roc")
        with pr:
            plot(px.line(result["pr"], x="Recall", y="Precision", color_discrete_sequence=PALETTE),
                 "evaluation_pr")
    for name, field in [("False positives", "false_positives"), ("False negatives", "false_negatives")]:
        errors = result[field]
        with st.expander(f"{name} · {len(errors)}"):
            if errors.empty:
                st.write("Không có cửa sổ thuộc nhóm này trong tập đang chọn.")
            else:
                st.dataframe(errors[["file", "window_start_s", "label", "prediction", score]], hide_index=True)


def _ablation():
    try:
        ablation = pd.read_csv(BENCHMARK / "final" / "all_ablation.csv")
    except (OSError, ValueError) as exc:
        st.error(f"Không đọc được ablation: {exc}")
        return
    groups = {"anchor": "Biên độ neo", "qae_depth": "Độ sâu QAE",
              "fusion": "Feature fusion", "early_stopping": "Early stopping"}
    group = st.selectbox("Component", [key for key in groups if key in set(ablation.group)],
                         format_func=groups.get)
    rows = ablation.loc[ablation.group == group]
    metric = "auc" if group in ("anchor", "qae_depth") else "macro_f1"
    summary = rows.groupby(["dataset", "variant"], as_index=False).agg(
        mean=(metric, "mean"), std=(metric, "std"), folds=(metric, "count"),
    )
    plot(px.bar(summary, x="dataset", y="mean", error_y="std", color="variant", barmode="group",
                color_discrete_sequence=PALETTE, hover_data=["folds"], labels={"mean": METRICS[metric]}),
         "ablation_chart")
    st.dataframe(rows.dropna(axis=1, how="all"), hide_index=True, width="stretch")
    st.caption("Nguồn results/benchmark/final/all_ablation.csv · phân tích khám phá trên outer test.")


def about_page():
    page_header("SYSTEM CONTEXT", "About QAE-QNN IDS",
                "A reproducible research interface for offline DDoS detection with a quantum-classical pipeline.")
    pills("OFFLINE PCAP", "CPU SIMULATION", "QAE + QNN", "NO RETRAINING")
    st.markdown("""
QAE-QNN IDS nghiên cứu phát hiện DDoS theo từng cửa sổ của capture offline.

**Kiến trúc**

PCAP / PCAPNG → cửa sổ 5 giây → f1–f6 → log1p và scaler đã fit → QAE + VQNN → dự đoán.

QAE mã hóa biên độ trên 3 qubit, áp dụng RX, RY, RZ và CX rồi đo xác suất của qubit trash
và bốn xác suất biên. VQNN mã hóa sáu feature bằng Ry, dùng hai layer Ry/CX học được
và đưa tám xác suất đo cùng năm đặc trưng QAE vào đầu phân loại tuyến tính.
Softmax cho bốn lớp Normal, SYN, HTTP và UDP.

Hai mạch chạy bằng mô phỏng statevector trên CPU cổ điển.
""")
    st.subheader("Input features")
    st.table(pd.DataFrame({
        "Feature": ["f1", "f2", "f3", "f4", "f5", "f6"],
        "Definition": [
            "Tổng số gói",
            "Số TCP flags = 2 / max(số TCP flags = 18, 1)",
            "Số địa chỉ IPv4 nguồn phân biệt",
            "Số gói TCP chứa GET/POST lớn nhất theo nguồn IPv4",
            "Entropy nguồn IPv4 với mẫu số là tổng số gói",
            "Số gói UDP",
        ],
    }))
    st.subheader("Recorded experiment environment")
    try:
        versions = json.loads((MODEL_DIR / "environment.json").read_text(encoding="utf-8"))
        st.dataframe(pd.DataFrame(versions.items(), columns=["Thư viện", "Phiên bản"]), hide_index=True)
    except (OSError, ValueError) as exc:
        st.warning(f"Không đọc được metadata môi trường: {exc}")
    st.markdown("""
**Giới hạn**

Dữ liệu PCAP tổng hợp dùng nhãn cấp capture. Quy tắc cửa sổ bỏ phần đuôi chưa đủ 5 giây
và các cửa sổ trống. Softmax chưa được đánh giá hiệu chuẩn trên mạng thực.
Kết quả benchmark mô tả thí nghiệm với hai fold và một seed.

**Tài liệu tham khảo**

[Dataset Zenodo](https://zenodo.org/records/21705919) ·
[Qiskit Quantum Information](https://qiskit.qotlabs.org/docs/api/qiskit/quantum_info) ·
[PyTorch](https://pytorch.org/get-started/previous-versions/).
""")
