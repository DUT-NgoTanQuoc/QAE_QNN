import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

VERDICTS = {"Benign": "Bình thường", "Attack": "Tấn công"}
TRAFFIC_CLASSES = {"Normal": "Bình thường", "SYN": "SYN", "HTTP": "HTTP", "UDP": "UDP"}
COLORS = {VERDICTS["Benign"]: "#46D6A0", VERDICTS["Attack"]: "#FF7288"}
PALETTE = ["#29D4E5", "#8FABFF", "#46D6A0", "#FFA873", "#FF7288", "#B991FF"]
FEATURE_LABELS = {
    "f1": "Số gói tin",
    "f2": "Tỷ lệ SYN/SYN-ACK",
    "f3": "Số IPv4 nguồn",
    "f4": "Số gói GET/POST tối đa",
    "f5": "Entropy IPv4 nguồn",
    "f6": "Số gói UDP",
}
TRAFFIC_COLUMNS = {
    "window_id": "Mã cửa sổ",
    "window_start_s": "Bắt đầu (giây)",
    "window_end_s": "Kết thúc (giây)",
    "packet_count": "Số gói tin",
    "binary_prediction": "Kết luận",
    "prediction": "Lớp dự đoán",
    "attack_probability": "Xác suất tấn công",
    "qae_alert": "Cảnh báo QAE",
    "anomaly_score": "Điểm bất thường",
    "confidence": "Độ tin cậy",
    "inference_ms": "Thời gian suy luận (ms)",
}


def plot(figure, key, height=360):
    has_axes = any(hasattr(trace, "xaxis") for trace in figure.data)
    has_legend = figure.layout.showlegend is not False and any(
        trace.type == "pie" or getattr(trace, "showlegend", False) for trace in figure.data
    )
    figure.update_layout(
        height=height,
        margin=dict(l=76 if has_axes else 28, r=28, t=72 if has_legend else 44,
                    b=68 if has_axes else 30),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#E8F1FB",
        font_family="Inter, Segoe UI, sans-serif",
        hoverlabel=dict(bgcolor="#0E2033", bordercolor="#365871", font_color="#E8F1FB", align="left"),
        modebar=dict(bgcolor="#0B1929", color="#A0B5C9", activecolor="#2BD4E6"),
        barcornerradius=4,
        legend_title_text="",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0,
                    font=dict(color="#D3E2EF", size=12)),
    )
    axis_style = dict(automargin=True, title_standoff=14, ticks="outside", ticklen=4,
                      tickfont=dict(color="#AFC3D5", size=12), tickcolor="#36536D",
                      gridcolor="#21374B", zerolinecolor="#36536D", linecolor="#36536D")
    figure.update_xaxes(**axis_style, showgrid=False)
    figure.update_yaxes(**axis_style, showgrid=True)
    st.plotly_chart(figure, theme=None, key=key, width="stretch", config={"displaylogo": False})


def timeline(rows, key):
    display = rows.assign(
        binary_prediction=rows.binary_prediction.replace(VERDICTS),
        prediction=rows.prediction.replace(TRAFFIC_CLASSES),
        qae_alert=rows.qae_alert.map({True: "Có", False: "Không"}),
    )
    figure = px.bar(
        display, x="window_start_s", y="packet_count", color="binary_prediction",
        color_discrete_map=COLORS, opacity=.9,
        labels=TRAFFIC_COLUMNS,
        hover_data={"window_id": True, "prediction": True, "attack_probability": ":.1%",
                    "qae_alert": True, "window_start_s": ":.1f", "packet_count": ":,d"},
    )
    window_width = display.window_end_s.iloc[0] - display.window_start_s.iloc[0]
    figure.update_traces(width=.72 * window_width, marker_line_width=0)
    figure.update_yaxes(rangemode="tozero")
    plot(figure, key)


def feature_chart(rows, feature, key):
    figure = px.line(
        rows, x="window_start_s", y=feature, markers=True, color_discrete_sequence=PALETTE,
        labels={"window_start_s": "Thời điểm trong file (giây)", feature: FEATURE_LABELS[feature]},
        hover_data={"window_start_s": ":.1f", feature: ":.4~g"},
    )
    figure.update_traces(line_width=2.5, marker=dict(size=7, line=dict(color="#0B1929", width=1.5)))
    plot(figure, key)


def risk_gauge(attack_ratio, key):
    color = COLORS[VERDICTS["Attack" if attack_ratio > 0 else "Benign"]]
    figure = go.Figure(go.Indicator(
        mode="gauge+number",
        value=attack_ratio * 100,
        number={"suffix": "%", "font": {"size": 36, "color": "#E8F1FB"}},
        title={"text": "Cửa sổ tấn công", "font": {"size": 14, "color": "#8EA6BA"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#8EA6BA"},
            "bar": {"color": color, "thickness": .28},
            "bgcolor": "#0B1929",
            "bordercolor": "#1D3850",
            "steps": [{"range": [0, 100], "color": "#102238"}],
        },
    ))
    plot(figure, key)


def events(rows, count=10):
    table = rows.tail(count).iloc[::-1].loc[:, [
        "window_start_s", "packet_count", "binary_prediction", "prediction",
        "attack_probability", "qae_alert",
    ]].replace({"binary_prediction": VERDICTS, "prediction": TRAFFIC_CLASSES})
    st.dataframe(
        table,
        hide_index=True,
        width="stretch",
        column_config={
            **TRAFFIC_COLUMNS,
            "attack_probability": st.column_config.ProgressColumn(
                TRAFFIC_COLUMNS["attack_probability"], min_value=0., max_value=1., format="%.1%%"
            ),
            "qae_alert": st.column_config.CheckboxColumn(TRAFFIC_COLUMNS["qae_alert"]),
        },
    )
