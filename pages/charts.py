import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

COLORS = {"Benign": "#46D6A0", "Attack": "#FF7288"}
PALETTE = ["#29D4E5", "#8FABFF", "#46D6A0", "#FFA873", "#FF7288", "#B991FF"]


def plot(figure, key, height=310):
    figure.update_layout(
        height=height,
        margin=dict(l=12, r=12, t=28, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#E8F1FB",
        font_family="Inter, Segoe UI, sans-serif",
        hoverlabel=dict(bgcolor="#0E2033", bordercolor="#2A4A62", font_color="#E8F1FB"),
        legend_title_text="",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    figure.update_xaxes(gridcolor="#193047", zerolinecolor="#193047", linecolor="#28445B")
    figure.update_yaxes(gridcolor="#193047", zerolinecolor="#193047", linecolor="#28445B")
    st.plotly_chart(figure, theme=None, key=key, width="stretch")


def timeline(rows, key):
    figure = px.bar(
        rows, x="window_start_s", y="packet_count", color="binary_prediction",
        color_discrete_map=COLORS, opacity=.92,
        labels={"window_start_s": "Capture time (s)", "packet_count": "Packets"},
        hover_data={"window_id": True, "prediction": True, "attack_probability": ":.3f",
                    "qae_alert": True, "window_start_s": ":.1f"},
    )
    figure.update_traces(marker_line_width=0)
    plot(figure, key)


def risk_gauge(attack_ratio, key):
    color = COLORS["Attack"] if attack_ratio > 0 else COLORS["Benign"]
    figure = go.Figure(go.Indicator(
        mode="gauge+number",
        value=attack_ratio * 100,
        number={"suffix": "%", "font": {"size": 36, "color": "#E8F1FB"}},
        title={"text": "Attack windows", "font": {"size": 14, "color": "#8EA6BA"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#8EA6BA"},
            "bar": {"color": color, "thickness": .28},
            "bgcolor": "#0B1929",
            "bordercolor": "#1D3850",
            "steps": [{"range": [0, 100], "color": "#102238"}],
        },
    ))
    plot(figure, key, height=270)


def events(rows, count=10):
    table = rows.tail(count).iloc[::-1].loc[:, [
        "window_start_s", "packet_count", "binary_prediction", "prediction",
        "attack_probability", "qae_alert",
    ]].rename(columns={
        "window_start_s": "Time (s)",
        "packet_count": "Packets",
        "binary_prediction": "Verdict",
        "prediction": "Class",
        "attack_probability": "Attack probability",
        "qae_alert": "QAE alert",
    })
    st.dataframe(
        table,
        hide_index=True,
        width="stretch",
        column_config={
            "Attack probability": st.column_config.ProgressColumn(
                "Attack probability", min_value=0., max_value=1., format="%.1%%"
            ),
            "QAE alert": st.column_config.CheckboxColumn("QAE alert"),
        },
    )
