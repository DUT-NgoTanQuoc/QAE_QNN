import plotly.express as px
import streamlit as st

COLORS = {"Benign": "#46D6A0", "Attack": "#FF7288"}
PALETTE = ["#29D4E5", "#8FABFF", "#46D6A0", "#FFA873", "#FF7288", "#B991FF"]


def plot(figure, key, height=310):
    figure.update_layout(
        height=height,
        margin=dict(l=8, r=8, t=24, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#E8F1FB",
        legend_title_text="",
    )
    figure.update_xaxes(gridcolor="#203248")
    figure.update_yaxes(gridcolor="#203248")
    st.plotly_chart(figure, theme=None, key=key, width="stretch")


def timeline(rows, key):
    st.markdown("**Timeline cửa sổ**")
    plot(px.bar(
        rows, x="window_start_s", y="packet_count", color="binary_prediction",
        color_discrete_map=COLORS,
        labels={"window_start_s": "Mốc capture (giây)", "packet_count": "Số gói"},
        hover_data=["window_id", "prediction", "attack_probability", "qae_alert"],
    ), key)


def events(rows, count=10):
    fields = ["window_start_s", "binary_prediction", "prediction", "attack_probability", "qae_alert"]
    st.dataframe(rows.tail(count).iloc[::-1].loc[:, fields], hide_index=True, width="stretch")
