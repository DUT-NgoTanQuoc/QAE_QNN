import streamlit as st

from core.model_loader import ModelLoadError, load_model
from pages.research import about_page, benchmark_page, evaluation_page
from pages.traffic import analysis_page, dashboard, replay_page


def main():
    st.set_page_config(page_title="QAE-QNN IDS", layout="wide")
    st.markdown("""
<style>
.block-container { max-width: 1400px; padding-top: 2.25rem; }
[data-testid="stSidebar"] { border-right: 1px solid #23374e; }
[data-testid="stMetric"] { background: #101f33; border-color: #263b54; }
[data-testid="stMetricLabel"] { color: #b5c8da; }
[data-testid="stCaptionContainer"] { color: #a3bad0; }
@media (max-width: 640px) {
    .block-container { padding-top: 2rem; padding-left: 1rem; padding-right: 1rem; }
}
</style>
""", unsafe_allow_html=True)
    st.sidebar.title("QAE-QNN IDS")
    page = st.sidebar.radio("Điều hướng", [
        "Dashboard", "PCAP Analysis", "PCAP Replay", "Benchmark Research", "Model Evaluation", "About",
    ])
    st.title("QAE-QNN IDS")
    st.caption("Hybrid Quantum DDoS Detection System")
    if page in ("Dashboard", "PCAP Analysis", "PCAP Replay"):
        engine, error = None, None
        try:
            engine = load_model()
        except ModelLoadError as exc:
            error = str(exc)
        views = {"Dashboard": dashboard, "PCAP Analysis": analysis_page, "PCAP Replay": replay_page}
        views[page](engine, error)
    else:
        views = {"Benchmark Research": benchmark_page, "Model Evaluation": evaluation_page, "About": about_page}
        views[page]()


if __name__ == "__main__":
    main()
