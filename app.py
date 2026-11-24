import streamlit as st

from core.model_loader import ModelLoadError, load_model
from pages.research import about_page, benchmark_page, evaluation_page
from pages.traffic import analysis_page, dashboard, replay_page
from pages.ui import APP_CSS


def main():
    st.set_page_config(page_title="QAE-QNN IDS", page_icon="🛡️", layout="wide",
                       initial_sidebar_state="auto")
    st.markdown(APP_CSS, unsafe_allow_html=True)
    st.sidebar.markdown('<div class="soc-sidebar-brand">QAE-QNN IDS</div>'
                        '<div class="soc-sidebar-sub">Hybrid Quantum DDoS Detection</div>',
                        unsafe_allow_html=True)
    page = st.sidebar.radio("Navigation", [
        "Dashboard", "PCAP Analysis", "PCAP Replay", "Benchmark Research", "Model Evaluation", "About",
    ], label_visibility="collapsed")
    st.sidebar.markdown("---")
    st.sidebar.markdown('<div class="soc-status"><strong>● CPU inference ready</strong><br>'
                        'Offline PCAP analysis<br>5-second windows</div>', unsafe_allow_html=True)
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
