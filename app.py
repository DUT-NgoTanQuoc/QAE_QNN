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
                        '<div class="soc-sidebar-sub">Phát hiện DDoS bằng mô hình lượng tử lai</div>',
                        unsafe_allow_html=True)
    traffic_views = {"Bảng điều khiển": dashboard, "Phân tích PCAP": analysis_page,
                     "Phát lại PCAP": replay_page}
    research_views = {"Kết quả thực nghiệm": benchmark_page, "Đánh giá mô hình": evaluation_page,
                      "Giới thiệu": about_page}
    page = st.sidebar.radio("Điều hướng", [*traffic_views, *research_views], label_visibility="collapsed")
    st.sidebar.markdown("---")
    st.sidebar.markdown('<div class="soc-status"><strong>Phân tích PCAP ngoại tuyến</strong><br>'
                        'Suy luận trên CPU · Cửa sổ 5 giây</div>', unsafe_allow_html=True)
    if page in traffic_views:
        engine, error = None, None
        try:
            engine = load_model()
        except ModelLoadError as exc:
            error = str(exc)
        traffic_views[page](engine, error)
    else:
        research_views[page]()


if __name__ == "__main__":
    main()
