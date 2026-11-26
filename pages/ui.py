import html

import streamlit as st


APP_CSS = """
<style>
:root {
  --soc-bg: #06101d;
  --soc-panel: #0b1929;
  --soc-panel-2: #0e2033;
  --soc-line: #1d3850;
  --soc-muted: #8ea6ba;
  --soc-text: #e7f2fb;
  --soc-cyan: #2bd4e6;
  --soc-green: #39d89f;
  --soc-red: #ff6178;
}

html, body, [class*="css"] { font-family: "Inter", "Segoe UI", sans-serif; }
.stApp {
  background:
    radial-gradient(circle at 82% -10%, rgba(43, 212, 230, .08), transparent 32rem),
    var(--soc-bg);
  color: var(--soc-text);
}
.block-container { max-width: 1480px; padding: 1.35rem 2rem 3rem; }
[data-testid="stSidebar"] {
  background: #071422;
  border-right: 1px solid var(--soc-line);
  min-width: 17rem;
}
[data-testid="stSidebar"] .block-container { padding: 1.25rem 1rem; }
[data-testid="stSidebar"] [role="radiogroup"] label {
  min-height: 2.75rem;
  padding: .55rem .7rem;
  border-radius: .45rem;
}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
  background: rgba(43, 212, 230, .11);
  border: 1px solid rgba(43, 212, 230, .36);
}
h1 { font-size: clamp(1.65rem, 2.5vw, 2.25rem) !important; letter-spacing: -.035em; }
h2 { font-size: clamp(1.25rem, 2vw, 1.55rem) !important; letter-spacing: -.02em; }
h3 { font-size: 1.05rem !important; }
p, li, [data-testid="stMarkdownContainer"] { line-height: 1.55; }
[data-testid="stCaptionContainer"] { color: var(--soc-muted); font-size: .84rem; }
[data-testid="stMetric"] {
  min-height: 7.2rem;
  background: linear-gradient(145deg, rgba(14,32,51,.97), rgba(9,24,40,.97));
  border: 1px solid var(--soc-line);
  border-radius: .65rem;
  padding: 1rem 1.05rem;
  box-shadow: 0 10px 28px rgba(0, 0, 0, .16);
}
[data-testid="stMetricLabel"] { color: #a9bed0; font-size: .85rem; }
[data-testid="stMetricValue"] { color: var(--soc-text); font-variant-numeric: tabular-nums; }
[data-testid="stAlert"] {
  border-radius: .55rem;
  border: 1px solid var(--soc-line);
  background: var(--soc-panel);
}
[data-testid="stDataFrame"], [data-testid="stTable"] {
  border: 1px solid var(--soc-line);
  border-radius: .55rem;
  overflow: hidden;
}
[data-testid="stPlotlyChart"] {
  background: var(--soc-panel);
  border: 1px solid var(--soc-line);
  border-radius: .65rem;
}
.stButton > button, .stDownloadButton > button {
  min-height: 2.7rem;
  border-radius: .45rem;
  border: 1px solid #31516a;
  font-weight: 650;
}
.stButton > button[kind="primary"] {
  background: var(--soc-cyan);
  border-color: var(--soc-cyan);
  color: #04121c;
}
.stTabs [data-baseweb="tab-list"] { gap: .45rem; border-bottom: 1px solid var(--soc-line); }
.stTabs [data-baseweb="tab"] { min-height: 2.8rem; padding: 0 .85rem; }
[data-baseweb="select"] > div, [data-baseweb="input"] > div {
  background: var(--soc-panel);
  border-color: var(--soc-line);
}
.soc-eyebrow {
  color: var(--soc-cyan);
  font-size: .74rem;
  font-weight: 750;
  letter-spacing: .13em;
  text-transform: uppercase;
  margin-bottom: .2rem;
}
.soc-page-title { margin: 0 0 .3rem; font-size: clamp(1.65rem, 3vw, 2.25rem); }
.soc-page-copy { color: var(--soc-muted); max-width: 52rem; margin: 0 0 1.2rem; }
.soc-sidebar-brand {
  color: var(--soc-text);
  font-size: 1.08rem;
  font-weight: 780;
  letter-spacing: -.02em;
}
.soc-sidebar-sub { color: var(--soc-muted); font-size: .78rem; margin: .2rem 0 1.25rem; }
.soc-status {
  border: 1px solid var(--soc-line);
  background: var(--soc-panel);
  border-radius: .6rem;
  padding: .8rem .9rem;
  color: #b8cad8;
  font-size: .82rem;
}
.soc-status strong { color: var(--soc-green); font-size: .86rem; }
.soc-panel {
  background: linear-gradient(145deg, rgba(14,32,51,.92), rgba(8,23,38,.92));
  border: 1px solid var(--soc-line);
  border-radius: .65rem;
  padding: 1rem 1.1rem;
  margin: .2rem 0 1rem;
}
.soc-panel-title { font-size: .86rem; font-weight: 720; color: #cfe0ec; margin-bottom: .35rem; }
.soc-panel-copy { font-size: .86rem; color: var(--soc-muted); line-height: 1.5; }
.soc-empty {
  min-height: 13rem;
  display: grid;
  place-content: center;
  text-align: center;
  border: 1px dashed #2a4c66;
  border-radius: .7rem;
  background: rgba(11,25,41,.58);
  padding: 2rem;
}
.soc-empty strong { color: var(--soc-text); font-size: 1.05rem; }
.soc-empty span { color: var(--soc-muted); max-width: 34rem; margin-top: .4rem; }
.soc-pill {
  display: inline-flex;
  align-items: center;
  border: 1px solid var(--soc-line);
  border-radius: 999px;
  padding: .28rem .6rem;
  color: #b7ccda;
  background: rgba(12, 29, 47, .95);
  font-size: .76rem;
  margin: 0 .3rem .35rem 0;
}
.soc-accent { color: var(--soc-cyan); }
.soc-good { color: var(--soc-green); }
.soc-bad { color: var(--soc-red); }
@media (max-width: 1100px) {
  .block-container { padding-left: 1.35rem; padding-right: 1.35rem; }
  [data-testid="stMetric"] { min-height: 6.6rem; padding: .8rem; }
}
@media (max-width: 700px) {
  .block-container { padding: .9rem .8rem 2rem; }
  h1 { font-size: 1.55rem !important; }
  [data-testid="stHorizontalBlock"] { gap: .65rem; }
  [data-testid="stMetric"] { min-height: 6rem; }
  .soc-page-copy { font-size: .91rem; }
  .soc-empty { min-height: 10rem; padding: 1.25rem; }
  .stButton > button, .stDownloadButton > button { width: 100%; }
}
</style>
"""


def page_header(eyebrow, title, copy):
    st.markdown(
        f'<div class="soc-eyebrow">{html.escape(eyebrow)}</div>'
        f'<h1 class="soc-page-title">{html.escape(title)}</h1>'
        f'<p class="soc-page-copy">{html.escape(copy)}</p>',
        unsafe_allow_html=True,
    )


def panel(title, copy):
    st.markdown(
        f'<div class="soc-panel"><div class="soc-panel-title">{html.escape(title)}</div>'
        f'<div class="soc-panel-copy">{html.escape(copy)}</div></div>',
        unsafe_allow_html=True,
    )


def empty_state(title, copy):
    st.markdown(
        f'<div class="soc-empty"><strong>{html.escape(title)}</strong>'
        f'<span>{html.escape(copy)}</span></div>',
        unsafe_allow_html=True,
    )


def pills(*labels):
    content = "".join(f'<span class="soc-pill">{html.escape(str(label))}</span>' for label in labels)
    st.markdown(content, unsafe_allow_html=True)
