"""AI-Powered Log Analyzer - demo dashboard.

Run from the project folder:
    streamlit run app/dashboard.py
"""
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.parser import parse_openssh  # noqa: E402
from src.detect import build_alerts, evaluate_bgl  # noqa: E402

SAMPLE_SSH = ROOT / "data/loghub-master/OpenSSH/OpenSSH_2k.log"
SAMPLE_BGL = ROOT / "data/loghub-master/BGL/BGL_2k.log_structured.csv"
RISK_COLOR = {"High": "#FF7B5C", "Medium": "#E9C46A", "Low": "#7FB8E6"}
AMBER, GREY = "#F0A04B", "#3A4656"

st.set_page_config(page_title="AI Log Analyzer", layout="wide")
st.markdown("""
<style>
.block-container {padding-top: 4rem;}
div[data-baseweb="tab-list"] {gap: 28px; padding-top: 6px;}
button[data-baseweb="tab"] {padding: 10px 2px; height: auto;}
button[data-baseweb="tab"] p {font-size: 16px; font-weight: 600; line-height: 1.4;}
div[data-testid="stMetricValue"] {font-family: 'IBM Plex Mono', monospace;}
.pill {padding: 2px 10px; border-radius: 999px; font-weight: 600; font-size: 12px;}
.High {background:#3A1E18; color:#FF9A80;} .Medium {background:#352C14; color:#F2D27E;} .Low {background:#16283A; color:#9CCBF0;}
.tag {display:inline-block; margin:0 6px 6px 0; padding:4px 10px; border-radius:6px; background:#1C232C; border:1px solid #2A323D; font-size:12px;}
</style>
""", unsafe_allow_html=True)


@st.cache_data
def analyze(text):
    df = parse_openssh(text.splitlines())
    feat, alerts = build_alerts(df)
    return df, feat, alerts


@st.cache_data
def bgl_eval(path):
    return evaluate_bgl(path)


def chart_style(fig, h=320):
    fig.update_layout(height=h, margin=dict(l=10, r=10, t=40, b=10), paper_bgcolor="rgba(0,0,0,0)",
                      plot_bgcolor="rgba(0,0,0,0)", legend=dict(orientation="h", y=1.02, yanchor="bottom", title=None),
                      font=dict(family="IBM Plex Sans, sans-serif"))
    fig.update_xaxes(showgrid=False)
    fig.update_yaxes(gridcolor="#222A33")
    return fig


# ---------------- sidebar: input ----------------
with st.sidebar:
    st.title("AI Log Analyzer")
    st.caption("Final Year Project · demo")
    upload = st.file_uploader("Upload an OpenSSH log", type=["log", "txt"])
    if upload is not None:
        text, name = upload.getvalue().decode("utf-8", errors="ignore"), upload.name
    elif SAMPLE_SSH.exists():
        text, name = SAMPLE_SSH.read_text(encoding="utf-8", errors="ignore"), SAMPLE_SSH.name
    else:
        st.error("Sample log not found. Put Loghub in data/loghub-master or upload a file.")
        st.stop()
    st.markdown(f"**Current file:** `{name}`")

df, feat, alerts = analyze(text)
if df.empty:
    st.error("No OpenSSH lines found in this file.")
    st.stop()

with st.sidebar:
    st.caption(f"{len(df):,} lines · {df.timestamp.min():%b %d %H:%M} – {df.timestamp.max():%H:%M}")
    st.divider()
    st.caption("Pipeline: Parse → Features → Isolation Forest → Risk score → Explain → Map to frameworks")

counts = pd.Series([a["risk"] for a in alerts]).value_counts()
tab_over, tab_alerts, tab_models, tab_comp = st.tabs(["Overview", "Alerts", "Models", "Compliance"])

# ---------------- Overview ----------------
with tab_over:
    st.header("Security overview")
    c1, c2, c3, c4 = st.columns(4)
    failed = int((df.event == "failed_password").sum())
    c1.metric("Events analyzed", f"{len(df):,}")
    c1.caption(f"{df.timestamp.min():%H:%M} – {df.timestamp.max():%H:%M}")
    c2.metric("Failed logins", f"{failed:,}")
    c2.caption(f"{failed / len(df):.0%} of all events")
    c3.metric("Source IPs", df.ip.nunique())
    c3.caption(f"{int((feat.failed >= 5).sum())} with 5+ failed logins")
    c4.metric("Alerts", len(alerts))
    c4.caption(f"{counts.get('High', 0)} high · {counts.get('Medium', 0)} medium · {counts.get('Low', 0)} low")

    st.subheader("Activity timeline")
    t = df.set_index("timestamp")
    tl = pd.DataFrame({
        "All events": t.resample("15min").size(),
        "Failed logins": t[t.event == "failed_password"].resample("15min").size(),
    }).fillna(0).reset_index()
    fig = go.Figure()
    fig.add_bar(x=tl.timestamp, y=tl["All events"], name="All events", marker_color=GREY)
    fig.add_bar(x=tl.timestamp, y=tl["Failed logins"], name="Failed logins", marker_color=AMBER)
    fig.update_layout(barmode="overlay", bargap=0.15)
    fig.update_xaxes(tickformat="%H:%M")
    st.plotly_chart(chart_style(fig), use_container_width=True)

    left, right = st.columns(2)
    with left:
        st.subheader("Top source IPs by failed logins")
        top = feat.nlargest(8, "failed")[["ip", "failed", "risk"]].fillna({"risk": "None"})
        fig = px.bar(top.sort_values("failed"), x="failed", y="ip", orientation="h", color="risk",
                     color_discrete_map={**RISK_COLOR, "None": GREY})
        st.plotly_chart(chart_style(fig, 300), use_container_width=True)
    with right:
        st.subheader("Usernames attackers tried")
        users = df[df.event == "failed_password"].user.value_counts().head(10).reset_index()
        users.columns = ["user", "attempts"]
        fig = px.bar(users.sort_values("attempts"), x="attempts", y="user", orientation="h",
                     color_discrete_sequence=[AMBER])
        st.plotly_chart(chart_style(fig, 300), use_container_width=True)

# ---------------- Alerts ----------------
with tab_alerts:
    st.header("Alerts")
    pick = st.radio("Risk", ["All", "High", "Medium", "Low"], horizontal=True)
    shown = [a for a in alerts if pick == "All" or a["risk"] == pick]

    table = pd.DataFrame([{
        "ID": a["id"], "Risk": a["risk"], "Source IP": a["ip"], "What happened": a["title"],
        "Time": f"{a['first_seen']:%H:%M}–{a['last_seen']:%H:%M}", "ML score": a["ml_score"],
        "Simple rule catches it": "Yes" if a["rule_hit"] else "No", "MITRE": a["technique"].split()[0],
    } for a in shown])
    st.dataframe(table, use_container_width=True, hide_index=True,
                 column_config={"ML score": st.column_config.ProgressColumn(min_value=0, max_value=1, format="%.2f")})

    if shown:
        choice = st.selectbox("Open alert", [f"{a['id']} · {a['ip']}" for a in shown])
        a = next(x for x in shown if choice.startswith(x["id"]))
        st.divider()
        h1, h2 = st.columns([3, 1])
        h1.markdown(f"<span class='pill {a['risk']}'>{a['risk']} risk</span>", unsafe_allow_html=True)
        h1.subheader(f"{a['ip']}")
        h1.write(a["title"])
        if a["ml_score"] is not None:
            h2.metric("ML anomaly score", f"{a['ml_score']:.2f}")

        cols = st.columns(len(a["stats"]))
        for col, (k, v) in zip(cols, a["stats"].items()):
            col.metric(k, v)

        w1, w2 = st.columns(2)
        with w1:
            st.markdown("**Why it was flagged**")
            for w in a["why"]:
                st.markdown(f"- {w}")
        with w2:
            st.markdown("**Summary**")
            st.info(a["summary"])
            st.markdown("**Framework mapping**")
            st.markdown("".join(f"<span class='tag'><b>{f}</b> {c}</span>" for f, c in a["tags"]),
                        unsafe_allow_html=True)

        report = pd.DataFrame([{k: v for k, v in x.items() if k in ("id", "risk", "ip", "title", "technique", "ml_score", "summary")} for x in alerts])
        st.download_button("Download all alerts (CSV)", report.to_csv(index=False), "alerts.csv", "text/csv")

# ---------------- Models ----------------
with tab_models:
    st.header("Model evaluation on BGL (labeled)")
    if SAMPLE_BGL.exists():
        res, labels, info = bgl_eval(str(SAMPLE_BGL))
        st.caption(f"{info['lines']:,} lines with {info['anomalies']} labeled anomalies, grouped into "
                   f"{info['windows']} windows of {info['window']} lines ({info['bad_windows']} contain an anomaly).")
        st.dataframe(res.style.format({"Precision": "{:.2f}", "Recall": "{:.2f}", "F1": "{:.2f}", "Time (s)": "{:.3f}"}),
                     use_container_width=True, hide_index=True)
        st.caption("Small 2k sample, so the rule baseline is hard to beat here. The full BGL/HDFS datasets are the real test.")
        lab = labels.reset_index()
        lab.columns = ["Anomaly type", "Lines"]
        fig = px.bar(lab.sort_values("Lines"), x="Lines", y="Anomaly type", orientation="h",
                     color_discrete_sequence=["#7FB8E6"])
        st.subheader("What the BGL anomalies are")
        st.plotly_chart(chart_style(fig, 320), use_container_width=True)
    else:
        st.warning("BGL sample not found in data/loghub-master/BGL.")

    st.subheader("How a score becomes a risk level")
    st.markdown("""
| Level | Rule |
|---|---|
| **High** | 20+ failed logins at 10+ per minute |
| **Medium** | 15+ failed at 3+ per minute, 10+ usernames from one IP, ML score ≥ 0.75, or a login right after an attack |
| **Low** | 5+ failed logins |
""")

# ---------------- Compliance ----------------
with tab_comp:
    st.header("Compliance mapping")
    st.caption("Alerts are mapped to related controls. The tool supports these frameworks; it does not certify compliance.")
    rows = [{"Framework": f, "Control": c, "Alert": a["id"]} for a in alerts for f, c in a["tags"]]
    m = pd.DataFrame(rows).groupby(["Framework", "Control"]).Alert.agg(["count", lambda s: ", ".join(s)]).reset_index()
    m.columns = ["Framework", "Control", "Alerts", "Alert IDs"]
    cols = st.columns(4)
    for col, fw in zip(cols, ["MITRE", "OWASP", "CIS", "ISO 27001"]):
        col.metric(f"{fw} controls", int((m.Framework == fw).sum()))
    st.dataframe(m.sort_values(["Framework", "Alerts"], ascending=[True, False]),
                 use_container_width=True, hide_index=True)
