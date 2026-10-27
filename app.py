import json
import streamlit as st
import pandas as pd
import plotly.express as px

from config import AWS_PROFILE, AWS_REGION, DEMO_MODE
from auditor.aws_auditor import AWSAuditor
from auditor.checks import demo_findings
from utils.security import severity_counts, compliance_score, failed_findings
from utils.report import report_json

st.set_page_config(
    page_title="SinhaSecure | AWS CSPM",
    page_icon="🛡️",
    layout="wide",
)

st.markdown("""
<style>
.block-container {padding-top: 2rem;}
.hero {padding: 1.2rem 1.4rem; border: 1px solid #d8dee9; border-radius: 14px; margin-bottom: 1rem;}
.small {color: #6b7280;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="hero"><h1>🛡️ SinhaSecure</h1><p class="small">AWS Cloud Security & Compliance Dashboard · CSPM</p></div>', unsafe_allow_html=True)

with st.sidebar:
    st.header("Audit Configuration")
    mode = st.radio("Audit mode", ["Demo Mode", "Live AWS"], index=0 if DEMO_MODE else 1)
    region = st.text_input("AWS Region", AWS_REGION)
    profile = st.text_input("AWS Profile (optional)", AWS_PROFILE)
    st.divider()
    st.caption("Use least-privilege AWS credentials. Never paste secret keys into the source code.")

if "findings" not in st.session_state:
    st.session_state.findings = demo_findings() if mode == "Demo Mode" else []

if st.button("🔍 Run Security Audit", type="primary", use_container_width=True):
    if mode == "Demo Mode":
        st.session_state.findings = demo_findings()
        st.success("Demo security audit completed.")
    else:
        try:
            auditor = AWSAuditor(profile=profile or None, region=region)
            st.session_state.findings = auditor.run()
            st.success(f"Live AWS audit completed for account {auditor.account_id()}.")
        except Exception as exc:
            st.error(str(exc))

findings = st.session_state.findings
counts = severity_counts(findings)
score = compliance_score(findings)
failed = failed_findings(findings)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Compliance Score", f"{score}%")
c2.metric("Total Findings", len(findings))
c3.metric("Failed", len(failed))
c4.metric("Critical", counts.get("Critical", 0))

st.divider()

left, right = st.columns([1, 1])
with left:
    st.subheader("Severity Distribution")
    sev_df = pd.DataFrame({"Severity": list(counts.keys()), "Findings": list(counts.values())})
    fig = px.bar(sev_df, x="Severity", y="Findings", text="Findings")
    fig.update_layout(height=350, margin=dict(l=10, r=10, t=20, b=10))
    st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Service Coverage")
    if findings:
        service_df = pd.DataFrame(findings).groupby("service").size().reset_index(name="Findings")
        fig2 = px.pie(service_df, names="service", values="Findings", hole=0.45)
        fig2.update_layout(height=350, margin=dict(l=10, r=10, t=20, b=10))
        st.plotly_chart(fig2, use_container_width=True)

st.subheader("Security Findings")
if findings:
    df = pd.DataFrame(findings)
    display_cols = ["check_id", "service", "severity", "status", "title", "resource"]
    st.dataframe(df[display_cols], use_container_width=True, hide_index=True)

    with st.expander("Finding details"):
        for item in findings:
            st.markdown(f"### {item['check_id']} · {item['title']}")
            st.write(f"**Service:** {item['service']}  |  **Severity:** {item['severity']}  |  **Status:** {item['status']}")
            st.write(item["description"])
            st.info(f"Recommendation: {item['recommendation']}")

    st.download_button(
        "⬇️ Download JSON Security Report",
        data=report_json(findings),
        file_name="sinhasecure-security-report.json",
        mime="application/json",
    )
else:
    st.info("Click 'Run Security Audit' to begin.")

st.divider()
st.caption("SinhaSecure · AWS Cloud Security & Compliance Auditor")
