import streamlit as st
import pandas as pd
from analyzer import analyze_pcap
from score import calculate_suspicion_score

st.set_page_config(page_title="ENC-FORENSIC-AI", layout="wide")

st.title("🔐 ENC-FORENSIC-AI")
st.subheader("Encrypted Communication Forensics Tool")

uploaded_file = st.file_uploader("📂 Upload PCAP File", type=["pcap"])

if uploaded_file:
    analysis = analyze_pcap(uploaded_file)

    if analysis:
        for pkt in analysis:
            pkt["Suspicion Score"] = calculate_suspicion_score(pkt)

        df = pd.DataFrame(analysis)

        st.markdown("### 📊 Packet Analysis")
        st.dataframe(df)

        st.markdown("### 🚨 High Risk Encrypted Traffic")
        st.dataframe(df[df["Suspicion Score"] >= 70])
    else:
        st.warning("No valid TCP payload packets found.")
