"""
Professional Hybrid IDS Dashboard
"""

import sqlite3
import pandas as pd
import streamlit as st
from pathlib import Path

# ==============================
# Page Configuration
# ==============================
st.set_page_config(
    page_title="Hybrid IDS Dashboard",
    page_icon="🚨",
    layout="wide"
)

# ==============================
# Header
# ==============================
st.markdown("## 🚨 Hybrid Intrusion Detection System")
st.caption("Rule-based + Machine Learning + Explainable IDS")

st.divider()

# ==============================
# Paths
# ==============================
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "db" / "alerts.db"

# ==============================
# Database Loader
# ==============================
def load_alerts():
    if not DB_PATH.exists():
        return pd.DataFrame()

    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT * FROM alerts ORDER BY id DESC", conn)
    conn.close()
    return df

# ==============================
# Sidebar Controls
# ==============================
st.sidebar.header("⚙ Controls")

if st.sidebar.button("🔄 Refresh Alerts"):
    st.rerun()

severity_filter = st.sidebar.multiselect(
    "Filter by Severity",
    options=["critical", "high", "medium", "low"],
    default=["critical", "high", "medium", "low"]
)

max_rows = st.sidebar.slider("Max alerts to display", 10, 500, 100)

# ==============================
# Load Data
# ==============================
alerts_df = load_alerts()

if alerts_df.empty:
    st.warning("No alerts detected yet. Start traffic simulation.")
    st.stop()

alerts_df = alerts_df[alerts_df["severity"].isin(severity_filter)]
alerts_df = alerts_df.head(max_rows)

alerts_df["timestamp"] = pd.to_datetime(alerts_df["timestamp"])
alerts_df["Time"] = alerts_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

# ==============================
# KPI Metrics (SOC-style)
# ==============================
st.subheader("📊 Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Alerts", len(alerts_df))
col2.metric("Critical", (alerts_df["severity"] == "critical").sum())
col3.metric("High", (alerts_df["severity"] == "high").sum())
col4.metric("Medium", (alerts_df["severity"] == "medium").sum())

st.divider()

# ==============================
# Alert Table
# ==============================
st.subheader("🔎 Detected Security Incidents")

display_df = alerts_df[[
    "Time",
    "ml_score",
    "rule_score",
    "final_score",
    "severity",
    "matched_rules"
]]

display_df.columns = [
    "Time",
    "ML Confidence",
    "Rule Confidence",
    "Final Confidence",
    "Severity",
    "Triggered Rules"
]

st.dataframe(
    display_df,
    width="stretch",
    hide_index=True
)

st.divider()

# ==============================
# Severity Distribution
# ==============================
st.subheader("📈 Alert Severity Distribution")

severity_counts = alerts_df["severity"].value_counts()
st.bar_chart(severity_counts)
