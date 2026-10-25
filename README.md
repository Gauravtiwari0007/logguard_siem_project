from __future__ import annotations

import io
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from logguard import (
    analyze_events,
    load_events,
    make_alerts_csv,
    make_alerts_json,
    summarize_events,
)

APP_DIR = Path(__file__).parent
SAMPLE_LOG = APP_DIR / "data" / "sample_auth.log"

st.set_page_config(page_title="LogGuard Mini-SIEM", page_icon="🛡️", layout="wide")
st.title("🛡️ LogGuard — Authentication Log Analyzer")
st.caption("A beginner-friendly mini-SIEM for detecting suspicious authentication activity.")
st.info(
    "Use only logs you own or are authorized to analyze. This tool analyzes uploaded files "
    "locally; it does not attempt logins, scan networks, or block accounts."
)

with st.sidebar:
    st.header("Detection settings")
    failure_threshold = st.slider(
        "Failed attempts to trigger alert", min_value=2, max_value=30, value=5
    )
    window_minutes = st.slider(
        "Detection time window (minutes)", min_value=1, max_value=120, value=10
    )
    distinct_users_threshold = st.slider(
        "Distinct usernames from one IP", min_value=2, max_value=20, value=5
    )
    st.divider()
    st.write("**Input formats**")
    st.caption("Linux OpenSSH auth.log text, or CSV with timestamp, event, username, ip, and optional details.")

uploaded = st.file_uploader(
    "Upload an authentication log (.log, .txt, or .csv)",
    type=["log", "txt", "csv"],
    help="For a quick demo, leave the upload empty to use the included sample log.",
)

if uploaded is None:
    st.caption("Showing bundled demo data: data/sample_auth.log")
    raw = SAMPLE_LOG.read_text(encoding="utf-8", errors="replace")
    events, parse_warnings = load_events(raw, source_name="sample_auth.log")
else:
    raw_bytes = uploaded.getvalue()
    raw = raw_bytes.decode("utf-8", errors="replace")
    events, parse_warnings = load_events(
        raw, source_name=uploaded.name, is_csv=uploaded.name.lower().endswith(".csv")
    )

if parse_warnings:
    with st.expander(f"Import notes ({len(parse_warnings)})"):
        for warning in parse_warnings[:100]:
            st.write(f"• {warning}")
        if len(parse_warnings) > 100:
            st.caption(f"{len(parse_warnings) - 100} additional notes omitted.")

if events.empty:
    st.error("No supported authentication events were parsed. Check the input format and README.")
    st.stop()

events, alerts = analyze_events(
    events,
    failure_threshold=failure_threshold,
    window_minutes=window_minutes,
    distinct_users_threshold=distinct_users_threshold,
)
summary = summarize_events(events, alerts)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Parsed events", f"{summary['total_events']:,}")
c2.metric("Failed logins", f"{summary['failed_logins']:,}")
c3.metric("Successful logins", f"{summary['successful_logins']:,}")
c4.metric("Alerts", f"{len(alerts):,}")

tab_overview, tab_events, tab_alerts, tab_about = st.tabs(
    ["Overview", "Events", "Alerts & export", "About"]
)

with tab_overview:
    left, right = st.columns(2)
    with left:
        st.subheader("Authentication events over time")
        chart_data = events.copy()
        chart_data["minute"] = chart_data["timestamp"].dt.floor("min")
        trend = (
            chart_data.groupby(["minute", "event_type"])
            .size()
            .unstack(fill_value=0)
            .sort_index()
        )
        if not trend.empty:
            fig, ax = plt.subplots(figsize=(9, 4))
            trend.plot(ax=ax, marker="o", linewidth=1.6)
            ax.set_xlabel("Time")
            ax.set_ylabel("Events / minute")
            ax.grid(True, alpha=0.25)
            fig.tight_layout()
            st.pyplot(fig)
            plt.close(fig)
        else:
            st.caption("No events available for the trend chart.")
    with right:
        st.subheader("Top source IPs by failed logins")
        failures = events[events["event_type"] == "failure"]
        if failures.empty:
            st.success("No failed login events in this dataset.")
        else:
            top_ips = failures.groupby("ip").size().sort_values(ascending=False).head(10)
            fig, ax = plt.subplots(figsize=(9, 4))
            top_ips.sort_values().plot(kind="barh", ax=ax)
            ax.set_xlabel("Failed login events")
            ax.set_ylabel("Source IP")
            ax.grid(axis="x", alpha=0.25)
            fig.tight_layout()
            st.pyplot(fig)
            plt.close(fig)

    st.subheader("Quick breakdown")
    b1, b2 = st.columns(2)
    with b1:
        st.write("**Events by type**")
        st.dataframe(
            events["event_type"].value_counts().rename_axis("event_type").reset_index(name="count"),
            use_container_width=True,
            hide_index=True,
        )
    with b2:
        st.write("**Failed attempts by username**")
        by_user = (
            events[events["event_type"] == "failure"]
            .groupby("username").size().sort_values(ascending=False)
            .head(10).rename("failed_attempts").reset_index()
        )
        st.dataframe(by_user, use_container_width=True, hide_index=True)

with tab_events:
    st.subheader("Normalized events")
    event_types = sorted(events["event_type"].dropna().unique().tolist())
    selected_types = st.multiselect("Filter event types", event_types, default=event_types)
    ip_values = sorted([x for x in events["ip"].dropna().unique().tolist() if x and x != "-"])
    selected_ips = st.multiselect("Filter source IPs", ip_values, default=[])
    view = events[events["event_type"].isin(selected_types)]
    if selected_ips:
        view = view[view["ip"].isin(selected_ips)]
    st.dataframe(view.sort_values("timestamp", ascending=False), use_container_width=True, hide_index=True)
    st.download_button(
        "Download normalized events CSV",
        data=view.to_csv(index=False).encode("utf-8"),
        file_name="logguard_normalized_events.csv",
        mime="text/csv",
    )

with tab_alerts:
    st.subheader("Detection alerts")
    if alerts.empty:
        st.success("No alerts matched the current thresholds.")
    else:
        st.dataframe(alerts.sort_values("first_seen", ascending=False), use_container_width=True, hide_index=True)
        st.download_button(
            "Download alerts CSV",
            data=make_alerts_csv(alerts),
            file_name="logguard_alerts.csv",
            mime="text/csv",
        )
        st.download_button(
            "Download alerts JSON",
            data=make_alerts_json(alerts),
            file_name="logguard_alerts.json",
            mime="application/json",
        )
    st.caption(
        "Alerts are heuristic indicators, not proof of compromise. Review surrounding events and "
        "environmental context before taking action."
    )

with tab_about:
    st.subheader("What this mini-SIEM detects")
    st.markdown(
        """
        - **Repeated failures:** the same source IP has at least the configured number of failed logins
          inside the selected rolling time window.
        - **Username spray / enumeration signal:** one source IP fails against several distinct usernames
          within the time window.
        - **Failure followed by success:** a successful login from an IP follows recent failed attempts
          for the same username.
        - **Event trends:** event counts over time, top source IPs, and failures by username.

        **Limitations:** parsing depends on log format; NAT, shared hosts, automation, and legitimate
        user mistakes can cause false positives. The tool does not infer attribution or automatically
        block users/IPs.
        """
    )
    st.markdown("**CSV schema**")
    st.code("timestamp,event,username,ip,details\n2026-10-25T10:00:00,failure,alice,192.0.2.10,invalid password")
    st.markdown("**Event values:** `failure`, `success`, `invalid_user`, or `other`.")
    st.markdown("See `README.md` for setup, test instructions, and sample data details.")
