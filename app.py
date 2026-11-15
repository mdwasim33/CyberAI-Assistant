import streamlit as st
import pandas as pd
import hashlib
import ipaddress
import json
import re
import sqlite3

from pathlib import Path
from ollama import chat
from io import BytesIO
from datetime import datetime
from xml.sax.saxutils import escape

from log_analyzer import (
    analyze_log,
    classify_attacks,
    generate_event_timeline
)

from database import (
    init_db,
    save_investigation,
    get_history,
    delete_investigation
)

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch


# =====================================
# PAGE CONFIGURATION
# =====================================

st.set_page_config(
    page_title="CyberAI Assistant",
    page_icon="🛡️",
    layout="wide"
)

# Initialise SQLite database
init_db()


# =====================================
# CASE MANAGEMENT DATABASE HELPERS
# =====================================

def init_case_management():
    """Add case-management fields to the existing investigations table."""
    conn = sqlite3.connect("cyberai_history.db")
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(investigations)")
    existing_columns = {row[1] for row in cursor.fetchall()}

    new_columns = {
        "case_status": "TEXT DEFAULT 'Open'",
        "assigned_analyst": "TEXT DEFAULT ''",
        "analyst_notes": "TEXT DEFAULT ''",
        "updated_at": "TEXT DEFAULT ''"
    }

    for column_name, column_type in new_columns.items():
        if column_name not in existing_columns:
            cursor.execute(
                f"ALTER TABLE investigations ADD COLUMN {column_name} {column_type}"
            )

    conn.commit()
    conn.close()


def update_case_management(
    record_id,
    case_status,
    assigned_analyst,
    analyst_notes
):
    """Update case-management information for an investigation."""
    conn = sqlite3.connect("cyberai_history.db")
    cursor = conn.cursor()

    updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        """
        UPDATE investigations
        SET case_status = ?,
            assigned_analyst = ?,
            analyst_notes = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            case_status,
            assigned_analyst,
            analyst_notes,
            updated_at,
            record_id
        )
    )

    conn.commit()
    conn.close()


def get_case_status_counts():
    """Return case counts grouped by status."""
    conn = sqlite3.connect("cyberai_history.db")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            COALESCE(case_status, 'Open') AS status,
            COUNT(*) AS total
        FROM investigations
        GROUP BY COALESCE(case_status, 'Open')
        """
    )

    rows = cursor.fetchall()
    conn.close()

    counts = {
        "Open": 0,
        "Investigating": 0,
        "Resolved": 0
    }

    for status, total in rows:
        if status in counts:
            counts[status] = total

    return counts


init_case_management()


# =====================================
# GENERAL HELPERS
# =====================================

def calculate_risk_score(
    total_failed,
    suspicious_count,
    max_attempts
):
    score = min(
        100,
        (total_failed * 3)
        + (suspicious_count * 15)
        + (max_attempts * 2)
    )

    if total_failed >= 20 or max_attempts >= 10:
        threat_level = "CRITICAL"
    elif score >= 70:
        threat_level = "HIGH"
    elif score >= 35:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    return score, threat_level


def get_client_ip():
    """Try to obtain client IP from Streamlit headers."""
    try:
        headers = st.context.headers

        forwarded = headers.get("X-Forwarded-For")

        if forwarded:
            return forwarded.split(",")[0].strip()

        return headers.get("X-Real-IP", "Unknown")

    except Exception:
        return "Unknown"


def calculate_sha256(file_bytes):
    """Calculate SHA-256 hash."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_bytes)
    return sha256_hash.hexdigest()


def safe_text(value):
    """Safely convert values to text."""
    if value is None:
        return ""

    return str(value)


# =====================================
# AI INVESTIGATION
# =====================================

def generate_ai_investigation(
    log_text,
    failed_attempts,
    suspicious_ips,
    attack_classification,
    event_timeline,
    risk_score,
    threat_level
):
    """Generate evidence-grounded investigation using Ollama."""

    evidence = {
        "failed_attempts": dict(failed_attempts),
        "suspicious_ips": suspicious_ips,
        "attack_classification": attack_classification,
        "event_timeline": event_timeline,
        "risk_score": risk_score,
        "threat_level": threat_level
    }

    evidence_json = json.dumps(
        evidence,
        indent=2,
        default=str
    )

    prompt = f"""
You are CyberAI Assistant, a defensive cybersecurity SOC analyst.

Analyze the security investigation using ONLY the evidence provided below.

IMPORTANT:
- Do not invent IP addresses.
- Do not invent timestamps.
- Do not invent attack events.
- Do not claim evidence that is not present.
- Clearly distinguish observed evidence from recommendations.
- Keep the investigation suitable for a SOC analyst.

Provide:

1. Executive Summary
2. Observed Indicators
3. Attack Classification
4. Risk Assessment
5. Recommended Actions
6. SOC Analyst Conclusion

Evidence:

{evidence_json}

Original log:

{log_text[:12000]}
"""

    try:
        response = chat(
            model="llama3.2",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a defensive cybersecurity SOC analyst. "
                        "Your analysis must be evidence-grounded."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        return response["message"]["content"]

    except Exception as e:
        return (
            "AI investigation could not be generated.\n\n"
            f"Error: {e}"
        )


# =====================================
# PDF REPORT
# =====================================

def create_pdf_report(
    filename,
    source,
    total_failed,
    unique_ips,
    suspicious_count,
    risk_score,
    threat_level,
    failed_attempts,
    suspicious_ips,
    attack_classification,
    event_timeline,
    ai_report,
    sha256_hash,
    case_status="Open",
    assigned_analyst="",
    analyst_notes=""
):
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        spaceAfter=15
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=14,
        spaceBefore=12,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13
    )

    story = []

    story.append(
        Paragraph(
            "🛡️ CyberAI Assistant - Security Investigation Report",
            title_style
        )
    )

    story.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            body_style
        )
    )

    story.append(Spacer(1, 12))

    story.append(
        Paragraph("Investigation Overview", heading_style)
    )

    overview_data = [
        ["Field", "Value"],
        ["Source", safe_text(source)],
        ["Filename", safe_text(filename)],
        ["Total Failed Logins", str(total_failed)],
        ["Unique IP Addresses", str(unique_ips)],
        ["Suspicious IPs", str(suspicious_count)],
        ["Risk Score", str(risk_score)],
        ["Threat Level", threat_level],
        ["Case Status", case_status],
        ["Assigned Analyst", safe_text(assigned_analyst)],
        ["SHA-256", safe_text(sha256_hash)]
    ]

    table = Table(
        overview_data,
        colWidths=[160, 340]
    )

    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke)
        ])
    )

    story.append(table)

    story.append(
        Paragraph("Case Management", heading_style)
    )

    story.append(
        Paragraph(
            f"<b>Case Status:</b> {escape(safe_text(case_status))}",
            body_style
        )
    )

    story.append(
        Paragraph(
            f"<b>Assigned Analyst:</b> "
            f"{escape(safe_text(assigned_analyst))}",
            body_style
        )
    )

    story.append(Spacer(1, 5))

    story.append(
        Paragraph(
            "<b>Analyst Notes:</b>",
            body_style
        )
    )

    story.append(
        Paragraph(
            escape(safe_text(analyst_notes)).replace("\n", "<br/>"),
            body_style
        )
    )

    story.append(
        Paragraph("Failed Login Activity", heading_style)
    )

    failed_data = [["IP Address", "Failed Attempts"]]

    for ip, count in failed_attempts.items():
        failed_data.append([str(ip), str(count)])

    failed_table = Table(
        failed_data,
        colWidths=[250, 150]
    )

    failed_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8)
        ])
    )

    story.append(failed_table)

    story.append(
        Paragraph("Suspicious IP Addresses", heading_style)
    )

    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            story.append(
                Paragraph(
                    f"{escape(str(ip))} - {count} failed login attempts",
                    body_style
                )
            )
    else:
        story.append(
            Paragraph(
                "No suspicious IP addresses identified.",
                body_style
            )
        )

    story.append(
        Paragraph("Attack Classification", heading_style)
    )

    if attack_classification:
        for item in attack_classification:
            story.append(
                Paragraph(
                    escape(str(item)),
                    body_style
                )
            )
    else:
        story.append(
            Paragraph(
                "No attack classification available.",
                body_style
            )
        )

    story.append(
        Paragraph("Event Timeline", heading_style)
    )

    if event_timeline:
        for event in event_timeline:
            story.append(
                Paragraph(
                    escape(str(event)),
                    body_style
                )
            )
    else:
        story.append(
            Paragraph(
                "No event timeline available.",
                body_style
            )
        )

    story.append(
        Paragraph("AI Investigation", heading_style)
    )

    for paragraph in ai_report.split("\n"):
        if paragraph.strip():
            story.append(
                Paragraph(
                    escape(paragraph),
                    body_style
                )
            )

    document.build(story)

    buffer.seek(0)

    return buffer


# =====================================
# SOC DASHBOARD
# =====================================

def show_soc_dashboard():

    st.title("📊 SOC Dashboard")

    st.caption(
        "Security Operations Center overview and investigation monitoring"
    )

    history = get_history()

    if not history:
        st.info(
            "No investigations have been saved yet."
        )
        return

    df = pd.DataFrame(history)

    # ---------------------------------
    # OVERALL METRICS
    # ---------------------------------

    total_investigations = len(df)

    total_failed_logins = int(
        df["failed_logins"].fillna(0).sum()
    )

    total_suspicious_ips = int(
        df["suspicious_ips"].fillna(0).sum()
    )

    average_risk = round(
        df["risk_score"].fillna(0).mean(),
        1
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Total Investigations",
            total_investigations
        )

    with col2:
        st.metric(
            "Failed Logins",
            total_failed_logins
        )

    with col3:
        st.metric(
            "Suspicious IPs",
            total_suspicious_ips
        )

    with col4:
        st.metric(
            "Average Risk Score",
            average_risk
        )

    st.divider()

    # ---------------------------------
    # CASE MANAGEMENT
    # ---------------------------------

    st.subheader("📁 Case Management Overview")

    case_counts = get_case_status_counts()

    case_col1, case_col2, case_col3 = st.columns(3)

    with case_col1:
        st.metric(
            "🟢 Open Cases",
            case_counts["Open"]
        )

    with case_col2:
        st.metric(
            "🟡 Investigating",
            case_counts["Investigating"]
        )

    with case_col3:
        st.metric(
            "🔵 Resolved",
            case_counts["Resolved"]
        )

    case_chart = pd.DataFrame({
        "Status": [
            "Open",
            "Investigating",
            "Resolved"
        ],
        "Cases": [
            case_counts["Open"],
            case_counts["Investigating"],
            case_counts["Resolved"]
        ]
    })

    st.bar_chart(
        case_chart.set_index("Status")
    )

    st.divider()

    # ---------------------------------
    # THREAT LEVEL DISTRIBUTION
    # ---------------------------------

    st.subheader("🚨 Threat Level Distribution")

    threat_counts = (
        df["threat_level"]
        .fillna("UNKNOWN")
        .value_counts()
    )

    st.bar_chart(threat_counts)

    # ---------------------------------
    # RISK SCORE TREND
    # ---------------------------------

    st.subheader("📈 Risk Score Trend")

    trend_df = df.copy()

    trend_df["timestamp"] = pd.to_datetime(
        trend_df["timestamp"],
        errors="coerce"
    )

    trend_df = trend_df.sort_values("timestamp")

    if not trend_df.empty:
        trend_chart = trend_df[
            ["timestamp", "risk_score"]
        ].dropna()

        if not trend_chart.empty:
            trend_chart = trend_chart.set_index(
                "timestamp"
            )

            st.line_chart(
                trend_chart["risk_score"]
            )

    # ---------------------------------
    # RECENT INVESTIGATIONS
    # ---------------------------------

    st.subheader("🕒 Recent Investigations")

    display_columns = [
        "id",
        "timestamp",
        "source",
        "filename",
        "failed_logins",
        "suspicious_ips",
        "risk_score",
        "threat_level",
        "case_status",
        "assigned_analyst",
        "updated_at"
    ]

    available_columns = [
        column
        for column in display_columns
        if column in df.columns
    ]

    recent_df = df[
        available_columns
    ].head(10)

    st.dataframe(
        recent_df,
        use_container_width=True,
        hide_index=True
    )


# =====================================
# AI CHAT
# =====================================

def show_ai_chat():

    st.title("💬 AI Chat")

    st.caption(
        "Ask CyberAI Assistant cybersecurity questions"
    )

    if "messages" not in st.session_state:
        st.session_state.messages = [
            {
                "role": "system",
                "content": """
You are CyberAI Assistant.

You are a beginner-friendly defensive cybersecurity assistant.

Your focus includes:
- SOC operations
- Network security
- Log analysis
- Incident response
- Threat detection
- Blue Team security
- Ethical hacking concepts
- Cybersecurity learning

Always prioritize legal, authorized, and defensive security practices.
"""
            }
        ]

    for message in st.session_state.messages:
        if message["role"] == "system":
            continue

        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    user_input = st.chat_input(
        "Ask a cybersecurity question..."
    )

    if user_input:

        st.session_state.messages.append(
            {
                "role": "user",
                "content": user_input
            }
        )

        with st.chat_message("user"):
            st.markdown(user_input)

        with st.chat_message("assistant"):

            with st.spinner("CyberAI is thinking..."):

                try:
                    response = chat(
                        model="llama3.2",
                        messages=st.session_state.messages
                    )

                    answer = response[
                        "message"
                    ][
                        "content"
                    ]

                except Exception as e:

                    answer = (
                        "Unable to connect to Ollama.\n\n"
                        f"Error: {e}"
                    )

                st.markdown(answer)

        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": answer
            }
        )


# =====================================
# LOG ANALYZER
# =====================================

def show_log_analyzer():

    st.title("🔍 Security Log Analyzer")

    st.caption(
        "Upload a security log file to detect suspicious login activity."
    )

    uploaded_file = st.file_uploader(
        "Upload security log",
        type=["log", "txt"]
    )

    if uploaded_file is None:

        st.info(
            "Upload a .log or .txt file to begin analysis."
        )

        return

    file_bytes = uploaded_file.getvalue()

    sha256_hash = calculate_sha256(
        file_bytes
    )

    log_text = file_bytes.decode(
        "utf-8",
        errors="ignore"
    )

    st.success(
        f"File loaded: {uploaded_file.name}"
    )

    st.caption(
        f"SHA-256: {sha256_hash}"
    )

    # ---------------------------------
    # ANALYZE LOG
    # ---------------------------------

    failed_attempts, suspicious_ips = analyze_log(
        log_text
    )

    total_failed = sum(
        failed_attempts.values()
    )

    unique_ips = len(
        failed_attempts
    )

    suspicious_count = len(
        suspicious_ips
    )

    max_attempts = (
        max(failed_attempts.values())
        if failed_attempts
        else 0
    )

    risk_score, threat_level = calculate_risk_score(
        total_failed,
        suspicious_count,
        max_attempts
    )

    # ---------------------------------
    # METRICS
    # ---------------------------------

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Total Failed Logins",
            total_failed
        )

    with col2:
        st.metric(
            "Unique IP Addresses",
            unique_ips
        )

    with col3:
        st.metric(
            "Suspicious IPs",
            suspicious_count
        )

    with col4:
        st.metric(
            "Risk Score",
            risk_score
        )

    if threat_level == "CRITICAL":
        st.error(
            f"🚨 Threat Level: {threat_level}"
        )
    elif threat_level == "HIGH":
        st.warning(
            f"⚠️ Threat Level: {threat_level}"
        )
    elif threat_level == "MEDIUM":
        st.warning(
            f"🟡 Threat Level: {threat_level}"
        )
    else:
        st.success(
            f"🟢 Threat Level: {threat_level}"
        )

    # ---------------------------------
    # FAILED ATTEMPTS
    # ---------------------------------

    st.subheader("Failed Login Attempts")

    if failed_attempts:

        attempts_df = pd.DataFrame(
            list(failed_attempts.items()),
            columns=[
                "IP Address",
                "Failed Attempts"
            ]
        )

        st.dataframe(
            attempts_df,
            use_container_width=True,
            hide_index=True
        )

        st.bar_chart(
            attempts_df.set_index(
                "IP Address"
            )
        )

    else:

        st.info(
            "No failed login attempts detected."
        )

    # ---------------------------------
    # SUSPICIOUS IPS
    # ---------------------------------

    st.subheader("🚨 Suspicious IP Addresses")

    if suspicious_ips:

        for ip, count in suspicious_ips.items():

            st.warning(
                f"{ip} had {count} failed login attempts."
            )

    else:

        st.success(
            "No suspicious IP addresses identified."
        )

    # ---------------------------------
    # ATTACK CLASSIFICATION
    # ---------------------------------

    try:

        attack_classification = classify_attacks(
            log_text
        )

    except Exception:

        attack_classification = []

    st.subheader("🎯 Attack Classification")

    if attack_classification:

        for attack in attack_classification:

            st.write(
                f"• {attack}"
            )

    else:

        st.info(
            "No attack classification available."
        )

    # ---------------------------------
    # EVENT TIMELINE
    # ---------------------------------

    try:

        event_timeline = generate_event_timeline(
            log_text
        )

    except Exception:

        event_timeline = []

    st.subheader("🕒 Event Timeline")

    if event_timeline:

        for event in event_timeline:

            st.write(
                f"• {event}"
            )

    else:

        st.info(
            "No event timeline available."
        )

    # ---------------------------------
    # AI INVESTIGATION
    # ---------------------------------

    st.subheader("🤖 AI Investigation")

    if st.button(
        "Generate AI Investigation",
        type="primary"
    ):

        with st.spinner(
            "CyberAI is investigating the evidence..."
        ):

            ai_report = generate_ai_investigation(
                log_text=log_text,
                failed_attempts=failed_attempts,
                suspicious_ips=suspicious_ips,
                attack_classification=attack_classification,
                event_timeline=event_timeline,
                risk_score=risk_score,
                threat_level=threat_level
            )

        st.session_state[
            "latest_ai_report"
        ] = ai_report

        st.session_state[
            "latest_analysis"
        ] = {
            "filename": uploaded_file.name,
            "source": "Uploaded Log",
            "total_failed": total_failed,
            "unique_ips": unique_ips,
            "suspicious_count": suspicious_count,
            "risk_score": risk_score,
            "threat_level": threat_level,
            "failed_attempts": failed_attempts,
            "suspicious_ips": suspicious_ips,
            "attack_classification": attack_classification,
            "event_timeline": event_timeline,
            "sha256_hash": sha256_hash,
            "log_text": log_text
        }

    if "latest_ai_report" in st.session_state:

        st.markdown(
            st.session_state["latest_ai_report"]
        )

        analysis = st.session_state[
            "latest_analysis"
        ]

        st.divider()

        # ---------------------------------
        # SAVE INVESTIGATION
        # ---------------------------------

        if st.button(
            "💾 Save Investigation"
        ):

            save_investigation(
                source=analysis["source"],
                filename=analysis["filename"],
                failed_logins=analysis["total_failed"],
                unique_ips=analysis["unique_ips"],
                suspicious_ips=analysis["suspicious_count"],
                risk_score=analysis["risk_score"],
                threat_level=analysis["threat_level"],
                report=st.session_state[
                    "latest_ai_report"
                ]
            )

            st.success(
                "Investigation saved successfully."
            )

        # ---------------------------------
        # PDF REPORT
        # ---------------------------------

        pdf = create_pdf_report(
            filename=analysis["filename"],
            source=analysis["source"],
            total_failed=analysis["total_failed"],
            unique_ips=analysis["unique_ips"],
            suspicious_count=analysis["suspicious_count"],
            risk_score=analysis["risk_score"],
            threat_level=analysis["threat_level"],
            failed_attempts=analysis["failed_attempts"],
            suspicious_ips=analysis["suspicious_ips"],
            attack_classification=analysis["attack_classification"],
            event_timeline=analysis["event_timeline"],
            ai_report=st.session_state[
                "latest_ai_report"
            ],
            sha256_hash=analysis["sha256_hash"]
        )

        st.download_button(
            label="📄 Download PDF Report",
            data=pdf,
            file_name="CyberAI_Security_Report.pdf",
            mime="application/pdf"
        )


# =====================================
# LIVE SOC MONITOR
# =====================================

def show_live_soc_monitor():

    st.title("📡 Live SOC Monitor")

    st.caption(
        "Real-time local security log monitoring"
    )

    log_path = st.text_input(
        "Log file path",
        value="sample.log"
    )

    refresh_seconds = 5

    st.info(
        f"Refresh interval: {refresh_seconds} seconds"
    )

    @st.fragment(run_every=f"{refresh_seconds}s")
    def live_monitor():

        path = Path(log_path)

        if not path.exists():

            st.warning(
                f"Log file not found: {log_path}"
            )

            return

        try:

            log_text = path.read_text(
                encoding="utf-8",
                errors="ignore"
            )

        except Exception as e:

            st.error(
                f"Unable to read log file: {e}"
            )

            return

        failed_attempts, suspicious_ips = analyze_log(
            log_text
        )

        total_failed = sum(
            failed_attempts.values()
        )

        unique_ips = len(
            failed_attempts
        )

        suspicious_count = len(
            suspicious_ips
        )

        max_attempts = (
            max(failed_attempts.values())
            if failed_attempts
            else 0
        )

        risk_score, threat_level = calculate_risk_score(
            total_failed,
            suspicious_count,
            max_attempts
        )

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "Failed Logins",
                total_failed
            )

        with col2:
            st.metric(
                "Unique IPs",
                unique_ips
            )

        with col3:
            st.metric(
                "Suspicious IPs",
                suspicious_count
            )

        with col4:
            st.metric(
                "Risk Score",
                risk_score
            )

        if threat_level == "CRITICAL":

            st.error(
                f"🚨 CRITICAL - Risk Score {risk_score}"
            )

        elif threat_level == "HIGH":

            st.warning(
                f"⚠️ HIGH - Risk Score {risk_score}"
            )

        elif threat_level == "MEDIUM":

            st.warning(
                f"🟡 MEDIUM - Risk Score {risk_score}"
            )

        else:

            st.success(
                f"🟢 LOW - Risk Score {risk_score}"
            )

        st.subheader(
            "Live Failed Login Activity"
        )

        if failed_attempts:

            live_df = pd.DataFrame(
                list(failed_attempts.items()),
                columns=[
                    "IP Address",
                    "Failed Attempts"
                ]
            )

            st.dataframe(
                live_df,
                use_container_width=True,
                hide_index=True
            )

            st.bar_chart(
                live_df.set_index(
                    "IP Address"
                )
            )

        else:

            st.success(
                "No failed login attempts detected."
            )

    live_monitor()


# =====================================
# INVESTIGATION HISTORY
# =====================================

def show_investigation_history():

    st.title("📚 Investigation History")

    st.caption(
        "Previously saved cybersecurity investigations"
    )

    history = get_history()

    if not history:

        st.info(
            "No saved investigations found."
        )

        return

    df = pd.DataFrame(history)

    # ---------------------------------
    # HISTORY TABLE
    # ---------------------------------

    display_columns = [
        "id",
        "timestamp",
        "source",
        "filename",
        "failed_logins",
        "unique_ips",
        "suspicious_ips",
        "risk_score",
        "threat_level",
        "case_status",
        "assigned_analyst",
        "updated_at"
    ]

    available_columns = [
        column
        for column in display_columns
        if column in df.columns
    ]

    st.dataframe(
        df[available_columns],
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    st.subheader(
        "Saved Investigations"
    )

    for record in history:

        record_id = record["id"]

        case_status = record.get(
            "case_status",
            "Open"
        ) or "Open"

        assigned_analyst = record.get(
            "assigned_analyst",
            ""
        ) or ""

        analyst_notes = record.get(
            "analyst_notes",
            ""
        ) or ""

        updated_at = record.get(
            "updated_at",
            ""
        ) or ""

        title = (
            f"Investigation #{record_id} - "
            f"{record.get('filename', 'Unknown')}"
        )

        with st.expander(title):

            # ---------------------------------
            # BASIC INFORMATION
            # ---------------------------------

            col1, col2, col3 = st.columns(3)

            with col1:

                st.write(
                    f"**Timestamp:** "
                    f"{record.get('timestamp', '')}"
                )

                st.write(
                    f"**Source:** "
                    f"{record.get('source', '')}"
                )

                st.write(
                    f"**Filename:** "
                    f"{record.get('filename', '')}"
                )

            with col2:

                st.write(
                    f"**Failed Logins:** "
                    f"{record.get('failed_logins', 0)}"
                )

                st.write(
                    f"**Unique IPs:** "
                    f"{record.get('unique_ips', 0)}"
                )

                st.write(
                    f"**Suspicious IPs:** "
                    f"{record.get('suspicious_ips', 0)}"
                )

            with col3:

                st.write(
                    f"**Risk Score:** "
                    f"{record.get('risk_score', 0)}"
                )

                st.write(
                    f"**Threat Level:** "
                    f"{record.get('threat_level', '')}"
                )

                st.write(
                    f"**Case Status:** "
                    f"{case_status}"
                )

            st.divider()

            # ---------------------------------
            # CASE MANAGEMENT
            # ---------------------------------

            st.subheader(
                "📁 Case Management"
            )

            status_options = [
                "Open",
                "Investigating",
                "Resolved"
            ]

            current_status_index = (
                status_options.index(case_status)
                if case_status in status_options
                else 0
            )

            selected_status = st.selectbox(
                "Case Status",
                status_options,
                index=current_status_index,
                key=f"status_{record_id}"
            )

            selected_analyst = st.text_input(
                "Assigned Analyst",
                value=assigned_analyst,
                key=f"analyst_{record_id}"
            )

            selected_notes = st.text_area(
                "Analyst Notes",
                value=analyst_notes,
                key=f"notes_{record_id}",
                height=120
            )

            if st.button(
                "💾 Save Case Update",
                key=f"save_case_{record_id}"
            ):

                update_case_management(
                    record_id=record_id,
                    case_status=selected_status,
                    assigned_analyst=selected_analyst,
                    analyst_notes=selected_notes
                )

                st.success(
                    "Case management information updated."
                )

                st.rerun()

            if updated_at:

                st.caption(
                    f"Last Updated: {updated_at}"
                )

            # ---------------------------------
            # AI REPORT
            # ---------------------------------

            st.subheader(
                "🤖 AI Investigation Report"
            )

            report = record.get(
                "report",
                ""
            )

            if report:

                st.markdown(
                    report
                )

            else:

                st.info(
                    "No AI report available."
                )

            st.divider()

            # ---------------------------------
            # PDF REPORT
            # ---------------------------------

            pdf = create_pdf_report(
                filename=record.get(
                    "filename",
                    "investigation"
                ),
                source=record.get(
                    "source",
                    ""
                ),
                total_failed=record.get(
                    "failed_logins",
                    0
                ),
                unique_ips=record.get(
                    "unique_ips",
                    0
                ),
                suspicious_count=record.get(
                    "suspicious_ips",
                    0
                ),
                risk_score=record.get(
                    "risk_score",
                    0
                ),
                threat_level=record.get(
                    "threat_level",
                    ""
                ),
                failed_attempts={},
                suspicious_ips={},
                attack_classification=[],
                event_timeline=[],
                ai_report=report,
                sha256_hash="Not available",
                case_status=case_status,
                assigned_analyst=assigned_analyst,
                analyst_notes=analyst_notes
            )

            st.download_button(
                label="📄 Download Investigation PDF",
                data=pdf,
                file_name=(
                    f"CyberAI_Investigation_{record_id}.pdf"
                ),
                mime="application/pdf",
                key=f"pdf_{record_id}"
            )

            # ---------------------------------
            # DELETE
            # ---------------------------------

            if st.button(
                "🗑️ Delete Investigation",
                key=f"delete_{record_id}"
            ):

                delete_investigation(
                    record_id
                )

                st.success(
                    "Investigation deleted."
                )

                st.rerun()


# =====================================
# SIDEBAR
# =====================================

st.sidebar.title(
    "🛡️ CyberAI Assistant"
)

st.sidebar.caption(
    "AI-powered Security Platform"
)

st.sidebar.divider()

page = st.sidebar.radio(
    "Navigation",
    [
        "📊 SOC Dashboard",
        "💬 AI Chat",
        "🔍 Log Analyzer",
        "📡 Live SOC Monitor",
        "📚 Investigation History"
    ]
)

st.sidebar.divider()

st.sidebar.info(
    "Model: Llama 3.2"
)

st.sidebar.success(
    "Ollama Connected"
)

st.sidebar.divider()

st.sidebar.caption(
    "CyberAI Assistant - Defensive Security Platform"
)


# =====================================
# PAGE ROUTING
# =====================================

if page == "📊 SOC Dashboard":

    show_soc_dashboard()

elif page == "💬 AI Chat":

    show_ai_chat()

elif page == "🔍 Log Analyzer":

    show_log_analyzer()

elif page == "📡 Live SOC Monitor":

    show_live_soc_monitor()

elif page == "📚 Investigation History":

    show_investigation_history()