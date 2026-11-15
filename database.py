
import sqlite3
import json
from datetime import datetime

DB_NAME = "cyberai_history.db"


# =========================
# DATABASE CONNECTION
# =========================

def get_connection():
    return sqlite3.connect(DB_NAME)


# =========================
# CREATE DATABASE TABLE
# =========================

def init_db():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,

            source TEXT,

            filename TEXT,

            failed_logins INTEGER,

            unique_ips INTEGER,

            suspicious_ips INTEGER,

            risk_score INTEGER,

            threat_level TEXT,

            report TEXT
        )
    """)

    conn.commit()
    conn.close()


# =========================
# SAVE INVESTIGATION
# =========================

def save_investigation(
    source,
    filename,
    failed_logins,
    unique_ips,
    suspicious_ips,
    risk_score,
    threat_level,
    report
):

    conn = get_connection()
    cursor = conn.cursor()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO investigations (
            timestamp,
            source,
            filename,
            failed_logins,
            unique_ips,
            suspicious_ips,
            risk_score,
            threat_level,
            report
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        source,
        filename,
        failed_logins,
        unique_ips,
        suspicious_ips,
        risk_score,
        threat_level,
        report
    ))

    conn.commit()
    conn.close()


# =========================
# GET INVESTIGATION HISTORY
# =========================

def get_history():

    conn = get_connection()
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM investigations
        ORDER BY id DESC
    """)

    records = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return records


# =========================
# DELETE INVESTIGATION
# =========================

def delete_investigation(record_id):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM investigations WHERE id = ?",
        (record_id,)
    )

    conn.commit()
    conn.close()
