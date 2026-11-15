
import re
from collections import defaultdict
from datetime import datetime


def analyze_log(log_text):

    failed_attempts = defaultdict(int)
    suspicious_ips = {}

    for line in log_text.splitlines():

        if "FAILED_LOGIN" in line:

            match = re.search(r"ip=(\S+)", line)

            if match:
                ip = match.group(1)
                failed_attempts[ip] += 1

    for ip, count in failed_attempts.items():

        if count >= 3:
            suspicious_ips[ip] = count

    return failed_attempts, suspicious_ips


# =========================
# ATTACK CLASSIFICATION
# =========================

def classify_attacks(failed_attempts, suspicious_ips):

    classifications = []

    for ip, count in failed_attempts.items():

        if count >= 10:

            attack_type = "Possible Brute Force Attack"
            severity = "CRITICAL"

        elif count >= 3:

            attack_type = "Repeated Login Failure"
            severity = "MEDIUM"

        else:

            attack_type = "Normal Failed Login Activity"
            severity = "LOW"

        classifications.append({
            "IP Address": ip,
            "Failed Attempts": count,
            "Attack Type": attack_type,
            "Severity": severity
        })

    return classifications


# =========================
# SECURITY EVENT TIMELINE
# =========================

def generate_event_timeline(log_text):

    events = []

    for line in log_text.splitlines():

        if "FAILED_LOGIN" in line:

            time_match = re.search(
                r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",
                line
            )

            ip_match = re.search(
                r"ip=(\S+)",
                line
            )

            username_match = re.search(
                r"username=(\S+)",
                line
            )

            if time_match and ip_match:

                timestamp = time_match.group(1)
                ip = ip_match.group(1)

                username = (
                    username_match.group(1)
                    if username_match
                    else "Unknown"
                )

                try:
                    event_time = datetime.strptime(
                        timestamp,
                        "%Y-%m-%d %H:%M:%S"
                    )
                except ValueError:
                    continue

                events.append({
                    "Timestamp": event_time,
                    "IP Address": ip,
                    "Username": username,
                    "Event": "Failed Login"
                })

    events.sort(key=lambda event: event["Timestamp"])

    return events
