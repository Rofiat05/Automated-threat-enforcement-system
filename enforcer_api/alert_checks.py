import ipaddress
import re

ALLOWED_FIELDS = [
    "host",
    "source_ip",
    "window_start",
    "window_end",
    "failed_attempts",
    "criticality",
    "threshold",
    "alert",
]
ALLOWED_CRITICALITY = ["critical", "high", "medium", "low"]
TIME_PATTERN = (
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r" \d{2} \d{2}:\d{2}:\d{2}"
)


def is_real_ip(text):
    if not isinstance(text, str):
        return False
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def is_valid_hostname(text):
    if not isinstance(text, str):
        return False
    return re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", text) is not None


def is_valid_count(value):
    # must be a whole number, 1 or more
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def is_valid_criticality(text):
    return text in ALLOWED_CRITICALITY


def is_valid_time_text(text):
    # B's format, for example "Nov 05 10:00:00"
    if not isinstance(text, str):
        return False
    return re.fullmatch(TIME_PATTERN, text) is not None


def check_alert(alert):
    """Return a list of problems. An empty list means the alert is fine."""
    problems = []

    # 1. no unexpected fields, none missing
    for name in alert:
        if name not in ALLOWED_FIELDS:
            problems.append("unexpected field: " + name)
    for name in ALLOWED_FIELDS:
        if name not in alert:
            problems.append("missing field: " + name)
    if problems:
        return problems

    # 2. each field must be valid
    if not is_valid_hostname(alert["host"]):
        problems.append("host is not valid")
    if not is_real_ip(alert["source_ip"]):
        problems.append("source_ip is not a real IP address")
    if not is_valid_time_text(alert["window_start"]):
        problems.append("window_start is not a valid time")
    if not is_valid_time_text(alert["window_end"]):
        problems.append("window_end is not a valid time")
    if not is_valid_count(alert["failed_attempts"]):
        problems.append("failed_attempts must be a whole number of 1 or more")
    if not is_valid_criticality(alert["criticality"]):
        problems.append("criticality is not an allowed value")
    if not is_valid_count(alert["threshold"]):
        problems.append("threshold must be a whole number of 1 or more")

    # 3. only alerts that crossed the threshold are accepted
    if not isinstance(alert["alert"], bool):
        problems.append("alert must be true or false")
    elif alert["alert"] is False:
        problems.append("alert is false (below threshold)")

    return problems