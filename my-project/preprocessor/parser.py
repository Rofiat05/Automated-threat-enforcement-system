import re

def parse_log_line(line):
    """Extract useful fields from a Linux SSH authentication log line."""

    pattern = (
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
        r"\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
        r"(?P<message>.*)$"
    )
    match = re.match(pattern, line.strip())

    if not match:
        return None

    timestamp = match.group("timestamp")
    host = match.group("host")
    message = match.group("message")

    event = {
        "timestamp": timestamp,
        "host": host,
        "event": "unknown",
        "username": None,
        "source_ip": None,
        "source_port": None,
    }

    failed_login = re.search(
        r"Failed password for (?:invalid user )?(\S+) from "
        r"(\d{1,3}(?:\.\d{1,3}){3}) port (\d+)",
        message,
    )

    successful_login = re.search(
        r"Accepted password for (\S+) from "
        r"(\d{1,3}(?:\.\d{1,3}){3}) port (\d+)",
        message,
    )

    if failed_login:
        event["event"] = "failed_login"
        event["username"] = failed_login.group(1)
        event["source_ip"] = failed_login.group(2)
        event["source_port"] = int(failed_login.group(3))

    elif successful_login:
        event["event"] = "successful_login"
        event["username"] = successful_login.group(1)
        event["source_ip"] = successful_login.group(2)
        event["source_port"] = int(successful_login.group(3))

    return event