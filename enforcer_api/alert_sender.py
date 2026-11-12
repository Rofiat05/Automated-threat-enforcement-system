import json
import os
import ssl
import sys
import time

import httpx

from sign_helper import make_signed_headers

DEFAULT_URL = "https://localhost:8443/v1/alerts"
ATTEMPTS = 2
WAIT_SECONDS = 2


def read_alerts(path):
    """Read B's output file: one JSON object per line.
    Returns (alerts, bad_lines). bad_lines holds the numbers of lines
    that could not be read."""
    alerts = []
    bad_lines = []
    with open(path, "r", encoding="utf-8") as f:
        for number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except ValueError:
                bad_lines.append(number)
                continue
            if isinstance(alert, dict):
                alerts.append(alert)
            else:
                bad_lines.append(number)
    return alerts, bad_lines


def make_ssl_context(cert_file=None):
    # certificate checking stays ON; a test certificate is only added as trusted
    if cert_file:
        return ssl.create_default_context(cafile=cert_file)
    return ssl.create_default_context()


def send_alert(alert, secret, url, client, wait=WAIT_SECONDS):
    body = json.dumps(alert).encode("utf-8")
    last_error = None
    for attempt in range(ATTEMPTS):
        headers = make_signed_headers(body, secret)
        headers["Content-Type"] = "application/json"
        try:
            response = client.post(url, content=body, headers=headers)
        except (httpx.ConnectError, httpx.TimeoutException) as error:
            last_error = error
            if "CERTIFICATE_VERIFY_FAILED" in str(error):
                break
            if attempt < ATTEMPTS - 1:
                time.sleep(wait)
            continue
        try:
            answer = response.json()
        except ValueError:
            answer = {}
        return {
            "status_code": response.status_code,
            "decision": answer.get("decision"),
            "reason": answer.get("reason"),
        }
    return {
        "status_code": None,
        "decision": "not sent",
        "reason": "could not connect: " + str(last_error),
    }


def send_file(path, secret, url, cert_file=None, wait=WAIT_SECONDS,
              client=None):
    alerts, bad_lines = read_alerts(path)
    own_client = client is None
    if own_client:
        client = httpx.Client(verify=make_ssl_context(cert_file), timeout=5.0)
    results = []
    below_threshold = 0
    try:
        for alert in alerts:
            if alert.get("alert") is not True:
                below_threshold += 1
                continue
            results.append((alert, send_alert(alert, secret, url, client, wait)))
    finally:
        if own_client:
            client.close()
    return {
        "results": results,
        "below_threshold": below_threshold,
        "bad_lines": bad_lines,
    }


def describe(alert, result):
    who = f"{alert.get('host')} {alert.get('source_ip')} {alert.get('window_start')}"
    return f"{who}: {result['status_code']} {result['decision']} ({result['reason']})"


def main():
    if len(sys.argv) != 2:
        print("Usage: python alert_sender.py <path to the alerts file>")
        sys.exit(1)
    secret = os.environ.get("ALERT_SECRET")
    if not secret:
        print("ALERT_SECRET is not set in this window.")
        sys.exit(1)
    url = os.environ.get("ALERT_URL", DEFAULT_URL)
    cert_file = os.environ.get("ALERT_CERT_FILE")

    try:
        report = send_file(sys.argv[1], secret.encode("utf-8"), url, cert_file)
    except OSError as error:
        print("Could not read a file: " + str(error))
        sys.exit(1)

    for alert, result in report["results"]:
        print(describe(alert, result))
    print(f"sent: {len(report['results'])}, "
          f"skipped (below threshold): {report['below_threshold']}, "
          f"unreadable lines: {len(report['bad_lines'])}")
    if any(result["status_code"] is None for _, result in report["results"]):
        sys.exit(1)


if __name__ == "__main__":
    main()