import json
import os
import ssl
import sys
import time

import httpx

from sign_helper import make_signed_headers

URL = os.environ.get("ALERT_URL", "https://localhost:8443/v1/alerts")
TIME_FORMAT = "%b %d %H:%M:%S"


def make_ssl_context():
    # certificate checking stays ON; we only add our own certificate as trusted
    cert_file = os.environ.get("ALERT_CERT_FILE")
    if cert_file:
        return ssl.create_default_context(cafile=cert_file)
    return ssl.create_default_context()


def fresh_alert(**changes):
    # a new alert whose time window starts right now, so each run is new
    start = time.time()
    alert = {
        "host": "web01",
        "source_ip": "203.0.113.10",
        "window_start": time.strftime(TIME_FORMAT, time.localtime(start)),
        "window_end": time.strftime(TIME_FORMAT, time.localtime(start + 300)),
        "failed_attempts": 5,
        "criticality": "high",
        "threshold": 5,
        "alert": True,
    }
    alert.update(changes)
    return alert


def to_body(alert):
    return json.dumps(alert).encode("utf-8")


def post(secret, body, headers=None):
    if headers is None:
        headers = make_signed_headers(body, secret)
    return httpx.post(URL, content=body, headers=headers, timeout=5.0,
                      verify=make_ssl_context())


def show(label, response):
    print(f"{label}: {response.status_code} {response.json()}")


def good(secret):
    body = to_body(fresh_alert(source_ip="203.0.113.10"))
    show("good alert", post(secret, body))


def replay(secret):
    body = to_body(fresh_alert(source_ip="203.0.113.11"))
    headers = make_signed_headers(body, secret)
    show("replay, first send", post(secret, body, headers))
    show("replay, same request sent again", post(secret, body, headers))


def duplicate(secret):
    body = to_body(fresh_alert(source_ip="203.0.113.12"))
    show("duplicate, first send", post(secret, body))
    show("duplicate, same attack with a new nonce", post(secret, body))


def tampered(secret):
    alert = fresh_alert(source_ip="203.0.113.13")
    headers = make_signed_headers(to_body(alert), secret)
    changed = to_body(dict(alert, source_ip="203.0.113.99"))
    show("alert changed after signing", post(secret, changed, headers))


def stale(secret):
    body = to_body(fresh_alert(source_ip="203.0.113.14"))
    headers = make_signed_headers(body, secret, now=int(time.time()) - 3600)
    show("old timestamp", post(secret, body, headers))


def below(secret):
    body = to_body(fresh_alert(source_ip="203.0.113.15", alert=False))
    show("below threshold", post(secret, body))


def injection(secret):
    body = to_body(fresh_alert(source_ip="203.0.113.16; shutdown"))
    show("command hidden in the IP", post(secret, body))


SCENARIOS = {
    "good": good,
    "replay": replay,
    "duplicate": duplicate,
    "tampered": tampered,
    "stale": stale,
    "below": below,
    "injection": injection,
}


def main():
    secret = os.environ.get("ALERT_SECRET")
    if not secret:
        print("ALERT_SECRET is not set in this window.")
        sys.exit(1)
    secret = secret.encode("utf-8")

    name = sys.argv[1] if len(sys.argv) > 1 else "all"
    if name != "all" and name not in SCENARIOS:
        print("Choose one of: all, " + ", ".join(SCENARIOS))
        sys.exit(1)

    chosen = SCENARIOS.values() if name == "all" else [SCENARIOS[name]]
    try:
        for scenario in chosen:
            scenario(secret)
    except httpx.ConnectError as error:
        print("Could not connect to the service: " + str(error))
        print("Check that it is running, and that ALERT_CERT_FILE is set.")
        sys.exit(1)


if __name__ == "__main__":
    main()