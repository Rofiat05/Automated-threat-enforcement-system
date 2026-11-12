import json
import ssl

import httpx
import pytest
from fastapi.testclient import TestClient

from alert_sender import make_ssl_context, read_alerts, send_file
from api import create_app

SECRET = b"test-secret"
URL = "/v1/alerts"
GOOD = {
    "host": "web01",
    "source_ip": "203.0.113.7",
    "window_start": "Nov 05 10:00:00",
    "window_end": "Nov 05 10:05:00",
    "failed_attempts": 5,
    "criticality": "high",
    "threshold": 5,
    "alert": True,
}


class FailingClient:
    """A pretend client that can never connect."""

    def __init__(self, error):
        self.error = error
        self.calls = 0

    def post(self, url, content=None, headers=None):
        self.calls += 1
        raise self.error


class CountingClient:
    """Wraps the real endpoint, counts the calls and can fail the first ones."""

    def __init__(self, real, fail_first=0):
        self.real = real
        self.fail_first = fail_first
        self.calls = 0

    def post(self, url, content=None, headers=None):
        self.calls += 1
        if self.calls <= self.fail_first:
            raise httpx.ConnectError("connection refused")
        return self.real.post(url, content=content, headers=headers)


def make_client(tmp_path):
    return TestClient(create_app(SECRET, tmp_path / "audit.jsonl"))


def write_alerts(path, alerts, extra_lines=()):
    lines = [json.dumps(a) for a in alerts] + list(extra_lines)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_read_alerts_reads_good_lines_and_reports_bad_ones(tmp_path):
    path = tmp_path / "alerts.jsonl"
    write_alerts(path, [GOOD], extra_lines=["not json", "[1, 2]", ""])
    alerts, bad_lines = read_alerts(path)
    assert alerts == [GOOD]
    assert bad_lines == [2, 3]


def test_missing_file_raises_an_error(tmp_path):
    with pytest.raises(OSError):
        read_alerts(tmp_path / "nothing.jsonl")


def test_only_alerts_above_the_threshold_are_sent(tmp_path):
    path = tmp_path / "alerts.jsonl"
    below = dict(GOOD, source_ip="203.0.113.8", alert=False)
    write_alerts(path, [GOOD, below])
    report = send_file(path, SECRET, URL, client=make_client(tmp_path))
    assert len(report["results"]) == 1
    assert report["below_threshold"] == 1


def test_good_alert_is_accepted_by_the_real_endpoint(tmp_path):
    path = tmp_path / "alerts.jsonl"
    write_alerts(path, [GOOD])
    report = send_file(path, SECRET, URL, client=make_client(tmp_path))
    result = report["results"][0][1]
    assert result["status_code"] == 202
    assert result["decision"] == "accepted"


def test_two_different_alerts_are_both_accepted(tmp_path):
    path = tmp_path / "alerts.jsonl"
    other = dict(GOOD, source_ip="203.0.113.8")
    write_alerts(path, [GOOD, other])
    report = send_file(path, SECRET, URL, client=make_client(tmp_path))
    codes = [result["status_code"] for _, result in report["results"]]
    assert codes == [202, 202]


def test_sending_the_same_file_twice_gives_409_the_second_time(tmp_path):
    path = tmp_path / "alerts.jsonl"
    write_alerts(path, [GOOD])
    client = make_client(tmp_path)
    send_file(path, SECRET, URL, client=client)
    report = send_file(path, SECRET, URL, client=client)
    result = report["results"][0][1]
    assert result["status_code"] == 409
    assert result["reason"] == "duplicate alert"


def test_answer_409_is_not_retried(tmp_path):
    path = tmp_path / "alerts.jsonl"
    write_alerts(path, [GOOD])
    client = CountingClient(make_client(tmp_path))
    send_file(path, SECRET, URL, client=client)
    send_file(path, SECRET, URL, client=client)
    assert client.calls == 2


def test_wrong_secret_gets_401(tmp_path):
    path = tmp_path / "alerts.jsonl"
    write_alerts(path, [GOOD])
    report = send_file(path, b"other-secret", URL, client=make_client(tmp_path))
    assert report["results"][0][1]["status_code"] == 401


def test_command_hidden_in_ip_is_refused_by_the_front_door(tmp_path):
    path = tmp_path / "alerts.jsonl"
    bad = dict(GOOD, source_ip="1.2.3.4; shutdown")
    write_alerts(path, [bad])
    report = send_file(path, SECRET, URL, client=make_client(tmp_path))
    assert report["results"][0][1]["status_code"] == 400


def test_connection_failure_is_retried_once_then_reported(tmp_path):
    path = tmp_path / "alerts.jsonl"
    write_alerts(path, [GOOD])
    client = FailingClient(httpx.ConnectError("connection refused"))
    report = send_file(path, SECRET, URL, wait=0, client=client)
    result = report["results"][0][1]
    assert client.calls == 2
    assert result["status_code"] is None
    assert result["decision"] == "not sent"


def test_connection_that_works_on_the_second_try_is_accepted(tmp_path):
    path = tmp_path / "alerts.jsonl"
    write_alerts(path, [GOOD])
    client = CountingClient(make_client(tmp_path), fail_first=1)
    report = send_file(path, SECRET, URL, wait=0, client=client)
    result = report["results"][0][1]
    assert client.calls == 2
    assert result["status_code"] == 202


def test_certificate_failure_is_not_retried(tmp_path):
    path = tmp_path / "alerts.jsonl"
    write_alerts(path, [GOOD])
    client = FailingClient(httpx.ConnectError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate"))
    report = send_file(path, SECRET, URL, wait=0, client=client)
    assert client.calls == 1
    assert report["results"][0][1]["status_code"] is None


def test_certificate_checking_is_on_by_default():
    context = make_ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True