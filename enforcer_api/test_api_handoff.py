import json

import pytest
from fastapi.testclient import TestClient

from api import create_app, create_app_from_env
from sign_helper import make_signed_headers

SECRET = b"test-secret"
GOOD = {
    "host": "NORTHMEN-WEBSERVER",
    "source_ip": "203.0.113.7",
    "window_start": "Nov 12 10:00:00",
    "window_end": "Nov 12 10:05:00",
    "failed_attempts": 9,
    "criticality": "medium",
    "threshold": 8,
    "alert": True,
}
BLOCK = {
    "action": "block",
    "reason": "untrusted address",
    "control_point": "mock-router-1",
    "source_ip": "203.0.113.7",
    "ttl_seconds": 900,
}
IGNORE = {
    "action": "ignore",
    "reason": "trusted address on the allowlist",
    "control_point": None,
    "source_ip": "203.0.113.7",
    "ttl_seconds": 0,
}
APPLIED = {"status": "applied", "detail": "block added"}


class Recorder:
    """A pretend decide() or driver that remembers how it was called."""

    def __init__(self, answer=None):
        self.answer = answer
        self.calls = []

    def __call__(self, argument):
        self.calls.append(argument)
        return self.answer


def make_client(tmp_path, decide=None, apply_block=None):
    app = create_app(SECRET, tmp_path / "audit.jsonl", decide, apply_block)
    return TestClient(app)


def post(client, alert=GOOD, secret=SECRET, headers=None):
    body = json.dumps(alert).encode("utf-8")
    if headers is None:
        headers = make_signed_headers(body, secret)
    return client.post("/v1/alerts", content=body, headers=headers)


def audit_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    return [json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()]


def test_without_the_hand_off_the_reply_is_the_same_as_before(tmp_path):
    response = post(make_client(tmp_path))
    assert response.status_code == 202
    assert response.json() == {"decision": "accepted",
                               "reason": "all checks passed"}


def test_block_reply_shows_the_action_and_what_the_driver_did(tmp_path):
    client = make_client(tmp_path, Recorder(BLOCK), Recorder(APPLIED))
    response = post(client)
    assert response.status_code == 202
    assert response.json()["decision"] == "accepted"
    assert response.json()["action"] == "block"
    assert response.json()["enforcement"] == "applied"


def test_ignore_reply_does_not_call_the_driver(tmp_path):
    driver = Recorder(APPLIED)
    client = make_client(tmp_path, Recorder(IGNORE), driver)
    response = post(client)
    assert response.status_code == 202
    assert response.json()["action"] == "ignore"
    assert response.json()["enforcement"] is None
    assert driver.calls == []


def test_failed_block_is_still_accepted_but_reported(tmp_path):
    driver = Recorder({"status": "failed", "detail": "DeviceError"})
    client = make_client(tmp_path, Recorder(BLOCK), driver)
    response = post(client)
    assert response.status_code == 202
    assert response.json()["enforcement"] == "failed"


def test_rejected_alert_never_reaches_decide(tmp_path):
    decide = Recorder(BLOCK)
    driver = Recorder(APPLIED)
    client = make_client(tmp_path, decide, driver)
    body = json.dumps(GOOD).encode("utf-8")
    headers = make_signed_headers(body, SECRET)
    headers["X-Signature"] = "0" * 64
    response = post(client, headers=headers)
    assert response.status_code == 401
    assert decide.calls == []
    assert driver.calls == []


def test_same_attack_sent_twice_is_blocked_only_once(tmp_path):
    driver = Recorder(APPLIED)
    client = make_client(tmp_path, Recorder(BLOCK), driver)
    first = post(client)
    second = post(client)
    assert first.status_code == 202
    assert second.status_code == 409
    assert len(driver.calls) == 1


def test_outcome_is_written_to_the_audit_log(tmp_path):
    client = make_client(tmp_path, Recorder(BLOCK), Recorder(APPLIED))
    post(client)
    decisions = [entry["decision"] for entry in audit_lines(tmp_path)]
    assert decisions == ["accepted", "block applied"]


def set_up_environment(monkeypatch, tmp_path, mode=None):
    monkeypatch.setenv("ALERT_SECRET", "some-secret")
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    if mode is None:
        monkeypatch.delenv("ENFORCE_MODE", raising=False)
    else:
        monkeypatch.setenv("ENFORCE_MODE", mode)


def test_hand_off_is_off_unless_it_is_switched_on(monkeypatch, tmp_path):
    set_up_environment(monkeypatch, tmp_path)
    client = TestClient(create_app_from_env())
    response = post(client, secret=b"some-secret")
    assert response.status_code == 202
    assert "action" not in response.json()


def test_stub_mode_ignores_a_server_that_is_not_in_the_inventory(
        monkeypatch, tmp_path):
    set_up_environment(monkeypatch, tmp_path, "stub")
    client = TestClient(create_app_from_env())
    response = post(client, dict(GOOD, host="server01"), secret=b"some-secret")
    assert response.status_code == 202
    assert response.json()["action"] == "ignore"
    assert response.json()["detail"] == "server not in inventory"


def test_stub_mode_never_blocks_a_trusted_address(monkeypatch, tmp_path):
    set_up_environment(monkeypatch, tmp_path, "stub")
    client = TestClient(create_app_from_env())
    response = post(client, dict(GOOD, source_ip="192.168.1.10"),
                    secret=b"some-secret")
    assert response.status_code == 202
    assert response.json()["action"] == "ignore"
    assert response.json()["detail"] == "trusted address on the allowlist"


def test_unknown_mode_stops_the_service_from_starting(monkeypatch, tmp_path):
    set_up_environment(monkeypatch, tmp_path, "maybe")
    with pytest.raises(RuntimeError):
        create_app_from_env()