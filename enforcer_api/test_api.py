import json
import time

import pytest
from fastapi.testclient import TestClient

from api import create_app, create_app_from_env
from sign_helper import make_signed_headers

SECRET = b"test-secret"
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


def make_client(tmp_path):
    return TestClient(create_app(SECRET, tmp_path / "audit.jsonl"))


def post(client, alert=GOOD, headers=None, body=None):
    if body is None:
        body = json.dumps(alert).encode("utf-8")
    if headers is None:
        headers = make_signed_headers(body, SECRET)
    return client.post("/v1/alerts", content=body, headers=headers)


def test_health_check_says_ok(tmp_path):
    response = make_client(tmp_path).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_good_alert_returns_202(tmp_path):
    response = post(make_client(tmp_path))
    assert response.status_code == 202
    assert response.json() == {"decision": "accepted",
                               "reason": "all checks passed"}


def test_body_that_is_not_json_returns_400(tmp_path):
    response = post(make_client(tmp_path), body=b"not json")
    assert response.status_code == 400
    assert response.json()["reason"] == "body is not valid JSON"


def test_command_hidden_in_ip_returns_400(tmp_path):
    bad = dict(GOOD, source_ip="1.2.3.4; shutdown")
    response = post(make_client(tmp_path), alert=bad)
    assert response.status_code == 400
    assert "source_ip" in response.json()["reason"]


def test_alert_below_threshold_returns_400(tmp_path):
    below = dict(GOOD, alert=False)
    response = post(make_client(tmp_path), alert=below)
    assert response.status_code == 400


def test_wrong_signature_returns_401(tmp_path):
    body = json.dumps(GOOD).encode("utf-8")
    headers = make_signed_headers(body, SECRET)
    headers["X-Signature"] = "0" * 64
    response = post(make_client(tmp_path), body=body, headers=headers)
    assert response.status_code == 401
    assert response.json()["reason"] == "signature is not valid"


def test_missing_headers_return_401(tmp_path):
    response = post(make_client(tmp_path), headers={})
    assert response.status_code == 401


def test_old_timestamp_returns_401(tmp_path):
    body = json.dumps(GOOD).encode("utf-8")
    headers = make_signed_headers(body, SECRET, now=int(time.time()) - 3600)
    response = post(make_client(tmp_path), body=body, headers=headers)
    assert response.status_code == 401
    assert response.json()["reason"] == "timestamp is too old or not valid"


def test_replayed_request_returns_409(tmp_path):
    client = make_client(tmp_path)
    body = json.dumps(GOOD).encode("utf-8")
    headers = make_signed_headers(body, SECRET)
    first = post(client, body=body, headers=headers)
    second = post(client, body=body, headers=headers)
    assert first.status_code == 202
    assert second.status_code == 409
    assert second.json()["reason"] == "nonce was already used (replay)"


def test_same_attack_with_new_nonce_returns_409(tmp_path):
    client = make_client(tmp_path)
    first = post(client)
    second = post(client)
    assert first.status_code == 202
    assert second.status_code == 409
    assert second.json()["reason"] == "duplicate alert"


def test_body_that_is_too_large_returns_413(tmp_path):
    response = post(make_client(tmp_path), body=b"x" * 10001)
    assert response.status_code == 413


def test_decision_is_written_to_the_audit_log(tmp_path):
    post(make_client(tmp_path))
    log = tmp_path / "audit.jsonl"
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["decision"] == "accepted"


def test_service_refuses_to_start_without_a_secret(monkeypatch):
    monkeypatch.delenv("ALERT_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        create_app_from_env()


def test_service_starts_when_secret_is_set(monkeypatch, tmp_path):
    monkeypatch.setenv("ALERT_SECRET", "some-secret")
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    client = TestClient(create_app_from_env())
    assert client.get("/health").status_code == 200