import json

from duplicate_check import AlertIdStore
from gatekeeper import handle_alert
from replay_check import NonceStore
from seal_check import signature_is_valid
from sign_helper import make_signed_headers

SECRET = b"test-secret"
NOW = 1762246800
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
BODY = json.dumps(GOOD).encode("utf-8")


def test_three_headers_are_returned():
    headers = make_signed_headers(BODY, SECRET, now=NOW)
    assert set(headers) == {"X-Timestamp", "X-Nonce", "X-Signature"}


def test_timestamp_is_the_time_given():
    headers = make_signed_headers(BODY, SECRET, now=NOW)
    assert headers["X-Timestamp"] == str(NOW)


def test_each_call_gets_a_fresh_nonce():
    first = make_signed_headers(BODY, SECRET, now=NOW)
    second = make_signed_headers(BODY, SECRET, now=NOW)
    assert first["X-Nonce"] != second["X-Nonce"]


def test_signature_is_accepted_by_the_signature_check():
    h = make_signed_headers(BODY, SECRET, now=NOW)
    assert signature_is_valid(SECRET, h["X-Timestamp"], h["X-Nonce"],
                              BODY, h["X-Signature"])


def test_changed_body_does_not_match_the_signature():
    h = make_signed_headers(BODY, SECRET, now=NOW)
    changed = json.dumps(dict(GOOD, source_ip="203.0.113.8")).encode("utf-8")
    assert not signature_is_valid(SECRET, h["X-Timestamp"], h["X-Nonce"],
                                  changed, h["X-Signature"])


def test_wrong_secret_does_not_match_the_signature():
    h = make_signed_headers(BODY, SECRET, now=NOW)
    assert not signature_is_valid(b"other-secret", h["X-Timestamp"],
                                  h["X-Nonce"], BODY, h["X-Signature"])


def test_signed_alert_is_accepted_by_the_front_door(tmp_path):
    h = make_signed_headers(BODY, SECRET, now=NOW)
    result = handle_alert(BODY, h["X-Timestamp"], h["X-Nonce"],
                          h["X-Signature"], SECRET, NonceStore(),
                          AlertIdStore(), tmp_path / "audit.jsonl", NOW)
    assert result == ("accepted", "all checks passed")


def test_alert_changed_after_signing_is_rejected_by_the_front_door(tmp_path):
    h = make_signed_headers(BODY, SECRET, now=NOW)
    changed = json.dumps(dict(GOOD, source_ip="203.0.113.8")).encode("utf-8")
    result = handle_alert(changed, h["X-Timestamp"], h["X-Nonce"],
                          h["X-Signature"], SECRET, NonceStore(),
                          AlertIdStore(), tmp_path / "audit.jsonl", NOW)
    assert result == ("rejected", "signature is not valid")