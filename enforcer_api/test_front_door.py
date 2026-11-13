import json

import pytest

from alert_id import make_alert_id
from duplicate_check import AlertIdStore
from front_door import process_alert
from replay_check import NonceStore
from seal_check import make_signature

SECRET = b"test-secret"
NOW = 1762246800
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

    def __init__(self, answer=None, error=None):
        self.answer = answer
        self.error = error
        self.calls = []

    def __call__(self, argument):
        self.calls.append(argument)
        if self.error is not None:
            raise self.error
        return self.answer


def make_body(alert=GOOD):
    return json.dumps(alert).encode("utf-8")


def send(tmp_path, decide=None, apply_block=None, body=None, nonce="nonce-1",
         signature=None, nonce_store=None, id_store=None, now=NOW):
    if body is None:
        body = make_body()
    timestamp = str(NOW)
    if signature is None:
        signature = make_signature(SECRET, timestamp, nonce, body)
    if nonce_store is None:
        nonce_store = NonceStore()
    if id_store is None:
        id_store = AlertIdStore()
    return process_alert(body, timestamp, nonce, signature, SECRET,
                         nonce_store, id_store, tmp_path / "audit.jsonl", now,
                         decide=decide, apply_block=apply_block)


def audit_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    return [json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()]


def test_without_a_decision_function_the_answer_is_unchanged(tmp_path):
    assert send(tmp_path) == {"decision": "accepted",
                              "reason": "all checks passed"}


def test_rejected_alert_never_reaches_decide_or_the_driver(tmp_path):
    decide = Recorder(BLOCK)
    driver = Recorder(APPLIED)
    result = send(tmp_path, decide, driver, signature="0" * 64)
    assert result["decision"] == "rejected"
    assert decide.calls == []
    assert driver.calls == []
    assert "action" not in result


def test_decide_receives_the_alert(tmp_path):
    decide = Recorder(IGNORE)
    send(tmp_path, decide)
    assert decide.calls == [GOOD]


def test_ignore_decision_stops_before_the_driver(tmp_path):
    decide = Recorder(IGNORE)
    driver = Recorder(APPLIED)
    result = send(tmp_path, decide, driver)
    assert result["decision"] == "accepted"
    assert result["action"] == "ignore"
    assert result["enforcement"] is None
    assert driver.calls == []
    last = audit_lines(tmp_path)[-1]
    assert last["decision"] == "ignored"
    assert last["reason"] == "trusted address on the allowlist"


def test_block_decision_is_handed_to_the_driver(tmp_path):
    decide = Recorder(BLOCK)
    driver = Recorder(APPLIED)
    result = send(tmp_path, decide, driver)
    assert result["action"] == "block"
    assert result["enforcement"] == "applied"
    assert driver.calls == [BLOCK]
    assert audit_lines(tmp_path)[-1]["decision"] == "block applied"


def test_address_that_is_already_blocked_is_reported(tmp_path):
    driver = Recorder({"status": "already_applied",
                       "detail": "address was already blocked"})
    result = send(tmp_path, Recorder(BLOCK), driver)
    assert result["enforcement"] == "already_applied"
    assert audit_lines(tmp_path)[-1]["decision"] == "block already_applied"


def test_driver_that_fails_is_reported_and_audited(tmp_path):
    driver = Recorder({"status": "failed", "detail": "DeviceError: no connection"})
    result = send(tmp_path, Recorder(BLOCK), driver)
    assert result["decision"] == "accepted"
    assert result["enforcement"] == "failed"
    assert audit_lines(tmp_path)[-1]["decision"] == "block failed"


def test_driver_that_crashes_does_not_crash_the_front_door(tmp_path):
    driver = Recorder(error=RuntimeError("boom"))
    result = send(tmp_path, Recorder(BLOCK), driver)
    assert result["enforcement"] == "failed"
    last = audit_lines(tmp_path)[-1]
    assert last["decision"] == "block failed"
    assert last["reason"] == "RuntimeError"


def test_driver_that_gives_a_strange_answer_counts_as_failed(tmp_path):
    result = send(tmp_path, Recorder(BLOCK), Recorder("APPLIED"))
    assert result["enforcement"] == "failed"
    last = audit_lines(tmp_path)[-1]
    assert last["decision"] == "block failed"
    assert last["reason"] == "unexpected answer from the driver"


def test_decide_that_crashes_blocks_nothing(tmp_path):
    driver = Recorder(APPLIED)
    result = send(tmp_path, Recorder(error=ValueError("bad")), driver)
    assert result["decision"] == "accepted"
    assert result["action"] is None
    assert driver.calls == []
    last = audit_lines(tmp_path)[-1]
    assert last["decision"] == "decision failed"
    assert last["reason"] == "ValueError"


@pytest.mark.parametrize("strange", [None, "block", {"action": "maybe"}, []])
def test_strange_decision_blocks_nothing(tmp_path, strange):
    driver = Recorder(APPLIED)
    send(tmp_path, Recorder(strange), driver)
    assert driver.calls == []
    assert audit_lines(tmp_path)[-1]["decision"] == "decision failed"


def test_block_without_a_driver_is_not_applied(tmp_path):
    result = send(tmp_path, Recorder(BLOCK), None)
    assert result["enforcement"] == "failed"
    assert audit_lines(tmp_path)[-1]["decision"] == "block not applied"


def test_audit_log_has_a_line_from_the_gatekeeper_and_one_for_the_outcome(tmp_path):
    send(tmp_path, Recorder(BLOCK), Recorder(APPLIED))
    lines = audit_lines(tmp_path)
    expected_id = make_alert_id(GOOD["host"], GOOD["source_ip"],
                                GOOD["window_start"], GOOD["window_end"])
    assert len(lines) == 2
    assert lines[0]["decision"] == "accepted"
    assert lines[1]["decision"] == "block applied"
    assert lines[0]["alert_id"] == expected_id
    assert lines[1]["alert_id"] == expected_id


def test_replayed_request_does_not_call_decide_again(tmp_path):
    nonces, ids = NonceStore(), AlertIdStore()
    decide = Recorder(IGNORE)
    send(tmp_path, decide, nonce_store=nonces, id_store=ids)
    second = send(tmp_path, decide, nonce_store=nonces, id_store=ids, now=NOW + 5)
    assert second["decision"] == "rejected"
    assert len(decide.calls) == 1


def test_same_attack_with_a_new_nonce_is_not_blocked_twice(tmp_path):
    nonces, ids = NonceStore(), AlertIdStore()
    decide = Recorder(BLOCK)
    driver = Recorder(APPLIED)
    send(tmp_path, decide, driver, nonce="nonce-1",
         nonce_store=nonces, id_store=ids)
    second = send(tmp_path, decide, driver, nonce="nonce-2",
                  nonce_store=nonces, id_store=ids, now=NOW + 5)
    assert second["reason"] == "duplicate alert"
    assert len(decide.calls) == 1
    assert len(driver.calls) == 1