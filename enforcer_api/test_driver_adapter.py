import json
from datetime import datetime, timezone

import pytest

from driver_adapter import apply_block, load_driver

_, DeviceError = load_driver()

DECISION = {
    "action": "block",
    "reason": "untrusted address",
    "control_point": "mock-router-1",
    "source_ip": "198.51.100.25",
    "ttl_seconds": 900,
}
RULE_ID = "com732-198-51-100-25"


class FakeDevice:
    """A pretend device that keeps its rules in memory."""

    def __init__(self, fail_on_list=False, forget_rules=False):
        self.rules = {}
        self.puts = 0
        self.fail_on_list = fail_on_list
        self.forget_rules = forget_rules

    def list_rules(self):
        if self.fail_on_list:
            raise DeviceError("Device connection failed or timed out")
        return dict(self.rules)

    def put_rule(self, rule_id, rule):
        self.puts += 1
        if not self.forget_rules:
            self.rules[rule_id] = rule
        return {}


def test_block_is_applied(tmp_path):
    device = FakeDevice()
    result = apply_block(DECISION, tmp_path / "audit.jsonl", device)
    assert result["status"] == "applied"
    assert RULE_ID in device.rules


def test_rule_holds_the_address_and_ends_after_the_time_limit(tmp_path):
    device = FakeDevice()
    apply_block(DECISION, tmp_path / "audit.jsonl", device)
    rule = device.rules[RULE_ID]
    assert rule["source_ip"] == "198.51.100.25"
    expires = datetime.fromisoformat(rule["expires_at"])
    seconds_left = (expires - datetime.now(timezone.utc)).total_seconds()
    assert 880 <= seconds_left <= 900


def test_same_address_twice_is_already_applied(tmp_path):
    device = FakeDevice()
    audit = tmp_path / "audit.jsonl"
    first = apply_block(DECISION, audit, device)
    second = apply_block(DECISION, audit, device)
    assert first["status"] == "applied"
    assert second["status"] == "already_applied"
    assert device.puts == 1


def test_ignore_decision_is_never_sent_to_the_driver(tmp_path):
    device = FakeDevice()
    result = apply_block(dict(DECISION, action="ignore"),
                         tmp_path / "audit.jsonl", device)
    assert result["status"] == "failed"
    assert device.puts == 0
    assert device.rules == {}


def test_decision_that_is_not_a_dictionary_fails(tmp_path):
    device = FakeDevice()
    result = apply_block("block", tmp_path / "audit.jsonl", device)
    assert result["status"] == "failed"
    assert device.puts == 0


@pytest.mark.parametrize("bad_ip", [
    "not-an-ip", "1.2.3.4; shutdown", None, "2001:db8::1"])
def test_bad_address_fails_and_nothing_is_blocked(tmp_path, bad_ip):
    device = FakeDevice()
    result = apply_block(dict(DECISION, source_ip=bad_ip),
                         tmp_path / "audit.jsonl", device)
    assert result["status"] == "failed"
    assert device.puts == 0


@pytest.mark.parametrize("bad_ttl", [0, -5, 86401, None, "900", 1.5, True])
def test_time_limit_must_be_between_1_and_86400(tmp_path, bad_ttl):
    device = FakeDevice()
    result = apply_block(dict(DECISION, ttl_seconds=bad_ttl),
                         tmp_path / "audit.jsonl", device)
    assert result["status"] == "failed"
    assert device.puts == 0


def test_longest_allowed_time_limit_is_accepted(tmp_path):
    device = FakeDevice()
    result = apply_block(dict(DECISION, ttl_seconds=86400),
                         tmp_path / "audit.jsonl", device)
    assert result["status"] == "applied"


def test_device_that_cannot_be_reached_gives_failed(tmp_path):
    device = FakeDevice(fail_on_list=True)
    result = apply_block(DECISION, tmp_path / "audit.jsonl", device)
    assert result["status"] == "failed"
    assert "DeviceError" in result["detail"]


def test_block_that_cannot_be_confirmed_gives_failed(tmp_path):
    device = FakeDevice(forget_rules=True)
    result = apply_block(DECISION, tmp_path / "audit.jsonl", device)
    assert result["status"] == "failed"
    assert "Read-back" in result["detail"]


def test_driver_writes_its_own_audit_line(tmp_path):
    audit = tmp_path / "audit.jsonl"
    apply_block(DECISION, audit, FakeDevice())
    entry = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
    assert entry["status"] == "applied"
    assert entry["source_ip"] == "198.51.100.25"


def test_failed_attempt_is_also_audited(tmp_path):
    audit = tmp_path / "audit.jsonl"
    apply_block(dict(DECISION, source_ip="not-an-ip"), audit, FakeDevice())
    entry = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
    assert entry["status"].startswith("failed")