import json

from duplicate_check import AlertIdStore
from gatekeeper import handle_alert
from replay_check import NonceStore
from seal_check import make_signature

SECRET = b"test-secret"
NOW = 1762246800
GOOD = {"host": "web01", "source_ip": "203.0.113.7",
        "count": 5, "criticality": "high"}


def make_body(alert=GOOD):
    return json.dumps(alert).encode("utf-8")


def send(tmp_path, body=None, timestamp=None, nonce="nonce-1", signature=None,
         nonce_store=None, id_store=None, now=NOW):
    if body is None:
        body = make_body()
    if timestamp is None:
        timestamp = str(NOW)
    if signature is None:
        signature = make_signature(SECRET, timestamp, nonce, body)
    if nonce_store is None:
        nonce_store = NonceStore()
    if id_store is None:
        id_store = AlertIdStore()
    return handle_alert(body, timestamp, nonce, signature, SECRET,
                        nonce_store, id_store, tmp_path / "audit.jsonl", now)


def test_good_alert_is_accepted(tmp_path):
    assert send(tmp_path) == ("accepted", "all checks passed")


def test_body_that_is_not_json_is_rejected(tmp_path):
    result = send(tmp_path, body=b"this is not json")
    assert result == ("rejected", "body is not valid JSON")


def test_command_hidden_in_ip_is_rejected(tmp_path):
    bad = dict(GOOD, source_ip="1.2.3.4; shutdown")
    result = send(tmp_path, body=make_body(bad))
    assert result[0] == "rejected"
    assert "source_ip" in result[1]


def test_alert_changed_after_sealing_is_rejected(tmp_path):
    original = make_body()
    sig = make_signature(SECRET, str(NOW), "nonce-1", original)
    changed = make_body(dict(GOOD, source_ip="203.0.113.8"))
    result = send(tmp_path, body=changed, signature=sig)
    assert result == ("rejected", "signature is not valid")


def test_wrong_signature_is_rejected(tmp_path):
    result = send(tmp_path, signature="0" * 64)
    assert result == ("rejected", "signature is not valid")


def test_old_timestamp_is_rejected(tmp_path):
    result = send(tmp_path, timestamp=str(NOW - 3600))
    assert result == ("rejected", "timestamp is too old or not valid")


def test_same_nonce_twice_is_a_replay(tmp_path):
    nonces = NonceStore()
    ids = AlertIdStore()
    send(tmp_path, nonce_store=nonces, id_store=ids)
    result = send(tmp_path, nonce_store=nonces, id_store=ids, now=NOW + 5)
    assert result == ("rejected", "nonce was already used (replay)")


def test_same_attack_with_new_nonce_is_a_duplicate(tmp_path):
    nonces = NonceStore()
    ids = AlertIdStore()
    send(tmp_path, nonce="nonce-1", nonce_store=nonces, id_store=ids)
    result = send(tmp_path, nonce="nonce-2", nonce_store=nonces,
                  id_store=ids, now=NOW + 5)
    assert result == ("rejected", "duplicate alert")


def test_decision_is_written_to_the_audit_log(tmp_path):
    send(tmp_path)
    log = tmp_path / "audit.jsonl"
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["decision"] == "accepted"
    assert len(entry["alert_id"]) == 64