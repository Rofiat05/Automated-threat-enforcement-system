import json

from alert_checks import check_alert
from alert_id import make_alert_id
from audit_log import write_audit
from duplicate_check import AlertIdStore
from freshness_check import timestamp_is_fresh
from replay_check import NonceStore
from seal_check import signature_is_valid

WINDOW_SECONDS = 300


def _reject(audit_path, now, alert_id, reason):
    write_audit(audit_path, now, alert_id, "rejected", reason)
    return "rejected", reason


def handle_alert(body, timestamp, nonce, signature, secret,
                 nonce_store, id_store, audit_path, now):
    # check 1: form
    try:
        alert = json.loads(body)
    except ValueError:
        return _reject(audit_path, now, None, "body is not valid JSON")
    if not isinstance(alert, dict):
        return _reject(audit_path, now, None, "body is not a JSON object")
    problems = check_alert(alert)
    if problems:
        return _reject(audit_path, now, None, "; ".join(problems))

    # check 2: signature
    try:
        signature_ok = signature_is_valid(secret, timestamp, nonce, body, signature)
    except (TypeError, ValueError, AttributeError):
        signature_ok = False
    if not signature_ok:
        return _reject(audit_path, now, None, "signature is not valid")

    # check 3: freshness
    if not timestamp_is_fresh(timestamp, now):
        return _reject(audit_path, now, None, "timestamp is too old or not valid")

    # check 4: replay
    if nonce_store.is_replay(nonce, now):
        return _reject(audit_path, now, None, "nonce was already used (replay)")

    # check 5: duplicate
    window_start = int(timestamp) // WINDOW_SECONDS * WINDOW_SECONDS
    alert_id = make_alert_id(alert["host"], alert["source_ip"],
                             window_start, WINDOW_SECONDS)
    if id_store.is_duplicate(alert_id, now):
        return _reject(audit_path, now, alert_id, "duplicate alert")

    write_audit(audit_path, now, alert_id, "accepted", "all checks passed")
    return "accepted", "all checks passed"
