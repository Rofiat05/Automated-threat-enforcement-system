import json

from alert_id import make_alert_id
from audit_log import write_audit
from gatekeeper import handle_alert


def _finish(result, audit_path, now, alert_id, action, outcome, detail,
            enforcement=None):
    write_audit(audit_path, now, alert_id, outcome, detail)
    result["action"] = action
    result["enforcement"] = enforcement
    result["detail"] = detail
    return result


def process_alert(body, timestamp, nonce, signature, secret,
                  nonce_store, id_store, audit_path, now,
                  decide=None, apply_block=None):
    """Run the five checks; if the alert is accepted, ask decide() what to do
    and, for a block, hand it to the driver. Every outcome is audited."""
    decision, reason = handle_alert(body, timestamp, nonce, signature, secret,
                                    nonce_store, id_store, audit_path, now)
    result = {"decision": decision, "reason": reason}

    # rejected alerts stop here; without a decision function, so does everything
    if decision != "accepted" or decide is None:
        return result

    alert = json.loads(body)
    alert_id = make_alert_id(alert["host"], alert["source_ip"],
                             alert["window_start"], alert["window_end"])

    # a crash or a strange answer must never cause a block
    try:
        answer = decide(alert)
    except Exception as error:
        return _finish(result, audit_path, now, alert_id, None,
                       "decision failed", type(error).__name__)
    if not isinstance(answer, dict) or answer.get("action") not in ("block", "ignore"):
        return _finish(result, audit_path, now, alert_id, None,
                       "decision failed", "unexpected answer from decide")

    if answer["action"] == "ignore":
        return _finish(result, audit_path, now, alert_id, "ignore",
                       "ignored", str(answer.get("reason")))

    # the decision is to block
    if apply_block is None:
        return _finish(result, audit_path, now, alert_id, "block",
                       "block not applied", "no driver configured", "failed")
    try:
        outcome = apply_block(answer)
    except Exception as error:
        outcome = {"status": "failed", "detail": type(error).__name__}

    if isinstance(outcome, dict):
        status = outcome.get("status")
        detail = str(outcome.get("detail"))
    else:
        status = None
        detail = "unexpected answer from the driver"
    if status not in ("applied", "already_applied"):
        status = "failed"
    return _finish(result, audit_path, now, alert_id, "block",
                   "block " + status, detail, status)