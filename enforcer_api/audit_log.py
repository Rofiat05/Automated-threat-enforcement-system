import json


def write_audit(path, now, alert_id, decision, reason):
    entry = {
        "time": now,
        "alert_id": alert_id,
        "decision": decision,
        "reason": reason,
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
        