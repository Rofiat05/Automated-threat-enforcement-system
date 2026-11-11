"""Test the connection between log processing, alert validation and simulated Cisco blocking."""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "my-project"))
sys.path.insert(0, str(ROOT / "enforcer_api"))
sys.path.insert(0, str(ROOT / "cisco_driver" / "com732_build"))

from preprocessor.main import run_preprocessor
from gatekeeper import handle_alert
from duplicate_check import AlertIdStore
from replay_check import NonceStore
from seal_check import make_signature
from cisco_driver.enforcer import block_approved
from cisco_driver.expiry import cleanup


class FakeCiscoClient:
    def __init__(self):
        self.rules = {}
    def list_rules(self):
        return dict(self.rules)
    def put_rule(self, rule_id, rule):
        self.rules[rule_id] = rule
    def delete_rule(self, rule_id):
        del self.rules[rule_id]


def test_end_to_end_offline(tmp_path):
    log_path = ROOT / "my-project" / "sample_data" / "auth.log"
    summaries_path = tmp_path / "alerts.jsonl"
    stats = run_preprocessor([log_path], summaries_path,
                             asset_criticality={"server01": "critical"})
    assert stats["summaries_written"] == 1
    alert = json.loads(summaries_path.read_text(encoding="utf-8").splitlines()[0])
    assert alert["failed_attempts"] == 3
    assert alert["alert"] is True

    secret = b"offline-test-secret"
    now = 1800000000
    timestamp = str(now)
    nonce = "test-nonce-1"
    # Adapter: the preprocessor produces a rich summary, while the API accepts
    # only these four fields. Preserve the original summary for auditing.
    api_alert = {
        "host": alert["host"],
        "source_ip": alert["source_ip"],
        "count": alert["failed_attempts"],
        "criticality": alert["criticality"],
    }
    body = json.dumps(api_alert).encode("utf-8")
    signature = make_signature(secret, timestamp, nonce, body)
    decision, reason = handle_alert(body, timestamp, nonce, signature, secret,
                                     NonceStore(), AlertIdStore(),
                                     tmp_path / "gatekeeper_audit.jsonl", now)
    assert decision == "accepted", reason

    # Explicit test-only authorisation. Real policy approval is NOT implemented.
    fake_device = FakeCiscoClient()
    request = {"action": "block", "approved": True,
               "source_ip": alert["source_ip"], "ttl": 30}
    audit_path = tmp_path / "driver_audit.jsonl"
    assert block_approved(request, fake_device, audit_path) == "APPLIED"
    assert block_approved(request, fake_device, audit_path) == "ALREADY_PRESENT"
    assert len(fake_device.rules) == 1
    future = datetime.now(timezone.utc) + timedelta(seconds=31)
    assert cleanup(fake_device, audit_path, future) == [alert["source_ip"]]
    assert fake_device.rules == {}
    assert len(audit_path.read_text(encoding="utf-8").splitlines()) == 3
