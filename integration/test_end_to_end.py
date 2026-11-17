
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
    """Simulate a Cisco device without changing a real router."""

    def __init__(self):
        self.rules = {}

    def list_rules(self):
        return dict(self.rules)

    def put_rule(self, rule_id, rule):
        self.rules[rule_id] = rule

    def delete_rule(self, rule_id):
        del self.rules[rule_id]


def test_end_to_end_offline(tmp_path):

    # STEP 1: Read and analyse Linux authentication logs.
    log_path = ROOT / "my-project" / "sample_data" / "auth.log"
    summaries_path = tmp_path / "alerts.jsonl"

    stats = run_preprocessor(
        [log_path],
        summaries_path,
        asset_criticality={"server01": "critical"},
    )

    assert stats["summaries_written"] == 1

    alert = json.loads(
        summaries_path.read_text(encoding="utf-8").splitlines()[0]
    )

    assert alert["failed_attempts"] == 3
    assert alert["alert"] is True

    # STEP 2: Prepare the alert for the updated validation API.
    secret = b"offline-test-secret"
    now = 1800000000
    timestamp = str(now)
    nonce = "test-nonce-1"

    api_alert = {
        "host": alert["host"],
        "source_ip": alert["source_ip"],
        "criticality": alert["criticality"],
        "window_start": alert["window_start"],
        "window_end": alert["window_end"],
        "failed_attempts": alert["failed_attempts"],
        "threshold": alert["threshold"],
        "alert": alert["alert"],
    }

    # STEP 3: Sign and validate the alert.
    body = json.dumps(api_alert).encode("utf-8")

    signature = make_signature(
        secret,
        timestamp,
        nonce,
        body,
    )

    decision, reason = handle_alert(
        body,
        timestamp,
        nonce,
        signature,
        secret,
        NonceStore(),
        AlertIdStore(),
        tmp_path / "gatekeeper_audit.jsonl",
        now,
    )

    assert decision == "accepted", reason

    # STEP 4: Simulate an approved Cisco blocking request.
    # This is test-only approval, NOT a real policy-engine decision.
    fake_device = FakeCiscoClient()

    request = {
        "action": "block",
        "approved": True,
        "source_ip": alert["source_ip"],
        "ttl": 30,
    }

    audit_path = tmp_path / "driver_audit.jsonl"

    # STEP 5: Verify the block is applied.
    assert block_approved(
        request,
        fake_device,
        audit_path,
    ) == "APPLIED"

    # STEP 6: Verify duplicate blocking is prevented.
    assert block_approved(
        request,
        fake_device,
        audit_path,
    ) == "ALREADY_PRESENT"

    assert len(fake_device.rules) == 1

    # STEP 7: Simulate expiry after 31 seconds.
    future = datetime.now(timezone.utc) + timedelta(seconds=31)

    assert cleanup(
        fake_device,
        audit_path,
        future,
    ) == [alert["source_ip"]]

    assert fake_device.rules == {}

    # STEP 8: Verify the Cisco Driver audit records.
    assert len(
        audit_path.read_text(encoding="utf-8").splitlines()
    ) == 3
