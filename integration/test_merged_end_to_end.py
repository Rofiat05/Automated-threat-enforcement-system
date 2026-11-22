"""Integration tests for the real policy and merged Cisco Driver.

All network operations use temporary simulated Cisco ACL files.
No physical router is modified.
"""

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
API_FOLDER = ROOT / "enforcer_api"
MERGED_FOLDER = ROOT / "cisco_driver_merged"

if str(API_FOLDER) not in sys.path:
    sys.path.insert(0, str(API_FOLDER))

from api import create_app_from_env
from sign_helper import make_signed_headers


@pytest.fixture
def test_client(tmp_path, monkeypatch):
    """Create an isolated merged-mode API and simulated Cisco device."""

    # Select the merged Cisco package for this test only.
    # Other tests may already have imported the original package.
    monkeypatch.syspath_prepend(str(MERGED_FOLDER))

    for name in list(sys.modules):
        if name == "cisco_driver" or name.startswith("cisco_driver."):
            monkeypatch.delitem(sys.modules, name)

    monkeypatch.setenv(
        "ALERT_SECRET",
        "integration-test-secret"
    )
    monkeypatch.setenv(
        "ENFORCE_MODE",
        "merged"
    )
    monkeypatch.setenv(
        "AUDIT_LOG_PATH",
        str(tmp_path / "audit.jsonl")
    )
    monkeypatch.setenv(
        "MERGED_ACL_PATH",
        str(tmp_path / "acl.json")
    )
    monkeypatch.setenv(
        "MERGED_DB_PATH",
        str(tmp_path / "blocks.db")
    )

    app = create_app_from_env()

    with TestClient(app) as client:
        yield client, tmp_path


def send_alert(client, source_ip, window_start="Nov 22 10:00:00"):
    """Send a signed security alert to the actual API."""

    alert = {
        "host": "dataserver",
        "source_ip": source_ip,
        "criticality": "high",
        "window_start": window_start,
        "window_end": "Nov 22 10:05:00",
        "failed_attempts": 5,
        "threshold": 5,
        "alert": True,
    }

    body = json.dumps(alert).encode("utf-8")

    headers = make_signed_headers(
        body,
        b"integration-test-secret"
    )

    return client.post(
        "/v1/alerts",
        content=body,
        headers=headers,
    )


def test_untrusted_ip_is_blocked(test_client):
    """An untrusted IP should reach the merged Cisco Driver."""

    client, folder = test_client

    response = send_alert(client, "198.51.100.25")

    assert response.status_code == 202
    assert response.json()["action"] == "block"
    assert response.json()["enforcement"] == "applied"

    acl_path = folder / "acl.json"

    assert acl_path.exists()

    acl = json.loads(
        acl_path.read_text(encoding="utf-8")
    )

    assert "198.51.100.25" in json.dumps(acl)


def test_trusted_ip_is_ignored(test_client):
    """An allowlisted address must not be blocked."""

    client, folder = test_client

    response = send_alert(client, "192.168.1.20")

    assert response.status_code == 202
    assert response.json()["action"] == "ignore"
    assert response.json()["enforcement"] is None

    assert not (folder / "acl.json").exists()


def test_internal_ip_is_ignored(test_client):
    """A registered internal device must not be blocked."""

    client, folder = test_client

    response = send_alert(client, "192.168.1.50")

    assert response.status_code == 202
    assert response.json()["action"] == "ignore"
    assert response.json()["enforcement"] is None

    assert not (folder / "acl.json").exists()


def test_duplicate_alert_is_rejected(test_client):
    """The API should reject a repeated security alert."""

    client, folder = test_client

    first = send_alert(client, "198.51.100.25")
    second = send_alert(client, "198.51.100.25")

    assert first.status_code == 202
    assert second.status_code == 409

    assert first.json()["enforcement"] == "applied"


def test_block_is_recorded_in_audit(test_client):
    """Successful simulated enforcement must be recorded."""

    client, folder = test_client

    response = send_alert(client, "198.51.100.25")

    assert response.status_code == 202

    audit_path = folder / "audit.jsonl"

    assert audit_path.exists()

    entries = [
        json.loads(line)
        for line in audit_path.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    assert any(
        entry.get("decision") == "block applied"
        for entry in entries
    )
