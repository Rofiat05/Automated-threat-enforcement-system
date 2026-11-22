"""Test the real policy and merged Cisco Driver through the API.

All network changes are simulated and stored in temporary files.
"""

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
API_FOLDER = ROOT / "enforcer_api"

if str(API_FOLDER) not in sys.path:
    sys.path.insert(0, str(API_FOLDER))

from api import create_app_from_env
from sign_helper import make_signed_headers


@pytest.fixture
def test_client(tmp_path, monkeypatch):
    monkeypatch.setenv("ALERT_SECRET", "integration-test-secret")
    monkeypatch.setenv("ENFORCE_MODE", "merged")
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("MERGED_ACL_PATH", str(tmp_path / "acl.json"))
    monkeypatch.setenv("MERGED_DB_PATH", str(tmp_path / "blocks.db"))

    app = create_app_from_env()

    with TestClient(app) as client:
        yield client, tmp_path


def send_alert(client, source_ip, window_start="Nov 22 10:00:00"):
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
        body, b"integration-test-secret"
    )

    return client.post(
        "/v1/alerts",
        content=body,
        headers=headers,
    )


def test_untrusted_ip_is_blocked(test_client):
    client, folder = test_client

    response = send_alert(client, "198.51.100.25")

    assert response.status_code == 202
    assert response.json()["action"] == "block"
    assert response.json()["enforcement"] == "applied"

    acl = json.loads(
        (folder / "acl.json").read_text(encoding="utf-8")
    )
    assert "198.51.100.25" in json.dumps(acl)


def test_trusted_ip_is_ignored(test_client):
    client, folder = test_client

    response = send_alert(client, "192.168.1.20")

    assert response.status_code == 202
    assert response.json()["action"] == "ignore"
    assert response.json()["enforcement"] is None
    assert not (folder / "acl.json").exists()


def test_internal_ip_is_ignored(test_client):
    client, folder = test_client

    response = send_alert(client, "192.168.1.50")

    assert response.status_code == 202
    assert response.json()["action"] == "ignore"
    assert response.json()["enforcement"] is None
    assert not (folder / "acl.json").exists()


def test_duplicate_alert_is_rejected(test_client):
    client, folder = test_client

    first = send_alert(client, "198.51.100.25")
    second = send_alert(client, "198.51.100.25")

    assert first.status_code == 202
    assert second.status_code == 409


def test_block_is_recorded_in_audit(test_client):
    client, folder = test_client

    response = send_alert(client, "198.51.100.25")

    assert response.status_code == 202

    entries = [
        json.loads(line)
        for line in (folder / "audit.jsonl")
        .read_text(encoding="utf-8").splitlines()
    ]

    assert any(
        entry.get("decision") == "block applied"
        for entry in entries
    )
