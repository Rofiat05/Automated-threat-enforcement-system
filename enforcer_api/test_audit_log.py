import json

from audit_log import write_audit

NOW = 1762246800


def test_entry_is_written_with_all_details(tmp_path):
    log = tmp_path / "audit.jsonl"
    write_audit(log, NOW, "id-one", "rejected", "signature is not valid")

    entry = json.loads(log.read_text(encoding="utf-8").strip())
    assert entry == {
        "time": NOW,
        "alert_id": "id-one",
        "decision": "rejected",
        "reason": "signature is not valid",
    }


def test_entries_are_added_not_overwritten(tmp_path):
    log = tmp_path / "audit.jsonl"
    write_audit(log, NOW, "id-one", "accepted", "all checks passed")
    write_audit(log, NOW + 1, "id-two", "rejected", "duplicate alert")

    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2


def test_line_break_in_a_field_cannot_fake_an_entry(tmp_path):
    log = tmp_path / "audit.jsonl"
    write_audit(log, NOW, "id-one", "rejected", "bad\nfake line")

    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1