from decision_stub import CONTROL_POINT, TTL_SECONDS, decide

GOOD = {
    "host": "NORTHMEN-WEBSERVER",
    "source_ip": "198.51.100.25",
    "window_start": "Nov 12 10:00:00",
    "window_end": "Nov 12 10:05:00",
    "failed_attempts": 9,
    "criticality": "medium",
    "threshold": 8,
    "alert": True,
}

KEYS = {"action", "reason", "control_point", "source_ip", "ttl_seconds"}


def test_untrusted_address_is_blocked():
    answer = decide(GOOD)
    assert answer["action"] == "block"
    assert answer["source_ip"] == "198.51.100.25"
    assert answer["control_point"] == CONTROL_POINT
    assert answer["ttl_seconds"] == TTL_SECONDS["medium"]


def test_answer_always_has_the_five_agreed_keys():
    assert set(decide(GOOD)) == KEYS
    assert set(decide(dict(GOOD, host="nobody"))) == KEYS
    assert set(decide(dict(GOOD, source_ip=None))) == KEYS


def test_server_name_ignores_capital_letters():
    answer = decide(dict(GOOD, host="northmen-webserver"))
    assert answer["action"] == "block"


def test_server_name_ignores_spaces_around_it():
    answer = decide(dict(GOOD, host="  NORTHMEN-WEBSERVER "))
    assert answer["action"] == "block"


def test_unknown_server_is_ignored_with_a_reason():
    answer = decide(dict(GOOD, host="server01"))
    assert answer["action"] == "ignore"
    assert answer["reason"] == "server not in inventory"
    assert answer["ttl_seconds"] == 0
    assert answer["control_point"] is None


def test_missing_host_is_ignored():
    alert = dict(GOOD)
    del alert["host"]
    assert decide(alert)["action"] == "ignore"


def test_trusted_address_is_never_blocked():
    answer = decide(dict(GOOD, source_ip="192.168.1.10"))
    assert answer["action"] == "ignore"
    assert answer["reason"] == "trusted address on the allowlist"


def test_our_own_machine_is_not_auto_blocked():
    answer = decide(dict(GOOD, source_ip="192.168.1.60"))
    assert answer["action"] == "ignore"
    assert answer["reason"] == "internal machine, review manually"


def test_block_time_depends_on_how_important_the_server_is():
    high = decide(dict(GOOD, host="NORTHMEN-DATABASE"))
    low = decide(dict(GOOD, host="NORTHMEN-PC02"))
    assert high["ttl_seconds"] == TTL_SECONDS["high"]
    assert low["ttl_seconds"] == TTL_SECONDS["low"]
    assert high["ttl_seconds"] > low["ttl_seconds"]


def test_source_address_that_is_not_text_is_ignored():
    answer = decide(dict(GOOD, source_ip=12345))
    assert answer["action"] == "ignore"


def test_decide_does_not_change_the_alert():
    alert = dict(GOOD)
    decide(alert)
    assert alert == GOOD