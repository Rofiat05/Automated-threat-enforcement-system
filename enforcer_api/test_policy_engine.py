"""Tests for C's policy_engine.decide(), written by D.

These tests do not change C's code. They check the rules in order:
1. unknown host -> ignore
2. address on the allow list -> ignore
3. attacker address equals one of our own machines -> ignore
4. otherwise block, with a time limit set by the importance of the host
"""

import pytest

from policy_engine import (
    CONTROL_POINT,
    TTL_SECONDS,
    decide,
    load_allowed_ips,
    load_assets,
)

# A small made-up inventory, so these tests do not depend on the real files.
ASSETS = [
    ["webserver", "192.168.1.50", "Medium"],
    ["dataserver", "192.168.1.60", "High"],
    ["pc02", "192.168.1.100", "Low"],
    ["server01", "192.168.1.110", "Critical"],
    ["pc03", "192.168.1.10", "Low"],  # its address is also on the allow list
]
ALLOWED = ["192.168.1.10", "192.168.1.20"]
OUTSIDER = "203.0.113.99"

KEYS = {"action", "reason", "control_point", "source_ip", "ttl_seconds"}


def alert(host="server01", source_ip=OUTSIDER, **more):
    base = {
        "host": host,
        "source_ip": source_ip,
        "window_start": "Oct 28 09:00:00",
        "window_end": "Oct 28 09:05:00",
        "failed_attempts": 3,
        "criticality": "critical",
        "threshold": 3,
        "alert": True,
    }
    base.update(more)
    return base


def run(a):
    return decide(a, allowed_ips=ALLOWED, assets=ASSETS)


# ---------- the four rules ----------

def test_unknown_host_is_ignored():
    answer = run(alert(host="unknown-host"))
    assert answer["action"] == "ignore"
    assert answer["reason"] == "server not in inventory"
    assert answer["ttl_seconds"] == 0
    assert answer["control_point"] is None


def test_allow_listed_address_is_ignored():
    answer = run(alert(source_ip="192.168.1.20"))
    assert answer["action"] == "ignore"
    assert answer["reason"] == "trusted address on the allowlist"


def test_attacker_that_is_one_of_our_machines_is_ignored():
    answer = run(alert(source_ip="192.168.1.60"))
    assert answer["action"] == "ignore"
    assert answer["reason"] == "internal machine, review manually"


def test_untrusted_outside_address_is_blocked():
    answer = run(alert())
    assert answer["action"] == "block"
    assert answer["reason"] == "untrusted address"
    assert answer["source_ip"] == OUTSIDER
    assert answer["control_point"] == CONTROL_POINT


# ---------- block time depends on how important the host is ----------

@pytest.mark.parametrize("host, seconds", [
    ("server01", 3600),    # Critical
    ("dataserver", 1800),  # High
    ("webserver", 900),    # Medium
    ("pc02", 300),         # Low
])
def test_block_time_follows_importance_of_host(host, seconds):
    answer = run(alert(host=host))
    assert answer["action"] == "block"
    assert answer["ttl_seconds"] == seconds
    assert seconds == TTL_SECONDS[ASSETS_BY_NAME[host].lower()]


ASSETS_BY_NAME = {name: importance for name, _ip, importance in ASSETS}


def test_importance_comes_from_the_inventory_not_from_the_alert():
    # The alert claims "low", but the inventory says server01 is Critical.
    answer = run(alert(host="server01", criticality="low"))
    assert answer["ttl_seconds"] == 3600


def test_strange_importance_falls_back_to_the_shortest_block_time():
    odd_assets = [["oddbox", "192.168.1.200", "Weird"]]
    answer = decide(alert(host="oddbox"), allowed_ips=ALLOWED, assets=odd_assets)
    assert answer["action"] == "block"
    assert answer["ttl_seconds"] == TTL_SECONDS["low"]


# ---------- order of the rules ----------

def test_unknown_host_is_checked_before_the_allow_list():
    answer = run(alert(host="unknown-host", source_ip="192.168.1.20"))
    assert answer["reason"] == "server not in inventory"


def test_allow_list_is_checked_before_the_internal_machine_rule():
    # 192.168.1.10 is both on the allow list and the address of pc03.
    answer = run(alert(source_ip="192.168.1.10"))
    assert answer["reason"] == "trusted address on the allowlist"


# ---------- tidy handling of odd input ----------

def test_host_name_ignores_capital_letters_and_spaces():
    assert run(alert(host="SERVER01"))["action"] == "block"
    assert run(alert(host="  server01 "))["action"] == "block"


def test_alert_that_is_not_a_dictionary_is_ignored():
    for bad in (None, "text", 42, ["a"]):
        answer = decide(bad, allowed_ips=ALLOWED, assets=ASSETS)
        assert answer["action"] == "ignore"
        assert answer["reason"] == "alert is not a dictionary"


def test_source_ip_that_is_not_text_is_ignored():
    answer = run(alert(source_ip=None))
    assert answer["action"] == "ignore"
    assert answer["reason"] == "source_ip is not text"


def test_answer_always_has_the_five_agreed_keys():
    for a in (alert(), alert(host="nobody"), alert(source_ip=None), None):
        assert set(decide(a, allowed_ips=ALLOWED, assets=ASSETS)) == KEYS


# ---------- the real data files (catches name mismatches between B and C) ----------

def test_real_inventory_has_server01_as_critical():
    names = {row[0].lower(): row[2].lower() for row in load_assets()}
    assert names.get("server01") == "critical"


def test_b_alert_for_server01_is_blocked_with_the_real_files():
    # The alert B's preprocessor produces in the demo.
    answer = decide(alert(host="server01", source_ip="192.168.1.55"))
    assert answer["action"] == "block"
    assert answer["ttl_seconds"] == 3600


def test_every_host_in_the_real_inventory_can_be_blocked_from_outside():
    for name, _ip, importance in load_assets():
        answer = decide(alert(host=name, source_ip=OUTSIDER))
        assert answer["action"] == "block", name
        assert answer["ttl_seconds"] == TTL_SECONDS[importance.strip().lower()], name


def test_every_address_on_the_real_allow_list_is_ignored():
    for ip in load_allowed_ips():
        assert decide(alert(source_ip=ip))["action"] == "ignore", ip