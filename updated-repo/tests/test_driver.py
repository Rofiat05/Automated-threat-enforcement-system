"""Driver behaviour: idempotency, TTL expiry, rollback, limits, drift, persistence."""

import pytest

from cisco_driver.driver import CiscoDriver
from cisco_driver.restconf_client import RestconfClient, deny_rule
from cisco_driver.store import BlockStore
from cisco_driver.validation import ValidationError

from .conftest import PASSWORD, USER, acl_rules

ATTACKER = "203.0.113.7"
ATTACKER2 = "198.51.100.23"


# ------------------------------------------------------------------ block

def test_first_block_creates_acl_with_deny_and_permit_any(driver, router):
    result = driver.block(ATTACKER, "R1", 3600, alert_id="A-1", reason="ssh brute force")
    assert result.status == "blocked" and result.seq == 10
    rules = acl_rules(router)
    assert sorted(rules) == [10, 1000]
    assert rules[10]["ace-rule"] == {"action": "deny", "protocol": "ip", "host": ATTACKER, "dst-any": [None]}
    assert rules[1000]["ace-rule"]["action"] == "permit"    # normal traffic still allowed


def test_block_is_idempotent(driver, router, clock):
    driver.block(ATTACKER, "R1", 600)
    writes_before = router.state.count("PUT") + router.state.count("PATCH")
    clock.advance(100)
    again = driver.block(ATTACKER, "R1", 600)
    assert again.status == "already_blocked"
    assert router.state.count("PUT") + router.state.count("PATCH") == writes_before  # no new write
    assert sorted(acl_rules(router)) == [10, 1000]                                 # still one rule
    assert again.expires_at == clock.now + 600                                     # TTL refreshed


def test_duplicate_alert_does_not_extend_ttl(driver, router, clock):
    first = driver.block(ATTACKER, "R1", 600, alert_id="A-1")
    clock.advance(100)
    again = driver.block(ATTACKER, "R1", 600, alert_id="A-1")      # same alert re-delivered
    assert again.status == "already_blocked"
    assert again.expires_at == first.expires_at                     # TTL NOT extended
    assert "expiry unchanged" in again.message
    assert sorted(acl_rules(router)) == [10, 1000]


def test_new_alert_refreshes_ttl_and_is_recorded(driver, router, clock):
    driver.block(ATTACKER, "R1", 600, alert_id="A-1")
    clock.advance(100)
    again = driver.block(ATTACKER, "R1", 600, alert_id="A-2")      # a different, new alert
    assert again.expires_at == clock.now + 600                      # TTL refreshed
    assert driver.list_active()[0]["alert_id"] == "A-2"
    clock.advance(100)
    dup = driver.block(ATTACKER, "R1", 600, alert_id="A-2")        # A-2 re-delivered
    assert dup.expires_at == again.expires_at                       # not extended again


def test_second_attacker_gets_next_sequence(driver, router):
    driver.block(ATTACKER, "R1", 600)
    result = driver.block(ATTACKER2, "R1", 600)
    assert result.seq == 20
    assert sorted(acl_rules(router)) == [10, 20, 1000]


def test_freed_sequence_numbers_are_reused(driver, router):
    driver.block(ATTACKER, "R1", 600)
    driver.block(ATTACKER2, "R1", 600)
    driver.unblock(ATTACKER, "R1")
    assert driver.block("192.0.2.99", "R1", 600).seq == 10


def test_existing_acl_without_permit_gets_permit_added(driver, client, router):
    client.create_acl("BLOCKLIST", [deny_rule(500, "192.0.2.1")])
    driver.block(ATTACKER, "R1", 600)
    assert sorted(acl_rules(router)) == [10, 500, 1000]


def test_rule_not_created_by_driver_is_left_alone(driver, client, router, clock):
    client.create_acl("BLOCKLIST", [deny_rule(500, ATTACKER)])   # e.g. added by an admin
    result = driver.block(ATTACKER, "R1", 600)
    assert result.status == "already_blocked" and result.seq == 500
    assert driver.list_active() == []
    clock.advance(10_000)
    driver.expire_due()
    assert 500 in acl_rules(router)                                 # expiry did not remove it


def test_manual_unblock_never_deletes_rule_not_created_by_driver(driver, client, router):
    client.create_acl("BLOCKLIST", [deny_rule(500, ATTACKER)])   # e.g. added by an admin
    result = driver.unblock(ATTACKER, "R1")
    assert result.status == "refused" and result.seq == 500
    assert "not created by this driver" in result.message
    assert 500 in acl_rules(router)                                 # admin rule still there
    assert router.state.count("DELETE") == 0


def test_manual_unblock_removes_only_own_rule_when_both_exist(driver, client, router):
    driver.block(ATTACKER, "R1", 600)                               # driver's rule, seq 10
    client.add_rules("BLOCKLIST", [deny_rule(500, ATTACKER)])       # admin adds another
    result = driver.unblock(ATTACKER, "R1")
    assert result.status == "unblocked" and result.seq == 10
    assert "left untouched" in result.message
    assert sorted(acl_rules(router)) == [500, 1000]


def test_drift_rule_removed_on_router_is_reapplied(driver, router):
    driver.block(ATTACKER, "R1", 600)
    with router.state.lock:                                         # someone deletes it by hand
        del router.state.acls["BLOCKLIST"][10]
    result = driver.block(ATTACKER, "R1", 600)
    assert result.status == "blocked" and "re-applied" in result.message
    assert 10 in acl_rules(router)
    assert len(driver.list_active()) == 1


def test_block_survives_router_hiccup(driver, router, sleeps):
    router.state.fail_next(2, 503)
    assert driver.block(ATTACKER, "R1", 600).status == "blocked"
    assert sleeps == [1.0, 2.0]


def test_router_down_returns_error_and_records_nothing(driver, router):
    router.state.fail_next(50, 503)
    result = driver.block(ATTACKER, "R1", 600)
    assert result.status == "error" and not result.ok
    assert driver.list_active() == []


def test_failed_write_is_not_recorded(driver, router):
    # GET works, then the PUT is rejected
    driver.block("192.0.2.1", "R1", 600)
    router.state.fail_next(0)
    original = router.state.take_failure
    calls = {"n": 0}

    def fail_on_write():
        calls["n"] += 1
        return 400 if calls["n"] == 2 else None   # 1st call = GET, 2nd = PATCH
    router.state.take_failure = fail_on_write
    try:
        result = driver.block(ATTACKER, "R1", 600)
    finally:
        router.state.take_failure = original
    assert result.status == "error"
    assert [r["ip"] for r in driver.list_active()] == ["192.0.2.1"]


# ------------------------------------------------------------ input safety

@pytest.mark.parametrize("ip", ["10.0.0.0/8", "not-an-ip", "127.0.0.1", "1.2.3.4 any"])
def test_bad_ip_never_reaches_router(driver, router, ip):
    with pytest.raises(ValidationError):
        driver.block(ip, "R1", 600)
    assert router.state.count() == 0


def test_unknown_device_rejected(driver, router):
    with pytest.raises(ValidationError):
        driver.block(ATTACKER, "R9", 600)
    assert router.state.count() == 0


@pytest.mark.parametrize("ttl", [0, 59, 86401])
def test_ttl_outside_limits_rejected(driver, ttl):
    with pytest.raises(ValidationError):
        driver.block(ATTACKER, "R1", ttl)


# ------------------------------------------------------------------ limits

def test_rate_limit_per_minute(driver, router, clock):
    for i in range(5):
        assert driver.block(f"192.0.2.{i + 1}", "R1", 600).status == "blocked"
    refused = driver.block("192.0.2.50", "R1", 600)
    assert refused.status == "refused" and "Rate limit" in refused.message
    assert len(acl_rules(router)) == 6                 # 5 denies + permit
    clock.advance(61)                                  # a minute later it is allowed again
    assert driver.block("192.0.2.50", "R1", 600).status == "blocked"


def test_max_active_blocks_per_device(driver, clock):
    for i in range(8):
        clock.advance(61)                              # stay under the rate limit
        assert driver.block(f"192.0.2.{i + 1}", "R1", 600 + 3600).status == "blocked"
    clock.advance(61)
    refused = driver.block("192.0.2.100", "R1", 3600)
    assert refused.status == "refused" and "active blocks" in refused.message


def test_rollback_and_expiry_are_not_rate_limited(driver, clock):
    for i in range(5):
        driver.block(f"192.0.2.{i + 1}", "R1", 600)
    assert driver.unblock("192.0.2.1", "R1").status == "unblocked"
    clock.advance(601)
    assert all(r.status == "unblocked" for r in driver.expire_due())


# ---------------------------------------------------------------- rollback

def test_manual_rollback_removes_rule_immediately(driver, router):
    driver.block(ATTACKER, "R1", 3600)
    result = driver.unblock(ATTACKER, "R1")
    assert result.status == "unblocked" and result.seq == 10
    assert sorted(acl_rules(router)) == [1000]
    assert driver.list_active() == []
    history = driver.store.history()
    assert history[0].status == "removed" and history[0].ended_by == "manual"


def test_rollback_of_unknown_ip_is_harmless(driver, router):
    assert driver.unblock(ATTACKER, "R1").status == "not_found"


def test_rollback_when_router_down_keeps_record(driver, router):
    driver.block(ATTACKER, "R1", 3600)
    router.state.fail_next(50, 503)
    assert driver.unblock(ATTACKER, "R1").status == "error"
    assert len(driver.list_active()) == 1              # still tracked, can retry


# ------------------------------------------------------------------ expiry

def test_block_expires_after_ttl(driver, router, clock):
    driver.block(ATTACKER, "R1", 120)
    clock.advance(119)
    assert driver.expire_due() == []                   # not yet
    assert 10 in acl_rules(router)
    clock.advance(1)
    results = driver.expire_due()
    assert [r.status for r in results] == ["unblocked"]
    assert sorted(acl_rules(router)) == [1000]
    assert driver.store.history()[0].status == "expired"


def test_expiry_only_removes_due_blocks(driver, router, clock):
    driver.block(ATTACKER, "R1", 120)
    driver.block(ATTACKER2, "R1", 3600)
    clock.advance(200)
    driver.expire_due()
    assert sorted(acl_rules(router)) == [20, 1000]


def test_expiry_retries_later_if_router_down(driver, router, clock):
    driver.block(ATTACKER, "R1", 120)
    clock.advance(200)
    router.state.fail_next(50, 503)
    assert driver.expire_due()[0].status == "error"
    assert len(driver.list_active()) == 1
    router.state.reset()
    router.state.acls["BLOCKLIST"] = {10: deny_rule(10, ATTACKER)}
    assert driver.expire_due()[0].status == "unblocked"
    assert driver.list_active() == []


def test_expiry_still_works_after_restart(tmp_path, router, clock):
    """Blocks are saved in SQLite, so a new process still removes them on time."""
    def make_driver():
        c = RestconfClient(router.url, USER, PASSWORD, verify=str(router.cert_path), sleep=lambda s: None)
        return CiscoDriver({"R1": c}, BlockStore(tmp_path / "persist.db"), clock=clock)

    first = make_driver()
    first.block(ATTACKER, "R1", 300)
    first.store.close()                                # "process stops"

    second = make_driver()                             # "process restarts"
    clock.advance(301)
    assert [r.status for r in second.expire_due()] == ["unblocked"]
    assert sorted(acl_rules(router)) == [1000]
    second.store.close()


def test_multiple_devices(router, store, clock, sleeps):
    c = RestconfClient(router.url, USER, PASSWORD, verify=str(router.cert_path), sleep=sleeps.append)
    d = CiscoDriver({"EDGE1": c, "DC1": c}, store, clock=clock)
    assert d.block(ATTACKER, "EDGE1", 600).status == "blocked"
    assert store.count_active("EDGE1") == 1 and store.count_active("DC1") == 0
