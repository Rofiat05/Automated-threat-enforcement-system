"""v1.1 enhancements: IP-blocking logic, duplicate prevention, TTL, rollback & recovery.

Grouped by responsibility:
    A. IP-blocking logic        - protected list, block_many, status
    B. Duplicate prevention     - cross-process lock, concurrent requests, batch duplicates
    C. Temporary blocking / TTL - lifetime cap, repeat offenders, extend, worker health
    D. Rollback and recovery    - compensation, recover(), reconcile(), bulk rollback, backup
    E. Command line             - the new commands
"""

import json
import logging
import sqlite3
import threading

import pytest

from cisco_driver import cli
from cisco_driver.driver import CiscoDriver
from cisco_driver.expiry_worker import ExpiryWorker
from cisco_driver.restconf_client import RestconfClient, deny_rule
from cisco_driver.store import BlockStore, LockTimeout
from cisco_driver.validation import ValidationError, parse_networks

from .conftest import PASSWORD, USER, acl_rules

ATTACKER = "203.0.113.7"
ATTACKER2 = "198.51.100.23"
ADMIN_IP = "192.0.2.77"


def make_driver(router, db_path, clock, **kwargs):
    client = RestconfClient(router.url, USER, PASSWORD, verify=str(router.cert_path),
                            sleep=lambda s: None)
    options = dict(max_changes_per_minute=100, max_blocks_per_device=100)
    options.update(kwargs)
    return CiscoDriver({"R1": client}, BlockStore(db_path), clock=clock, **options)


def fail_on_calls(router, failing_calls, status=400):
    """Make the router fail exactly on the given RESTCONF call numbers (1 = next call)."""
    calls = {"n": 0}

    def take_failure():
        calls["n"] += 1
        return status if calls["n"] in failing_calls else None
    router.state.take_failure = take_failure


@pytest.fixture
def restore_failure_hook(router):
    original = router.state.take_failure
    yield
    router.state.take_failure = original


# =========================================================== A. IP-blocking logic

def test_protected_ip_is_refused_without_touching_router(router, tmp_path, clock):
    d = make_driver(router, tmp_path / "p.db", clock, protected="192.0.2.1, 10.10.0.0/16")
    result = d.block("10.10.5.5", "R1", 600)
    assert result.status == "refused" and "protected list (10.10.0.0/16)" in result.message
    assert d.block("192.0.2.1", "R1", 600).status == "refused"
    assert router.state.count() == 0                    # no RESTCONF call at all
    assert d.block(ATTACKER, "R1", 600).status == "blocked"
    d.store.close()


def test_protected_list_parsing():
    nets = parse_networks("10.0.0.1, 192.168.1.0/24  172.16.0.5/16")
    assert [str(n) for n in nets] == ["10.0.0.1/32", "192.168.1.0/24", "172.16.0.0/16"]
    assert parse_networks("") == () and parse_networks(None) == ()
    with pytest.raises(ValidationError):
        parse_networks("10.0.0.300")
    with pytest.raises(ValidationError):
        parse_networks("2001:db8::/32")


def test_blocking_policy_from_environment():
    from cisco_driver.blocking_policy import BlockingPolicy
    p = BlockingPolicy.from_env({"BLOCK_PROTECTED": "10.0.0.0/24", "BLOCK_MAX_LIFETIME": "0",
                                 "BLOCK_REPEAT_FACTOR": "2"})
    assert (p.protected, p.max_lifetime, p.repeat_factor) == ("10.0.0.0/24", 0, 2.0)
    assert BlockingPolicy.from_env({}) == BlockingPolicy("", 604800, 1.0)   # v1.0 behaviour


@pytest.mark.parametrize("env", [{"BLOCK_REPEAT_FACTOR": "0.5"}, {"BLOCK_MAX_LIFETIME": "-1"},
                                 {"BLOCK_MAX_LIFETIME": "abc"}, {"BLOCK_PROTECTED": "10.0.0.999"}])
def test_blocking_policy_rejects_bad_values(env):
    from cisco_driver.blocking_policy import BlockingPolicy
    with pytest.raises(ValidationError):
        BlockingPolicy.from_env(env)


def test_block_many_blocks_each_distinct_ip_once(driver, router):
    results = driver.block_many([ATTACKER, ATTACKER2, ATTACKER, "not-an-ip", "10.0.0.0/8"],
                                "R1", 600, alert_id="A-50", reason="scan")
    assert [(r.ip, r.status) for r in results] == [
        (ATTACKER, "blocked"), (ATTACKER2, "blocked"),
        ("not-an-ip", "invalid"), ("10.0.0.0/8", "invalid")]
    assert sorted(acl_rules(router)) == [10, 20, 1000]   # one rule per IP, no duplicate
    assert {r["alert_id"] for r in driver.list_active()} == {"A-50"}


def test_block_many_rejects_bad_ttl_or_device_for_whole_batch(driver, router):
    with pytest.raises(ValidationError):
        driver.block_many([ATTACKER], "R1", 5)
    with pytest.raises(ValidationError):
        driver.block_many([ATTACKER], "R9", 600)
    assert router.state.count() == 0


def test_block_many_respects_rate_limit(driver, router):
    ips = [f"192.0.2.{i}" for i in range(1, 8)]        # driver fixture: 5 changes / minute
    statuses = [r.status for r in driver.block_many(ips, "R1", 600)]
    assert statuses == ["blocked"] * 5 + ["refused"] * 2


def test_status_reports_all_four_states(driver, client, router):
    assert driver.status(ATTACKER, "R1")["state"] == "not_blocked"
    driver.block(ATTACKER, "R1", 600)
    st = driver.status(ATTACKER, "R1")
    assert st["state"] == "blocked" and st["router_seqs"] == [10]
    assert st["record"]["remaining_seconds"] == 600
    with router.state.lock:
        del router.state.acls["BLOCKLIST"][10]          # rule deleted by hand
    assert driver.status(ATTACKER, "R1")["state"] == "drift"
    client.add_rules("BLOCKLIST", [deny_rule(500, ADMIN_IP)])
    assert driver.status(ADMIN_IP, "R1")["state"] == "blocked_foreign"


def test_status_shows_protection(router, tmp_path, clock):
    d = make_driver(router, tmp_path / "s.db", clock, protected="192.0.2.0/24")
    assert d.status("192.0.2.9", "R1")["protected_by"] == "192.0.2.0/24"
    d.store.close()


# ========================================================= B. Duplicate prevention

def test_cross_process_lock_blocks_second_writer(tmp_path):
    a = BlockStore(tmp_path / "shared.db")
    b = BlockStore(tmp_path / "shared.db")              # separate handle = another process
    try:
        with a.exclusive():
            with pytest.raises(LockTimeout):
                with b.exclusive(timeout=0.2):
                    pass
        with b.exclusive(timeout=0.2):                  # free again after release
            pass
    finally:
        a.close()
        b.close()


def test_lock_is_reentrant_and_released_when_owner_closes(tmp_path):
    a = BlockStore(tmp_path / "shared.db")
    b = BlockStore(tmp_path / "shared.db")
    with a.exclusive():
        with a.exclusive():                             # same owner may nest
            pass
    a._file_lock.try_acquire()                          # simulate a process that holds the lock ...
    a.close()                                           # ... and then dies: the OS releases it
    with b.exclusive(timeout=0.5):
        pass
    b.close()


def test_driver_reports_busy_lock_as_error(driver, tmp_path, router):
    other = BlockStore(driver.store.path)
    driver.lock_timeout = 0.2
    with other.exclusive():
        result = driver.block(ATTACKER, "R1", 600)
    other.close()
    assert result.status == "error" and "Another driver process" in result.message
    assert router.state.count() == 0
    assert driver.block(ATTACKER, "R1", 600).status == "blocked"


def test_two_processes_blocking_same_ip_create_one_rule(router, tmp_path, clock):
    drivers = [make_driver(router, tmp_path / "race.db", clock) for _ in range(4)]
    results = []
    barrier = threading.Barrier(len(drivers))

    def run(d):
        barrier.wait()
        results.append(d.block(ATTACKER, "R1", 600, alert_id="A-1"))

    threads = [threading.Thread(target=run, args=(d,)) for d in drivers]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(r.status for r in results) == ["already_blocked"] * 3 + ["blocked"]
    assert sorted(acl_rules(router)) == [10, 1000]       # exactly one deny line
    assert len(drivers[0].list_active()) == 1
    for d in drivers:
        d.store.close()


def test_two_processes_blocking_different_ips_never_share_a_sequence(router, tmp_path, clock):
    drivers = [make_driver(router, tmp_path / "race2.db", clock) for _ in range(4)]
    ips = [f"198.51.100.{i}" for i in range(1, 5)]
    barrier = threading.Barrier(len(drivers))

    def run(d, ip):
        barrier.wait()
        assert d.block(ip, "R1", 600).status == "blocked"

    threads = [threading.Thread(target=run, args=(d, ip)) for d, ip in zip(drivers, ips)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    rules = acl_rules(router)
    assert sorted(rules) == [10, 20, 30, 40, 1000]       # no rule overwritten by another
    assert sorted(r["ace-rule"]["host"] for s, r in rules.items() if s != 1000) == sorted(ips)
    for d in drivers:
        d.store.close()


# ================================================== C. Temporary blocking and TTL

def test_refresh_is_capped_at_maximum_lifetime(router, tmp_path, clock):
    d = make_driver(router, tmp_path / "cap.db", clock, max_lifetime=1000)
    first = d.block(ATTACKER, "R1", 600, alert_id="A-1")
    clock.advance(500)
    again = d.block(ATTACKER, "R1", 600, alert_id="A-2")      # would be +1100 from start
    assert again.expires_at == first.expires_at - 600 + 1000  # created_at + 1000
    assert "maximum block lifetime" in again.message
    clock.advance(100)
    third = d.block(ATTACKER, "R1", 600, alert_id="A-3")
    assert third.expires_at == again.expires_at and "expiry unchanged" in third.message
    d.store.close()


def test_default_lifetime_cap_does_not_change_normal_refresh(driver, clock):
    driver.block(ATTACKER, "R1", 600, alert_id="A-1")
    clock.advance(100)
    assert driver.block(ATTACKER, "R1", 600, alert_id="A-2").expires_at == clock.now + 600


def test_repeat_offender_gets_longer_ttl(router, tmp_path, clock):
    d = make_driver(router, tmp_path / "rep.db", clock, repeat_factor=2, max_ttl=3000)
    assert d.block(ATTACKER, "R1", 600).expires_at == clock.now + 600
    clock.advance(601)
    d.expire_due()
    second = d.block(ATTACKER, "R1", 600)
    assert second.expires_at == clock.now + 1200 and "repeat offender: 1" in second.message
    clock.advance(1201)
    d.expire_due()
    third = d.block(ATTACKER, "R1", 600)
    assert third.expires_at == clock.now + 2400
    clock.advance(2401)
    d.expire_due()
    assert d.block(ATTACKER, "R1", 600).expires_at == clock.now + 3000   # capped at max_ttl
    d.store.close()


def test_rolled_back_false_positive_never_escalates(router, tmp_path, clock):
    d = make_driver(router, tmp_path / "fp.db", clock, repeat_factor=2)
    d.block(ATTACKER, "R1", 600, alert_id="FP-1")
    d.unblock_alert("FP-1")                              # analyst: false positive
    d.block(ATTACKER, "R1", 600, alert_id="FP-2")
    d.unblock(ATTACKER, "R1")                            # removed by hand: also no offence
    d.block(ATTACKER, "R1", 600, alert_id="FP-3")
    d.unblock_all()                                      # emergency rollback: also no offence
    again = d.block(ATTACKER, "R1", 600, alert_id="A-4")
    assert again.expires_at == clock.now + 600 and "repeat offender" not in again.message
    d.store.close()


def test_repeat_escalation_is_off_by_default_and_window_limited(driver, router, tmp_path, clock):
    driver.block(ATTACKER, "R1", 600)
    clock.advance(601)
    driver.expire_due()
    assert driver.block(ATTACKER, "R1", 600).expires_at == clock.now + 600   # off by default

    d = make_driver(router, tmp_path / "win.db", clock, repeat_factor=2, repeat_window=1000)
    d.block(ATTACKER2, "R1", 600)
    clock.advance(601)
    d.expire_due()
    clock.advance(2000)                                  # earlier block is outside the window
    assert d.block(ATTACKER2, "R1", 600).expires_at == clock.now + 600
    d.store.close()


def test_extend_pushes_expiry_and_never_shortens(driver, router, clock):
    driver.block(ATTACKER, "R1", 600)
    writes = router.state.count("PATCH") + router.state.count("PUT")
    r = driver.extend(ATTACKER, "R1", 3600)
    assert r.status == "extended" and r.expires_at == clock.now + 3600
    assert router.state.count("PATCH") + router.state.count("PUT") == writes  # record only
    shorter = driver.extend(ATTACKER, "R1", 120)
    assert shorter.expires_at == clock.now + 3600 and "already later" in shorter.message
    assert driver.extend(ATTACKER2, "R1", 600).status == "not_found"
    with pytest.raises(ValidationError):
        driver.extend(ATTACKER, "R1", 10 ** 9)


def test_list_active_shows_remaining_time(driver, clock):
    driver.block(ATTACKER, "R1", 600)
    clock.advance(100)
    assert driver.list_active()[0]["remaining_seconds"] == 500


def test_failed_expiry_counts_attempts_and_warns_when_stuck(driver, router, clock, caplog):
    driver.stuck_after = 3
    driver.block(ATTACKER, "R1", 120)
    clock.advance(200)
    router.state.fail_next(1000, 503)
    with caplog.at_level(logging.ERROR, logger="cisco_driver.driver"):
        for _ in range(3):
            assert driver.expire_due()[0].status == "error"
    record = driver.store.get_active("R1", ATTACKER)
    assert record.attempts == 3 and "503" in record.last_error
    assert any("could not be removed after 3 attempts" in m for m in caplog.messages)
    router.state.failures.clear()
    assert driver.expire_due()[0].status == "unblocked"


def test_worker_health_and_stats(driver, router, clock):
    import time as _time
    driver.block(ATTACKER, "R1", 120)
    clock.advance(121)
    worker = ExpiryWorker(driver, interval=0.05)
    worker.start()
    deadline = _time.monotonic() + 5
    while worker.health()["removed"] < 1 and _time.monotonic() < deadline:
        _time.sleep(0.05)
    health = worker.health()
    worker.stop()
    assert health["alive"] and health["healthy"] and health["removed"] == 1
    assert worker.health()["alive"] is False


# ================================================== D. Rollback and recovery

def test_partial_write_is_rolled_back(driver, router, restore_failure_hook):
    # call 1 = GET (read), 2 = PUT (write lands), 3 = GET (verify) fails
    fail_on_calls(router, {3})
    result = driver.block(ATTACKER, "R1", 600)
    assert result.status == "error"
    assert 10 not in acl_rules(router)                   # no untracked rule left behind
    last = driver.store.history()[0]
    assert last.status == "failed" and last.ended_by == "rollback" and last.attempts == 1
    assert driver.list_active() == []


def test_partial_write_when_router_stays_down_is_recovered_on_retry(driver, router,
                                                                    restore_failure_hook):
    # write lands (call 2), then the router is lost: verify + rollback attempts all fail
    fail_on_calls(router, set(range(3, 20)), status=503)
    assert driver.block(ATTACKER, "R1", 600, alert_id="A-1").status == "error"
    assert driver.store.list_pending()[0].ip == ATTACKER  # journal remembers it
    assert 10 in acl_rules(router)
    router.state.take_failure = lambda: None              # router is back
    retry = driver.block(ATTACKER, "R1", 600, alert_id="A-1")
    # the driver recognises its own half-finished rule instead of calling it "foreign"
    assert retry.status == "already_blocked" and retry.seq == 10
    assert "not created by this driver" not in retry.message
    assert driver.store.list_pending() == [] and len(driver.list_active()) == 1
    assert sorted(acl_rules(router)) == [10, 1000]


def test_recover_after_crash_adopts_rule_that_reached_router(router, tmp_path, clock, client):
    db = tmp_path / "crash.db"
    store = BlockStore(db)                               # process A crashed after writing:
    store.add("R1", ATTACKER, "BLOCKLIST", 10, "A-9", "crash", clock.now, clock.now + 300,
              status="pending")
    store.close()
    client.create_acl("BLOCKLIST", [deny_rule(10, ATTACKER)])

    d = make_driver(router, db, clock)                   # process B starts
    results = d.recover()
    assert [r.status for r in results] == ["recovered"]
    assert d.status(ATTACKER, "R1")["state"] == "blocked"
    clock.advance(301)
    assert [r.status for r in d.expire_due()] == ["unblocked"]   # expires as planned
    assert 10 not in acl_rules(router)
    d.store.close()


def test_recover_after_crash_during_drift_repair_keeps_live_rule(driver, client, router, clock):
    assert driver.block(ATTACKER, "R1", 600, alert_id="A-1").seq == 10
    client.delete_rule("BLOCKLIST", 10)                  # rule vanished from the router (drift)
    clock.advance(5)                                     # new alert re-applies at the free seq 10,
    driver.store.add("R1", ATTACKER, "BLOCKLIST", 10, "A-2", "", clock.now, clock.now + 600,
                     status="pending")                   # then the process crashes before
    client.add_rules("BLOCKLIST", [deny_rule(10, ATTACKER)])   # switching records
    assert [r.status for r in driver.recover()] == ["recovered"]
    assert 10 in acl_rules(router)                       # the live rule was NOT deleted
    state = driver.status(ATTACKER, "R1")
    assert state["state"] == "blocked" and state["record"]["alert_id"] == "A-2"
    assert [r.status for r in driver.store.history()[:2]] == ["active", "replaced"]


def test_recover_closes_write_that_never_reached_router(driver, clock):
    driver.store.add("R1", ATTACKER, "BLOCKLIST", 10, "", "", clock.now, clock.now + 300,
                     status="pending")
    assert [r.status for r in driver.recover()] == ["discarded"]
    assert driver.store.list_pending() == [] and driver.list_active() == []
    assert driver.recover() == []                         # nothing left: no router call


def test_recover_removes_duplicate_rule(driver, client, router, clock):
    driver.block(ATTACKER, "R1", 600)                    # active block, seq 10
    driver.store.add("R1", ATTACKER, "BLOCKLIST", 20, "", "", clock.now, clock.now + 300,
                     status="pending")
    client.add_rules("BLOCKLIST", [deny_rule(20, ATTACKER)])
    result = driver.recover()[0]
    assert result.status == "discarded" and "duplicate" in result.message
    assert sorted(acl_rules(router)) == [10, 1000]


def test_worker_runs_recovery(driver, clock):
    driver.store.add("R1", ATTACKER, "BLOCKLIST", 10, "", "", clock.now, clock.now + 300,
                     status="pending")
    worker = ExpiryWorker(driver, interval=1)
    worker.run_once()
    assert worker.stats["recovered"] == 1 and driver.store.list_pending() == []


def test_reconcile_reports_without_changing_anything(driver, client, router):
    driver.block(ATTACKER, "R1", 600)
    driver.block(ATTACKER2, "R1", 600)
    with router.state.lock:
        del router.state.acls["BLOCKLIST"][20]
    client.add_rules("BLOCKLIST", [deny_rule(500, ADMIN_IP), deny_rule(510, ATTACKER)])
    writes = router.state.count("PATCH")
    report = driver.reconcile("R1")
    assert [e["ip"] for e in report["in_sync"]] == [ATTACKER]
    assert [e["ip"] for e in report["missing_on_router"]] == [ATTACKER2]
    assert {(f["ip"], f["seq"]) for f in report["foreign_rules"]} == {(ADMIN_IP, 500), (ATTACKER, 510)}
    assert report["duplicate_rules"] == [{"ip": ATTACKER, "seqs": [10, 510]}]
    assert report["ok"] is False and router.state.count("PATCH") == writes


def test_reconcile_fix_restores_blocks_after_router_restart(driver, router, clock):
    driver.block(ATTACKER, "R1", 600)
    driver.block(ATTACKER2, "R1", 3600)
    driver.block("192.0.2.5", "R1", 120)
    clock.advance(200)                                    # 192.0.2.5 is now past its TTL
    with router.state.lock:
        router.state.acls.clear()                         # router reloaded without saved config
    report = driver.reconcile("R1", fix=True)
    assert report["ok"] is True
    actions = {e["ip"]: e["action"] for e in report["repaired"]}
    assert actions[ATTACKER] == actions[ATTACKER2] == "rule re-applied"
    assert "TTL already passed" in actions["192.0.2.5"]
    assert sorted(acl_rules(router)) == [10, 20, 1000]   # permit-any restored as well
    assert driver.reconcile("R1")["ok"] is True           # now in sync


def test_reconcile_fix_moves_rule_if_sequence_was_taken(driver, client, router):
    driver.block(ATTACKER, "R1", 600)                     # seq 10
    with router.state.lock:
        router.state.acls["BLOCKLIST"][10] = deny_rule(10, ADMIN_IP)   # admin re-used seq 10
    report = driver.reconcile("R1", fix=True)
    assert report["repaired"][0]["seq"] == 20
    assert acl_rules(router)[10]["ace-rule"]["host"] == ADMIN_IP       # admin rule untouched
    assert driver.store.get_active("R1", ATTACKER).seq == 20


def test_reconcile_fix_never_adds_second_rule_for_foreign_denied_ip(driver, client, router):
    driver.block(ATTACKER, "R1", 600)
    with router.state.lock:
        del router.state.acls["BLOCKLIST"][10]
    client.add_rules("BLOCKLIST", [deny_rule(500, ATTACKER)])
    report = driver.reconcile("R1", fix=True)
    assert report["ok"] is False and "no second rule" in report["not_repaired"][0]["reason"]
    assert sorted(acl_rules(router)) == [500, 1000]


def test_reconcile_router_down_is_reported(driver, router):
    router.state.fail_next(50, 503)
    report = driver.reconcile("R1")
    assert report["ok"] is False and "503" in report["error"]


def test_rollback_by_alert_removes_only_that_alerts_blocks(driver, client, router):
    driver.block(ATTACKER, "R1", 600, alert_id="FP-1")
    driver.block(ATTACKER2, "R1", 600, alert_id="FP-1")
    driver.block("192.0.2.5", "R1", 600, alert_id="REAL-2")
    results = driver.unblock_alert("FP-1")
    assert sorted(r.ip for r in results) == sorted([ATTACKER, ATTACKER2])
    assert all(r.status == "unblocked" for r in results)
    assert [r["ip"] for r in driver.list_active()] == ["192.0.2.5"]
    assert driver.store.history()[1].ended_by == "alert-rollback"
    with pytest.raises(ValidationError):
        driver.unblock_alert("")


def test_rollback_all_keeps_admin_rules(driver, client, router):
    driver.block(ATTACKER, "R1", 600)
    driver.block(ATTACKER2, "R1", 600)
    client.add_rules("BLOCKLIST", [deny_rule(500, ADMIN_IP)])
    results = driver.unblock_all()
    assert len(results) == 2 and all(r.status == "unblocked" for r in results)
    assert sorted(acl_rules(router)) == [500, 1000]
    assert driver.list_active() == []


def test_rollback_all_for_one_device(router, store, clock, sleeps):
    c = RestconfClient(router.url, USER, PASSWORD, verify=str(router.cert_path), sleep=sleeps.append)
    d = CiscoDriver({"EDGE1": c, "DC1": c}, store, clock=clock)
    d.block(ATTACKER, "EDGE1", 600)
    d.block(ATTACKER2, "DC1", 600)
    assert [r.ip for r in d.unblock_all("EDGE1")] == [ATTACKER]
    assert [r["device"] for r in d.list_active()] == ["DC1"]
    assert ATTACKER2 in [r["ace-rule"].get("host") for r in acl_rules(router).values()]


def test_backup_is_consistent_and_never_overwrites(driver, tmp_path):
    driver.block(ATTACKER, "R1", 600)
    integrity, count = driver.store.backup(tmp_path / "bk" / "copy.db")
    assert integrity == "ok" and count == 1
    with pytest.raises(FileExistsError):
        driver.store.backup(tmp_path / "bk" / "copy.db")


def test_v1_0_database_is_upgraded_in_place(tmp_path, router, clock):
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE blocks (id INTEGER PRIMARY KEY AUTOINCREMENT, device TEXT NOT NULL,
            ip TEXT NOT NULL, acl TEXT NOT NULL, seq INTEGER NOT NULL, alert_id TEXT, reason TEXT,
            created_at REAL NOT NULL, expires_at REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'active', ended_at REAL, ended_by TEXT);
        CREATE TABLE changes (device TEXT NOT NULL, ts REAL NOT NULL);
    """)
    conn.execute("INSERT INTO blocks (device, ip, acl, seq, created_at, expires_at)"
                 " VALUES ('R1', '203.0.113.7', 'BLOCKLIST', 10, ?, ?)", (clock.now, clock.now + 60))
    conn.commit()
    conn.close()
    store = BlockStore(db)
    record = store.list_active()[0]
    assert record.ip == ATTACKER and record.attempts == 0 and record.last_error is None
    store.close()


# ======================================================== E. Command line

@pytest.fixture
def cli_env(router, tmp_path, monkeypatch):
    monkeypatch.setenv("RESTCONF_DEVICES", f"R1={router.url}")
    monkeypatch.setenv("RESTCONF_USER", "admin")
    monkeypatch.setenv("RESTCONF_PASSWORD", PASSWORD)
    monkeypatch.setenv("RESTCONF_VERIFY", str(router.cert_path))
    monkeypatch.setenv("RESTCONF_BACKOFF", "0.01")
    monkeypatch.setenv("BLOCK_DB_PATH", str(tmp_path / "cli.db"))
    monkeypatch.chdir(tmp_path)
    return router


def run(capsys, *args):
    code = cli.main(list(args))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_status_extend_and_block_many(cli_env, capsys, tmp_path):
    ip_file = tmp_path / "ips.txt"
    ip_file.write_text("# from ALERT-9\n198.51.100.23\n198.51.100.24  # second host\n", encoding="utf-8")
    code, out, _ = run(capsys, "block-many", "203.0.113.7", "--file", str(ip_file),
                       "--device", "R1", "--ttl", "300", "--alert-id", "ALERT-9")
    assert code == 0 and [r["seq"] for r in json.loads(out)] == [10, 20, 30]

    code, out, _ = run(capsys, "status", "203.0.113.7", "--device", "R1")
    assert code == 0 and json.loads(out)["state"] == "blocked"

    code, out, _ = run(capsys, "extend", "203.0.113.7", "--device", "R1", "--ttl", "3600")
    assert code == 0 and json.loads(out)["status"] == "extended"

    code, out, _ = run(capsys, "rollback-alert", "ALERT-9")
    assert code == 0 and len(json.loads(out)) == 3


def test_cli_block_many_with_invalid_ip_exit_1(cli_env, capsys):
    code, out, _ = run(capsys, "block-many", "203.0.113.7", "bad", "--device", "R1")
    assert code == 1 and [r["status"] for r in json.loads(out)] == ["blocked", "invalid"]
    code, _, err = run(capsys, "block-many", "--device", "R1")
    assert code == 2 and "at least one IP" in err


def test_cli_reconcile_fix_and_recover(cli_env, capsys):
    run(capsys, "block", "203.0.113.7", "--device", "R1", "--ttl", "300")
    with cli_env.state.lock:
        cli_env.state.acls.clear()
    code, out, _ = run(capsys, "reconcile", "--device", "R1")
    assert code == 1 and json.loads(out)["missing_on_router"][0]["ip"] == "203.0.113.7"
    code, out, _ = run(capsys, "reconcile", "--device", "R1", "--fix")
    assert code == 0 and json.loads(out)["repaired"][0]["action"] == "rule re-applied"
    code, out, _ = run(capsys, "recover")
    assert code == 0 and json.loads(out) == []


def test_cli_rollback_all_needs_confirmation(cli_env, capsys):
    run(capsys, "block", "203.0.113.7", "--device", "R1")
    code, _, err = run(capsys, "rollback-all")
    assert code == 2 and "--yes" in err
    code, out, _ = run(capsys, "rollback-all", "--yes")
    assert code == 0 and json.loads(out)[0]["status"] == "unblocked"


def test_cli_backup(cli_env, capsys, tmp_path):
    run(capsys, "block", "203.0.113.7", "--device", "R1")
    code, out, _ = run(capsys, "backup", "--out", str(tmp_path / "b" / "x.db"))
    data = json.loads(out)
    assert code == 0 and data["integrity_check"] == "ok" and data["records"] == 1
    code, _, err = run(capsys, "backup", "--out", str(tmp_path / "b" / "x.db"))
    assert code == 2 and "already exists" in err
    code, out, _ = run(capsys, "backup")                  # default name in backups\
    assert code == 0 and json.loads(out)["backup"].startswith("backups")


def test_cli_protected_setting(cli_env, capsys, monkeypatch):
    monkeypatch.setenv("BLOCK_PROTECTED", "203.0.113.0/24")
    code, out, _ = run(capsys, "block", "203.0.113.7", "--device", "R1")
    assert code == 1 and "protected list" in json.loads(out)["message"]
    monkeypatch.setenv("BLOCK_PROTECTED", "not-a-network")
    code, _, err = run(capsys, "list")
    assert code == 2 and "Settings error" in err
