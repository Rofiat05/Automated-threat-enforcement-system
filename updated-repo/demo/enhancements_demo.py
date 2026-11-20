"""Role E v1.1 demonstration: IP-blocking logic, duplicate prevention, TTL, rollback & recovery.

Runs on the bundled Mock IOS XE router (no real Cisco device needed) and shows the
v1.1 enhancements in ten steps:
     1. Start the mock router and a driver with a protected (never-block) list
     2. Protected addresses are never blocked
     3. Batch blocking for an alert with several source IPs
     4. Duplicate prevention between several driver processes at the same moment
     5. TTL: lifetime cap, manual extend, repeat-offender escalation
     6. "Is this IP blocked?" - status() in all four states
     7. Recovery from a write that fails half-way and from a crash
     8. Router restart: reconcile, then reconcile --fix
     9. Rollback by alert (false positive) and emergency rollback-all
    10. Safe online backup of blocks.db

Usage:
    python demo/enhancements_demo.py            # about 5 seconds
    python demo/enhancements_demo.py --pause    # wait for Enter between steps
"""

from __future__ import annotations

import argparse
import logging
import secrets
import sys
import tempfile
import threading
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests  # noqa: E402

from cisco_driver.driver import CiscoDriver  # noqa: E402
from cisco_driver.restconf_client import RestconfClient, deny_rule  # noqa: E402
from cisco_driver.store import BlockStore, iso  # noqa: E402
from mock_router import MockServer  # noqa: E402

USER = "admin"
PASSWORD = secrets.token_urlsafe(12)
DEVICE = "R1"
STEPS = 10
PAUSE = False


class DemoClock:
    """Real time plus a manual offset, so hours of TTL can be shown in seconds."""

    def __init__(self) -> None:
        self.offset = 0.0

    def __call__(self) -> float:
        import time
        return time.time() + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += seconds


def step(number: int, title: str) -> None:
    if PAUSE and number > 1:
        input("\n    (press Enter for the next step)")
    print(f"\n{'=' * 78}\n[{datetime.now():%H:%M:%S}] STEP {number}/{STEPS} - {title}\n{'=' * 78}")


def say(text: str = "") -> None:
    print(f"    {text}")


def show(r) -> None:
    extra = f", expires {iso(r.expires_at)}" if r.expires_at else ""
    say(f"-> {r.ip:<15} {r.status.upper()}: {r.message} (seq={r.seq}{extra})")


def router_view(mock: MockServer) -> None:
    text = requests.get(f"{mock.url}/_mock/show", auth=(USER, PASSWORD),
                        verify=str(mock.cert_path), timeout=5).text
    say("Router> show access-lists")
    for line in (text.rstrip().splitlines() or ["(no access lists configured)"]):
        say(f"  {line}")


def main() -> int:
    global PAUSE
    ap = argparse.ArgumentParser(description="Role E v1.1 enhancements demonstration")
    ap.add_argument("--pause", action="store_true", help="wait for Enter between steps")
    PAUSE = ap.parse_args().pause

    logging.basicConfig(level=logging.CRITICAL)            # keep the output readable
    logging.getLogger("werkzeug").setLevel(logging.ERROR)  # hide the mock's access log
    workdir = Path(tempfile.mkdtemp(prefix="role_e_v11_demo_"))
    db = workdir / "blocks.db"
    clock = DemoClock()

    step(1, "Start the mock router and a driver with a protected list")
    mock = MockServer(USER, PASSWORD, workdir / "certs").start()

    def new_driver(**kw) -> CiscoDriver:
        client = RestconfClient(mock.url, USER, PASSWORD, verify=str(mock.cert_path),
                                timeout=3, max_retries=1, backoff_base=0.1)
        options = dict(min_ttl=10, max_changes_per_minute=100, clock=clock,
                       protected="192.0.2.1, 192.0.2.53, 10.0.0.0/24",
                       max_lifetime=7200, repeat_factor=2)
        options.update(kw)
        return CiscoDriver({DEVICE: client}, BlockStore(db), **options)

    try:
        driver = new_driver()
        say(f"Mock router : {mock.url}")
        say("Protected   : 192.0.2.1 (gateway), 192.0.2.53 (DNS), 10.0.0.0/24 (management LAN)")
        say("TTL options : max lifetime 7200 s, repeat-offender factor x2")

        step(2, "Protected addresses are never blocked")
        for ip in ("192.0.2.1", "10.0.0.25"):
            show(driver.block(ip, DEVICE, 600, alert_id="ALERT-100"))
        say(f"RESTCONF requests sent to the router: {mock.state.count()} (nothing was changed)")

        step(3, "Batch blocking: one alert, several source IPs")
        say("ALERT-101 lists: 203.0.113.7, 203.0.113.8, 203.0.113.7 (again), 'bad-ip'")
        for r in driver.block_many(["203.0.113.7", "203.0.113.8", "203.0.113.7", "bad-ip"],
                                   DEVICE, 600, alert_id="ALERT-101", reason="ssh brute force"):
            show(r)
        router_view(mock)

        step(4, "Duplicate prevention: 4 driver processes block the same IP at once")
        racers = [new_driver() for _ in range(4)]
        results, barrier = [], threading.Barrier(4)

        def race(d: CiscoDriver) -> None:
            barrier.wait()
            results.append(d.block("198.51.100.23", DEVICE, 600, alert_id="ALERT-102"))

        threads = [threading.Thread(target=race, args=(d,)) for d in racers]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for r in sorted(results, key=lambda r: r.status, reverse=True):
            show(r)
        rules = [s for s, r in mock.state.acls["BLOCKLIST"].items()
                 if r["ace-rule"].get("host") == "198.51.100.23"]
        say(f"Deny lines for 198.51.100.23 on the router: {len(rules)} (one, no duplicate)")
        for d in racers:
            d.store.close()

        step(5, "TTL: lifetime cap, extend, repeat offenders")
        say("Every ~33 min a new alert arrives for 203.0.113.7 (1 h TTL, 2 h lifetime cap):")
        for n in range(3):
            clock.advance(2000)
            show(driver.block("203.0.113.7", DEVICE, 3600, alert_id=f"ALERT-11{n}"))
        say("")
        say("Operator extends 203.0.113.8 to 1 hour (record only, no router change):")
        show(driver.extend("203.0.113.8", DEVICE, 3600))
        say("")
        say("198.51.100.99 is blocked, expires, then attacks again -> TTL doubles:")
        show(driver.block("198.51.100.99", DEVICE, 600, alert_id="ALERT-120"))
        clock.advance(601)
        driver.expire_due()
        show(driver.block("198.51.100.99", DEVICE, 600, alert_id="ALERT-121"))

        step(6, "Is this IP blocked? status() compares router and record")
        mock.state.acls["BLOCKLIST"][500] = deny_rule(500, "192.0.2.77")   # admin's own rule
        del mock.state.acls["BLOCKLIST"][20]                                # someone deletes ours
        for ip in ("203.0.113.7", "203.0.113.8", "192.0.2.77", "192.0.2.50"):
            st = driver.status(ip, DEVICE)
            say(f"{ip:<15} {st['state']:<16} router seqs {st['router_seqs']}")
        say("(203.0.113.8 = drift: recorded but missing on the router - repaired in step 8)")

        step(7, "Recovery: a write that fails half-way, and a crash")
        original = mock.state.take_failure
        calls = {"n": 0}

        def fail_verify():                 # 1 = read, 2 = write (lands), 3 = verify fails
            calls["n"] += 1
            return 400 if calls["n"] == 3 else None
        mock.state.take_failure = fail_verify
        say("The write for 198.51.100.50 reaches the router, but the verification read fails:")
        show(driver.block("198.51.100.50", DEVICE, 600, alert_id="ALERT-130"))
        mock.state.take_failure = original
        say(f"Rule left on router for 198.51.100.50: "
            f"{driver.status('198.51.100.50', DEVICE)['blocked_on_router']} (the partial write was undone)")
        say("")
        say("Simulated crash: a process wrote seq 700 and died before confirming it.")
        driver.store.add(DEVICE, "198.51.100.60", "BLOCKLIST", 700, "ALERT-131", "crash",
                         clock(), clock() + 600, status="pending")
        mock.state.acls["BLOCKLIST"][700] = deny_rule(700, "198.51.100.60")
        for r in driver.recover():
            show(r)

        step(8, "Router restart: reconcile, then reconcile --fix")
        with mock.state.lock:
            mock.state.acls.clear()
        say("The router reloaded without a saved configuration: the ACL is gone.")
        report = driver.reconcile(DEVICE)
        say(f"reconcile       -> ok={report['ok']}, missing on router: "
            f"{[e['ip'] for e in report['missing_on_router']]}")
        report = driver.reconcile(DEVICE, fix=True)
        say(f"reconcile --fix -> ok={report['ok']}")
        for e in report["repaired"]:
            say(f"   {e['ip']:<15} seq {e['seq']:<4} {e['action']}")
        router_view(mock)

        step(9, "Rollback by alert and emergency rollback-all")
        say("ALERT-101 turns out to be a false positive:")
        for r in driver.unblock_alert("ALERT-101"):
            show(r)
        say("(203.0.113.7 is kept: later alerts ALERT-110..112 confirmed it, so it now belongs to them)")
        mock.state.acls["BLOCKLIST"][500] = deny_rule(500, "192.0.2.77")
        say("Emergency: remove every block this driver created (admin rule 500 must stay):")
        for r in driver.unblock_all(DEVICE):
            show(r)
        router_view(mock)

        step(10, "Safe online backup of blocks.db")
        integrity, count = driver.store.backup(workdir / "backups" / "blocks-demo.db")
        say(f"Backup written: backups/blocks-demo.db  integrity_check={integrity}  records={count}")
        say("")
        say("History (newest first):")
        for rec in driver.store.history(12):
            say(f"  {rec.ip:<15} seq={rec.seq:<4} {rec.status:<8} by={rec.ended_by or '-'}")

        print(f"\n{'=' * 78}\nDemonstration complete: all {STEPS} steps shown.")
        driver.store.close()
        return 0
    finally:
        mock.stop()


if __name__ == "__main__":
    sys.exit(main())
