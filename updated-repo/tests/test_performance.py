"""Performance: how long enforcement takes. Team target: under 30 seconds per block.

Run with  pytest tests/test_performance.py -s  to see the numbers.
"""

import statistics
import time

from cisco_driver.driver import CiscoDriver
from cisco_driver.restconf_client import RestconfClient
from cisco_driver.store import BlockStore

from .conftest import PASSWORD, USER, acl_rules

TARGET_SECONDS = 30


def make_driver(router, tmp_path, clock):
    client = RestconfClient(router.url, USER, PASSWORD, verify=str(router.cert_path),
                            sleep=lambda s: None)
    return CiscoDriver({"R1": client}, BlockStore(tmp_path / "perf.db"), clock=clock,
                       max_changes_per_minute=1000, max_blocks_per_device=1000)


def report(name, timings):
    timings = sorted(timings)
    p95 = timings[int(len(timings) * 0.95) - 1]
    print(f"\n{name}: n={len(timings)} mean={statistics.mean(timings) * 1000:.1f}ms "
          f"p95={p95 * 1000:.1f}ms max={timings[-1] * 1000:.1f}ms")
    return timings[-1]


def test_block_and_expire_50_ips(router, tmp_path, clock):
    driver = make_driver(router, tmp_path, clock)
    ips = [f"192.0.2.{i}" for i in range(1, 51)]

    block_times = []
    for ip in ips:
        start = time.perf_counter()
        assert driver.block(ip, "R1", 120).status == "blocked"
        block_times.append(time.perf_counter() - start)
    assert len(acl_rules(router)) == 51

    clock.advance(121)
    start = time.perf_counter()
    results = driver.expire_due()
    expire_total = time.perf_counter() - start
    assert len(results) == 50 and all(r.status == "unblocked" for r in results)

    worst = report("block()", block_times)
    print(f"expire_due() removed 50 blocks in {expire_total:.2f}s")
    assert worst < TARGET_SECONDS
    driver.store.close()


def test_block_time_with_slow_router(router, tmp_path, clock):
    """Router takes 0.2s per reply and fails twice first: still far under the target."""
    driver = make_driver(router, tmp_path, clock)
    router.state.delay = 0.2
    router.state.fail_next(2, 503)
    start = time.perf_counter()
    assert driver.block("203.0.113.7", "R1", 120).status == "blocked"
    elapsed = time.perf_counter() - start
    print(f"\nblock() with slow router + 2 failures: {elapsed:.2f}s")
    assert elapsed < TARGET_SECONDS
    driver.store.close()
