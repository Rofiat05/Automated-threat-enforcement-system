"""Background expiry worker and the command line."""

import json
import time

import pytest

from cisco_driver import cli
from cisco_driver.expiry_worker import ExpiryWorker

from .conftest import PASSWORD, acl_rules


def wait_until(condition, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.05)
    return False


def test_worker_removes_block_in_background(driver, router, clock):
    driver.block("203.0.113.7", "R1", 120)
    with ExpiryWorker(driver, interval=0.05):
        time.sleep(0.2)
        assert 10 in acl_rules(router)          # not expired yet
        clock.advance(121)
        assert wait_until(lambda: 10 not in acl_rules(router))
    assert driver.list_active() == []


def test_worker_survives_errors(driver, router, clock):
    driver.block("203.0.113.7", "R1", 120)
    clock.advance(121)
    router.state.fail_next(1000, 503)
    worker = ExpiryWorker(driver, interval=0.05)
    worker.start()
    time.sleep(0.3)
    assert worker._thread.is_alive()             # did not crash
    router.state.failures.clear()
    assert wait_until(lambda: driver.list_active() == [])
    worker.stop()


def test_worker_rejects_bad_interval(driver):
    with pytest.raises(ValueError):
        ExpiryWorker(driver, interval=0)


@pytest.fixture
def cli_env(router, tmp_path, monkeypatch):
    monkeypatch.setenv("RESTCONF_DEVICES", f"R1={router.url}")
    monkeypatch.setenv("RESTCONF_USER", "admin")
    monkeypatch.setenv("RESTCONF_PASSWORD", PASSWORD)
    monkeypatch.setenv("RESTCONF_VERIFY", str(router.cert_path))
    monkeypatch.setenv("RESTCONF_BACKOFF", "0.01")
    monkeypatch.setenv("BLOCK_DB_PATH", str(tmp_path / "cli.db"))
    return router


def run(capsys, *args):
    code = cli.main(list(args))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_full_cycle(cli_env, capsys):
    code, out, _ = run(capsys, "block", "203.0.113.7", "--device", "R1", "--ttl", "300",
                       "--reason", "ssh brute force", "--alert-id", "A-77")
    assert code == 0 and json.loads(out)["status"] == "blocked"

    code, out, _ = run(capsys, "list")
    active = json.loads(out)
    assert active[0]["ip"] == "203.0.113.7" and active[0]["alert_id"] == "A-77"

    code, out, _ = run(capsys, "show-acl", "--device", "R1")
    assert [r["sequence"] for r in json.loads(out)["rules"]] == ["10", "1000"]

    code, out, _ = run(capsys, "unblock", "203.0.113.7", "--device", "R1")
    assert code == 0 and json.loads(out)["status"] == "unblocked"

    code, out, _ = run(capsys, "history")
    assert json.loads(out)[0]["status"] == "removed"

    code, out, _ = run(capsys, "expire")
    assert code == 0 and json.loads(out) == []


def test_cli_bad_input_exit_code_2(cli_env, capsys):
    code, _, err = run(capsys, "block", "10.0.0.0/8", "--device", "R1")
    assert code == 2 and "Invalid input" in err


def test_cli_missing_settings(monkeypatch, capsys):
    monkeypatch.delenv("RESTCONF_DEVICES", raising=False)
    code, _, err = run(capsys, "list")
    assert code == 2 and "RESTCONF_DEVICES" in err


def test_cli_router_down_exit_code_1(cli_env, capsys):
    cli_env.state.fail_next(100, 503)
    code, out, _ = run(capsys, "block", "203.0.113.7", "--device", "R1")
    assert code == 1 and json.loads(out)["status"] == "error"


def test_password_never_printed(cli_env, capsys):
    cli_env.state.fail_next(100, 503)
    run(capsys, "-v", "block", "203.0.113.7", "--device", "R1")
    out = capsys.readouterr()
    assert PASSWORD not in out.out + out.err
