"""Command line for the Cisco driver.

    python -m cisco_driver block 203.0.113.7 --device R1 --ttl 3600 --reason "ssh brute force"
    python -m cisco_driver unblock 203.0.113.7 --device R1        (rollback)
    python -m cisco_driver list
    python -m cisco_driver history
    python -m cisco_driver show-acl --device R1
    python -m cisco_driver expire                                 (run expiry once)
    python -m cisco_driver worker                                 (run expiry forever)

v1.1:
    python -m cisco_driver status 203.0.113.7 --device R1         (is it blocked? router + record)
    python -m cisco_driver block-many 203.0.113.7 198.51.100.23 --device R1 --alert-id A-9
    python -m cisco_driver extend 203.0.113.7 --device R1 --ttl 7200
    python -m cisco_driver reconcile --device R1 [--fix]          (router vs record; repair)
    python -m cisco_driver recover                                (resolve interrupted writes)
    python -m cisco_driver rollback-alert A-9                     (undo a false-positive alert)
    python -m cisco_driver rollback-all [--device R1] --yes       (emergency: remove all own blocks)
    python -m cisco_driver backup [--out backups\\blocks.db]       (safe online copy of blocks.db)

Settings come from environment variables - see config.py.
Exit codes: 0 = ok, 1 = refused / router error, 2 = bad input or settings.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import List, Optional

from .config import Settings
from .driver import CiscoDriver
from .expiry_worker import ExpiryWorker
from .restconf_client import RestconfError
from .validation import ValidationError


def _print(data) -> None:
    print(json.dumps(data, indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cisco_driver", description="Role E - Cisco IOS XE block driver")
    p.add_argument("-v", "--verbose", action="store_true", help="show retry and audit logs")
    sub = p.add_subparsers(dest="command", required=True)

    b = sub.add_parser("block", help="block one IP on a device")
    b.add_argument("ip")
    b.add_argument("--device", required=True)
    b.add_argument("--ttl", type=int, default=3600, help="seconds until the block is removed")
    b.add_argument("--reason", default="")
    b.add_argument("--alert-id", default="")

    u = sub.add_parser("unblock", help="rollback: remove a block now")
    u.add_argument("ip")
    u.add_argument("--device", required=True)

    sub.add_parser("list", help="show active blocks")
    sub.add_parser("history", help="show recent blocks, including removed ones")

    s = sub.add_parser("show-acl", help="read the ACL from the router")
    s.add_argument("--device", required=True)

    sub.add_parser("expire", help="remove expired blocks once")

    w = sub.add_parser("worker", help="keep removing expired blocks (Ctrl+C to stop)")
    w.add_argument("--interval", type=float, default=None)

    # ---- v1.1
    st = sub.add_parser("status", help="is this IP blocked? (router and record compared)")
    st.add_argument("ip")
    st.add_argument("--device", required=True)

    bm = sub.add_parser("block-many", help="block several IPs from one alert")
    bm.add_argument("ips", nargs="*", help="IPv4 hosts (or use --file)")
    bm.add_argument("--file", help="text file with one IP per line (# comments allowed)")
    bm.add_argument("--device", required=True)
    bm.add_argument("--ttl", type=int, default=3600)
    bm.add_argument("--reason", default="")
    bm.add_argument("--alert-id", default="")

    e = sub.add_parser("extend", help="keep an active block until at least now + TTL")
    e.add_argument("ip")
    e.add_argument("--device", required=True)
    e.add_argument("--ttl", type=int, required=True, help="seconds from now")

    rc = sub.add_parser("reconcile", help="compare router and record; --fix repairs drift")
    rc.add_argument("--device", required=True)
    rc.add_argument("--fix", action="store_true", help="re-apply lost driver rules, resolve interrupted writes")

    sub.add_parser("recover", help="resolve writes interrupted by a crash or router failure")

    ra = sub.add_parser("rollback-alert", help="remove every block created by one alert")
    ra.add_argument("alert_id")

    rall = sub.add_parser("rollback-all", help="emergency: remove ALL blocks this driver created")
    rall.add_argument("--device", default=None, help="only this device (default: all devices)")
    rall.add_argument("--yes", action="store_true", help="confirm; required")

    bk = sub.add_parser("backup", help="consistent online copy of the block database")
    bk.add_argument("--out", default=None, help="target file (default backups\\blocks-<time>.db)")
    return p


def _read_ip_file(path: str) -> List[str]:
    with open(path, encoding="utf-8") as fh:
        return [line.split("#", 1)[0].strip() for line in fh if line.split("#", 1)[0].strip()]


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        settings = Settings.from_env()
        driver = CiscoDriver.from_settings(settings)
    except (ValueError, ValidationError) as exc:
        print(f"Settings error: {exc}", file=sys.stderr)
        return 2

    try:
        if args.command == "block":
            result = driver.block(args.ip, args.device, args.ttl, args.alert_id, args.reason)
            _print(result.to_dict())
            return 0 if result.ok else 1
        if args.command == "unblock":
            result = driver.unblock(args.ip, args.device)
            _print(result.to_dict())
            return 0 if result.ok else 1
        if args.command == "list":
            _print(driver.list_active())
            return 0
        if args.command == "history":
            _print([r.to_dict() for r in driver.store.history()])
            return 0
        if args.command == "show-acl":
            rules = driver.show_acl(args.device)
            _print({"acl": driver.acl, "exists": rules is not None, "rules": rules or []})
            return 0
        if args.command == "expire":
            results = driver.expire_due()
            _print([r.to_dict() for r in results])
            return 0 if all(r.ok for r in results) else 1
        if args.command == "worker":
            worker = ExpiryWorker(driver, args.interval or settings.expiry_interval)
            print(f"Expiry worker running every {worker.interval}s - press Ctrl+C to stop")
            worker.start()
            try:
                while True:
                    worker._stop.wait(3600)
            except KeyboardInterrupt:
                worker.stop()
                health = worker.health()
                print(f"Stopped. runs={health['runs']} removed={health['removed']} "
                      f"failed={health['failed']} recovered={health['recovered']}")
            return 0
        # ---- v1.1
        if args.command == "status":
            _print(driver.status(args.ip, args.device))
            return 0
        if args.command == "block-many":
            ips = list(args.ips) + (_read_ip_file(args.file) if args.file else [])
            if not ips:
                print("Invalid input: give at least one IP or --file", file=sys.stderr)
                return 2
            results = driver.block_many(ips, args.device, args.ttl, args.alert_id, args.reason)
            _print([r.to_dict() for r in results])
            return 0 if all(r.ok for r in results) else 1
        if args.command == "extend":
            result = driver.extend(args.ip, args.device, args.ttl)
            _print(result.to_dict())
            return 0 if result.status == "extended" else 1
        if args.command == "reconcile":
            report = driver.reconcile(args.device, fix=args.fix)
            _print(report)
            return 0 if report["ok"] else 1
        if args.command == "recover":
            results = driver.recover()
            _print([r.to_dict() for r in results])
            return 0 if all(r.ok for r in results) else 1
        if args.command == "rollback-alert":
            results = driver.unblock_alert(args.alert_id)
            _print([r.to_dict() for r in results])
            return 0 if all(r.ok for r in results) else 1
        if args.command == "rollback-all":
            if not args.yes:
                print("Refusing to remove every block without --yes", file=sys.stderr)
                return 2
            results = driver.unblock_all(args.device)
            _print([r.to_dict() for r in results])
            return 0 if all(r.ok for r in results) else 1
        if args.command == "backup":
            out = args.out or str(Path("backups") / f"blocks-{time.strftime('%Y%m%d-%H%M%S')}.db")
            try:
                integrity, count = driver.store.backup(out)
            except FileExistsError as exc:
                print(f"Invalid input: {exc}", file=sys.stderr)
                return 2
            _print({"backup": out, "integrity_check": integrity, "records": count})
            return 0 if integrity == "ok" else 1
    except ValidationError as exc:
        print(f"Invalid input: {exc}", file=sys.stderr)
        return 2
    except RestconfError as exc:
        print(f"Router error: {exc}", file=sys.stderr)
        return 1
    finally:
        driver.store.close()
    return 2


if __name__ == "__main__":
    sys.exit(main())
