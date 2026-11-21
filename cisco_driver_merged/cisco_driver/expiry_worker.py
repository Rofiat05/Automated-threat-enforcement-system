"""Background job that removes blocks when their TTL runs out.

v1.1: every round it also resolves interrupted writes (driver.recover()), and it
keeps health counters (stats / health()) so another component can check that
automatic expiry is really running.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import List, Optional

from .driver import CiscoDriver, Result

log = logging.getLogger(__name__)


class ExpiryWorker:
    def __init__(self, driver: CiscoDriver, interval: float = 10.0, recover: bool = True):
        if interval <= 0:
            raise ValueError("interval must be positive")
        self.driver = driver
        self.interval = interval
        self.recover = recover
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._stats_lock = threading.Lock()
        self.stats = {
            "runs": 0, "removed": 0, "failed": 0, "recovered": 0,
            "last_run": None, "last_error": None, "started_at": None,
        }

    def run_once(self) -> List[Result]:
        if self.recover:
            for r in self.driver.recover():
                log.info("recovery: %s %s on %s -> %s", r.ip, r.seq, r.device, r.status)
                if r.status in ("recovered", "discarded"):
                    self._count("recovered")
        results = self.driver.expire_due()
        for r in results:
            log.info("expiry: %s %s on %s -> %s", r.ip, r.seq, r.device, r.status)
        with self._stats_lock:
            self.stats["runs"] += 1
            self.stats["removed"] += sum(1 for r in results if r.status == "unblocked")
            self.stats["failed"] += sum(1 for r in results if not r.ok)
            self.stats["last_run"] = time.time()
        return results

    def _count(self, key: str) -> None:
        with self._stats_lock:
            self.stats[key] += 1

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:  # keep the worker alive whatever happens
                with self._stats_lock:
                    self.stats["last_error"] = f"{type(exc).__name__}: {exc}"
                log.exception("Expiry run failed; will try again")
            self._stop.wait(self.interval)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        with self._stats_lock:
            self.stats["started_at"] = time.time()
        self._thread = threading.Thread(target=self._loop, name="expiry-worker", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    def health(self) -> dict:
        """Is automatic expiry working? healthy = running and checked within 3 intervals."""
        with self._stats_lock:
            data = dict(self.stats)
        alive = bool(self._thread and self._thread.is_alive())
        last = data["last_run"]
        data["alive"] = alive
        data["healthy"] = alive and last is not None and time.time() - last <= 3 * self.interval + 1
        return data

    def __enter__(self) -> "ExpiryWorker":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
