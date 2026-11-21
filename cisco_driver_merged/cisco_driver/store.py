"""SQLite record of every block, so expiry still works after a restart.

v1.1 additions (blocking / duplicate prevention / TTL / rollback & recovery):
  * write-ahead journal  - a block is recorded as 'pending' BEFORE the router is
                           changed, so a crash or timeout mid-write can be recovered
  * cross-process lock   - one OS file lock per database, so two driver processes
                           (CLI, worker, SIEM integration) never change the ACL at
                           the same moment and can never create duplicate rules
  * failure tracking     - how many times a removal failed and the last error
  * schema migration     - databases created by v1.0 are upgraded in place
  * online backup        - consistent copy of the database while the worker runs
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Optional, Tuple, Union

if os.name == "nt":  # pragma: no cover - platform specific
    import msvcrt
else:  # pragma: no cover - platform specific
    import fcntl

SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device      TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    acl         TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    alert_id    TEXT,
    reason      TEXT,
    created_at  REAL    NOT NULL,
    expires_at  REAL    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'active',  -- active / pending / expired / removed / replaced / failed
    ended_at    REAL,
    ended_by    TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_block ON blocks(device, ip) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS blocks_by_expiry ON blocks(status, expires_at);
CREATE TABLE IF NOT EXISTS changes (
    device TEXT NOT NULL,
    ts     REAL NOT NULL
);
"""

# Columns added in v1.1. Added with ALTER TABLE so v1.0 databases keep working.
MIGRATIONS = (
    ("attempts", "ALTER TABLE blocks ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0"),
    ("last_error", "ALTER TABLE blocks ADD COLUMN last_error TEXT"),
)
POST_MIGRATION = """
CREATE INDEX IF NOT EXISTS blocks_by_ip ON blocks(device, ip, created_at);
CREATE INDEX IF NOT EXISTS blocks_by_alert ON blocks(alert_id) WHERE status = 'active';
"""


def iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


class LockTimeout(RuntimeError):
    """Another driver process kept the database lock for too long."""


@dataclass
class BlockRecord:
    id: int
    device: str
    ip: str
    acl: str
    seq: int
    alert_id: Optional[str]
    reason: Optional[str]
    created_at: float
    expires_at: float
    status: str
    ended_at: Optional[float]
    ended_by: Optional[str]
    attempts: int = 0
    last_error: Optional[str] = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["created_at_utc"] = iso(self.created_at)
        data["expires_at_utc"] = iso(self.expires_at)
        data["ended_at_utc"] = iso(self.ended_at)
        return data


class _FileLock:
    """Exclusive OS lock on one file. Released by the OS if the process dies."""

    def __init__(self, path: Path):
        self.path = path
        self._fh = open(path, "a+b")  # noqa: SIM115 - kept open for the store's lifetime

    def try_acquire(self) -> bool:
        try:
            if os.name == "nt":
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def release(self) -> None:
        if os.name == "nt":
            self._fh.seek(0)
            msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)

    def close(self) -> None:
        self._fh.close()


class BlockStore:
    def __init__(self, path: Union[str, Path]):
        self.path = str(path)
        # check_same_thread=False + our own lock: the expiry worker thread shares it.
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None,
                                     timeout=10)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._migrate()
        # cross-process lock (not possible for an in-memory database)
        self._xlock = threading.RLock()
        self._xdepth = 0
        self._file_lock: Optional[_FileLock] = None
        if self.path != ":memory:" and not self.path.startswith("file:"):
            self._file_lock = _FileLock(Path(self.path + ".lock"))

    def _migrate(self) -> None:
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(blocks)")}
        for name, sql in MIGRATIONS:
            if name not in columns:
                self._conn.execute(sql)
        self._conn.executescript(POST_MIGRATION)

    def close(self) -> None:
        with self._lock:
            self._conn.close()
        if self._file_lock:
            self._file_lock.close()

    # ---- cross-process exclusive section

    @contextmanager
    def exclusive(self, timeout: float = 30.0, poll: float = 0.02) -> Iterator[None]:
        """Hold the database-wide lock: only one driver process changes the router at a time.

        Re-entrant inside one store. Raises LockTimeout if another process holds it
        for longer than `timeout` seconds. A crashed process releases it automatically.
        """
        deadline = time.monotonic() + timeout
        if not self._xlock.acquire(timeout=max(timeout, 0.001)):
            raise LockTimeout("Another thread kept the driver busy; try again")
        try:
            if self._xdepth == 0 and self._file_lock is not None:
                while not self._file_lock.try_acquire():
                    if time.monotonic() >= deadline:
                        raise LockTimeout(
                            f"Another driver process is changing the router (lock "
                            f"{self._file_lock.path.name} busy for {timeout:.0f}s); try again")
                    time.sleep(poll)
            self._xdepth += 1
            try:
                yield
            finally:
                self._xdepth -= 1
                if self._xdepth == 0 and self._file_lock is not None:
                    self._file_lock.release()
        finally:
            self._xlock.release()

    def _rows(self, sql: str, params: tuple = ()) -> List[BlockRecord]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [BlockRecord(**dict(r)) for r in rows]

    def _one(self, sql: str, params: tuple = ()) -> Optional[BlockRecord]:
        rows = self._rows(sql, params)
        return rows[0] if rows else None

    # ---- blocks

    def add(self, device: str, ip: str, acl: str, seq: int, alert_id: str, reason: str,
            created_at: float, expires_at: float, status: str = "active") -> BlockRecord:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO blocks (device, ip, acl, seq, alert_id, reason, created_at, expires_at, status)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (device, ip, acl, seq, alert_id, reason, created_at, expires_at, status),
            )
            new_id = cur.lastrowid
        record = self._one("SELECT * FROM blocks WHERE id = ?", (new_id,))
        if record is None:
            raise RuntimeError("Block record could not be read back after insert")
        return record

    def get(self, record_id: int) -> Optional[BlockRecord]:
        return self._one("SELECT * FROM blocks WHERE id = ?", (record_id,))

    def get_active(self, device: str, ip: str) -> Optional[BlockRecord]:
        return self._one(
            "SELECT * FROM blocks WHERE device = ? AND ip = ? AND status = 'active'", (device, ip)
        )

    def list_active(self, device: Optional[str] = None) -> List[BlockRecord]:
        if device is None:
            return self._rows("SELECT * FROM blocks WHERE status = 'active' ORDER BY expires_at")
        return self._rows(
            "SELECT * FROM blocks WHERE status = 'active' AND device = ? ORDER BY expires_at", (device,)
        )

    def list_pending(self) -> List[BlockRecord]:
        """Writes that were started but never confirmed (crash / timeout mid-write)."""
        return self._rows("SELECT * FROM blocks WHERE status = 'pending' ORDER BY id")

    def active_for_alert(self, alert_id: str) -> List[BlockRecord]:
        return self._rows(
            "SELECT * FROM blocks WHERE status = 'active' AND alert_id = ? ORDER BY id", (alert_id,)
        )

    def history(self, limit: int = 50) -> List[BlockRecord]:
        return self._rows("SELECT * FROM blocks ORDER BY id DESC LIMIT ?", (limit,))

    def due(self, now: float) -> List[BlockRecord]:
        return self._rows(
            "SELECT * FROM blocks WHERE status = 'active' AND expires_at <= ? ORDER BY expires_at", (now,)
        )

    def count_active(self, device: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM blocks WHERE status = 'active' AND device = ?", (device,)
            ).fetchone()
        return int(row[0])

    def count_previous(self, device: str, ip: str, since: float) -> int:
        """Blocks of this IP that ran their full TTL and started after `since`.

        Only 'expired' blocks count. A block removed early (unblock, rollback by alert,
        emergency rollback) may have been a false positive, so it never makes a later
        block of the same IP longer.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM blocks WHERE device = ? AND ip = ? AND created_at >= ?"
                " AND status = 'expired'",
                (device, ip, since),
            ).fetchone()
        return int(row[0])

    def extend(self, record_id: int, expires_at: float, alert_id: Optional[str] = None) -> None:
        """Push the expiry later. alert_id, if given, becomes the latest alert for this block."""
        with self._lock:
            if alert_id:
                self._conn.execute("UPDATE blocks SET expires_at = ?, alert_id = ? WHERE id = ?",
                                   (expires_at, alert_id, record_id))
            else:
                self._conn.execute("UPDATE blocks SET expires_at = ? WHERE id = ?", (expires_at, record_id))

    def activate(self, record_id: int) -> None:
        """Confirm a pending block: the rule is verified on the router."""
        with self._lock:
            self._conn.execute(
                "UPDATE blocks SET status = 'active', last_error = NULL WHERE id = ? AND status = 'pending'",
                (record_id,),
            )

    def update_seq(self, record_id: int, seq: int) -> None:
        with self._lock:
            self._conn.execute("UPDATE blocks SET seq = ? WHERE id = ?", (seq, record_id))

    def note_failure(self, record_id: int, error: str) -> int:
        """Count a failed router operation for this block; returns the new attempt count."""
        with self._lock:
            self._conn.execute(
                "UPDATE blocks SET attempts = attempts + 1, last_error = ? WHERE id = ?",
                (error[:300], record_id),
            )
            row = self._conn.execute("SELECT attempts FROM blocks WHERE id = ?", (record_id,)).fetchone()
        return int(row[0]) if row else 0

    def end(self, record_id: int, status: str, by: str, now: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE blocks SET status = ?, ended_by = ?, ended_at = ?"
                " WHERE id = ? AND status IN ('active', 'pending')",
                (status, by, now, record_id),
            )

    # ---- rate limiting (stored, so separate CLI runs share the limit)

    def record_change(self, device: str, now: float) -> None:
        with self._lock:
            self._conn.execute("INSERT INTO changes (device, ts) VALUES (?, ?)", (device, now))
            self._conn.execute("DELETE FROM changes WHERE ts < ?", (now - 3600,))

    def changes_since(self, device: str, since: float) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM changes WHERE device = ? AND ts > ?", (device, since)
            ).fetchone()
        return int(row[0])

    # ---- backup

    def backup(self, destination: Union[str, Path]) -> Tuple[str, int]:
        """Consistent online copy (safe while the worker runs).

        Returns (integrity_check result, number of block records in the copy).
        """
        destination = Path(destination)
        if destination.exists():
            raise FileExistsError(f"{destination} already exists; choose a new file name")
        destination.parent.mkdir(parents=True, exist_ok=True)
        target = sqlite3.connect(str(destination))
        try:
            with self._lock:
                self._conn.backup(target)
            integrity = target.execute("PRAGMA integrity_check").fetchone()[0]
            count = target.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
        finally:
            target.close()
        return str(integrity), int(count)
