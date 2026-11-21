"""The Cisco driver: safe block / unblock / expiry on top of RestconfClient.

Rules it follows:
  * read before write  - look at the router first; never add the same block twice
  * verify after write - read again and confirm the rule is really there
  * single hosts only  - never a whole network
  * limits             - max changes per minute and max active blocks per device
  * TTL                - every block has an end time and is removed automatically
  * keep traffic alive - the ACL always ends with "permit ip any any"

v1.1 enhancements (IP-blocking logic, duplicate prevention, TTL, rollback & recovery):
  * protected list     - critical addresses (gateway, DNS, SIEM, admin PCs) are never blocked
  * batch blocking     - block_many(): one call for an alert with several source IPs
  * status()           - one answer to "is this IP blocked?" (router + record compared)
  * one writer at once - a cross-process lock stops two driver processes from creating
                         duplicate rules or re-using the same sequence number
  * lifetime cap       - repeated alerts can never keep an IP blocked for ever
  * repeat offenders   - optional longer TTL for an IP that keeps coming back
  * extend()           - push a block's expiry later without touching the router
  * write-ahead journal and compensation - a write that fails half-way is undone;
                         one interrupted by a crash is resolved by recover()
  * reconcile()        - compare router and record; --fix re-applies rules lost when the
                         router restarted
  * bulk rollback      - unblock_alert() for a false-positive alert, unblock_all() for an
                         emergency, both ownership-aware like unblock()
"""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from .restconf_client import (
    RestconfClient,
    RestconfError,
    denied_host,
    deny_rule,
    is_permit_any,
    permit_any_rule,
)
from .blocking_policy import BlockingPolicy
from .store import BlockRecord, BlockStore, LockTimeout, iso
from .validation import (
    ValidationError,
    clean_text,
    parse_networks,
    validate_ip,
    validate_name,
    validate_ttl,
)

log = logging.getLogger(__name__)
audit = logging.getLogger("cisco_driver.audit")

# Statuses that mean "the request was handled correctly" (nothing for the caller to retry).
OK_STATUSES = (
    "blocked", "already_blocked", "unblocked", "not_found",
    "extended", "recovered", "discarded",
)


@dataclass
class Result:
    # blocked | already_blocked | unblocked | not_found | refused | error
    # v1.1: extended (extend) | invalid (block_many) | recovered / discarded (recover)
    status: str
    device: str
    ip: str
    message: str = ""
    seq: Optional[int] = None
    expires_at: Optional[float] = None
    duration_ms: float = field(default=0.0)

    @property
    def ok(self) -> bool:
        return self.status in OK_STATUSES

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "device": self.device,
            "ip": self.ip,
            "seq": self.seq,
            "expires_at": self.expires_at,
            "expires_at_utc": iso(self.expires_at),
            "message": self.message,
            "duration_ms": round(self.duration_ms, 1),
        }


class CiscoDriver:
    def __init__(
        self,
        clients: Dict[str, RestconfClient],
        store: BlockStore,
        *,
        acl_name: str = "BLOCKLIST",
        min_ttl: int = 60,
        max_ttl: int = 86400,
        max_changes_per_minute: int = 10,
        max_blocks_per_device: int = 50,
        first_seq: int = 10,
        seq_step: int = 10,
        last_block_seq: int = 990,
        permit_seq: int = 1000,
        clock: Callable[[], float] = time.time,
        # ---- v1.1 options (defaults keep v1.0 behaviour)
        protected: Iterable[str] | str = (),
        max_lifetime: Optional[int] = 604800,
        repeat_factor: float = 1.0,
        repeat_window: int = 7 * 86400,
        lock_timeout: float = 30.0,
        stuck_after: int = 5,
    ):
        if not clients:
            raise ValueError("At least one device is needed")
        for name in clients:
            validate_name(name, "device")
        if max_lifetime is not None and max_lifetime < 0:
            raise ValueError("max_lifetime must be 0/None (no cap) or a positive number of seconds")
        if repeat_factor < 1:
            raise ValueError("repeat_factor must be 1 (off) or larger")
        self.clients = dict(clients)
        self.store = store
        self.acl = validate_name(acl_name, "ACL")
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.max_changes_per_minute = max_changes_per_minute
        self.max_blocks_per_device = max_blocks_per_device
        self.first_seq = first_seq
        self.seq_step = seq_step
        self.last_block_seq = last_block_seq
        self.permit_seq = permit_seq
        self.protected = parse_networks(protected)
        self.max_lifetime = max_lifetime or None
        self.repeat_factor = float(repeat_factor)
        self.repeat_window = repeat_window
        self.lock_timeout = lock_timeout
        self.stuck_after = stuck_after
        self._clock = clock
        self._lock = threading.RLock()  # block/unblock/expiry never run at the same time

    @classmethod
    def from_settings(cls, settings, clock: Callable[[], float] = time.time) -> "CiscoDriver":
        policy = BlockingPolicy.for_settings(settings)      # fail before opening the DB
        protected = parse_networks(policy.protected)
        clients = {
            name: RestconfClient(
                url,
                settings.username,
                settings.password,
                verify=settings.verify_tls,
                timeout=settings.timeout,
                max_retries=settings.max_retries,
                backoff_base=settings.backoff_base,
            )
            for name, url in settings.devices.items()
        }
        return cls(
            clients,
            BlockStore(settings.db_path),
            acl_name=settings.acl_name,
            min_ttl=settings.min_ttl,
            max_ttl=settings.max_ttl,
            max_changes_per_minute=settings.max_changes_per_minute,
            max_blocks_per_device=settings.max_blocks_per_device,
            clock=clock,
            protected=[str(n) for n in protected],
            max_lifetime=policy.max_lifetime,
            repeat_factor=policy.repeat_factor,
        )

    # ---------------------------------------------------------------- helpers

    def _client(self, device: str) -> RestconfClient:
        validate_name(device, "device")
        if device not in self.clients:
            raise ValidationError(f"Unknown device {device!r}; known: {sorted(self.clients)}")
        return self.clients[device]

    @staticmethod
    def _deny_seqs(rules: List[dict], ip: str) -> List[int]:
        return [int(r["sequence"]) for r in rules if denied_host(r) == ip]

    def _free_seq(self, rules: List[dict]) -> Optional[int]:
        used = {int(r.get("sequence", -1)) for r in rules}
        for seq in range(self.first_seq, self.last_block_seq + 1, self.seq_step):
            if seq not in used:
                return seq
        return None

    def _finish(self, result: Result, started: float) -> Result:
        result.duration_ms = (time.perf_counter() - started) * 1000
        audit.info(json.dumps({"event": "enforcement", **result.to_dict()}))
        return result

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        """One change at a time: across threads (RLock) AND across processes (file lock)."""
        with self._lock:
            with self.store.exclusive(self.lock_timeout):
                yield

    def protected_by(self, ip: str) -> Optional[str]:
        """Return the protected network that covers this IP, or None."""
        address = ipaddress.ip_address(ip)
        for net in self.protected:
            if address in net:
                return str(net)
        return None

    def _write_deny(self, client: RestconfClient, rules: List[dict], acl_exists: bool,
                    seq: int, ip: str) -> None:
        """Write '<seq> deny ip host <ip> any' (plus permit-any if missing) and verify it."""
        new_rules = [deny_rule(seq, ip)]
        if not acl_exists:
            new_rules.append(permit_any_rule(self.permit_seq))
            client.create_acl(self.acl, new_rules)
        else:
            if not any(is_permit_any(r) for r in rules) and self.permit_seq not in {
                    int(r.get("sequence", -1)) for r in rules}:
                new_rules.append(permit_any_rule(self.permit_seq))
            client.add_rules(self.acl, new_rules)

        after = client.get_acl_rules(self.acl) or []      # verify after write
        if seq not in self._deny_seqs(after, ip):
            raise RestconfError("Verification failed: rule not found on router after writing it")

    def _refreshed_expiry(self, record: BlockRecord, wanted: float) -> Tuple[float, bool]:
        """New expiry for a refresh/extend: never earlier, never past the lifetime cap."""
        new_expiry = max(record.expires_at, wanted)
        if self.max_lifetime:
            limit = max(record.created_at + self.max_lifetime, record.expires_at)
            if new_expiry > limit:
                return limit, True
        return new_expiry, False

    def _escalate(self, device: str, ip: str, ttl: int, now: float) -> Tuple[int, int]:
        """Longer TTL for repeat offenders (only when repeat_factor > 1)."""
        if self.repeat_factor <= 1:
            return ttl, 0
        prior = self.store.count_previous(device, ip, now - self.repeat_window)
        if not prior:
            return ttl, 0
        factor = self.repeat_factor ** min(prior, 32)
        return int(min(ttl * factor, self.max_ttl)), prior

    # ------------------------------------------------------------------ block

    def block(self, ip: str, device: str, ttl_seconds: int,
              alert_id: Optional[str] = None, reason: str = "") -> Result:
        """Block one IP on one device for ttl_seconds.

        Raises ValidationError for bad input. Router problems come back as
        Result(status="error") so the caller can decide what to do.
        """
        started = time.perf_counter()
        ip = validate_ip(ip)
        ttl = validate_ttl(ttl_seconds, self.min_ttl, self.max_ttl)
        client = self._client(device)
        alert_id = clean_text(alert_id, 128)
        reason = clean_text(reason, 200)

        guard = self.protected_by(ip)                         # 0. never-block list
        if guard:
            return self._finish(Result(
                "refused", device, ip,
                f"{ip} is on the protected list ({guard}); protected addresses are never blocked"),
                started)

        try:
            with self._exclusive():
                result = self._block_locked(client, ip, device, ttl, alert_id, reason)
        except LockTimeout as exc:
            result = Result("error", device, ip, str(exc))
        return self._finish(result, started)

    def _resolve_pending(self, device: str, ip: str) -> None:
        """Before acting on an IP, finish any interrupted write for it, so the driver
        never mistakes its own half-written rule for someone else's."""
        for p in self.store.list_pending():
            if p.device == device and p.ip == ip:
                self._finish(self._recover_one(p), time.perf_counter())

    def _block_locked(self, client: RestconfClient, ip: str, device: str, ttl: int,
                      alert_id: str, reason: str) -> Result:
        self._resolve_pending(device, ip)
        now = self._clock()
        record = self.store.get_active(device, ip)
        pending: Optional[BlockRecord] = None
        prior = 0
        try:
            rules = client.get_acl_rules(self.acl)          # 1. read before write
            acl_exists = rules is not None
            rules = rules or []
            existing = self._deny_seqs(rules, ip)

            if existing and record:                          # 2. already done -> no new rule
                if alert_id and alert_id == (record.alert_id or ""):
                    # duplicate delivery of the same alert: never extend the TTL again
                    return Result(
                        "already_blocked", device, ip,
                        f"Duplicate of alert {alert_id}; IP already blocked, expiry unchanged",
                        seq=existing[0], expires_at=record.expires_at)
                # a new alert (or no alert id given): refresh the lifetime (within the cap)
                new_expiry, capped = self._refreshed_expiry(record, now + ttl)
                self.store.extend(record.id, new_expiry, alert_id or None)
                message = "IP already blocked; expiry refreshed"
                if capped and new_expiry == record.expires_at:
                    message = (f"IP already blocked; maximum block lifetime "
                               f"({self.max_lifetime} s) reached, expiry unchanged")
                elif capped:
                    message += f" up to the maximum block lifetime ({self.max_lifetime} s)"
                return Result("already_blocked", device, ip, message,
                              seq=existing[0], expires_at=new_expiry)

            if existing and not record:                      # someone else's rule: do not touch
                return Result(
                    "already_blocked", device, ip,
                    "A deny rule for this IP already exists but was not created by this "
                    "driver; it was left untouched and will not be auto-removed",
                    seq=existing[0])

            refusal = self._check_limits(device, ip, now, record)  # 3. safety limits
            if refusal:
                return refusal

            seq = self._free_seq(rules)
            if seq is None:
                return Result("refused", device, ip, "ACL has no free sequence numbers")

            ttl, prior = self._escalate(device, ip, ttl, now)
            # 4. journal first: if we crash or time out after this, recover() can tell
            #    whether the rule reached the router and clean up either way.
            pending = self.store.add(device, ip, self.acl, seq, alert_id, reason,
                                     now, now + ttl, status="pending")
            self._write_deny(client, rules, acl_exists, seq, ip)   # 5. write + verify

        except RestconfError as exc:
            log.error("Block of %s on %s failed: %s", ip, device, exc)
            if pending is not None:
                self._compensate(client, pending, exc)
            return Result("error", device, ip, str(exc))

        self.store.record_change(device, now)
        if record:  # rule had vanished from the router (drift): replace the record
            self.store.end(record.id, "replaced", "drift-repair", now)
        self.store.activate(pending.id)
        message = "Rule re-applied (it had disappeared from the router)" if record else "Blocked"
        if prior:
            message += (f" (repeat offender: {prior} earlier block(s) in the last "
                        f"{self.repeat_window // 86400} days; TTL raised to {ttl} s)")
        return Result("blocked", device, ip, message, seq=pending.seq,
                      expires_at=pending.expires_at)

    def _compensate(self, client: RestconfClient, pending: BlockRecord, cause: Exception) -> None:
        """Undo a write that failed half-way, so no untracked rule is left on the router.

        Example: the PATCH timed out but the router applied it anyway. Without this, the
        rule would stay for ever, because the driver would later treat it as foreign.
        """
        now = self._clock()
        try:
            rules = client.get_acl_rules(self.acl) or []
            if pending.seq in self._deny_seqs(rules, pending.ip):
                client.delete_rule(self.acl, pending.seq)
                left = client.get_acl_rules(self.acl) or []
                if pending.seq in self._deny_seqs(left, pending.ip):
                    raise RestconfError("rule still present after compensating delete")
                log.warning("Partial write of %s seq %s on %s was rolled back",
                            pending.ip, pending.seq, pending.device)
            self.store.note_failure(pending.id, str(cause))
            self.store.end(pending.id, "failed", "rollback", now)
        except RestconfError as again:
            self.store.note_failure(pending.id, f"{cause}; rollback postponed: {again}")
            log.warning("Could not check/undo the partial write of %s on %s (%s); "
                        "it stays 'pending' and recover() will resolve it",
                        pending.ip, pending.device, again)

    def block_many(self, ips: Sequence[str], device: str, ttl_seconds: int,
                   alert_id: Optional[str] = None, reason: str = "") -> List[Result]:
        """Block several IPs from one alert. One Result per distinct IP, in input order.

        A bad address does not stop the batch: it is reported as status "invalid".
        Duplicates in the input are blocked once. Each IP still passes every safety
        check (protected list, rate limit, block cap) on its own.
        """
        validate_ttl(ttl_seconds, self.min_ttl, self.max_ttl)   # bad TTL / device: whole batch
        self._client(device)
        results: List[Result] = []
        seen = set()
        for raw in ips:
            try:
                ip = validate_ip(raw)
            except ValidationError as exc:
                results.append(self._finish(Result("invalid", device, str(raw), str(exc)),
                                            time.perf_counter()))
                continue
            if ip in seen:
                continue
            seen.add(ip)
            results.append(self.block(ip, device, ttl_seconds, alert_id, reason))
        return results

    def _check_limits(self, device: str, ip: str, now: float,
                      record: Optional[BlockRecord]) -> Optional[Result]:
        active = self.store.count_active(device) - (1 if record else 0)
        if active >= self.max_blocks_per_device:
            return Result("refused", device, ip,
                          f"Device already has {active} active blocks (limit {self.max_blocks_per_device})")
        recent = self.store.changes_since(device, now - 60)
        if recent >= self.max_changes_per_minute:
            return Result("refused", device, ip,
                          f"Rate limit: {recent} changes on this device in the last minute "
                          f"(limit {self.max_changes_per_minute}); try again shortly")
        return None

    # ---------------------------------------------------------------- unblock

    def unblock(self, ip: str, device: str, by: str = "manual") -> Result:
        """Rollback: remove this driver's block for this IP immediately.

        Only the ACL line this driver created and recorded is deleted. Deny rules
        added by anyone else (e.g. an administrator) are never touched.
        """
        started = time.perf_counter()
        ip = validate_ip(ip)
        self._client(device)
        try:
            with self._exclusive():
                self._resolve_pending(device, ip)
                record = self.store.get_active(device, ip)
                result = self._remove(ip, device, record, by)
        except LockTimeout as exc:
            result = Result("error", device, ip, str(exc))
        return self._finish(result, started)

    def _remove(self, ip: str, device: str, record: Optional[BlockRecord], by: str) -> Result:
        client = self.clients[device]
        now = self._clock()
        try:
            rules = client.get_acl_rules(self.acl) or []
            all_seqs = self._deny_seqs(rules, ip)
            # only the exact line this driver created and recorded may be removed
            seqs = [s for s in all_seqs if record is not None and s == record.seq]
            foreign = [s for s in all_seqs if s not in seqs]
            for seq in seqs:
                client.delete_rule(self.acl, seq)
            if seqs:
                left = self._deny_seqs(client.get_acl_rules(self.acl) or [], ip)
                if any(s in left for s in seqs):
                    raise RestconfError("Verification failed: rule still on router after delete")
        except RestconfError as exc:
            log.error("Unblock of %s on %s failed: %s (will retry later)", ip, device, exc)
            if record is not None:
                attempts = self.store.note_failure(record.id, str(exc))
                if attempts >= self.stuck_after:
                    log.error("Block of %s on %s could not be removed after %d attempts "
                              "(last error: %s) - check the router", ip, device, attempts, exc)
            return Result("error", device, ip, str(exc), seq=record.seq if record else None)

        if record:
            self.store.end(record.id, "expired" if by == "ttl" else "removed", by, now)
        if not seqs and not record:
            if foreign:
                return Result(
                    "refused", device, ip,
                    f"A deny rule for this IP exists (seq {foreign[0]}) but was not created by "
                    "this driver; it was left untouched. A network administrator must remove "
                    "it on the router if that is intended.",
                    seq=foreign[0])
            return Result("not_found", device, ip, "No block found for this IP")
        message = "Block expired and was removed" if by == "ttl" else "Block removed"
        if foreign:
            message += f" (a deny rule not created by this driver, seq {foreign[0]}, was left untouched)"
        return Result("unblocked", device, ip, message, seq=seqs[0] if seqs else None)

    def _remove_records(self, records: List[BlockRecord], by: str) -> List[Result]:
        results = []
        for record in records:
            started = time.perf_counter()
            results.append(self._finish(
                self._remove(record.ip, record.device, record, by), started))
        return results

    def unblock_alert(self, alert_id: str) -> List[Result]:
        """Rollback every active block whose latest alert is `alert_id` (false positive).

        Ownership-aware like unblock(). A block refreshed by a later, different alert
        carries that newer alert ID and is therefore not touched.
        """
        alert_id = clean_text(alert_id, 128)
        if not alert_id:
            raise ValidationError("An alert ID is required")
        try:
            with self._exclusive():
                return self._remove_records(self.store.active_for_alert(alert_id), "alert-rollback")
        except LockTimeout as exc:
            return [Result("error", "-", "-", str(exc))]

    def unblock_all(self, device: Optional[str] = None) -> List[Result]:
        """Emergency rollback: remove every block this driver created (optionally one device).

        Rules added by anyone else are never touched.
        """
        if device is not None:
            self._client(device)
        try:
            with self._exclusive():
                return self._remove_records(self.store.list_active(device), "rollback-all")
        except LockTimeout as exc:
            return [Result("error", device or "-", "-", str(exc))]

    # ----------------------------------------------------------------- expiry

    def expire_due(self) -> List[Result]:
        """Remove every block whose TTL has passed. Failed ones stay active and retry next time."""
        results: List[Result] = []
        try:
            with self._exclusive():
                results = self._remove_records(self.store.due(self._clock()), "ttl")
        except LockTimeout as exc:
            log.warning("Expiry skipped this round: %s", exc)
        return results

    def extend(self, ip: str, device: str, seconds: int) -> Result:
        """Keep an active block until at least now + seconds (never shortens it).

        Only the record changes; the router already has the rule. The lifetime cap
        (max_lifetime) still applies.
        """
        started = time.perf_counter()
        ip = validate_ip(ip)
        seconds = validate_ttl(seconds, self.min_ttl, self.max_ttl)
        self._client(device)
        try:
            with self._exclusive():
                record = self.store.get_active(device, ip)
                if record is None:
                    result = Result("not_found", device, ip, "No active block for this IP")
                else:
                    new_expiry, capped = self._refreshed_expiry(record, self._clock() + seconds)
                    self.store.extend(record.id, new_expiry)
                    if new_expiry == record.expires_at:
                        message = ("Expiry unchanged: maximum block lifetime reached" if capped
                                   else "Expiry unchanged: it is already later than requested")
                    else:
                        message = "Expiry extended" + (" (capped at maximum block lifetime)" if capped else "")
                    result = Result("extended", device, ip, message, seq=record.seq,
                                    expires_at=new_expiry)
        except LockTimeout as exc:
            result = Result("error", device, ip, str(exc))
        return self._finish(result, started)

    # --------------------------------------------------------------- recovery

    def recover(self) -> List[Result]:
        """Resolve writes that were interrupted (crash, power loss, router lost mid-write).

        For each 'pending' record: if its rule is on the router, it becomes a normal
        active block (and expires as planned); if not, the record is closed. A rule that
        would duplicate another active block is removed. Safe to run at any time.
        """
        if not self.store.list_pending():        # cheap check, no lock needed
            return []
        results: List[Result] = []
        try:
            with self._exclusive():
                for record in self.store.list_pending():
                    started = time.perf_counter()
                    results.append(self._finish(self._recover_one(record), started))
        except LockTimeout as exc:
            log.warning("Recovery skipped this round: %s", exc)
        return results

    def _recover_one(self, p: BlockRecord) -> Result:
        now = self._clock()
        client = self.clients.get(p.device)
        if client is None or p.acl != self.acl:
            self.store.end(p.id, "failed", "recovery", now)
            return Result("discarded", p.device, p.ip,
                          "Interrupted block belongs to a device/ACL no longer configured; record closed",
                          seq=p.seq)
        try:
            rules = client.get_acl_rules(self.acl) or []
            present = p.seq in self._deny_seqs(rules, p.ip)
            active = self.store.get_active(p.device, p.ip)
            if present and active is None:
                self.store.activate(p.id)
                return Result("recovered", p.device, p.ip,
                              "Interrupted block was found on the router and is tracked again; "
                              "it expires as planned", seq=p.seq, expires_at=p.expires_at)
            if present and active is not None and active.seq == p.seq:
                # Crash during drift repair: the rule had vanished, the new write re-used the
                # old record's free sequence number, and the process died before switching
                # records. The rule on the router is the live block: keep it, retire the old record.
                self.store.end(active.id, "replaced", "drift-repair", now)
                self.store.activate(p.id)
                return Result("recovered", p.device, p.ip,
                              "Interrupted re-apply of a vanished rule was completed; "
                              "the block is tracked again and expires as planned",
                              seq=p.seq, expires_at=p.expires_at)
            if present:   # another active block already covers this IP: ours is a duplicate
                client.delete_rule(self.acl, p.seq)
                if p.seq in self._deny_seqs(client.get_acl_rules(self.acl) or [], p.ip):
                    raise RestconfError("Verification failed: duplicate rule still on router after delete")
                self.store.end(p.id, "failed", "recovery", now)
                return Result("discarded", p.device, p.ip,
                              f"Interrupted write left a duplicate rule (seq {p.seq}); it was removed",
                              seq=p.seq)
        except RestconfError as exc:
            self.store.note_failure(p.id, f"recovery postponed: {exc}")
            return Result("error", p.device, p.ip, f"Recovery postponed: {exc}", seq=p.seq)
        self.store.end(p.id, "failed", "recovery", now)
        return Result("discarded", p.device, p.ip,
                      "Interrupted write never reached the router; record closed", seq=p.seq)

    def reconcile(self, device: str, fix: bool = False) -> dict:
        """Compare the router's ACL with the driver's record for one device.

        Report only by default. With fix=True it also:
          * resolves interrupted writes (recover),
          * re-applies driver rules that vanished from the router (e.g. router restart
            without a saved config) - not rate-limited, because these blocks were already
            approved; a rule is never added if the IP is already denied by another rule,
          * closes records whose rule is gone and whose TTL has already passed.
        Foreign rules are only reported, never changed.
        """
        client = self._client(device)
        report: dict = {
            "device": device, "acl": self.acl, "fix": fix,
            "in_sync": [], "missing_on_router": [], "foreign_rules": [], "duplicate_rules": [],
            "pending": [], "recovered": [], "repaired": [], "not_repaired": [], "error": None,
        }
        try:
            with self._exclusive():
                if fix:
                    report["recovered"] = [r.to_dict() for r in self._recover_device(device)]
                now = self._clock()
                rules = client.get_acl_rules(self.acl)
                acl_exists = rules is not None
                rules = rules or []
                denied: Dict[str, List[int]] = {}
                for rule in rules:
                    host = denied_host(rule)
                    if host:
                        denied.setdefault(host, []).append(int(rule["sequence"]))
                records = self.store.list_active(device)
                owned = {(r.ip, r.seq) for r in records}
                missing = []
                for rec in records:
                    entry = {"ip": rec.ip, "seq": rec.seq, "expires_at_utc": iso(rec.expires_at)}
                    if rec.seq in denied.get(rec.ip, []):
                        report["in_sync"].append(entry)
                    else:
                        report["missing_on_router"].append(entry)
                        missing.append(rec)
                for host, seqs in sorted(denied.items()):
                    report["foreign_rules"] += [{"ip": host, "seq": s} for s in seqs if (host, s) not in owned]
                    if len(seqs) > 1:
                        report["duplicate_rules"].append({"ip": host, "seqs": sorted(seqs)})
                report["pending"] = [{"id": p.id, "ip": p.ip, "seq": p.seq}
                                     for p in self.store.list_pending() if p.device == device]

                if fix:
                    for rec in missing:
                        base = {"ip": rec.ip, "seq": rec.seq}
                        if rec.expires_at <= now:
                            self.store.end(rec.id, "expired", "reconcile", now)
                            report["repaired"].append({**base, "action": "record closed (TTL already passed)"})
                            continue
                        if denied.get(rec.ip):
                            report["not_repaired"].append({**base, "reason": (
                                f"IP is already denied by a rule not created by this driver "
                                f"(seq {denied[rec.ip][0]}); no second rule added")})
                            continue
                        used = {int(r.get("sequence", -1)) for r in rules}
                        seq = rec.seq if rec.seq not in used else self._free_seq(rules)
                        if seq is None:
                            report["not_repaired"].append({**base, "reason": "ACL has no free sequence numbers"})
                            continue
                        try:
                            self._write_deny(client, rules, acl_exists, seq, rec.ip)
                        except RestconfError as exc:
                            report["not_repaired"].append({**base, "reason": str(exc)})
                            continue
                        if seq != rec.seq:
                            self.store.update_seq(rec.id, seq)
                        rules = client.get_acl_rules(self.acl) or []
                        acl_exists = True
                        report["repaired"].append({"ip": rec.ip, "seq": seq, "action": "rule re-applied"})
        except (RestconfError, LockTimeout) as exc:
            report["error"] = str(exc)

        unresolved = report["not_repaired"] or report["pending"] or (
            report["missing_on_router"] and not fix)
        report["ok"] = report["error"] is None and not unresolved
        audit.info(json.dumps({"event": "reconcile", "device": device, "fix": fix, "ok": report["ok"],
                               "missing": len(report["missing_on_router"]),
                               "repaired": len(report["repaired"]),
                               "foreign": len(report["foreign_rules"])}))
        return report

    def _recover_device(self, device: str) -> List[Result]:
        results = []
        for record in self.store.list_pending():
            if record.device == device:
                started = time.perf_counter()
                results.append(self._finish(self._recover_one(record), started))
        return results

    # ------------------------------------------------------------------ views

    def list_active(self) -> List[dict]:
        now = self._clock()
        out = []
        for record in self.store.list_active():
            data = record.to_dict()
            data["remaining_seconds"] = max(0, int(round(record.expires_at - now)))
            out.append(data)
        return out

    def show_acl(self, device: str) -> Optional[List[dict]]:
        return self._client(device).get_acl_rules(self.acl)

    def status(self, ip: str, device: str) -> dict:
        """Is this IP blocked? One answer from both sources of truth.

        state: blocked          - driver rule on the router and an active record
               blocked_foreign  - denied on the router by a rule the driver does not own
               drift            - record active but its rule is missing on the router
               not_blocked      - neither
        Raises RestconfError if the router cannot be read.
        """
        ip = validate_ip(ip)
        seqs = self._deny_seqs(self._client(device).get_acl_rules(self.acl) or [], ip)
        record = self.store.get_active(device, ip)
        if record and record.seq in seqs:
            state = "blocked"
        elif record:
            state = "drift"
        elif seqs:
            state = "blocked_foreign"
        else:
            state = "not_blocked"
        rec = None
        if record:
            rec = record.to_dict()
            rec["remaining_seconds"] = max(0, int(round(record.expires_at - self._clock())))
        return {
            "ip": ip, "device": device, "state": state, "blocked_on_router": bool(seqs),
            "router_seqs": seqs, "record": rec, "protected_by": self.protected_by(ip),
        }
