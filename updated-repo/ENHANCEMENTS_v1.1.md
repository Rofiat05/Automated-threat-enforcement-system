# Cisco Driver v1.1: change log

**Scope of this contribution:** IP-blocking logic, prevention of duplicate blocking rules, temporary blocking and TTL expiry, rollback and recovery, and the user documentation for them.

**Contributor:** _(add your name / GitHub username)_

**Not changed:** the mock router (`mock_router/`), the RESTCONF client (`cisco_driver/restconf_client.py`), API communication, configuration (`config.py`), connection handling and the package interface (`__init__.py`). These files are byte-for-byte identical to the original. The three new optional settings are read by a new, separate file, `cisco_driver/blocking_policy.py`; their defaults keep v1.0 behaviour, except the 7-day lifetime cap (`BLOCK_MAX_LIFETIME=0` turns it off).

Nothing was removed. All 96 v1.0 tests pass unchanged; 49 new tests were added (145 in total).

---

## 1. IP-blocking logic

| Change | Where |
|---|---|
| **Protected (never-block) list**, `BLOCK_PROTECTED`: gateway, DNS, SIEM, admin hosts or whole networks are refused before the router is contacted | `driver.py` `protected_by()`, `validation.py` `parse_networks()`, `blocking_policy.py` |
| **Batch blocking**, `block_many()` / `block-many`: one alert with several IPs; de-duplicates, reports bad entries as `invalid` without stopping the batch, keeps every safety check per IP; `--file` input | `driver.py`, `cli.py` |
| **One-call status check**, `status()` / `status`: compares router and record, answers `blocked` / `blocked_foreign` / `drift` / `not_blocked`, with time remaining and protection | `driver.py`, `cli.py` |

## 2. Duplicate prevention

| Change | Where |
|---|---|
| **Cross-process lock** on `blocks.db.lock` (OS file lock, released automatically if a process crashes). It fixes a v1.0 race: two processes could pick the same sequence number, so one rule overwrote another, or the second process crashed with `IntegrityError` after writing. Verified by running the new race tests with the lock disabled: they fail; with the lock they pass. | `store.py` `exclusive()`, `driver.py` `_exclusive()` |
| Duplicate IPs inside one batch are blocked once | `driver.py` `block_many()` |
| Duplicate rule written by an interrupted process is removed by `recover()` | `driver.py` `_recover_one()` |
| `reconcile` reports IPs denied by more than one line; `--fix` never adds a second rule for an IP already denied by someone else | `driver.py` `reconcile()` |

## 3. Temporary blocking and TTL expiry

| Change | Where |
|---|---|
| **Lifetime cap** `BLOCK_MAX_LIFETIME` (default 7 days): repeated alerts can no longer keep an IP blocked for ever | `driver.py` `_refreshed_expiry()` |
| **Repeat-offender TTL** `BLOCK_REPEAT_FACTOR` (off by default): TTL × factor^(earlier blocks that ran their full TTL in 7 days), capped at `BLOCK_MAX_TTL`; blocks removed early (possible false positives) never count | `driver.py` `_escalate()`, `store.py` `count_previous()` |
| **`extend()` / `extend`**: push expiry later without touching the router; never shortens | `driver.py`, `cli.py` |
| `remaining_seconds` in `list` / `status` | `driver.py` |
| Failed removals counted (`attempts`, `last_error`); `ERROR` log after 5 attempts | `driver.py` `_remove()`, `store.py` `note_failure()` |
| Worker resolves interrupted writes each round; `health()` and Ctrl+C summary | `expiry_worker.py`, `cli.py` |

## 4. Rollback and recovery

| Change | Where |
|---|---|
| **Write-ahead journal**: block recorded as `pending` before the router write, `active` after verification | `driver.py` `_block_locked()`, `store.py` `add(status=)`, `activate()` |
| **Automatic undo** of a write that fails half-way (e.g. verification read fails after the write landed): no untracked rule is left behind. In v1.0 such a rule became "foreign" and was never removed. | `driver.py` `_compensate()` |
| **`recover()` / `recover`**: resolves writes interrupted by a crash; also runs automatically before any block/unblock of the same IP and in the worker | `driver.py` |
| **`reconcile()` / `reconcile [--fix]`**: router vs record report; `--fix` re-applies the driver's rules after a router restart, moves to a free sequence if the old one is taken, closes expired records, never touches foreign rules | `driver.py`, `cli.py` |
| **Rollback by alert**, `unblock_alert()` / `rollback-alert`, for false positives | `driver.py`, `cli.py` |
| **Emergency rollback**, `unblock_all()` / `rollback-all --yes`, optionally per device; ownership-aware | `driver.py`, `cli.py` |
| **`backup`** command: SQLite online backup + integrity check, never overwrites | `store.py` `backup()`, `cli.py` |
| **Schema migration**: v1.0 databases are upgraded in place (`attempts`, `last_error` columns) | `store.py` `_migrate()` |

## 5. Documentation, demo, tests

| Change | Where |
|---|---|
| User guide rewritten as one complete guide for these parts: sections of the five excluded areas removed; every v1.1 feature, command, output, safety rule and error documented; compatibility notes corrected; appendix listing what was removed, kept and added | `CISCO_DRIVER_USER_GUIDE.md` |
| 10-step demonstration of the new features | `demo/enhancements_demo.py` |
| 49 new tests in 5 groups | `tests/test_enhancements.py` |
| Project install and test files included (`requirements*.txt`, `pytest.ini` unchanged) | project root |

## 6. Fixes found in review

| Fix | Test | Where |
|---|---|---|
| A crash while a vanished rule was being re-applied at its old sequence number made `recover()` delete the **live** rule as a "duplicate" (the IP was silently unblocked). Now the rule is kept, the old record is closed as `replaced`. | `test_recover_after_crash_during_drift_repair_keeps_live_rule` | `driver.py` `_recover_one()` |
| A block rolled back as a false positive (`unblock`, `rollback-alert`, `rollback-all`) counted as an earlier offence and doubled the next TTL. Now only blocks that ran their full TTL count. | `test_rolled_back_false_positive_never_escalates` | `store.py` `count_previous()` |
| New evidence (replaces the v1.0 files of the same name) | `evidence/` |
| `.gitignore` needs `*.db.lock` and `backups/` (two lines to add when merging) | `.gitignore` |

## Compatibility

- Same public API, commands, results and messages as v1.0. New statuses appear only from new calls (`extended`, `invalid`, `recovered`, `discarded`).
- Deliberate behaviour changes: the lifetime cap (default 7 days; `BLOCK_MAX_LIFETIME=0` restores v1.0) and the automatic undo of partial writes.
- After v1.1 has opened a `blocks.db`, v1.0 can no longer read it (two extra columns). Back it up before upgrading.
