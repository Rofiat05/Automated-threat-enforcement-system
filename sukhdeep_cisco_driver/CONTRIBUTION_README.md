# Cisco Driver: contribution for IP blocking, duplicate prevention, TTL, rollback and documentation

**Contributor:** _(add your name / GitHub username)_

This folder holds **only** my assigned responsibilities, with the v1.1 enhancements:

- Implementing the IP-blocking logic
- Preventing duplicate blocking rules
- Managing temporary blocking and TTL expiry
- Implementing rollback and recovery
- Preparing the Cisco Driver user documentation for these parts

As agreed, the following are **not included**, because they are already in the group's Cisco Driver repository and uploading them again would create duplicate code and documentation:

| Excluded section | Files and documentation left out |
|---|---|
| 1. Technical architecture and mock environment | `mock_router/`, `packet_tracer/`, `tests/conftest.py` (test router set-up), `demo/lifecycle_demo.py`; guide sections on the mock server, project layout and installation |
| 2. RESTCONF client implementation | `cisco_driver/restconf_client.py`, `tests/test_restconf_client.py` |
| 3. API communication and configuration | `cisco_driver/config.py`; guide section on connection settings (`RESTCONF_*`) |
| 4. Connection security and error handling | TLS, credentials, retry/back-off and router-connection error documentation |
| 5. Integration with other components | `cisco_driver/__init__.py`, `cisco_driver/__main__.py`; guide section "From Python (for other components)" |

None of the excluded files were changed. My code works with them exactly as they are in the repository.

---

## What is in this folder

| File | Status | Responsibility |
|---|---|---|
| `cisco_driver/driver.py` | **updated** | Blocking logic, duplicate prevention, TTL, rollback, recovery, reconcile |
| `cisco_driver/store.py` | **updated** | Block records: write-ahead journal, cross-process lock, failure tracking, migration, backup |
| `cisco_driver/expiry_worker.py` | **updated** | Automatic expiry, recovery every round, health counters |
| `cisco_driver/validation.py` | **updated** (one function added) | IP address policy, TTL range, protected-list parsing |
| `cisco_driver/blocking_policy.py` | **new** | Reads the three new blocking settings, so `config.py` did not need to change |
| `cisco_driver/cli.py` | **updated** (commands added) | `status`, `block-many`, `extend`, `reconcile`, `recover`, `rollback-alert`, `rollback-all`, `backup` |
| `tests/test_enhancements.py` | **new** | 49 tests for the new features |
| `tests/test_driver.py`, `test_validation.py`, `test_worker_and_cli.py`, `test_performance.py` | unchanged | Existing tests of the blocking, TTL and rollback behaviour; all still pass |
| `demo/enhancements_demo.py` | **new** | 10-step demonstration of the new features |
| `CISCO_DRIVER_USER_GUIDE.md` | **rewritten** | The complete, updated user guide for these parts (replaces the v1.0 guide) |
| `ENHANCEMENTS_v1.1.md` | **new** | Change log: what changed, where and why |
| `evidence/` | **new** | Test, demo, scan and performance results, checksums |
| `requirements.txt`, `requirements-dev.txt`, `pytest.ini` | unchanged | The project's shared install and test files, identical to the repository's, so this folder is complete |
| `.gitignore` | **updated** | The repository's `.gitignore` plus `*.db.lock` and `backups/` |

`CISCO_DRIVER_USER_GUIDE.md` is the v1.0 guide fully updated for v1.1. Everything belonging to the five excluded sections (mock server, installation, `RESTCONF_*` settings, TLS/credentials/retries, connection errors, Python integration, real-hardware appendix) was removed from it; everything about blocking, duplicates, TTL, rollback and recovery was kept, corrected and extended. Its appendix lists exactly what was removed, kept and added.

## How to merge

1. Copy this folder's contents over the repository root (same folder structure). This **replaces** `CISCO_DRIVER_USER_GUIDE.md` and the `evidence/` files with the same names (`test_results.txt`, `junit_results.xml`, `performance_results.txt`, `bandit_report.txt`, `tool_versions.txt`, `SHA256SUMS.txt`). To keep the v1.0 versions, copy them to `evidence/v1.0/` first.
2. Install the packages if needed: `pip install -r requirements-dev.txt`.
3. Run `python -m pytest`. The expected result is **145 passed**: the 96 existing tests, unchanged, plus 49 new.

This folder is **not a standalone project**: it needs the group's files listed above (`restconf_client.py`, `config.py`, `__init__.py`, `__main__.py`, `mock_router/`, `tests/conftest.py`) to run. Push it into the group repository, not as a separate repository.

This was verified: the folder was copied onto an unmodified copy of the repository and the full test suite, both demonstrations and the security scan were run. See `evidence/`.

## Compatibility

- Every existing function, command, result and message behaves as before. All 96 original tests pass without modification.
- Two behaviours change on purpose: a block can no longer be refreshed beyond `BLOCK_MAX_LIFETIME` (7 days by default; `0` restores the unlimited v1.0 behaviour), and a write that fails half-way no longer leaves an untracked rule on the router.
- New settings are optional: `BLOCK_PROTECTED` (empty), `BLOCK_MAX_LIFETIME` (7 days), `BLOCK_REPEAT_FACTOR` (1 = off).
- After the new version opens an old `blocks.db`, it adds two columns, so the old version can no longer read that file. Back it up first.
