# Cisco Driver — User Guide

**Component:** Role E, Cisco Driver (`cisco_driver` v1.1)
**This guide covers:** IP-blocking logic · prevention of duplicate blocking rules · temporary blocking and TTL expiry · rollback and recovery
**Audience:** operators who block and unblock addresses, and reviewers of these features

> **Scope.** This guide explains **what the driver does with a block request and how to operate, check, expire and undo blocks**. The following topics belong to other parts of the project and are documented by their owners, not here:
>
> 1. Technical architecture and mock environment (mock IOS XE server, project layout, installation)
> 2. RESTCONF client implementation
> 3. API communication and configuration (`RESTCONF_*` connection settings)
> 4. Connection security and error handling (TLS, credentials, retries and back-off, router-connection errors)
> 5. Integration with other components (calling the driver from Python, package interface)
>
> **Before you start**, the driver must already be installed and connected to the router, with the connection settings in place in the current terminal. Every command in this guide assumes that.

All commands are for **Windows PowerShell**, run from the project folder. Every IP address in this guide comes from the RFC 5737 documentation ranges (§4.1); none is a real attacker.

---

## Contents

1. [What the driver does with a block request](#1-what-the-driver-does-with-a-block-request)
2. [Files for these features](#2-files-for-these-features)
3. [Blocking settings](#3-blocking-settings)
4. [IP-blocking logic: submitting block requests](#4-ip-blocking-logic-submitting-block-requests)
5. [Checking whether an IP is blocked](#5-checking-whether-an-ip-is-blocked)
6. [Preventing duplicate blocking rules](#6-preventing-duplicate-blocking-rules)
7. [Temporary blocking and TTL expiry](#7-temporary-blocking-and-ttl-expiry)
8. [Rollback and recovery](#8-rollback-and-recovery)
9. [Protecting, backing up and restoring `blocks.db`](#9-protecting-backing-up-and-restoring-blocksdb)
10. [Demonstration](#10-demonstration)
11. [Common errors and solutions](#11-common-errors-and-solutions)
12. [Tests and evidence](#12-tests-and-evidence)
13. [Quick reference](#13-quick-reference)

[Appendix: What changed since the v1.0 guide](#appendix-what-changed-since-the-v10-guide)

---

## 1. What the driver does with a block request

In one line: **the driver applies an IP block safely, never twice, keeps it only for its lifetime (TTL), and can always undo it.**

When an alert names a malicious IP address, the driver:

1. **Validates the request.** Only one IPv4 host, a known device and an allowed lifetime (TTL) are accepted (§4.1).
2. **Checks the protected list.** Critical addresses (gateway, DNS, SIEM, admin PCs) are never blocked (§4.2).
3. **Takes the driver lock**, so only one driver process changes the router at a time (§6.2).
4. **Finishes any interrupted write** for the same IP first, so it never mistakes its own half-written rule for someone else's (§8.3).
5. **Reads before it writes.** It reads the `BLOCKLIST` access list (ACL). If the IP is already denied, it adds **no second rule** (§6.1).
6. **Checks safety limits:** a maximum number of changes per minute and a maximum number of active blocks per device (§4.4).
7. **Journals the block as `pending`** in `blocks.db` before changing anything, so an interrupted write can always be cleaned up (§8.2).
8. **Writes the block:** one ACL line, `<seq> deny ip host <IP> any`.
9. **Verifies after writing.** It reads the ACL again and confirms the rule is really there. If anything fails after the write, it removes its own rule again (§8.2).
10. **Marks the record `active`**, with its expiry time and the alert that caused it.
11. **Removes the block** when the TTL passes (while an expiry process runs, §7.3), or immediately on rollback (§8). It always removes **only rules that the driver itself created**.

The ACL built by the driver looks like this:

```
Extended IP access list BLOCKLIST
    10 deny ip host 203.0.113.7 any
    20 deny ip host 198.51.100.23 any
    1000 permit ip any any
```

### About `1000 permit ip any any`

Every Cisco ACL ends with an invisible "deny everything" rule. The driver therefore adds `1000 permit ip any any` when it creates the ACL, so blocking one attacker does not block everyone. The driver never removes this line, so normal traffic keeps flowing when the ACL holds no deny rules. If the ACL is lost (for example after a router restart), `reconcile --fix` restores it together with the driver's rules (§8.5).

> ⚠️ This line permits all traffic that was not denied by an earlier line. It is correct **only** because `BLOCKLIST` is a **dedicated blocklist ACL** whose sole policy is "deny these listed hosts, allow everything else". Never point the driver (`BLOCK_ACL_NAME`) at an ACL that carries other security rules.

### Safety features

| Area | Feature | What it means |
|---|---|---|
| Blocking | Single hosts only | Networks such as `10.0.0.0/8` are refused, so a bad alert can never cut off a whole range. |
| Blocking | Special addresses refused | `0.0.0.0`, loopback, link-local, multicast and the reserved `240.0.0.0/4` block are refused (§4.1). |
| Blocking | Protected addresses | Addresses on `BLOCK_PROTECTED` are refused before the router is contacted (§4.2). |
| Blocking | Rate limit / block cap | By default at most **10 changes per device per minute** and **50 active blocks per device** (§4.4). |
| Duplicates | No duplicate ACL entries | Blocking an already blocked IP never adds a second rule (§6.1). |
| Duplicates | One writer at a time | A lock shared by all driver processes stops them creating duplicate rules or overwriting each other's sequence numbers (§6.2). |
| Duplicates | Duplicate alerts ignored | Re-delivery of the same alert ID does **not** extend the block (§7.2). |
| TTL | Every block is temporary | Every block has an expiry time stored on disk, and is removed when it passes (§7). |
| TTL | Lifetime cap | Repeated alerts can extend a block, but never beyond `BLOCK_MAX_LIFETIME` (7 days by default) in total (§7.5). |
| Rollback | Ownership-aware removal | Rollback and expiry delete **only** the exact ACL line the driver created and recorded. Rules added by hand are never removed. |
| Rollback | Undo of partial writes | A write that fails half-way is removed again, so no untracked rule is left behind (§8.2). |
| Recovery | Crash recovery | Writes interrupted by a crash are resolved automatically (§8.3). |
| Recovery | Drift repair | If a driver rule vanishes from the router, the next request for that IP re-applies it, and `reconcile --fix` repairs all of them at once (§8.5). |

### What is new in v1.1

| Responsibility | v1.1 additions |
|---|---|
| IP-blocking logic | Protected list (§4.2) · batch blocking `block-many` (§4.3) · one-call `status` check (§5.1) |
| Duplicate prevention | Cross-process lock (§6.2) · batch de-duplication, duplicate clean-up after a crash, duplicate reporting (§6.3) |
| Temporary blocking and TTL | Lifetime cap (§7.5) · optional repeat-offender TTL (§7.6) · `extend` (§7.7) · time remaining and stuck-expiry warnings (§7.8) · worker health summary (§7.3) |
| Rollback and recovery | Write-ahead journal and automatic undo (§8.2) · `recover` (§8.3) · `reconcile [--fix]` (§8.5) · `rollback-alert` (§8.6) · `rollback-all` (§8.7) · `backup` (§9.2) · automatic database upgrade (§9.5) |

Every v1.0 command keeps its arguments, results and messages. Two v1.0 behaviours change, both on purpose: a block can no longer be refreshed beyond the lifetime cap (§7.5), and a failed write no longer leaves an untracked rule on the router (§8.2).

---

## 2. Files for these features

```
cisco_driver/
├── driver.py            blocking logic, duplicate prevention, TTL, rollback, recovery, reconcile
├── store.py             SQLite record of every block (blocks.db): journal, lock, history, backup, upgrade
├── expiry_worker.py     background job: removes expired blocks, resolves interrupted writes, health counters
├── validation.py        input checks: IP address policy, TTL range, protected-list parsing
├── blocking_policy.py   reads the three v1.1 blocking settings (§3)
└── cli.py               the commands used in this guide
demo/enhancements_demo.py    10-step demonstration of these features (§10)
tests/                       tests for these features (§12)
evidence/                    test, demo, scan and performance results (§12)
requirements.txt             runtime packages (pinned): requests, flask, cryptography
requirements-dev.txt         runtime + test and security tools: pytest, bandit, pip-audit
pytest.ini                   test settings (python -m pytest finds tests/ automatically)
.gitignore                   keeps blocks.db, blocks.db.lock, backups/ and .venv out of Git
```

`requirements*.txt` and `pytest.ini` are the project's shared files, included unchanged so this folder is complete. To install the packages:

```powershell
pip install -r requirements-dev.txt     # or requirements.txt for runtime only
```

Created while the driver runs (local operational files; never commit them):

| File | Purpose |
|---|---|
| `blocks.db` | Every block, its expiry and how it ended. Expiry, rollback and ownership checks depend on it (§9). |
| `blocks.db.lock` | Empty lock file that makes driver processes take turns (§6.2). Safe to leave in place. |
| `backups/` | Copies made with the `backup` command (§9.2). |

The included `.gitignore` already excludes `*.db`, `*.db.lock` and `backups/`.

---

## 3. Blocking settings

These environment variables control blocking behaviour. All are optional. (Router connection settings are documented in the configuration part of the project.)

| Variable | Default | Meaning |
|---|---|---|
| `BLOCK_ACL_NAME` | `BLOCKLIST` | Name of the **dedicated** blocklist ACL the driver manages. Letters, digits, `_`, `.`, `-`; must start with a letter. |
| `BLOCK_DB_PATH` | `blocks.db` | Location of the block database. Use **one absolute path in every terminal** (see below). |
| `BLOCK_MIN_TTL` | `60` | Shortest allowed block, in seconds. |
| `BLOCK_MAX_TTL` | `86400` | Longest allowed TTL for one request, in seconds (24 h). Also the ceiling for repeat-offender TTLs (§7.6). |
| `BLOCK_MAX_CHANGES_PER_MINUTE` | `10` | Rate limit per device. |
| `BLOCK_MAX_PER_DEVICE` | `50` | Maximum active blocks per device. |
| `BLOCK_EXPIRY_INTERVAL` | `10` | How often, in seconds, the expiry worker checks for expired blocks. |
| `BLOCK_PROTECTED` | empty | Never-block list: IPv4 hosts and/or networks separated by commas or spaces, e.g. `192.0.2.1, 10.0.0.0/24` (§4.2). |
| `BLOCK_MAX_LIFETIME` | `604800` | Longest total time one block can be kept alive by refreshes and `extend`, in seconds (7 days). `0` = no cap (§7.5). |
| `BLOCK_REPEAT_FACTOR` | `1` | TTL multiplier for repeat offenders; `2` doubles the TTL for each earlier block of the same IP that ran its full TTL in the last 7 days. `1` = off (§7.6). |

A wrong value in one of the last three stops the driver at start-up with `Settings error: ...` and exit code 2, so a broken setting never runs silently.

> **Important: one database for everyone.** `BLOCK_DB_PATH` defaults to `blocks.db` in the **current folder**. If two terminals run from different folders, they use different databases: they do not see each other's blocks, ownership checks go wrong, and the duplicate-prevention lock (§6.2) cannot work between them. Always run from the same folder, or set `BLOCK_DB_PATH` to one absolute path everywhere:
>
> ```powershell
> $env:BLOCK_DB_PATH = "D:\driver-data\blocks.db"
> ```

---

## 4. IP-blocking logic: submitting block requests

### 4.1 One IP: `block`

```powershell
python -m cisco_driver block <IP> --device <NAME> [--ttl <seconds>] [--reason "<text>"] [--alert-id <id>]
```

| Argument | Required | Default | Notes |
|---|---|---|---|
| `<IP>` | yes | — | One IPv4 host, e.g. `203.0.113.7`. No `/prefix`. |
| `--device` | yes | — | A configured device name, e.g. `R1` (case-sensitive). |
| `--ttl` | no | `3600` (1 h) | Block lifetime in seconds, between `BLOCK_MIN_TTL` and `BLOCK_MAX_TTL`. |
| `--reason` | no | empty | Free text for the audit trail (200 characters maximum, one line). |
| `--alert-id` | no, but **strongly recommended** | empty | The alert that caused the block (128 characters maximum). Used to recognise duplicate deliveries (§7.2) and for rollback by alert (§8.6). |

**Example**

```powershell
python -m cisco_driver block 203.0.113.7 --device R1 --ttl 3600 --reason "ssh brute force" --alert-id ALERT-001
```

```json
{
  "status": "blocked",
  "device": "R1",
  "ip": "203.0.113.7",
  "seq": 10,
  "expires_at": 1794671876.08,
  "expires_at_utc": "2026-11-14T15:57:56+00:00",
  "message": "Blocked",
  "duration_ms": 76.9
}
```

Sequence numbers are taken from 10 to 990 in steps of 10 (99 slots); the lowest free one is used.

#### Address policy: which IPs can be blocked

| Category | Range | Accepted? | Why |
|---|---|---|---|
| Ordinary public addresses | e.g. `8.8.8.8` | ✅ yes | Normal external attacker sources. |
| Private addresses | single hosts inside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, e.g. `192.168.10.50` | ✅ yes, one host at a time | Internal or compromised hosts can also be attackers. |
| Documentation ranges (RFC 5737) | single hosts inside `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | ✅ yes, as test fixtures | See the note below. |
| Protected addresses | anything covered by `BLOCK_PROTECTED` | ❌ refused | Critical infrastructure (§4.2). |
| Unspecified | `0.0.0.0` | ❌ refused | Not a real host. |
| Loopback | `127.0.0.0/8` | ❌ refused | Never arrives over the network. |
| Link-local | `169.254.0.0/16` | ❌ refused | Not routed. |
| Multicast | `224.0.0.0/4` | ❌ refused | Not a single host. |
| Reserved ("Class E"), incl. broadcast | `240.0.0.0/4`, `255.255.255.255` | ❌ refused | Not usable as a source. |
| Networks (CIDR notation) | any input containing `/`, even `203.0.113.7/32` | ❌ refused | Only single hosts, so a bad alert cannot cut off a whole range. |
| IPv6 | e.g. `2001:db8::1` | ❌ refused | The `BLOCKLIST` extended ACL is IPv4 only. |

The **ranges** describe *where* an address may come from; they are not inputs. Submit one plain host address such as `192.168.10.50`. Typing a range (`192.168.0.0/16`) or a host with `/32` is network notation and is refused.

> **About the documentation ranges.** RFC 5737 reserves `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24` for examples; they are not meant to be routed on the Internet. The driver accepts them on purpose, so that the demonstration and the tests never use a real person's or company's address. In production, a block request for one of them means test data has leaked into a live alert feed: investigate it rather than treat it as a real attack. "Reserved" in the refused list means only `240.0.0.0/4`.

### 4.2 Protected addresses (never blocked)

A single wrong alert against the default gateway, a DNS server, the SIEM or an administrator's PC could cut off the network, or the people who must fix it. List them once:

```powershell
$env:BLOCK_PROTECTED = "192.0.2.1, 192.0.2.53, 10.0.0.0/24"
```

Entries are single hosts or networks, separated by commas or spaces. A request for a covered address is refused **before the router is contacted**:

```json
{ "status": "refused", "ip": "10.0.0.25",
  "message": "10.0.0.25 is on the protected list (10.0.0.0/24); protected addresses are never blocked" }
```

- The list only adds protection; it never makes another address acceptable.
- A network entry with host bits (`10.0.0.5/24`) is read as the whole network (`10.0.0.0/24`), so protection is never narrower than intended.
- A typo stops the driver at start-up (`Settings error: Protected entry 'x' is not an IPv4 address or network`, exit code 2), so a broken list can never silently protect nothing.
- `status` shows whether an address is protected (§5.1).

### 4.3 Several IPs from one alert: `block-many`

```powershell
python -m cisco_driver block-many 203.0.113.7 203.0.113.8 --device R1 --ttl 3600 --alert-id ALERT-101
python -m cisco_driver block-many --file ips.txt --device R1 --alert-id ALERT-101
```

`ips.txt` holds one address per line; `#` starts a comment. Command-line IPs and `--file` can be combined. `--ttl` (default 3600) and `--reason` work as for `block`.

```json
[
  { "status": "blocked", "ip": "203.0.113.7", "seq": 10, "message": "Blocked", ... },
  { "status": "blocked", "ip": "203.0.113.8", "seq": 20, "message": "Blocked", ... },
  { "status": "invalid", "ip": "bad-ip", "message": "'bad-ip' is not a valid IP address", ... }
]
```

- One result per distinct IP, in input order. An IP given twice is blocked **once**.
- A bad address does not stop the batch; it is reported as `invalid` and the others are still processed.
- Every IP passes every check on its own (protected list, rate limit, block cap). With the default limit of 10 changes per minute, a batch of 15 new IPs blocks 10 and returns `refused` for the rest. Resend those a minute later.
- A bad `--ttl` or unknown `--device` rejects the whole batch before anything is sent (exit code 2).
- Exit code 0 only if every result is OK; otherwise 1.

### 4.4 Understanding the result

| `status` | Exit code | Meaning |
|---|---|---|
| `blocked` | 0 | New deny rule written and verified on the router. |
| `already_blocked` | 0 | The IP was already denied. **No new ACL entry was created.** The expiry may or may not have changed; read the `message` (§7.2). |
| `refused` | 1 | A safety rule stopped the request: rate limit, block cap, no free ACL sequence numbers, or the IP is protected. Nothing was changed. |
| `error` | 1 | The block could not be completed. Nothing is left recorded as active, and any rule already written was removed again (§8.2). Safe to retry. |
| `invalid` | 1 | Only from `block-many`: this entry is not a valid IP. |
| *(text on stderr)* | 2 | Bad input or settings, e.g. `Invalid input: ...` or `Settings error: ...`. |

The safety limits behind `refused`:

| Limit | Default | Setting | Counts |
|---|---|---|---|
| Rate limit | 10 per device per minute | `BLOCK_MAX_CHANGES_PER_MINUTE` | New rules written on that device in the last 60 s |
| Block cap | 50 per device | `BLOCK_MAX_PER_DEVICE` | Active driver blocks on that device |
| Free sequence numbers | 99 (10–990) | — | Used ACL lines, including other people's |

Add `-v` before the command (`python -m cisco_driver -v block ...`) to also see the audit log: one JSON line per action (`{"event": "enforcement", ...}`).

---

## 5. Checking whether an IP is blocked

There are two sources of truth: the driver's record (`blocks.db`) and the router. A properly blocked IP appears in **both**.

### 5.1 One answer: `status`

```powershell
python -m cisco_driver status 203.0.113.7 --device R1
```

```json
{
  "ip": "203.0.113.7", "device": "R1", "state": "blocked",
  "blocked_on_router": true, "router_seqs": [10],
  "record": { "seq": 10, "alert_id": "ALERT-001", "expires_at_utc": "...", "remaining_seconds": 3540, ... },
  "protected_by": null
}
```

| `state` | Meaning | What to do |
|---|---|---|
| `blocked` | The driver's rule is on the router and recorded as active. | Nothing. |
| `blocked_foreign` | The router denies this IP with a rule the driver did not create. | Nothing for the driver; an administrator owns that rule. |
| `drift` | Recorded as active, but the rule is missing on the router. | `reconcile --device R1 --fix` (§8.5). |
| `not_blocked` | Neither. | — |

`protected_by` names the `BLOCK_PROTECTED` entry that covers the IP, or `null`. If the router cannot be read, `status` prints `Router error: ...` and exits with 1.

### 5.2 What the driver has recorded: `list`

```powershell
python -m cisco_driver list
```

Every **active** driver block, soonest expiry first:

```json
[
  {
    "id": 1, "device": "R1", "ip": "203.0.113.7", "acl": "BLOCKLIST", "seq": 10,
    "alert_id": "ALERT-001", "reason": "ssh brute force", "status": "active",
    "created_at_utc": "2026-11-14T15:56:56+00:00",
    "expires_at_utc": "2026-11-14T16:56:56+00:00",
    "ended_at_utc": null,
    "attempts": 0, "last_error": null, "remaining_seconds": 3540,
    ...
  }
]
```

- `alert_id` is the most recent alert that applied or refreshed the block.
- `remaining_seconds` is the time left before expiry.
- `attempts` / `last_error`: failed removal attempts, normally `0` / `null` (§7.8).
- An empty list `[]` means there are no active driver blocks.

To check one IP in PowerShell:

```powershell
python -m cisco_driver list | ConvertFrom-Json | Where-Object ip -eq "203.0.113.7"
```

### 5.3 What is on the router: `show-acl`

```powershell
python -m cisco_driver show-acl --device R1
```

```json
{
  "acl": "BLOCKLIST",
  "exists": true,
  "rules": [
    { "sequence": "10",   "ace-rule": { "action": "deny",   "protocol": "ip", "host": "203.0.113.7", "dst-any": [null] } },
    { "sequence": "1000", "ace-rule": { "action": "permit", "protocol": "ip", "any": [null],          "dst-any": [null] } }
  ]
}
```

The IP is blocked on the router if a rule shows `"action": "deny"` with `"host": "<IP>"`. `"exists": false` means the ACL has not been created yet (no block so far, or the router lost it).

### 5.4 Past blocks: `history`

```powershell
python -m cisco_driver history
```

The last 50 blocks, newest first, including finished ones. `status` and `ended_by` explain how each one ended:

| `status` | `ended_by` | Meaning |
|---|---|---|
| `active` | — | Still in force. |
| `pending` | — | A write in progress, or interrupted. Resolved automatically (§8.3). |
| `expired` | `ttl` | Removed automatically when its TTL passed. |
| `expired` | `reconcile` | The rule had already vanished and the TTL had passed; `reconcile --fix` closed the record. |
| `removed` | `manual` | Removed by an operator with `unblock`. |
| `removed` | `alert-rollback` | Removed by rollback by alert (§8.6). |
| `removed` | `rollback-all` | Removed by emergency rollback (§8.7). |
| `replaced` | `drift-repair` | The rule had vanished from the router and was re-applied under a new record. |
| `failed` | `rollback` | The write failed; any rule it had written was removed again (§8.2). |
| `failed` | `recovery` | An interrupted write was resolved by `recover` (§8.3). |

### 5.5 If the two views disagree

| `list` says | Router says | Meaning / what to do |
|---|---|---|
| active | deny rule present | Normal. |
| active | no rule | The rule was deleted on the router (drift), or the router restarted without its configuration. Run `reconcile --device R1 --fix` (§8.5). |
| not listed | deny rule present | A rule added by hand or by another system. The driver will neither expire nor unblock it. |

---

## 6. Preventing duplicate blocking rules

### 6.1 Repeated requests never create a second rule

The driver reads the ACL before every write. If the IP is already denied, no new line is written, however many times it is requested. The router keeps exactly one deny line for that IP. What happens to the expiry is explained in §7.2.

If a deny rule for the IP exists but was **not created by the driver** (an administrator's rule), the driver also adds nothing. It answers `already_blocked` with `...was not created by this driver; it was left untouched and will not be auto-removed`.

### 6.2 Several driver processes at the same time

In real use, several processes share one `blocks.db`: the expiry worker, operators using the command line, and the component forwarding alerts. Without coordination, two of them can read the ACL at the same moment, both choose the same free sequence number and both write. Then:

- for the **same IP**, the second process crashes after its rule is already on the router;
- for **different IPs**, the second write **overwrites** the first rule at the same sequence number, so one attacker silently stops being blocked.

The race tests in `tests/test_enhancements.py` reproduce both cases. In a verification run with the lock switched off, the same-IP test crashed with `sqlite3.IntegrityError`, and 4 simultaneous blocks for 4 different IPs left only **1** rule on the router. With the lock, the result is always exactly 1 rule for one IP and 4 rules for 4 IPs.

**How it works.** Every change (`block`, `block-many`, `unblock`, expiry, `extend`, `recover`, `reconcile`, rollbacks) first takes an exclusive lock on `blocks.db.lock`, so processes take turns. Read-only commands (`list`, `history`, `show-acl`, `status`) do not wait.

- It is an operating-system file lock: it is **released automatically if a process crashes**.
- A process waits up to **30 seconds** for it; otherwise it answers `"status": "error"`, `Another driver process is changing the router ... try again`. Nothing was changed, so the request can be repeated. The expiry worker simply skips that round and tries again.
- It only works between processes using **the same `BLOCK_DB_PATH`** (§3).

### 6.3 Other duplicate safeguards

| Situation | Behaviour |
|---|---|
| The same IP appears twice in one `block-many` | Blocked once (§4.3). |
| The same alert is delivered twice | No new rule, and the expiry is not extended (§7.2). |
| A crashed process left an extra rule for an IP that is blocked by another record | `recover` removes the extra rule (§8.3). |
| The router has more than one deny line for the same IP | `reconcile` lists it under `duplicate_rules`. Rules the driver does not own are only reported (§8.5). |
| `reconcile --fix` would re-apply a rule for an IP already denied by someone else's rule | No second rule is added; reported under `not_repaired`. |

---

## 7. Temporary blocking and TTL expiry

> ⚠️ **Automatic expiry only happens while an expiry process is running.** The TTL is enforced **by the driver, not by the router**: the router does not know a block is temporary. If neither the `worker` nor a scheduled `expire` is running, expired blocks stay on the router until one runs again (§7.3).

### 7.1 The lifecycle

```
 alert ──► block(ip, ttl, alert_id) ──► rule on router + record in blocks.db
                                  │       expires_at = now + ttl
          same alert again ───────┤   no new rule, expiry unchanged
          new alert ──────────────┤   no new rule, expiry pushed later (within the lifetime cap)
          extend ─────────────────┤   expiry pushed later (record only)
          unblock / rollback ─────┤──► driver's rule deleted, status = removed
          expiry worker ──────────┘──► when now ≥ expires_at: driver's rule deleted, status = expired
          (must be running)
```

1. Every block **must** have a TTL: default 3600 s, allowed `BLOCK_MIN_TTL` (60 s) to `BLOCK_MAX_TTL` (86 400 s = 24 h).
2. Creation and end time are stored in `blocks.db` on disk, so pending expiries survive a restart of the PC or the driver, and are processed as soon as an expiry process runs again.
3. For each expired block, the expiry process reads the ACL, deletes **only the exact sequence number the driver recorded**, reads again to confirm it is gone, and marks the record `expired` / `ttl`.
4. If the router cannot be reached, the block **stays active** and is retried on the next check. A block can never be "forgotten".
5. Line `1000 permit ip any any` is never removed.

### 7.2 Repeated requests for an IP that is already blocked

| Repeated request | ACL | Expiry | `message` |
|---|---|---|---|
| **Same `--alert-id`** (duplicate delivery) | unchanged | **unchanged**, never extended | `Duplicate of alert ALERT-001; IP already blocked, expiry unchanged` |
| **Different `--alert-id`** (a new alert) | unchanged | refreshed to `max(current expiry, now + new TTL)`, capped by the lifetime cap (§7.5); the new alert ID is recorded | `IP already blocked; expiry refreshed` |
| **No `--alert-id`** | unchanged | refreshed (duplicates cannot be detected without an ID) | `IP already blocked; expiry refreshed` |
| Rule exists but **not created by the driver** | unchanged | none; never auto-removed | `...was not created by this driver; it was left untouched...` |

**Example.** At 10:00, ALERT-001 blocks an IP for 60 minutes, so it expires at 11:00.
- At 10:10, ALERT-001 is delivered again → still **11:00**.
- At 10:10, a new ALERT-002 arrives with 60 minutes → now **11:10**.

A repeated request never shortens a block; use `unblock` to end it early. **Always pass the alert ID**, otherwise a queue that re-delivers the same alert keeps extending the block.

### 7.3 Running the expiry process (required)

Choose **one** and keep it running for as long as blocks exist, with the same settings and `BLOCK_DB_PATH` as the terminal you block from.

**Option 1: run the worker continuously (recommended)**

```powershell
python -m cisco_driver worker                 # checks every BLOCK_EXPIRY_INTERVAL seconds
python -m cisco_driver worker --interval 5    # or choose the interval
```

```
Expiry worker running every 10.0s - press Ctrl+C to stop
```

Keep this terminal open. On every round the worker also resolves interrupted writes (§8.3). It survives errors: if one round fails, it logs the error and tries again at the next interval. When stopped with Ctrl+C it prints a summary:

```
Stopped. runs=42 removed=3 failed=0 recovered=0
```

**Option 2: run expiry once on a schedule** (e.g. Windows Task Scheduler every minute)

```powershell
python -m cisco_driver expire
```

This prints the blocks it removed (`[]` if none were due). Exit code 1 means at least one removal failed and will be retried next time. With this option, blocks are removed up to one schedule interval late. Run `recover` on the same schedule (§8.3), because `expire` does not resolve interrupted writes.

**Is expiry working?** Run `list`: no block should show `remaining_seconds` of `0` for longer than one check interval.

### 7.4 Timing to expect

A block is removed between `ttl` and `ttl + interval` seconds after it was applied, plus the time the router takes to answer. In the performance test (`evidence/performance_results.txt`), one `block()` took **103.6 ms** on average (p95 137.3 ms), and `expire_due()` removed **50 blocks in 4.52 s**. Exact figures vary with the machine and router.

### 7.5 Lifetime cap: a block cannot live for ever

Without a cap, a steady stream of new alerts could keep an address blocked indefinitely, although every block is meant to be temporary. The **total** lifetime of one block is therefore capped:

```
expiry after a refresh = min( max(current expiry, now + TTL),  created_at + BLOCK_MAX_LIFETIME )
```

The default is 7 days; `0` turns the cap off (the v1.0 behaviour). The cap applies to refreshes by new alerts and to `extend`, and never shortens a block. Example with a 1-hour TTL and a 2-hour cap, first blocked at 10:00:

| Time | Event | Expiry | `message` |
|---|---|---|---|
| 10:00 | ALERT-1 | 11:00 | `Blocked` |
| 10:33 | ALERT-2 | 11:33 | `IP already blocked; expiry refreshed` |
| 11:06 | ALERT-3 | **12:00** (cap) | `IP already blocked; expiry refreshed up to the maximum block lifetime (7200 s)` |
| 11:40 | ALERT-4 | 12:00 | `IP already blocked; maximum block lifetime (7200 s) reached, expiry unchanged` |

After the block expires, a new alert starts a fresh block with a new lifetime.

### 7.6 Repeat offenders: longer TTL for an IP that keeps coming back

```powershell
$env:BLOCK_REPEAT_FACTOR = "2"     # 1 = off (default)
```

When a **new** block is created for an IP whose earlier blocks on the same device **ran their full TTL** in the last **7 days**:

```
TTL used = min( requested TTL × BLOCK_REPEAT_FACTOR ^ (earlier blocks), BLOCK_MAX_TTL )
```

With factor 2 and 600 s requested: 600 s, then 1200 s, then 2400 s… never more than `BLOCK_MAX_TTL`. The message says so:

```
Blocked (repeat offender: 1 earlier block(s) in the last 7 days; TTL raised to 1200 s)
```

- Only earlier blocks that ended as `expired` count, i.e. ones that ran their full TTL.
- Blocks removed early by `unblock`, `rollback-alert` or `rollback-all` **never count**: they may have been false positives, and a false positive must not make the next block of the same IP longer.
- Refreshing an existing block never escalates.

### 7.7 Extending or ending a block by hand

**Extend:**

```powershell
python -m cisco_driver extend 203.0.113.7 --device R1 --ttl 7200
```

- Keeps the block until **at least** now + 7200 s; it **never shortens** a block.
- Changes only the record (the rule is already on the router), so it is instant and not rate-limited.
- `--ttl` must be within `BLOCK_MIN_TTL`…`BLOCK_MAX_TTL`; the lifetime cap (§7.5) applies.
- Result `extended` (exit 0), possibly with `Expiry unchanged: it is already later than requested` or `Expiry unchanged: maximum block lifetime reached`; or `not_found` (exit 1) if the IP has no active block.

A block request with a **new** alert ID also extends a block (§7.2); re-sending the same alert ID does not.

**End early:** `unblock` (§8.1), or a bulk rollback (§8.6, §8.7).

### 7.8 Time remaining and stuck expiries

- `list` and `status` show `remaining_seconds` for every active block.
- Each failed removal increases the block's `attempts` and stores `last_error`. After **5** failed attempts the driver logs an `ERROR` (`Block of <ip> on <device> could not be removed after 5 attempts ... check the router`). The block keeps being retried every round.

---

## 8. Rollback and recovery

### 8.1 Manual rollback of one IP: `unblock`

```powershell
python -m cisco_driver unblock 203.0.113.7 --device R1
```

Manual rollback is **ownership-aware**, exactly like automatic expiry. It deletes only the ACL line that **this driver created and recorded** in `blocks.db` for that IP. Deny rules that someone else added, for example an administrator protecting a server, are **never** deleted.

| `status` | Exit code | Meaning |
|---|---|---|
| `unblocked` | 0 | The driver's rule was deleted and verified gone; record marked `removed` / `manual`. If a hand-added rule for the same IP also exists, the message says it `was left untouched`. |
| `not_found` | 0 | Nothing to remove (safe to repeat). |
| `refused` | 1 | A deny rule exists but was **not created by the driver**; an administrator must remove it on the router if that is intended. |
| `error` | 1 | The router could not be reached or the delete did not take effect; the block stays active. Try again. |

There is deliberately **no** "force" option to delete hand-added rules. Removing a rule the driver does not own is an administrator decision, made under normal change control.

### 8.2 Automatic undo of partial writes

A write can reach the router before something goes wrong: a timeout, the verification read failing, a crash. In v1.0 such a rule stayed on the router with no record. The driver then treated its own rule as foreign: it never expired and `unblock` refused it. In v1.1 every block is journalled as `pending` **before** writing:

```
 journal "pending" ──► write ──► verify ──► "active"                     (normal case)
                          └─ failure ──► rule on router? ─yes─► delete it ─► "failed"
                                               └─no─────────────────────► "failed"
       router lost during the undo ─► stays "pending" ─► resolved later (§8.3)
```

The caller receives `"status": "error"` and can simply retry. The failure reason is kept in the record's `last_error`.

### 8.3 Interrupted writes: `recover`

A record stays `pending` only after a crash mid-write, or if the router was lost during the undo. It is resolved automatically:

- by the **next block or unblock for that IP**, so a retry never mistakes the driver's own rule for a foreign one;
- by the **expiry worker** on every round;
- by `reconcile --device <NAME> --fix` (for that device);
- or by hand:

```powershell
python -m cisco_driver recover
```

| Result | Meaning |
|---|---|
| `recovered` | The rule is on the router: it becomes a normal active block and expires as planned. This also covers a crash while a vanished rule was being re-applied at its old sequence number: the rule is kept and the old record is closed as `replaced` / `drift-repair`. |
| `discarded` | The write never reached the router, or it duplicated another active block (the duplicate rule is removed), or its device/ACL is no longer configured. The record is closed as `failed` / `recovery`. |
| `error` | The router could not be read; it is tried again later. |

`[]` means there was nothing to recover. Exit code 0 unless a result is `error`.

### 8.4 Choosing the right rollback

| Situation | Command | Removes |
|---|---|---|
| One IP was blocked by mistake | `unblock <IP> --device <NAME>` | That IP's driver rule on that device |
| A whole alert was a false positive | `rollback-alert <ALERT-ID>` | Every active block whose latest alert is that ID, on all devices |
| The alert feed is blocking legitimate users | `rollback-all [--device <NAME>] --yes` | Every driver block (on one device or all) |
| The router restarted or rules vanished | `reconcile --device <NAME> --fix` | Nothing; puts the driver's missing rules back |
| A process crashed mid-write | `recover` (or just keep the worker running) | Only half-written or duplicate rules |

All of them are ownership-aware: **rules added by anyone else are never deleted**.

### 8.5 Compare and repair router and record: `reconcile`

```powershell
python -m cisco_driver reconcile --device R1          # report only, changes nothing
python -m cisco_driver reconcile --device R1 --fix    # report and repair
```

| Report field | Contents |
|---|---|
| `in_sync` | Active blocks whose rule is on the router. |
| `missing_on_router` | Active blocks whose rule is missing (drift or router restart). |
| `foreign_rules` | Deny rules the driver did not create. **Never changed.** |
| `duplicate_rules` | IPs denied by more than one line. |
| `pending` | Interrupted writes still to be resolved. |
| `recovered`, `repaired`, `not_repaired` | With `--fix`: what was done, and what could not be done and why. |
| `error` | Router or lock problem, if any. |
| `ok` | `true` when router and record agree. Exit code 0 if `ok`, else 1. |

With `--fix` the driver:

1. resolves `pending` records for that device (§8.3);
2. re-applies every missing driver rule whose TTL has not passed, at its original sequence number or, if that is now taken, the next free one; it restores `1000 permit ip any any` if the whole ACL vanished;
3. closes missing records whose TTL has already passed (`expired` / `reconcile`).

Safety rules: foreign rules are only reported; no second rule is added for an IP already denied by someone else; repairs are not rate-limited, because they restore blocks that were already approved, and after a router restart all of them must come back at once.

**After a router restart or reload without a saved configuration:**

```powershell
python -m cisco_driver reconcile --device R1          # what is missing
python -m cisco_driver reconcile --device R1 --fix    # put the driver's blocks back
python -m cisco_driver show-acl --device R1           # confirm
```

### 8.6 Rollback by alert: undo a false positive

```powershell
python -m cisco_driver rollback-alert ALERT-101
```

Removes every **active** block whose latest alert is `ALERT-101`, on all devices, exactly like `unblock`. Records end as `removed` / `alert-rollback`. `[]` means no active block belongs to that alert.

> A block refreshed by a later, **different** alert now belongs to that alert and is **not** removed, because an independent alert confirmed it. Use `unblock` for that IP if it must go too.

### 8.7 Emergency rollback: remove everything the driver blocked

```powershell
python -m cisco_driver rollback-all --device R1 --yes   # one device
python -m cisco_driver rollback-all --yes               # every device
```

Use this if the alert feed has gone wrong and is blocking legitimate users. It removes every block the driver created; **rules added by anyone else stay**. Without `--yes` it refuses (exit code 2). Records end as `removed` / `rollback-all`. Stop the source of bad alerts first, or new blocks will follow.

---

## 9. Protecting, backing up and restoring `blocks.db`

`blocks.db` is the driver's **memory of which ACL rules it owns**. Every expiry and rollback starts by looking up the block's record. If the database is lost or damaged:

- rules that the driver created stay on the router, but with no record they are treated as **foreign**;
- they then **never expire automatically**, and `unblock` **refuses** to remove them;
- an administrator would have to find and remove them by hand.

Treat it as operational data: back it up, restrict access, restore with care.

### 9.1 Find the database file that is actually in use

The driver uses whatever file `BLOCK_DB_PATH` points to; if it is not set, `blocks.db` in the folder the commands are run from. Back up and restore **that exact file**. In the same terminal and folder as the driver:

```powershell
$db = if ($env:BLOCK_DB_PATH) { $env:BLOCK_DB_PATH } else { "blocks.db" }
"Database in use: $db"
```

### 9.2 Back up with one command: `backup`

```powershell
python -m cisco_driver backup                          # backups\blocks-<date>-<time>.db
python -m cisco_driver backup --out D:\safe\blocks.db  # chosen file
```

```json
{ "backup": "backups\\blocks-20261119-123402.db", "integrity_check": "ok", "records": 7 }
```

- It uses SQLite's online backup, so it is **safe while the worker runs**. Never simply copy the file while the driver might be writing to it.
- It checks the copy (`integrity_check`) and counts its records; exit code 1 if the check is not `ok`.
- It **never overwrites** an existing file (`Invalid input: ... already exists; choose a new file name`, exit code 2).
- It backs up the database in use (§9.1), because it reads the same `BLOCK_DB_PATH` as the driver.

Recommendations:

- **How often:** on a schedule (e.g. hourly with Windows Task Scheduler) and before any maintenance, upgrade or move.
- **Where:** keep copies **off the machine** as well, so a disk failure does not take the backups with it.
- **How long:** at least the longest TTL (`BLOCK_MAX_TTL`), then according to your data-retention policy.

### 9.3 Restrict access

The database holds **IP addresses, alert IDs and free-text reasons**, which may be personal or security-sensitive data, and anyone who can edit it can change what the driver believes it owns. Limit the folder to the account that runs the driver plus administrators:

```powershell
icacls backups /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F" "Administrators:(OI)(CI)F"
```

Apply the same restriction to the folder of the live database, and store off-machine copies with equivalent protection (restricted access, encrypted where possible).

### 9.4 Restore consistently with the router

A backup is a snapshot. Between the backup and the restore, the router may have changed. Restore like this:

1. **Stop** the worker (Ctrl+C) and every other driver command. Set `$db` as in §9.1.
2. Keep the current file for investigation: `Rename-Item $db "$db.broken"`.
3. Put the newest good backup in place **at the same path**: `Copy-Item backups\blocks-20261119-123402.db $db`.
4. Compare: `python -m cisco_driver reconcile --device R1`.
5. Repair: `python -m cisco_driver reconcile --device R1 --fix`. This re-applies the driver's rules that are still needed and closes records whose TTL has passed. Rules on the router with no record (for example, blocks created after the backup was taken) are only reported under `foreign_rules`; an administrator must review them against the alert history and remove them if they are no longer wanted.
6. **Restart** the worker with the same `BLOCK_DB_PATH`.

The more recent the backup, the less there is to review in step 5. That is why scheduled backups matter.

### 9.5 Upgrading a v1.0 database

The first time v1.1 opens a v1.0 `blocks.db`, it adds two columns (`attempts`, `last_error`) and two indexes automatically; all blocks are kept and keep expiring as planned. After that, **v1.0 can no longer read the file**. Take a backup first (§9.2), stop every v1.0 process, and never run v1.0 and v1.1 on the same database.

---

## 10. Demonstration

```powershell
python demo/enhancements_demo.py            # about 5 seconds
python demo/enhancements_demo.py --pause    # waits for Enter between steps, for live presenting
```

It uses its own temporary database and test router, so your normal `blocks.db` is not touched, and it moves its own clock forward to show hours of TTL in seconds.

| # | Step | What the audience sees |
|---|---|---|
| 1 | Driver with a protected list | Protected gateway, DNS and management LAN |
| 2 | Protected addresses | Two `REFUSED` results; 0 requests reached the router |
| 3 | Batch blocking | 2 × `BLOCKED`, the repeated IP once, `bad-ip` → `INVALID` |
| 4 | Duplicate prevention between processes | 4 processes at once → 1 `BLOCKED` + 3 `ALREADY_BLOCKED`, exactly 1 deny line |
| 5 | TTL | Refresh → capped → `maximum block lifetime reached`; `extend`; repeat offender 600 → 1200 s |
| 6 | `status` | `blocked`, `drift`, `blocked_foreign`, `not_blocked` |
| 7 | Recovery | Failed half-way write undone (no rule left); crashed write `RECOVERED` |
| 8 | Router restart | `reconcile` → 4 missing; `reconcile --fix` → all re-applied, `ok=True` |
| 9 | Rollbacks | `rollback-alert` removes only the false positive's block; `rollback-all` keeps the admin's rule 500 |
| 10 | Backup | `integrity_check=ok`, and the history of how every block ended |

Full output of a real run: `evidence/enhancements_demo_output.txt`.

The same lifecycle can be shown by hand with the commands of §13: `block` → `status` → `show-acl` → `worker` (block expires) → `block` again → `unblock` → `history`.

---

## 11. Common errors and solutions

The CLI uses three exit codes: **0** = success, **1** = refused or router error, **2** = bad input or bad settings.

### 11.1 Input and settings errors (exit code 2)

| Message | Cause | Solution |
|---|---|---|
| `Invalid input: 'abc' is not a valid IP address` | Typo or hostname instead of IP. | Give a dotted IPv4 address. |
| `Invalid input: Only a single IP address can be blocked, not a network` | A CIDR such as `10.0.0.0/8`. | Block individual hosts; network-wide blocks are deliberately refused. |
| `Invalid input: Only IPv4 addresses are supported by this ACL` | IPv6 address. | IPv4 only. |
| `Invalid input: 127.0.0.1 is a special-purpose address and cannot be blocked` | Special-purpose address (§4.1). | Never a valid attacker source. Check the alert data. |
| `Invalid input: TTL must be between 60 and 86400 seconds` | TTL out of range. | Choose a TTL in range. |
| `Invalid input: Unknown device 'R9'; known: ['R1']` | Device name not configured. | Use a configured name (case-sensitive). |
| `Invalid input: give at least one IP or --file` | `block-many` with no addresses. | Add IPs or `--file`. |
| `Refusing to remove every block without --yes` | `rollback-all` without confirmation. | Add `--yes` if intended. |
| `Invalid input: ... already exists; choose a new file name` | `backup --out` points at an existing file. | Choose a new name. |
| `Invalid input: An alert ID is required` | `rollback-alert` with an empty ID. | Give the alert ID. |
| `Settings error: Protected entry 'x' is not an IPv4 address or network` | Typo in `BLOCK_PROTECTED`. | Use e.g. `192.0.2.1, 10.0.0.0/24`. |
| `Settings error: BLOCK_REPEAT_FACTOR must be 1 (off) or larger` / `BLOCK_MAX_LIFETIME must be 0 ...` / `Bad blocking-policy setting: ...` | Bad blocking setting. | Fix the value (§3). |

### 11.2 Refusals (exit code 1, `"status": "refused"`)

| Message | Cause | Solution |
|---|---|---|
| `Rate limit: 10 changes on this device in the last minute (limit 10); try again shortly` | Too many changes too fast; this protects the router. | Wait up to 60 s and resend. |
| `Device already has 50 active blocks (limit 50)` | Block cap reached. | Unblock old entries, shorten TTLs, or raise `BLOCK_MAX_PER_DEVICE`. |
| `ACL has no free sequence numbers` | Slots 10–990 are all used. | Remove unused blocks. |
| `... is on the protected list (...); protected addresses are never blocked` | Covered by `BLOCK_PROTECTED`. | Intended. An administrator must change the list first if it really must be blocked. |
| On `unblock`: `A deny rule for this IP exists (seq N) but was not created by this driver; it was left untouched...` | Hand-added rule. | Intended; the driver never deletes rules it does not own. |

### 11.3 Verification, consistency and locking

| Symptom | Cause | Solution |
|---|---|---|
| `Verification failed: rule not found on router after writing it` | The write was accepted but the rule is not there. | Retry; any partial rule was already removed again (§8.2). |
| `Verification failed: rule still on router after delete` | The delete did not take effect. | The block stays active and is retried at the next expiry, or run `unblock` again. |
| `already_blocked` with `expiry unchanged` | Same alert ID sent again (§7.2). | Intended. Send a new alert ID, or use `extend`. |
| `... maximum block lifetime (604800 s) reached, expiry unchanged` | Lifetime cap reached (§7.5). | Intended. Let it expire, or raise `BLOCK_MAX_LIFETIME`. |
| `"status": "error"`, `Another driver process is changing the router (lock blocks.db.lock busy for 30s); try again` | Another driver process held the lock for 30 s. | Retry when it finishes. A crashed process releases the lock automatically. |
| Log `Block of <ip> on <device> could not be removed after 5 attempts` | Expiry keeps failing for this block. | Check the router, then `expire` or `reconcile`. The block keeps being retried. |
| `history` shows `status: pending` | A write was interrupted. | `recover`, or leave the worker running (§8.3). |
| Blocks never disappear after their TTL | No expiry process running. | Start `worker` or schedule `expire` (§7.3). |
| `list` shows a block but `show-acl` does not | Drift or router restart. | `reconcile --device R1 --fix` (§8.5). |
| `list` is empty but the router has the driver's rule, or `unblock` says "not created by this driver" for a rule you blocked | Commands used different `blocks.db` files. | Set `BLOCK_DB_PATH` to one absolute path everywhere (§3). |
| `Router error: ...` (exit 1) | The router could not be reached or rejected the request. | See the connection part of the project documentation. Blocks stay safely recorded and are retried. |

---

## 12. Tests and evidence

```powershell
python -m pytest tests/test_enhancements.py tests/test_driver.py tests/test_validation.py tests/test_worker_and_cli.py tests/test_performance.py
```

| File | Tests | What is proved |
|---|---|---|
| `tests/test_driver.py` | 33 | Idempotency, duplicate alerts, TTL refresh, ownership-aware rollback and expiry, drift repair, limits, persistence after restart |
| `tests/test_validation.py` | 37 | The address policy of §4.1 and TTL limits |
| `tests/test_worker_and_cli.py` | 8 | Expiry worker in the background, command-line cycle and exit codes |
| `tests/test_performance.py` | 2 | 50 blocks + 50 expiries; slow router with failures |
| `tests/test_enhancements.py` | 49 | v1.1 features, see below |
| **Total for these features** | **129** | All pass. The full project suite is 145 tests; the other 16 belong to the RESTCONF client part. |

`tests/test_enhancements.py` by responsibility:

| Group | Tests | What is proved |
|---|---|---|
| A. IP-blocking logic | 12 | Protected IPs/networks refused with no router call; protected-list parsing; blocking settings and bad values; batch de-duplication, invalid entries, limits; all four `status` states |
| B. Duplicate prevention | 5 | Lock excludes a second process, is re-entrant and freed on crash; 4 concurrent processes → 1 rule for one IP, 4 distinct sequences for 4 IPs |
| C. Temporary blocking / TTL | 9 | Lifetime cap; default cap leaves normal refreshes unchanged; repeat escalation, window and `BLOCK_MAX_TTL` limit; rolled-back false positives never escalate; `extend`; `remaining_seconds`; stuck-expiry warning; worker health |
| D. Rollback and recovery | 17 | Partial write undone; retry after a lost router recognises its own rule; crash recovery; crash during drift repair keeps the live rule; duplicate clean-up; worker recovery; `reconcile` report and `--fix` (restart, moved sequence, foreign IP); rollback by alert / all / device; backup; v1.0 database upgraded |
| E. Command line | 6 | `status`, `block-many` (incl. `--file`), `extend`, `reconcile`, `recover`, `rollback-alert`, `rollback-all --yes`, `backup`, `BLOCK_PROTECTED` |

Evidence in `evidence/`:

| File | Contents |
|---|---|
| `test_results.txt`, `junit_results.xml` | Full test run of the merged project: **145 passed** |
| `performance_results.txt` | `block()` mean 103.6 ms, p95 137.3 ms; 50 expiries in 4.52 s; slow router with 2 failures 1.25 s |
| `bandit_report.txt` | Static security scan of the changed code: no issues |
| `enhancements_demo_output.txt` | Full 10-step demonstration run |
| `tool_versions.txt` | Python, pytest, bandit and pip-audit versions used |
| `SHA256SUMS.txt` | Checksums of every file in this contribution |

To confirm that no file has changed since the evidence was produced (Git Bash, from the project folder):

```bash
sha256sum -c evidence/SHA256SUMS.txt
```

If you change any code, re-run the tests, demo and scan and regenerate these files, so that the evidence always matches the code.

---

## 13. Quick reference

```powershell
python -m cisco_driver worker                                   # automatic expiry (keep running)

# block
python -m cisco_driver block 203.0.113.7 --device R1 --ttl 3600 --reason "ssh brute force" --alert-id ALERT-001
python -m cisco_driver block-many 203.0.113.7 203.0.113.8 --device R1 --alert-id ALERT-9
python -m cisco_driver block-many --file ips.txt --device R1 --alert-id ALERT-9

# check
python -m cisco_driver status 203.0.113.7 --device R1           # blocked / drift / foreign / not
python -m cisco_driver list                                     # active blocks (driver record)
python -m cisco_driver show-acl --device R1                     # what is on the router
python -m cisco_driver history                                  # last 50 blocks incl. ended ones

# TTL
python -m cisco_driver extend 203.0.113.7 --device R1 --ttl 7200   # keep longer (never shorter)
python -m cisco_driver expire                                   # remove expired blocks once

# rollback and recovery
python -m cisco_driver unblock 203.0.113.7 --device R1          # one IP (own rules only)
python -m cisco_driver rollback-alert ALERT-9                   # undo a false-positive alert
python -m cisco_driver rollback-all --device R1 --yes           # emergency: remove all driver blocks
python -m cisco_driver recover                                  # resolve interrupted writes
python -m cisco_driver reconcile --device R1 [--fix]            # compare / repair router and record
python -m cisco_driver backup                                   # safe copy of blocks.db

# settings
$env:BLOCK_DB_PATH       = "D:\driver-data\blocks.db"           # one database for every terminal
$env:BLOCK_PROTECTED     = "192.0.2.1, 10.0.0.0/24"             # never block these
$env:BLOCK_MAX_LIFETIME  = "604800"                             # lifetime cap (s), 0 = off
$env:BLOCK_REPEAT_FACTOR = "2"                                  # repeat offenders, 1 = off

python -m cisco_driver -v <command>                             # verbose: audit log
python demo/enhancements_demo.py                                # 10-step demonstration
```

| Exit code | Meaning |
|---|---|
| 0 | Success (`blocked`, `already_blocked`, `unblocked`, `not_found`, `extended`, `recovered`, `discarded`) |
| 1 | `refused`, `error` or `invalid` (safety rule, router problem, rule not owned by the driver) |
| 2 | Invalid input or settings |

---

## Appendix: What changed since the v1.0 guide

**Removed** (documented by the owners of those parts):

| v1.0 section | Belongs to |
|---|---|
| §1 "The Mock IOS XE server"; §2 software, project files, installation; §3.3 starting the mock server; §3.4 the 8-step mock demonstration; §7.5 set-up problems (PowerShell, packages, ports) | Technical architecture and mock environment |
| Retry/back-off and request behaviour of the RESTCONF calls | RESTCONF client implementation |
| §3.2 `RESTCONF_*` settings; §7.1 connection-settings errors | API communication and configuration |
| Safety rows "Retries with back-off", "Credentials not logged", "TLS verified"; the credentials note; §7.3 router and connection errors; §3.5 dependency audits; Appendix A real hardware | Connection security and error handling |
| §4.4 "From Python (for other components)"; §6.2 Option 3 (worker inside another program) | Integration with other components |

**Kept and updated:** address policy, block results, repeated requests, `list` / `show-acl` / `history`, lifecycle, expiry process, timing, manual rollback, database protection and restore, error tables, quick reference.

**Added:** protected list, `block-many`, `status`, cross-process lock, lifetime cap, repeat offenders, `extend`, stuck-expiry warnings, write-ahead journal and automatic undo, `recover`, `reconcile`, `rollback-alert`, `rollback-all`, `backup`, database upgrade, rollback chooser (§8.4), 10-step demonstration, tests and evidence for these features.
