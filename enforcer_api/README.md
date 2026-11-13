This folder contains API validation and enforcement security
# Enforcer API (role D)

This folder is the "front door" of the enforcer. It receives an alert about repeated failed logins, checks that the alert is genuine, asks a decision function whether to block the attacker, and, if the answer is "block", asks E's Cisco driver to add a time-limited block. Every step is written to an audit log.

## How an alert travels

1. B's preprocessor writes alerts (one JSON object per line).
2. `alert_sender.py` signs each serious alert (`alert` is true) and posts it over HTTPS.
3. `api.py` receives it at `POST /v1/alerts`.
4. `front_door.py` runs five checks, in this order:
   1. form: only the eight agreed fields, each with a safe value (`alert_checks.py`)
   2. signature: HMAC-SHA256 with a shared secret (`seal_check.py`)
   3. freshness: the timestamp must be within 60 seconds (`freshness_check.py`)
   4. replay: a nonce can only be used once (`replay_check.py`)
   5. duplicate: the same attack in the same window is handled once (`duplicate_check.py`, `alert_id.py`)
5. If the alert is accepted, `decide(alert)` answers "block" or "ignore" (for now the stand-in in `decision_stub.py`).
6. For "block", `driver_adapter.py` calls E's driver, which adds a rule with an expiry time on the (mock) Cisco device.
7. `audit_log.py` writes every outcome, one JSON line each.

A rejected alert stops at step 4. Nothing after the checks runs for it.

## The alert

| Field | What it holds |
|---|---|
| host | name of the attacked machine (letters, numbers, dots, dashes) |
| source_ip | address of the attacker (a real IP address) |
| window_start, window_end | text like `Nov 12 10:00:00` |
| failed_attempts | whole number, 1 or more |
| criticality | `critical`, `high`, `medium` or `low` |
| threshold | whole number, 1 or more |
| alert | `true` or `false`; `false` is rejected |

Any other field, or a missing field, is rejected.

## Signing

Each request carries three headers:

- `X-Timestamp`: the time in seconds since 1970, as text
- `X-Nonce`: a random one-time label
- `X-Signature`: HMAC-SHA256 of `timestamp + newline + nonce + newline + SHA-256 of the body`, made with the shared secret

`sign_helper.py` makes these headers. The secret is never written in a file.

## What you need

- Python (tested on 3.15.2; FastAPI and httpx need 3.8 or newer)
- Packages: `python -m pip install fastapi uvicorn httpx pytest`

## Run the tests

```
cd enforcer_api
python -m pytest
```

You should see `155 passed`. One harmless warning about `httpx` may also appear; it comes from FastAPI's test tool, not from this code.

## Settings

Settings are environment variables, so no secret is ever stored in a file.

| Setting | Meaning |
|---|---|
| ALERT_SECRET | the shared secret (required; the service refuses to start without it) |
| AUDIT_LOG_PATH | where the audit log is written (default `audit.jsonl`) |
| ENFORCE_MODE | `off` (default: checks only) or `stub` (checks, decision and driver) |
| ALERT_URL | address the sender posts to (default `https://localhost:8443/v1/alerts`) |
| ALERT_CERT_FILE | a test certificate the sender should trust |
| CISCO_MOCK_STATE | file where E's mock device saves its rules |

## Make a test certificate (once)

The service speaks HTTPS, which needs a certificate and a private key. For testing, make a self-signed pair with the OpenSSL that comes with Git for Windows. Keep the folder **outside the repository** and never commit `key.pem`.

```
$certs = "$HOME\enforcer_certs"
New-Item -ItemType Directory $certs
$env:MSYS2_ARG_CONV_EXCL = "*"
& "C:\Program Files\Git\usr\bin\openssl.exe" req -x509 -newkey rsa:2048 -nodes -keyout "$certs\key.pem" -out "$certs\cert.pem" -days 30 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

This certificate is for testing only. A real deployment needs a certificate from a trusted authority and a private key that is not stored in a synced folder.

## Try it (three terminals)

Terminal 1, E's mock Cisco device (from the repository folder):

```
cd cisco_driver\com732_build
$env:CISCO_MOCK_STATE = "$HOME\enforcer_certs\mock_device_state.json"
python mock_device.py
```

Terminal 2, the service, with the hand-off switched on:

```
cd enforcer_api
$env:ALERT_SECRET = "practice-secret-123"
$env:AUDIT_LOG_PATH = "$HOME\enforcer_certs\audit.jsonl"
$env:ENFORCE_MODE = "stub"
python -m uvicorn api:create_app_from_env --factory --port 8443 --ssl-keyfile "$HOME\enforcer_certs\key.pem" --ssl-certfile "$HOME\enforcer_certs\cert.pem"
```

Terminal 3, the sender:

```
cd enforcer_api
$env:ALERT_SECRET = "practice-secret-123"
$env:ALERT_CERT_FILE = "$HOME\enforcer_certs\cert.pem"
python alert_sender.py sample_alerts.jsonl
python demo_send.py
```

`sample_alerts.jsonl` holds four example alerts in B's format. `demo_send.py` sends one example of each case: a good alert, a replay, a duplicate, a changed alert, an old timestamp, an alert below the threshold and a command hidden in the IP. `python demo_send.py replay` runs just one case.

The practice secret above is for testing on one computer only. Use a long random secret for anything else.

Expired blocks are not removed automatically yet. To remove them, run `python driver_demo.py --cleanup-only` in `cisco_driver\com732_build`.

## Replies

| Code | Meaning |
|---|---|
| 202 | accepted (with the hand-off on, the reply also shows `action`, `enforcement` and `detail`) |
| 400 | bad form: not JSON, wrong or unsafe fields, or the alert is below the threshold |
| 401 | bad signature, missing headers, or a timestamp that is too old |
| 409 | replayed request, or the same attack already handled |
| 413 | body larger than 10,000 bytes |

`GET /health` answers `{"status": "ok"}`.

## Audit log

One JSON line per outcome: `time`, `alert_id`, `decision`, `reason`. The `decision` is one of `accepted`, `rejected`, `ignored`, `block applied`, `block already_applied`, `block failed`, `block not applied` or `decision failed`. The signature and the secret are never written to the log.

## Files

| File | Job |
|---|---|
| `alert_checks.py` | form check |
| `seal_check.py` | signature check |
| `freshness_check.py` | timestamp check (60 seconds) |
| `replay_check.py` | nonce check (nonces kept 120 seconds) |
| `duplicate_check.py`, `alert_id.py` | duplicate check (alert IDs kept 1 hour) |
| `gatekeeper.py` | runs the five checks in order |
| `front_door.py` | gatekeeper, then decision, then driver |
| `decision_stub.py` | STAND-IN for C's `decide(alert)` |
| `driver_adapter.py` | turns a block decision into a request for E's driver |
| `api.py` | the web endpoint |
| `sign_helper.py`, `alert_sender.py` | signs and sends alerts |
| `audit_log.py` | append-only audit log |
| `demo_send.py`, `sample_alerts.jsonl` | demo and test data |
| `test_*.py` | tests |

## Security notes

- **Command injection:** every value is checked before use (a real IP address, a safe host name, a fixed time format). Values are never put into commands. E's driver checks the address and time limit again.
- **Tampering and forgery:** a signature over the timestamp, nonce and body; compared in constant time.
- **Replay and duplicates:** the timestamp window, one-time nonces and the alert ID. E's driver is also idempotent: the same address twice gives `ALREADY_PRESENT`.
- **Transport:** HTTPS only. The sender refuses `http://` addresses and addresses with a password in them, and it keeps certificate checking on.
- **Secrets:** read from environment variables; the service will not start without one.
- **Failing safely:** if the decision function crashes or gives a strange answer, nothing is blocked. A driver failure is logged and never crashes the service.
- **Size limit:** bodies over 10,000 bytes are refused.

## Known limits

- `decision_stub.py` is a stand-in. Its inventory, allowlist, block times and device name are placeholders until C's function replaces it.
- Expired blocks are removed only when the cleanup is run by hand.
- The nonce and duplicate memories live in the running program, so they are lost on restart. E's driver still refuses to add the same block twice.
- The alert times in B's format have no year.
- The driver talks to the mock device over plain HTTP on this computer only; the default demo token in E's `config.py` is for the mock only.
- There is no rate limiting, and the service runs as a single process.