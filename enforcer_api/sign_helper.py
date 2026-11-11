import secrets
import time

from seal_check import make_signature


def make_signed_headers(body, secret, now=None, nonce=None):
    if now is None:
        now = int(time.time())
    if nonce is None:
        nonce = secrets.token_hex(16)
    timestamp = str(int(now))
    signature = make_signature(secret, timestamp, nonce, body)
    return {
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": signature,
    }