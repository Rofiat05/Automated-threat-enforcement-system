import hashlib
import hmac


def make_signature(secret, timestamp, nonce, body):
    body_fingerprint = hashlib.sha256(body).hexdigest()
    message = timestamp + "\n" + nonce + "\n" + body_fingerprint
    return hmac.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest()


def signature_is_valid(secret, timestamp, nonce, body, received_signature):
    expected = make_signature(secret, timestamp, nonce, body)
    return hmac.compare_digest(expected, received_signature)