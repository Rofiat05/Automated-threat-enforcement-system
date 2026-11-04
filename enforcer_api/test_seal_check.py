from seal_check import make_signature, signature_is_valid

SECRET = b"test-secret"
TIMESTAMP = "1762246800"
NONCE = "abc123"
BODY = b'{"host": "web01", "source_ip": "203.0.113.7"}'


def test_correct_signature_is_accepted():
    sig = make_signature(SECRET, TIMESTAMP, NONCE, BODY)
    assert signature_is_valid(SECRET, TIMESTAMP, NONCE, BODY, sig)


def test_changed_body_is_rejected():
    sig = make_signature(SECRET, TIMESTAMP, NONCE, BODY)
    changed = b'{"host": "web01", "source_ip": "203.0.113.8"}'
    assert not signature_is_valid(SECRET, TIMESTAMP, NONCE, changed, sig)


def test_wrong_secret_is_rejected():
    sig = make_signature(SECRET, TIMESTAMP, NONCE, BODY)
    assert not signature_is_valid(b"other-secret", TIMESTAMP, NONCE, BODY, sig)


def test_changed_timestamp_is_rejected():
    sig = make_signature(SECRET, TIMESTAMP, NONCE, BODY)
    assert not signature_is_valid(SECRET, "1762246801", NONCE, BODY, sig)


def test_changed_nonce_is_rejected():
    sig = make_signature(SECRET, TIMESTAMP, NONCE, BODY)
    assert not signature_is_valid(SECRET, TIMESTAMP, "xyz789", BODY, sig)