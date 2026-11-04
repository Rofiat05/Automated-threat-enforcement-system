from replay_check import NonceStore

NOW = 1762246800


def test_new_nonce_is_accepted():
    store = NonceStore()
    assert not store.is_replay("abc123", NOW)


def test_same_nonce_twice_is_a_replay():
    store = NonceStore()
    store.is_replay("abc123", NOW)
    assert store.is_replay("abc123", NOW + 5)


def test_different_nonces_are_both_accepted():
    store = NonceStore()
    assert not store.is_replay("abc123", NOW)
    assert not store.is_replay("xyz789", NOW + 1)


def test_nonce_is_still_remembered_at_the_limit():
    store = NonceStore()
    store.is_replay("abc123", NOW)
    assert store.is_replay("abc123", NOW + 120)


def test_nonce_is_forgotten_after_the_limit():
    store = NonceStore()
    store.is_replay("abc123", NOW)
    assert not store.is_replay("abc123", NOW + 121)