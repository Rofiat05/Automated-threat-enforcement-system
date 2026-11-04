from duplicate_check import AlertIdStore
from alert_id import make_alert_id

NOW = 1762246800


def test_new_alert_id_is_accepted():
    store = AlertIdStore()
    assert not store.is_duplicate("id-one", NOW)


def test_same_alert_id_twice_is_a_duplicate():
    store = AlertIdStore()
    store.is_duplicate("id-one", NOW)
    assert store.is_duplicate("id-one", NOW + 30)


def test_different_alert_ids_are_both_accepted():
    store = AlertIdStore()
    assert not store.is_duplicate("id-one", NOW)
    assert not store.is_duplicate("id-two", NOW + 1)


def test_alert_id_is_still_remembered_at_the_limit():
    store = AlertIdStore()
    store.is_duplicate("id-one", NOW)
    assert store.is_duplicate("id-one", NOW + 3600)


def test_alert_id_is_forgotten_after_the_limit():
    store = AlertIdStore()
    store.is_duplicate("id-one", NOW)
    assert not store.is_duplicate("id-one", NOW + 3601)


def test_same_attack_reported_twice_is_caught_using_real_alert_ids():
    store = AlertIdStore()
    first = make_alert_id("web01", "203.0.113.7", "2026-11-04T09:00:00Z", 300)
    second = make_alert_id("web01", "203.0.113.7", "2026-11-04T09:00:00Z", 300)
    assert not store.is_duplicate(first, NOW)
    assert store.is_duplicate(second, NOW + 5)