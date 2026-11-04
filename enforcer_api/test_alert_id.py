from alert_id import make_alert_id


def test_same_details_give_same_id():
    a = make_alert_id("web01", "203.0.113.7", "2026-11-04T09:00:00Z", 300)
    b = make_alert_id("web01", "203.0.113.7", "2026-11-04T09:00:00Z", 300)
    assert a == b


def test_different_ip_gives_different_id():
    a = make_alert_id("web01", "203.0.113.7", "2026-11-04T09:00:00Z", 300)
    b = make_alert_id("web01", "203.0.113.8", "2026-11-04T09:00:00Z", 300)
    assert a != b


def test_id_is_64_characters():
    a = make_alert_id("web01", "203.0.113.7", "2026-11-04T09:00:00Z", 300)
    assert len(a) == 64