from alert_checks import check_alert, is_real_ip, is_valid_hostname

GOOD = {"host": "web01", "source_ip": "203.0.113.7", "count": 14, "criticality": "high"}


def test_good_alert_passes():
    assert check_alert(GOOD) == []


def test_ip_with_command_is_rejected():
    assert is_real_ip("1.2.3.4; reload") is False


def test_hostname_with_command_is_rejected():
    assert is_valid_hostname("web01; reload") is False


def test_negative_count_is_rejected():
    alert = dict(GOOD, count=-5)
    assert "count must be a whole number of 1 or more" in check_alert(alert)


def test_extra_field_is_rejected():
    alert = dict(GOOD, extra="x")
    assert any("unexpected field" in problem for problem in check_alert(alert))


def test_missing_field_is_rejected():
    alert = dict(GOOD)
    del alert["host"]
    assert "missing field: host" in check_alert(alert)