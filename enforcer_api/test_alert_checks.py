from alert_checks import check_alert

GOOD = {
    "host": "web01",
    "source_ip": "203.0.113.7",
    "window_start": "Nov 05 10:00:00",
    "window_end": "Nov 05 10:05:00",
    "failed_attempts": 5,
    "criticality": "high",
    "threshold": 5,
    "alert": True,
}


def test_good_alert_passes():
    assert check_alert(GOOD) == []


def test_ip_with_command_is_rejected():
    alert = dict(GOOD, source_ip="1.2.3.4; shutdown")
    assert "source_ip is not a real IP address" in check_alert(alert)


def test_hostname_with_command_is_rejected():
    alert = dict(GOOD, host="web01; reload")
    assert "host is not valid" in check_alert(alert)


def test_negative_count_is_rejected():
    alert = dict(GOOD, failed_attempts=-5)
    assert "failed_attempts must be a whole number of 1 or more" in check_alert(alert)


def test_extra_field_is_rejected():
    alert = dict(GOOD, extra="x")
    assert "unexpected field: extra" in check_alert(alert)


def test_missing_field_is_rejected():
    alert = dict(GOOD)
    del alert["host"]
    assert "missing field: host" in check_alert(alert)


def test_old_count_field_name_is_rejected():
    alert = dict(GOOD)
    del alert["failed_attempts"]
    alert["count"] = 5
    problems = check_alert(alert)
    assert "unexpected field: count" in problems
    assert "missing field: failed_attempts" in problems


def test_command_in_window_time_is_rejected():
    alert = dict(GOOD, window_start="Nov 05 10:00:00; reload")
    assert "window_start is not a valid time" in check_alert(alert)


def test_bad_threshold_is_rejected():
    alert = dict(GOOD, threshold=0)
    assert "threshold must be a whole number of 1 or more" in check_alert(alert)


def test_alert_below_threshold_is_rejected():
    alert = dict(GOOD, alert=False)
    assert "alert is false (below threshold)" in check_alert(alert)


def test_alert_flag_must_be_true_or_false():
    alert = dict(GOOD, alert="yes")
    assert "alert must be true or false" in check_alert(alert)