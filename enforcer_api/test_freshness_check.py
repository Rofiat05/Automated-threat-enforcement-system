from freshness_check import timestamp_is_fresh

NOW = 1762246800


def test_recent_timestamp_is_fresh():
    assert timestamp_is_fresh(str(NOW - 10), NOW)


def test_old_timestamp_is_rejected():
    assert not timestamp_is_fresh(str(NOW - 3600), NOW)


def test_future_timestamp_is_rejected():
    assert not timestamp_is_fresh(str(NOW + 3600), NOW)


def test_exactly_at_the_limit_is_fresh():
    assert timestamp_is_fresh(str(NOW - 60), NOW)


def test_just_past_the_limit_is_rejected():
    assert not timestamp_is_fresh(str(NOW - 61), NOW)


def test_non_number_is_rejected():
    assert not timestamp_is_fresh("hello", NOW)


def test_missing_timestamp_is_rejected():
    assert not timestamp_is_fresh(None, NOW)