def timestamp_is_fresh(timestamp, now, max_age_seconds=60):
    try:
        sent = int(timestamp)
    except (TypeError, ValueError):
        return False
    return abs(now - sent) <= max_age_seconds