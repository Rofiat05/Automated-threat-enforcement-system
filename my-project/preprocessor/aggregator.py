from collections import defaultdict
from datetime import datetime, timedelta, timezone, tzinfo
import re

# Initial example thresholds.
# These values would be reviewed and agreed by the project team.
DEFAULT_THRESHOLDS = {
    "critical": 3,
    "high": 5,
    "medium": 8,
    "low": 10,
}


def aggregate_failed_logins(
    events,
    window_minutes=5,
    asset_criticality=None,
    thresholds_by_criticality=None,
):
    """
    Group failed login events by host, source IP and time window.

    Return a summary containing the failure count,
    asset criticality, threshold and alert status.
    """

    # Validate the time-window setting.
    if (
        not isinstance(window_minutes, int)
        or not 1 <= window_minutes <= 1440
    ):
        raise ValueError(
            "window_minutes must be an integer between 1 and 1440."
        )

    # Use an empty inventory mapping if none is supplied.
    if asset_criticality is None:
        asset_criticality = {}

    # Start with the default thresholds.
    thresholds = DEFAULT_THRESHOLDS.copy()

    # Allow the project configuration to override defaults.
    if thresholds_by_criticality is not None:
        thresholds.update({
            level.lower(): value
            for level, value in thresholds_by_criticality.items()
        })

    # Store the number of failures for each group.
    groups = defaultdict(int)

    for event in events:

        # Ignore entries that are not parsed event dictionaries.
        if not isinstance(event, dict):
            continue

        # Only unsuccessful login events are relevant here.
        if event.get("event") != "failed_login":
            continue

        host = event.get("host")
        source_ip = event.get("source_ip")
        timestamp_text = event.get("timestamp")

        # We need these fields to identify a group.
        if not host or not source_ip or not timestamp_text:
            continue

        # Convert the timestamp string into a datetime object.
        try:
            timestamp = datetime.strptime(
                timestamp_text,
                "%b %d %H:%M:%S"
            )
        except (ValueError, TypeError):
            continue

        # Find the start of the applicable fixed time window.
        total_minutes = (
            timestamp.hour * 60 + timestamp.minute
        )

        start_minutes = (
            total_minutes // window_minutes
        ) * window_minutes

        window_start = timestamp.replace(
            hour=start_minutes // 60,
            minute=start_minutes % 60,
            second=0,
            microsecond=0
        )

        # Group events by host, source IP and window start.
        group_key = (
            host,
            source_ip,
            window_start
        )

        groups[group_key] += 1

    # Convert the group counts into alert summaries.
    summaries = []

    for (host, source_ip, window_start), count in sorted(
        groups.items(),
        key=lambda item: (
            item[0][2],
            item[0][0],
            item[0][1]
        )
    ):

        # Obtain the asset's criticality.
        criticality = str(
            asset_criticality.get(host, "medium")
        ).lower()

        # Use medium as the fallback for an unknown criticality.
        if criticality not in thresholds:
            criticality = "medium"

        # Select the threshold for this asset.
        threshold = thresholds.get(
            criticality,
            thresholds["medium"]
        )

        # Determine whether the threshold has been reached.
        alert = count >= threshold

        summary = {
            "host": host,
            "source_ip": source_ip,
            "window_start": window_start.strftime(
                "%b %d %H:%M:%S"
            ),
            "window_end": (
                window_start + timedelta(
                    minutes=window_minutes
                )
            ).strftime("%b %d %H:%M:%S"),
            "failed_attempts": count,
            "criticality": criticality,
            "threshold": threshold,
            "alert": alert,
        }

        summaries.append(summary)

    return summaries