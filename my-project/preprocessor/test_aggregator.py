from pathlib import Path

from log_reader import read_log_file
from parser import parse_log_line
from aggregator import aggregate_failed_logins


# Locate the sample authentication log using this file's location.
# This works regardless of the folder where pytest is started.
project_folder = Path(__file__).resolve().parent.parent
log_path = project_folder / "sample_data" / "auth.log"

# Load the sample authentication log.
log_lines = read_log_file(str(log_path))

# Parse each line into an event dictionary.
events = [
    parse_log_line(line)
    for line in log_lines
]

# Test the aggregator using a five-minute window.
summaries = aggregate_failed_logins(
    events,
    window_minutes=5,
    asset_criticality={
        "server01": "critical"
    }
)

# Check that we have one relevant failed-login group.
assert len(summaries) == 1, (
    "Expected one failed-login summary."
)

summary = summaries[0]

# Check the aggregated failure count.
assert summary["failed_attempts"] == 3, (
    "Expected three failed login attempts."
)

# Check the criticality and threshold.
assert summary["criticality"] == "critical"
assert summary["threshold"] == 3

# Check the alert decision.
assert summary["alert"] is True, (
    "The alert should trigger at the threshold."
)

# Check the source and destination context.
assert summary["host"] == "server01"
assert summary["source_ip"] == "192.168.1.50"

print("Test passed: failed logins were aggregated correctly.")
print("Summary:")
print(summary)
