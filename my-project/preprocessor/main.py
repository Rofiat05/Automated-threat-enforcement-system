from pathlib import Path

from preprocessor.log_reader import read_log_files
from preprocessor.parser import parse_log_line
from preprocessor.aggregator import aggregate_failed_logins
from preprocessor.output_writer import write_jsonl

def run_preprocessor(
        log_file_paths,
        output_path,
        window_minutes=5,
        asset_criticality=None,
        thresholds_by_criticality=None
):
    """Run the complete authentication-log preprocessing pipeline."""

    # Step 1: Read the authentication logs.
    lines_read = 0
    events = []

    for line in read_log_files(log_file_paths):
        lines_read += 1

        # Step 2: Parse each log line.
        event = parse_log_line(line)

        if event is not None:
            events.append(event)

    # Step 3: Aggregate failed authentication events.
    summaries = aggregate_failed_logins(
        events,
        window_minutes=window_minutes,
        asset_criticality=asset_criticality,
        thresholds_by_criticality=thresholds_by_criticality
    )

    # Step 4: Write the generated summaries to JSONL.
    records_written = write_jsonl(summaries, output_path)

    # Return information about the processing operation.
    return {
        "lines_read": lines_read,
        "structured_events": len(events),
        "failed_login_events": sum(
            event["event"] == "failed_login"
            for event in events
        ),
        "summaries_generated": len(summaries),
        "summaries_written": records_written
    }