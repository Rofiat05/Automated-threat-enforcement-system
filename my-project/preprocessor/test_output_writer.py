import json
from pathlib import Path
from tempfile import TemporaryDirectory

from log_reader import read_log_file
from parser import parse_log_line
from aggregator import aggregate_failed_logins
from output_writer import write_jsonl


# Locate the project directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Locate the sample authentication log.
SAMPLE_LOG = PROJECT_ROOT / "sample_data" / "auth.log"


def main():

    # Step 1: Read the authentication log.
    log_lines = read_log_file(SAMPLE_LOG)

    # Step 2: Parse the log lines.
    events = [
        parse_log_line(line)
        for line in log_lines
    ]

    # Step 3: Aggregate failed login events.
    summaries = aggregate_failed_logins(
        events,
        window_minutes=5,
        asset_criticality={
            "server01": "critical"
        }
    )

    assert len(summaries) > 0, (
        "No alert summaries were generated."
    )

    print("Test 1 passed: alert summaries generated.")

    # Step 4: Create a temporary output directory.
    with TemporaryDirectory() as temp_dir:

        output_path = (
            Path(temp_dir) / "output" / "alerts.jsonl"
        )

        # Step 5: Write summaries to JSONL.
        written_count = write_jsonl(
            summaries,
            output_path
        )

        assert written_count == len(summaries), (
            "The number of written records is incorrect."
        )

        print("Test 2 passed: JSONL records written.")

        # Step 6: Confirm the output file exists.
        assert output_path.exists(), (
            "The JSONL output file was not created."
        )

        # Step 7: Read the generated JSONL file.
        with output_path.open(
            "r",
            encoding="utf-8"
        ) as output_file:

            output_lines = output_file.readlines()

        assert len(output_lines) == len(summaries), (
            "The number of JSONL lines is incorrect."
        )

        print("Test 3 passed: JSONL file contains expected lines.")

        # Step 8: Convert each JSON line back into a Python object.
        recovered_records = [
            json.loads(line)
            for line in output_lines
        ]

        # Step 9: Confirm the recovered data matches the original.
        assert recovered_records == summaries, (
            "The recovered JSON data does not match the original."
        )

        print("Test 4 passed: JSONL data integrity verified.")

        # Step 10: Test writing an empty collection.
        empty_output = Path(temp_dir) / "empty.jsonl"

        empty_count = write_jsonl(
            [],
            empty_output
        )

        assert empty_count == 0
        assert empty_output.exists()
        assert empty_output.read_text(
            encoding="utf-8"
        ) == ""

        print("Test 5 passed: empty JSONL output handled.")

    print("\nAll JSONL output tests passed.")


if __name__ == "__main__":
    main()