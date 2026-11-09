import gzip
from pathlib import Path
from tempfile import TemporaryDirectory

from log_reader import read_log_file, read_log_files


# Locate the project directory and sample log.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOG = PROJECT_ROOT / "sample_data" / "auth.log"


def main():
    # Test 1: Read the normal authentication log.
    plain_lines = list(read_log_file(SAMPLE_LOG))

    assert len(plain_lines) > 0, (
        "The normal authentication log is empty."
    )

    print("Test 1 passed: normal log read successfully.")

    # Test 2: Create a temporary compressed log.
    with TemporaryDirectory() as temp_dir:

        compressed_path = (
            Path(temp_dir) / "auth.log.gz"
        )

        # Compress one line from the existing sample log.
        with gzip.open(
            str(compressed_path),
            mode="wt",
            encoding="utf-8"
        ) as compressed_file:

            compressed_file.write(plain_lines[0])

        # Read the compressed log.
        compressed_lines = list(
            read_log_file(compressed_path)
        )

        assert compressed_lines == [plain_lines[0]], (
            "The compressed log was not read correctly."
        )

        print("Test 2 passed: compressed log read successfully.")

        # Test 3: Read both files in one operation.
        combined_lines = list(
            read_log_files([
                SAMPLE_LOG,
                compressed_path
            ])
        )

        expected_count = len(plain_lines) + 1

        assert len(combined_lines) == expected_count, (
            "The multiple-file reader returned an "
            "unexpected number of lines."
        )

        print("Test 3 passed: multiple logs read successfully.")

    print("\nAll log reader checks passed.")


if __name__ == "__main__":
    main()