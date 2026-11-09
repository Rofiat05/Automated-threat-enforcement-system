#creating a JSON file output writer
import json
from pathlib import Path
from typing import Iterable, Union


def write_jsonl(
    records: Iterable[dict],
    output_path: Union[str, Path]
) -> int:
    """
    Write alert summaries to a JSON Lines file.

    Each record is written as an independent JSON object.

    Returns the number of records written.
    """

    # Convert the supplied output path into a Path object.
    path = Path(output_path)

    # Create the output directory if it does not exist.
    path.parent.mkdir(parents=True, exist_ok=True)

    records_written = 0

    # Open the output file in write mode.
    with path.open(
        mode="w",
        encoding="utf-8",
        newline="\n"
    ) as output_file:

        for record in records:

            # Ensure that each record is a dictionary.
            if not isinstance(record, dict):
                raise TypeError(
                    "Each JSONL record must be a dictionary."
                )

            # Convert the Python dictionary into JSON.
            json_line = json.dumps(
                record,
                ensure_ascii=False
            )

            # Write the JSON object as one line.
            output_file.write(json_line + "\n")

            records_written += 1

    return records_written