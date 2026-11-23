import json

from pathlib import Path
from typing import Dict, Any, Union


def append_summary(
    summary: Dict[str, Any],
    output_path: Union[str, Path]
) -> None:

    # Ensure the summary is a dictionary
    if not isinstance(summary, dict):
        raise TypeError("Summary must be a dictionary.")

    # Validate the output path
    if not isinstance(output_path, (str, Path)):
        raise TypeError("Output path must be a string or Path object.")

    if not str(output_path).strip():
        raise ValueError("Output path cannot be empty.")

    # Convert the output path into a Path object
    file_path = Path(output_path)

    # Convert the dictionary into a JSON string
    json_record = json.dumps(
        summary,
        ensure_ascii=False,
        allow_nan=False
    )

    # Append the JSON record to the file
    with file_path.open("a", encoding="utf-8") as output_file:
        output_file.write(json_record + "\n")