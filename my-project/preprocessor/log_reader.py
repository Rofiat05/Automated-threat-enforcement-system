import gzip
from pathlib import Path
from typing import Iterable, Iterator, Union


def read_log_file(
    file_path: Union[str, Path]
) -> Iterator[str]:
    """
    Read a plain-text or gzip-compressed authentication log.

    Lines are yielded one at a time to reduce memory usage.
    """

    path = Path(file_path)

    # Check that the supplied path exists.
    if not path.exists():
        raise FileNotFoundError(
            "Log file not found: {}".format(path)
        )

    # Make sure the path points to a file.
    if not path.is_file():
        raise ValueError(
            "The supplied path is not a file: {}".format(path)
        )

    # Select the correct reader based on the file extension.
    if path.suffix.lower() == ".gz":
        open_function = gzip.open
    else:
        open_function = open

    # Open the file and read it one line at a time.
    with open_function(
        path,
        mode="rt",
        encoding="utf-8",
        errors="replace"
    ) as log_file:

        for line in log_file:
            yield line


def read_log_files(
    file_paths: Iterable[Union[str, Path]]
) -> Iterator[str]:
    """
    Read lines from multiple plain-text or gzip log files.

    The files are processed in the order provided.
    """

    for file_path in file_paths:
        yield from read_log_file(file_path)