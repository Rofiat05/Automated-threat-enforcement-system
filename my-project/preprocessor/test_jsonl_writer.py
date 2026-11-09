import unittest
import json

from pathlib import Path
from tempfile import TemporaryDirectory

from preprocessor.jsonl_writer import append_summary


class TestJSONLWriter(unittest.TestCase):

    def setUp(self):

        self.temp_dir = TemporaryDirectory()

        self.output_file = (
            Path(self.temp_dir.name) / "alerts.jsonl"
        )

        self.summary = {
            "host": "web-01",
            "source_ip": "192.168.1.50",
            "failed_attempts": 8,
            "alert": True
        }

    def tearDown(self):

        self.temp_dir.cleanup()

    def test_write_single_summary(self):

        append_summary(self.summary, self.output_file)

        with self.output_file.open("r", encoding="utf-8") as file:
            record = json.loads(file.readline())

        self.assertEqual(record, self.summary)

    def test_append_multiple_summaries(self):

        append_summary(self.summary, self.output_file)

        second_summary = {
            "host": "server-02",
            "source_ip": "192.168.1.70",
            "failed_attempts": 3,
            "alert": False
        }

        append_summary(second_summary, self.output_file)

        with self.output_file.open("r", encoding="utf-8") as file:
            lines = file.readlines()

        self.assertEqual(len(lines), 2)

        self.assertEqual(json.loads(lines[0]), self.summary)

        self.assertEqual(json.loads(lines[1]), second_summary)

    def test_reject_invalid_summary(self):

        with self.assertRaises(TypeError):

            append_summary(
                "invalid data",
                self.output_file
            )

    def test_reject_non_json_value(self):

        invalid_summary = {
            "attempts": float("nan")
        }

        with self.assertRaises(ValueError):

            append_summary(
                invalid_summary,
                self.output_file
            )


if __name__ == "__main__":
    unittest.main()