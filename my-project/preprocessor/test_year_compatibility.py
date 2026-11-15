import unittest
from preprocessor.aggregator import aggregate_failed_logins
from preprocessor.main import run_preprocessor
from pathlib import Path
from tempfile import TemporaryDirectory

class TestYearCompatibility(unittest.TestCase):
    def test_yearless_syslog_with_explicit_year(self):
        events = [{"event":"failed_login","host":"server01","source_ip":"192.0.2.10","timestamp":"Oct 28 09:01:15"}]
        rows = aggregate_failed_logins(events, log_year=2026)
        self.assertEqual(rows[0]["failed_attempts"], 1)
        self.assertEqual(rows[0]["window_start"], "Oct 28 09:00:00")

    def test_leap_day_year(self):
        events = [{"event":"failed_login","host":"server01","source_ip":"192.0.2.10","timestamp":"Feb 29 09:01:15"}]
        self.assertEqual(len(aggregate_failed_logins(events, log_year=2024)), 1)
        self.assertEqual(len(aggregate_failed_logins(events, log_year=2025)), 0)

    def test_invalid_year(self):
        with self.assertRaises(ValueError):
            aggregate_failed_logins([], log_year=0)

    def test_pipeline_accepts_year(self):
        base = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as directory:
            output = Path(directory) / "out.jsonl"
            result = run_preprocessor([base / "sample_data" / "auth.log"], output, log_year=2026)
            self.assertGreater(result["summaries_written"], 0)

if __name__ == "__main__":
    unittest.main()
