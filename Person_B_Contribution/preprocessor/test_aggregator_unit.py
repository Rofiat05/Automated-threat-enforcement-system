import unittest

from preprocessor.aggregator import aggregate_failed_logins


class TestAggregator(unittest.TestCase):

    def create_event(
        self,
        host,
        source_ip,
        timestamp,
        event="failed_login"
    ):

        return {
            "event": event,
            "host": host,
            "source_ip": source_ip,
            "timestamp": timestamp
        }

    def test_grouping_by_host_ip_and_time_window(self):

        events = [

            self.create_event(
                "server01",
                "192.168.1.50",
                "Oct 28 09:01:00"
            ),

            self.create_event(
                "server01",
                "192.168.1.50",
                "Oct 28 09:02:00"
            ),

            self.create_event(
                "server01",
                "192.168.1.50",
                "Oct 28 09:04:59"
            ),

            self.create_event(
                "server01",
                "192.168.1.50",
                "Oct 28 09:05:00"
            ),

            self.create_event(
                "server01",
                "192.168.1.70",
                "Oct 28 09:02:00"
            ),

            self.create_event(
                "server02",
                "192.168.1.50",
                "Oct 28 09:02:00"
            )

        ]

        summaries = aggregate_failed_logins(
            events,
            window_minutes=5
        )

        actual = {
            (
                item["host"],
                item["source_ip"],
                item["window_start"]
            ): item["failed_attempts"]

            for item in summaries
        }

        expected = {
            ("server01", "192.168.1.50", "Oct 28 09:00:00"): 3,
            ("server01", "192.168.1.50", "Oct 28 09:05:00"): 1,
            ("server01", "192.168.1.70", "Oct 28 09:00:00"): 1,
            ("server02", "192.168.1.50", "Oct 28 09:00:00"): 1
        }

        self.assertEqual(actual, expected)

    def test_successful_logins_are_ignored(self):

        events = [

            self.create_event(
                "server01",
                "192.168.1.50",
                "Oct 28 09:01:00",
                event="successful_login"
            )

        ]

        summaries = aggregate_failed_logins(events)

        self.assertEqual(summaries, [])

    def test_alert_at_exact_threshold(self):

        events = [

            self.create_event(
                "server01",
                "192.168.1.50",
                "Oct 28 09:01:00"
            ),

            self.create_event(
                "server01",
                "192.168.1.50",
                "Oct 28 09:02:00"
            ),

            self.create_event(
                "server01",
                "192.168.1.50",
                "Oct 28 09:03:00"
            )

        ]

        summaries = aggregate_failed_logins(
            events,
            asset_criticality={
                "server01": "critical"
            }
        )

        self.assertEqual(summaries[0]["failed_attempts"], 3)
        self.assertEqual(summaries[0]["threshold"], 3)
        self.assertTrue(summaries[0]["alert"])

    def test_alert_not_triggered_below_threshold(self):

        events = [

            self.create_event(
                "server01",
                "192.168.1.50",
                "Oct 28 09:01:00"
            ),

            self.create_event(
                "server01",
                "192.168.1.50",
                "Oct 28 09:02:00"
            )

        ]

        summaries = aggregate_failed_logins(
            events,
            asset_criticality={
                "server01": "critical"
            }
        )

        self.assertFalse(summaries[0]["alert"])

    def test_unknown_criticality_uses_medium(self):

        events = [

            self.create_event(
                "server01",
                "192.168.1.50",
                "Oct 28 09:01:00"
            )

        ]

        summaries = aggregate_failed_logins(
            events,
            asset_criticality={
                "server01": "unknown"
            }
        )

        self.assertEqual(
            summaries[0]["criticality"],
            "medium"
        )

        self.assertEqual(summaries[0]["threshold"], 8)

    def test_custom_threshold_configuration(self):

        events = [

            self.create_event(
                "server01",
                "192.168.1.50",
                "Oct 28 09:01:00"
            ),

            self.create_event(
                "server01",
                "192.168.1.50",
                "Oct 28 09:02:00"
            )

        ]

        summaries = aggregate_failed_logins(
            events,
            thresholds_by_criticality={
                "medium": 2
            }
        )

        self.assertEqual(summaries[0]["threshold"], 2)
        self.assertTrue(summaries[0]["alert"])

    def test_invalid_window_configuration(self):

        invalid_windows = [
            0,
            -1,
            1441,
            1.5,
            "five"
        ]

        for window in invalid_windows:

            with self.subTest(window=window):

                with self.assertRaises(ValueError):

                    aggregate_failed_logins(
                        [],
                        window_minutes=window
                    )

    def test_malformed_events_are_skipped(self):

        events = [

            self.create_event(
                None,
                "192.168.1.50",
                "Oct 28 09:01:00"
            ),

            self.create_event(
                "server01",
                "192.168.1.50",
                "invalid-timestamp"
            )

        ]

        summaries = aggregate_failed_logins(events)

        self.assertEqual(summaries, [])


if __name__ == "__main__":
    unittest.main()