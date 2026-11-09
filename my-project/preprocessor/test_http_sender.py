import unittest
import json

from unittest.mock import patch, MagicMock
from urllib.error import HTTPError, URLError

from preprocessor.http_sender import send_summary


class TestHTTPSender(unittest.TestCase):

    def setUp(self):

        self.summary = {
            "host": "web-01",
            "source_ip": "192.168.1.50",
            "failed_attempts": 8,
            "threshold": 5,
            "alert": True
        }

        self.endpoint = "https://example.com/api/alerts"

    @patch("preprocessor.http_sender.urllib.request.urlopen")
    def test_successful_request(self, mock_urlopen):

        response = MagicMock()
        response.status = 200

        mock_urlopen.return_value.__enter__.return_value = response

        result = send_summary(
            self.summary,
            self.endpoint
        )

        self.assertEqual(result["success"], True)
        self.assertEqual(result["status_code"], 200)

        request = mock_urlopen.call_args.args[0]

        self.assertEqual(request.get_method(), "POST")

        sent_data = json.loads(request.data.decode("utf-8"))

        self.assertEqual(sent_data, self.summary)

    def test_reject_http_endpoint(self):

        with self.assertRaises(ValueError):

            send_summary(
                self.summary,
                "http://example.com/api/alerts"
            )

    def test_reject_invalid_summary(self):

        with self.assertRaises(TypeError):

            send_summary(
                "invalid data",
                self.endpoint
            )

    @patch("preprocessor.http_sender.urllib.request.urlopen")
    def test_server_error(self, mock_urlopen):

        mock_urlopen.side_effect = HTTPError(
            self.endpoint,
            503,
            "Service Unavailable",
            None,
            None
        )

        result = send_summary(
            self.summary,
            self.endpoint
        )

        self.assertEqual(result["success"], False)
        self.assertEqual(result["status_code"], 503)

    @patch("preprocessor.http_sender.urllib.request.urlopen")
    def test_connection_error(self, mock_urlopen):

        mock_urlopen.side_effect = URLError("Connection refused")

        with self.assertRaises(ConnectionError):

            send_summary(
                self.summary,
                self.endpoint
            )


if __name__ == "__main__":
    unittest.main()