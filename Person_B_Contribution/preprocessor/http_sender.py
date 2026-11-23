import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

from typing import Dict, Any


def send_summary(summary: Dict[str, Any], endpoint: str,
                 timeout: float = 5.0) -> Dict[str, Any]:

    # Check that the summary is a dictionary
    if not isinstance(summary, dict):
        raise TypeError("Summary must be a dictionary.")

    # Validate the endpoint
    parsed_endpoint = urllib.parse.urlparse(endpoint)

    if parsed_endpoint.scheme.lower() != "https":
        raise ValueError("Only HTTPS endpoints are permitted.")

    if not parsed_endpoint.hostname:
        raise ValueError("A valid endpoint hostname is required.")

    if parsed_endpoint.username or parsed_endpoint.password:
        raise ValueError("Credentials must not be included in the endpoint URL.")

    # Check the timeout value
    if timeout <= 0:
        raise ValueError("Timeout must be greater than zero.")

    # Convert the Python dictionary into JSON bytes
    payload = json.dumps(summary).encode("utf-8")

    # Construct the HTTP POST request
    request = urllib.request.Request(
        url=endpoint,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        method="POST"
    )

    # Create a secure TLS context with certificate verification
    tls_context = ssl.create_default_context()

    try:

        # Send the request and wait for the response
        with urllib.request.urlopen(
            request,
            timeout=timeout,
            context=tls_context
        ) as response:

            status_code = response.status

            return {
                "success": 200 <= status_code < 300,
                "status_code": status_code
            }

    except urllib.error.HTTPError as error:

        return {
            "success": False,
            "status_code": error.code
        }

    except (urllib.error.URLError, ssl.SSLError, TimeoutError) as error:

        raise ConnectionError(
            "HTTPS delivery failed. Check the endpoint, "
            "network connection, TLS certificate and timeout."
        ) from error