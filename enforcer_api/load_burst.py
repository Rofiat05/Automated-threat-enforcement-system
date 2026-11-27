"""Simple load test for the front door (role D).

Sends a burst of signed alerts, plus some with a wrong signature, using
several threads at once. Prints how many of each reply came back, how long
the burst took and how quickly each request was answered.

Run the front door with ENFORCE_MODE=off for this test. Then the test only
exercises the five checks and does not add rules to the (mock) router.

Settings (environment variables):
  ALERT_SECRET     the shared secret (required)
  ALERT_URL        default https://localhost:8443/v1/alerts
  ALERT_CERT_FILE  the test certificate to trust

Usage: python load_burst.py [good_alerts] [bad_alerts] [threads]
       defaults: 200 50 10
"""

import json
import os
import statistics
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import httpx

from alert_sender import check_url, make_ssl_context
from sign_helper import make_signed_headers

DEFAULT_URL = "https://localhost:8443/v1/alerts"


TIME_FORMAT = "%b %d %H:%M:%S"


def make_alert(number, start):
    """A different alert each time (different address and time window), so
    the duplicate check does not treat them as the same attack."""
    begin = start + number
    return {
        "host": "server01",
        "source_ip": "198.51.100." + str(number % 250 + 1),
        "window_start": time.strftime(TIME_FORMAT, time.localtime(begin)),
        "window_end": time.strftime(TIME_FORMAT, time.localtime(begin + 300)),
        "failed_attempts": 5,
        "criticality": "high",
        "threshold": 5,
        "alert": True,
    }


def send_one(client, url, secret, number, start):
    alert = make_alert(number, start)
    body = json.dumps(alert).encode("utf-8")
    headers = make_signed_headers(body, secret)
    headers["Content-Type"] = "application/json"
    began = time.perf_counter()
    try:
        status = client.post(url, content=body, headers=headers).status_code
    except httpx.HTTPError as error:
        status = type(error).__name__
    return status, time.perf_counter() - began


def percentile(sorted_times, fraction):
    index = min(len(sorted_times) - 1, int(len(sorted_times) * fraction))
    return sorted_times[index]


def run(good, bad, threads, secret, url, cert_file):
    check_url(url)
    start = time.time()
    jobs = []
    for number in range(good):
        jobs.append((number, secret))
    for number in range(bad):
        jobs.append((good + number, b"the-wrong-secret"))

    with httpx.Client(verify=make_ssl_context(cert_file), timeout=10.0) as client:
        began = time.perf_counter()
        with ThreadPoolExecutor(max_workers=threads) as pool:
            results = list(pool.map(
                lambda job: send_one(client, url, job[1], job[0], start), jobs))
        total = time.perf_counter() - began

    return results, total


def report(results, total, good, bad, threads):
    codes = Counter(status for status, _ in results)
    times = sorted(seconds for _, seconds in results)
    print()
    print("Load test of the front door")
    print("---------------------------")
    print(f"Requests sent:      {len(results)} ({good} good, {bad} wrong signature)")
    print(f"Threads at once:    {threads}")
    print(f"Total time:         {total:.2f} seconds")
    print(f"Requests per second:{len(results) / total:8.1f}")
    print()
    print("Replies:")
    for code, count in sorted(codes.items(), key=lambda item: str(item[0])):
        print(f"  {code}: {count}")
    print()
    print("Time to answer one request (milliseconds):")
    print(f"  fastest {times[0] * 1000:.1f}   median {statistics.median(times) * 1000:.1f}"
          f"   95th {percentile(times, 0.95) * 1000:.1f}   slowest {times[-1] * 1000:.1f}")
    print()
    expected_ok = codes.get(202, 0) == good
    expected_bad = codes.get(401, 0) == bad
    print("Good alerts all accepted (202):    ", "YES" if expected_ok else "NO")
    print("Wrong signatures all refused (401):", "YES" if expected_bad else "NO")
    return expected_ok and expected_bad


def main():
    secret = os.environ.get("ALERT_SECRET")
    if not secret:
        print("ALERT_SECRET is not set in this window.")
        sys.exit(1)
    url = os.environ.get("ALERT_URL", DEFAULT_URL)
    cert_file = os.environ.get("ALERT_CERT_FILE")
    good = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    bad = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 10

    try:
        results, total = run(good, bad, threads, secret.encode("utf-8"), url, cert_file)
    except ValueError as error:
        print("Not sent: " + str(error))
        sys.exit(1)
    ok = report(results, total, good, bad, threads)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()   
