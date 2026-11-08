import os
import ssl
import base64
import urllib.request
import urllib.error

host = os.getenv("IOSXE_HOST")
username = os.getenv("IOSXE_USER")
password = os.getenv("IOSXE_PASS")

if not all([host, username, password]):
    print("Missing IOSXE_HOST, IOSXE_USER or IOSXE_PASS")
    raise SystemExit(1)

url = (
    f"https://{host}/restconf/data/"
    "Cisco-IOS-XE-native:native/hostname"
)

credentials = base64.b64encode(
    f"{username}:{password}".encode()
).decode()

request = urllib.request.Request(
    url,
    headers={
        "Authorization": f"Basic {credentials}",
        "Accept": "application/yang-data+json"
    }
)

try:
    with urllib.request.urlopen(
        request,
        timeout=10,
        context=ssl.create_default_context()
    ) as response:
        print("Connected to Cisco IOS XE")
        print("HTTP status:", response.status)
        print(response.read().decode())

except Exception as error:
    print("Connection failed:", error)