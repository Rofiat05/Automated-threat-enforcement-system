import os
import ssl
import json
import base64

from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


class IOSXEClient:

    def __init__(self):
        self.host = os.environ["IOSXE_HOST"]
        self.username = os.environ["IOSXE_USER"]
        self.password = os.environ["IOSXE_PASS"]

    def get(self, path):
        credentials = base64.b64encode(
            f"{self.username}:{self.password}".encode()
        ).decode()

        url = f"https://{self.host}/restconf/data/{path}"

        request = Request(
            url,
            headers={
                "Authorization": f"Basic {credentials}",
                "Accept": "application/yang-data+json"
            },
            method="GET"
        )

        try:
            # TEMPORARY: Cisco educational sandbox diagnostic only.
            # Disables certificate verification because the
            # sandbox certificate is not validating correctly.
            # Never use this setting in production.
            context = ssl._create_unverified_context()

            with urlopen(
                request,
                timeout=15,
                context=context
            ) as response:
                return json.loads(response.read().decode())

        except (HTTPError, URLError) as error:
            raise RuntimeError(
                f"Cisco RESTCONF request failed: {error}"
            ) from error

    def get_hostname(self):
        return self.get(
            "Cisco-IOS-XE-native:native/hostname"
        )
    def get_acl(self):
        return self.get("openconfig-acl:acl")