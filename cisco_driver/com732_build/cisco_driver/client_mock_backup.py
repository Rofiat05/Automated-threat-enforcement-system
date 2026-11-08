"""Transport layer. This mock API is NOT a real Cisco IOS XE YANG model."""
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from .config import BASE_URL, TOKEN, TIMEOUT

class DeviceError(Exception):
    pass

class CiscoClient:
    def __init__(self, base_url=BASE_URL, token=TOKEN, timeout=TIMEOUT):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.timeout = timeout

    def request(self, method, path, data=None):
        payload = None if data is None else json.dumps(data).encode('utf-8')
        req = Request(self.base_url + path, data=payload, method=method,
                      headers={'Authorization': f'Bearer {self.token}',
                               'Accept': 'application/yang-data+json',
                               'Content-Type': 'application/yang-data+json'})
        try:
            with urlopen(req, timeout=self.timeout) as response:
                body = response.read()
                return json.loads(body) if body else {}
        except HTTPError as exc:
            raise DeviceError(f'Device returned HTTP {exc.code}') from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise DeviceError('Device connection failed or timed out') from exc

    def list_rules(self):
        return self.request('GET', '/restconf/data/mock-acl')['rules']

    def put_rule(self, rule_id, rule):
        return self.request('PUT', '/restconf/data/mock-acl/' + rule_id, rule)

    def delete_rule(self, rule_id):
        return self.request('DELETE', '/restconf/data/mock-acl/' + rule_id)