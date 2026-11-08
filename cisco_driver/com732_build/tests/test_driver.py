import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cisco_driver.enforcer import block_approved
from cisco_driver.expiry import cleanup

class FakeClient:
    def __init__(self): self.rules = {}
    def list_rules(self): return dict(self.rules)
    def put_rule(self, rid, rule): self.rules[rid] = rule
    def delete_rule(self, rid): del self.rules[rid]

class DriverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.audit = Path(self.temp.name) / 'audit.jsonl'
        self.client = FakeClient()
        self.request = {'action': 'block', 'approved': True, 'source_ip': '192.0.2.15', 'ttl': 300}

    def test_block_and_verify(self):
        self.assertEqual(block_approved(self.request, self.client, self.audit), 'APPLIED')
        self.assertEqual(len(self.client.rules), 1)

    def test_idempotent(self):
        block_approved(self.request, self.client, self.audit)
        self.assertEqual(block_approved(self.request, self.client, self.audit), 'ALREADY_PRESENT')
        self.assertEqual(len(self.client.rules), 1)

    def test_reject_unapproved(self):
        with self.assertRaises(ValueError):
            block_approved({**self.request, 'approved': False}, self.client, self.audit)
        self.assertEqual(self.client.rules, {})

    def test_reject_invalid_ttl(self):
        with self.assertRaises(ValueError):
            block_approved({**self.request, 'ttl': -2}, self.client, self.audit)

    def test_expiry(self):
        block_approved(self.request, self.client, self.audit)
        future = datetime.now(timezone.utc) + timedelta(seconds=301)
        self.assertEqual(cleanup(self.client, self.audit, future), ['192.0.2.15'])
        self.assertEqual(self.client.rules, {})

    def test_unexpired_not_removed(self):
        block_approved(self.request, self.client, self.audit)
        self.assertEqual(cleanup(self.client, self.audit), [])

if __name__ == '__main__': unittest.main()
