"""End-to-end demo of an APPROVED request from an upstream mock API."""
import argparse
from cisco_driver.enforcer import block_approved
from cisco_driver.expiry import cleanup

parser = argparse.ArgumentParser()
parser.add_argument('--cleanup-only', action='store_true')
parser.add_argument('--ttl', type=int, default=5)
args = parser.parse_args()

try:
    if not args.cleanup_only:
        request = {'action': 'block', 'approved': True,
                   'source_ip': '192.0.2.15', 'ttl': args.ttl}
        print('Block result:', block_approved(request))
    print('Expired blocks removed:', cleanup())
except Exception as exc:
    print('Driver error:', exc)
    raise SystemExit(1)
