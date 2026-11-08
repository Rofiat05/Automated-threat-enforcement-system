"""Restart-safe expiry: expiry timestamps live in mock device state."""
from datetime import datetime, timezone
from .client import CiscoClient
from .enforcer import record, AUDIT

def cleanup(client=None, audit_path=AUDIT, current_time=None):
    client = client or CiscoClient()
    current_time = current_time or datetime.now(timezone.utc)
    removed = []
    for rid, rule in client.list_rules().items():
        if rule.get('owner') != 'com732-driver':
            continue
        expiry = datetime.fromisoformat(rule['expires_at'])
        if expiry <= current_time:
            client.delete_rule(rid)
            if rid in client.list_rules():
                raise RuntimeError('Rollback verification failed')
            record('unblock', rule['source_ip'], 'removed', rule['expires_at'], audit_path)
            removed.append(rule['source_ip'])
    return removed
