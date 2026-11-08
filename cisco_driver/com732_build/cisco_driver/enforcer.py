"""Validate approved requests, read before write, verify and audit."""
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .client import CiscoClient, DeviceError
from .config import MAX_TTL

AUDIT = Path('driver_audit.jsonl')

def record(action, ip, status, expiry=None, audit_path=AUDIT):
    entry = {'timestamp': datetime.now(timezone.utc).isoformat(),
             'action': action, 'source_ip': ip, 'status': status, 'expires_at': expiry}
    with Path(audit_path).open('a', encoding='utf-8') as f:
        f.write(json.dumps(entry) + '\n')

def rule_id_for(ip):
    address = ipaddress.ip_address(ip)
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError('This mock supports IPv4 only')
    if not address.is_global and not address.is_private:
        raise ValueError('Unsupported source address')
    return 'com732-' + str(address).replace('.', '-')

def block_approved(request, client=None, audit_path=AUDIT):
    """Called only after upstream authorisation; never accept raw alerts here."""
    client = client or CiscoClient()
    ip = request.get('source_ip')
    try:
        if request.get('action') != 'block' or request.get('approved') is not True:
            raise ValueError('Approved block request required')
        rid = rule_id_for(ip)
        ttl = request.get('ttl')
        if type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
            raise ValueError('TTL must be an integer between 1 and 86400 seconds')
        rules = client.list_rules()
        if rid in rules:
            record('block', ip, 'already_present', rules[rid]['expires_at'], audit_path)
            return 'ALREADY_PRESENT'
        expiry = (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()
        client.put_rule(rid, {'source_ip': ip, 'expires_at': expiry,
                              'owner': 'com732-driver', 'action': 'deny'})
        verified = client.list_rules().get(rid)
        if not verified or verified.get('source_ip') != ip:
            raise DeviceError('Read-back verification failed')
        record('block', ip, 'applied', expiry, audit_path)
        return 'APPLIED'
    except (ValueError, DeviceError, KeyError, TypeError) as exc:
        record('block', str(ip), 'failed:' + type(exc).__name__, audit_path=audit_path)
        raise
