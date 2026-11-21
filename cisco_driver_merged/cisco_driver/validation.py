"""Input checks. Everything that reaches the router passes through here first."""

from __future__ import annotations

import ipaddress
import re
from typing import Tuple

# Device and ACL names: start with a letter, then letters, digits, _ . -
# This stops path tricks such as "../" or "?" ending up inside RESTCONF URLs.
_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


class ValidationError(ValueError):
    """Raised when an input is not safe or not allowed."""


def validate_ip(value: object) -> str:
    """Return a normalised IPv4 address, or raise ValidationError.

    Only one single host can be blocked. Networks (e.g. 10.0.0.0/8) are refused
    so a bad alert can never cut off a whole range of users.

    Refused (cannot be a real traffic source):
        0.0.0.0/8 unspecified (0.0.0.0) | 127.0.0.0/8 loopback | 169.254.0.0/16 link-local
        224.0.0.0/4 multicast | 240.0.0.0/4 reserved "Class E", incl. 255.255.255.255
    Accepted on purpose:
        private ranges (10/8, 172.16/12, 192.168/16) - internal or compromised hosts
        RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
        - used as test fixtures with the mock router; they are not real attacker IPs.
    """
    if not isinstance(value, str):
        raise ValidationError("IP address must be text")
    text = value.strip()
    if "/" in text:
        raise ValidationError("Only a single IP address can be blocked, not a network")
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        raise ValidationError(f"{value!r} is not a valid IP address") from None
    if ip.version != 4:
        raise ValidationError("Only IPv4 addresses are supported by this ACL")
    if (
        ip.is_unspecified
        or ip.is_loopback
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_link_local
    ):
        raise ValidationError(f"{ip} is a special-purpose address and cannot be blocked")
    return str(ip)


def validate_ttl(value: object, minimum: int, maximum: int) -> int:
    """Return the block lifetime in seconds, or raise ValidationError."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError("TTL must be a whole number of seconds")
    if value < minimum or value > maximum:
        raise ValidationError(f"TTL must be between {minimum} and {maximum} seconds")
    return value


def validate_name(value: object, what: str) -> str:
    """Return a safe device or ACL name, or raise ValidationError."""
    if not isinstance(value, str) or not _NAME_RE.match(value):
        raise ValidationError(
            f"Invalid {what} name {value!r}: use letters, digits, '_', '.', '-' (max 64)"
        )
    return value


def parse_networks(value: object) -> Tuple[ipaddress.IPv4Network, ...]:
    """Parse the protected (never-block) list.

    Accepts a comma/space separated string or an iterable of strings. Each entry is
    one IPv4 host ("10.0.0.1") or network ("10.0.0.0/24"). Host bits are allowed
    ("10.0.0.1/24" means 10.0.0.0/24) because this list only ever widens protection.
    """
    if value is None:
        return ()
    if isinstance(value, str):
        items = [p for p in re.split(r"[,\s]+", value) if p]
    else:
        items = [str(p).strip() for p in value if str(p).strip()]  # type: ignore[union-attr]
    networks = []
    for item in items:
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValidationError(f"Protected entry {item!r} is not an IPv4 address or network") from None
        if net.version != 4:
            raise ValidationError(f"Protected entry {item!r}: only IPv4 is supported")
        networks.append(net)
    return tuple(networks)


def clean_text(value: object, max_length: int = 200) -> str:
    """Make free text (reason, alert id) safe to store and log: one line, limited length."""
    if value is None:
        return ""
    text = str(value).replace("\r", " ").replace("\n", " ")
    return text[:max_length]
