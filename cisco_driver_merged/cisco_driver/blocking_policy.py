"""Blocking-policy settings for the v1.1 enhancements (IP-blocking logic and TTL).

Kept separate from config.py on purpose: config.py (router connection settings) is
owned by the connection/configuration part of the project and is not changed.
These three optional variables only tune blocking behaviour:

    BLOCK_PROTECTED       never-block list, e.g. "192.0.2.1, 10.0.0.0/24"   (default: empty)
    BLOCK_MAX_LIFETIME    longest total life of one block in seconds        (default: 604800 = 7 days, 0 = no cap)
    BLOCK_REPEAT_FACTOR   TTL multiplier per earlier block of the same IP   (default: 1 = off)

If the Settings object passed to CiscoDriver.from_settings() already has the fields
`protected`, `max_lifetime` or `repeat_factor`, those values win.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Optional

from .validation import ValidationError, parse_networks


@dataclass(frozen=True)
class BlockingPolicy:
    protected: str = ""
    max_lifetime: int = 604800
    repeat_factor: float = 1.0

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "BlockingPolicy":
        env = os.environ if env is None else env
        try:
            max_lifetime = int(env.get("BLOCK_MAX_LIFETIME", "604800"))
            repeat_factor = float(env.get("BLOCK_REPEAT_FACTOR", "1"))
        except ValueError as exc:
            raise ValidationError(f"Bad blocking-policy setting: {exc}") from None
        if max_lifetime < 0:
            raise ValidationError("BLOCK_MAX_LIFETIME must be 0 (no cap) or a positive number of seconds")
        if repeat_factor < 1:
            raise ValidationError("BLOCK_REPEAT_FACTOR must be 1 (off) or larger")
        policy = cls(env.get("BLOCK_PROTECTED", ""), max_lifetime, repeat_factor)
        parse_networks(policy.protected)          # fail early on a typo in the list
        return policy

    @classmethod
    def for_settings(cls, settings) -> "BlockingPolicy":
        """Policy from the environment, overridden by any matching Settings fields."""
        base = cls.from_env()
        return cls(
            protected=getattr(settings, "protected", base.protected),
            max_lifetime=getattr(settings, "max_lifetime", base.max_lifetime),
            repeat_factor=getattr(settings, "repeat_factor", base.repeat_factor),
        )
