
"""RESTCONF compatibility helpers for the COM732 Cisco Driver.

This module is part of the local academic simulation.
"""

class RestconfError(Exception):
    """Raised when a simulated RESTCONF operation fails."""
    pass


def deny_rule(seq, ip):
    """Create a numbered ACL rule that denies an IP address."""
    return {
        "sequence": seq,
        "ace-rule": {
            "action": "deny",
            "protocol": "ip",
            "host": ip,
            "dst-any": [None],
        },
    }


def permit_any_rule(seq=1000):
    """Create a rule permitting traffic not otherwise denied."""
    return {
        "sequence": seq,
        "ace-rule": {
            "action": "permit",
            "protocol": "ip",
            "src-any": [None],
            "dst-any": [None],
        },
    }


def denied_host(rule):
    """Return the blocked IP from a deny rule, if present."""
    ace = rule.get("ace-rule", {})
    if ace.get("action") == "deny":
        return ace.get("host")
    return None


def is_permit_any(rule):
    """Check whether an ACL rule permits all remaining traffic."""
    ace = rule.get("ace-rule", {})
    return (
        ace.get("action") == "permit"
        and "src-any" in ace
        and "dst-any" in ace
    )


class RestconfClient:
    """Local numbered-ACL simulator for COM732 testing.

    This uses a JSON file, not a real Cisco IOS XE connection.
    """

    def __init__(self, base_url=None, username=None, password=None,
                 verify=True, timeout=5, max_retries=0,
                 backoff_base=0, state_path="mock_acl_state.json"):
        from pathlib import Path

        self.base_url = base_url
        self.state_path = Path(state_path)

    def _load(self):
        import json

        try:
            if not self.state_path.exists():
                return {}

            with self.state_path.open("r", encoding="utf-8") as file:
                data = json.load(file)

            if not isinstance(data, dict):
                raise RestconfError("Invalid ACL state format")

            return data

        except (OSError, ValueError) as exc:
            raise RestconfError(f"Cannot read ACL state: {exc}") from exc

    def _save(self, state):
        import json
        import os
        import tempfile

        try:
            folder = self.state_path.parent
            folder.mkdir(parents=True, exist_ok=True)

            fd, temporary = tempfile.mkstemp(
                dir=str(folder), prefix=".acl-"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as file:
                    json.dump(state, file, indent=2)
                os.replace(temporary, self.state_path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)

        except OSError as exc:
            raise RestconfError(f"Cannot save ACL state: {exc}") from exc

    def get_acl_rules(self, acl):
        state = self._load()
        if acl not in state:
            return None
        return list(state[acl])

    def create_acl(self, acl, rules):
        state = self._load()

        if acl in state and state[acl]:
            raise RestconfError("ACL already contains rules")

        self._check_rules(rules)
        state[acl] = list(rules)
        self._save(state)

    def add_rules(self, acl, rules):
        state = self._load()

        if acl not in state:
            raise RestconfError("ACL does not exist")

        self._check_rules(rules)

        existing = {
            int(rule["sequence"]) for rule in state[acl]
        }

        for rule in rules:
            if int(rule["sequence"]) in existing:
                raise RestconfError("ACL sequence already exists")

        state[acl].extend(rules)
        self._save(state)

    def delete_rule(self, acl, seq):
        state = self._load()

        if acl not in state:
            raise RestconfError("ACL does not exist")

        remaining = [
            rule for rule in state[acl]
            if int(rule["sequence"]) != int(seq)
        ]

        if len(remaining) == len(state[acl]):
            raise RestconfError("ACL rule not found")

        state[acl] = remaining
        self._save(state)

    @staticmethod
    def _check_rules(rules):
        if not isinstance(rules, list):
            raise RestconfError("Rules must be a list")

        sequences = []

        for rule in rules:
            if not isinstance(rule, dict):
                raise RestconfError("Invalid ACL rule")

            seq = rule.get("sequence")

            if isinstance(seq, bool) or not isinstance(seq, int):
                raise RestconfError("Invalid ACL sequence")

            if not 1 <= seq <= 1000:
                raise RestconfError("ACL sequence out of range")

            if not isinstance(rule.get("ace-rule"), dict):
                raise RestconfError("Missing ACL rule definition")

            sequences.append(seq)

        if len(sequences) != len(set(sequences)):
            raise RestconfError("Duplicate ACL sequences")
