# STAND-IN for C's decide(alert).
# It follows the rules C has described, so the whole chain can be tested.
# When C's real function is ready, it replaces this file.
# The data below is copied from C's asset_inventory.csv and allow_list.txt.
# The block times and the device name are placeholders to agree with C and E.

CONTROL_POINT = "mock-router-1"

ALLOWLIST = {"192.168.1.10", "192.168.1.20"}

# server name (small letters) -> (the machine's own IP address, importance)
INVENTORY = {
    "northmen-webserver": ("192.168.1.50", "medium"),
    "northmen-database": ("192.168.1.60", "high"),
    "northmen-pc01": ("192.168.1.70", "medium"),
    "northmen-mailserver": ("192.168.1.80", "high"),
    "northmen-fileserver": ("192.168.1.90", "high"),
    "northmen-pc02": ("192.168.1.100", "low"),
}

# how long a block lasts, in seconds, by importance
TTL_SECONDS = {"critical": 3600, "high": 1800, "medium": 900, "low": 300}


def _answer(action, reason, source_ip, ttl_seconds=0, control_point=None):
    return {
        "action": action,
        "reason": reason,
        "control_point": control_point,
        "source_ip": source_ip,
        "ttl_seconds": ttl_seconds,
    }


def decide(alert):
    host = str(alert.get("host", "")).strip().lower()
    source_ip = alert.get("source_ip")

    if not isinstance(source_ip, str):
        return _answer("ignore", "source_ip is not text", None)

    # 1. find the server by its NAME, ignoring capital letters
    server = INVENTORY.get(host)
    if server is None:
        return _answer("ignore", "server not in inventory", source_ip)

    # 2. never block a trusted address
    if source_ip in ALLOWLIST:
        return _answer("ignore", "trusted address on the allowlist", source_ip)

    # 3. never auto-block one of our own machines
    own_addresses = {address for address, _ in INVENTORY.values()}
    if source_ip in own_addresses:
        return _answer("ignore", "internal machine, review manually", source_ip)

    # 4. anything else is blocked, for a limited time
    importance = server[1]
    seconds = TTL_SECONDS.get(importance, TTL_SECONDS["low"])
    return _answer("block", "untrusted address", source_ip,
                   ttl_seconds=seconds, control_point=CONTROL_POINT)