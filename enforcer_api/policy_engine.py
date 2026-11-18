from pathlib import Path

HERE = Path(__file__).resolve().parent

CONTROL_POINT = "mock-router-1"
TTL_SECONDS = {"critical": 3600, "high": 1800, "medium": 900, "low": 300}


def load_allowed_ips(path=None):
    path = Path(path) if path else HERE / "allow_list.txt"
    allowed_ips = []
    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                allowed_ips.append(line.strip())
    return allowed_ips


def load_assets(path=None):
    path = Path(path) if path else HERE / "asset_inventory.csv"
    assets = []
    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            row = line.strip().split(",")
            if len(row) == 3:
                assets.append(row)
    return assets


def _answer(action, reason, source_ip, control_point=None, ttl_seconds=0):
    return {
        "action": action,
        "reason": reason,
        "control_point": control_point,
        "source_ip": source_ip,
        "ttl_seconds": ttl_seconds,
    }


def decide(alert, allowed_ips=None, assets=None):
    if not isinstance(alert, dict):
        return _answer("ignore", "alert is not a dictionary", None)

    source_ip = alert.get("source_ip")
    target_name = str(alert.get("host", "")).strip()

    if not isinstance(source_ip, str):
        return _answer("ignore", "source_ip is not text", None)

    if allowed_ips is None:
        allowed_ips = load_allowed_ips()
    if assets is None:
        assets = load_assets()

    target_found = False
    internal_source = False
    criticality = ""
    for asset in assets:
        if asset[0].strip().lower() == target_name.lower():
            target_found = True
            criticality = asset[2].strip().lower()

        if asset[1].strip() == source_ip:
            internal_source = True

    if not target_found:
        return _answer("ignore", "server not in inventory", source_ip)

    if source_ip in allowed_ips:
        return _answer("ignore", "trusted address on the allowlist", source_ip)

    if internal_source:
        return _answer("ignore", "internal machine, review manually", source_ip)

    seconds = TTL_SECONDS.get(criticality, TTL_SECONDS["low"])
    return _answer("block", "untrusted address", source_ip,
                   control_point=CONTROL_POINT, ttl_seconds=seconds)


if __name__ == "__main__":
    from aggregator import aggregate_failed_logins

    events = []
    with open(HERE / "auth.log", "r", encoding="utf-8") as file:
        for line in file:
            if "Failed password" in line and " from " in line:
                parts = line.split()
                events.append({
                    "event": "failed_login",
                    "timestamp": " ".join(parts[0:3]),
                    "host": parts[3],
                    "source_ip": line.split(" from ")[1].split(" ")[0],
                })

    assets = load_assets()
    asset_criticality = {asset[0]: asset[2] for asset in assets}
    asset_ips = {asset[0]: asset[1] for asset in assets}
    summaries = aggregate_failed_logins(events,
                                        asset_criticality=asset_criticality)

    print()
    print("Security policy engine working...")
    alerts_found = False

    for alert in summaries:
        if alert["alert"]:
            alerts_found = True
            answer = decide(alert)

            print()
            print("Source IP:", alert["source_ip"])
            if alert["host"] in asset_ips:
                print("Target IP:", asset_ips[alert["host"]])
            print("Target:", alert["host"])
            print("Criticality:", asset_criticality.get(alert["host"], "unknown"))
            print("Failed attempts:", alert["failed_attempts"])
            print("Threshold:", alert["threshold"])
            print("POLICY:", answer["action"].upper(), "-", answer["reason"])
            if answer["action"] == "block":
                print("Block for", answer["ttl_seconds"], "seconds on",
                      answer["control_point"])

    if not alerts_found:
        print()
        print("No threshold alerts to review.")
