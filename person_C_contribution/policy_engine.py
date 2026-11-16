from aggregator import aggregate_failed_logins

print()
print("Security policy engine working...")

# Read trusted source IPs
allowed_ips = []
file = open("allow_list.txt", "r")
for line in file:
    if line.strip():
        allowed_ips.append(line.strip())
file.close()

# Read your asset inventory
asset_inventory = []
file = open("asset_inventory.csv", "r")
for line in file:
    asset = line.strip().split(",")
    if len(asset) == 3:
        asset_inventory.append(asset)
file.close()

# Read failed logins and prepare them for your friend's aggregator
events = []
file = open("auth.log", "r")
for line in file:
    if "Failed password" in line and " from " in line:
        parts = line.split()
        timestamp = " ".join(parts[0:3])
        host = parts[3]
        source_ip = line.split(" from ")[1].split(" ")[0]

        events.append({"event": "failed_login", "timestamp": timestamp,
                       "host": host, "source_ip": source_ip})
file.close()

# Give the aggregator the criticality of each asset
asset_criticality = {}
for asset in asset_inventory:
    asset_criticality[asset[0]] = asset[2]

# Get the aggregator results directly (no alerts.csv needed)
summaries = aggregate_failed_logins(events, asset_criticality=asset_criticality)
alerts_found = False

for alert in summaries:
    if alert["alert"]:
        source_ip = alert["source_ip"]
        target_name = alert["host"]
        attempts = alert["failed_attempts"]
        alerts_found = True

        target_found = False
        internal_source = False

        for asset in asset_inventory:
            if asset[0] == target_name:
                target_found = True
                target_ip = asset[1]
                criticality = asset[2]

            if asset[1] == source_ip:
                internal_source = True

        print()
        print("Source IP:", source_ip)
        print("Failed attempts:", attempts)

        if not target_found:
            print("POLICY: UNKNOWN TARGET - No action")
        else:
            print("Target IP:", target_ip)
            print("Target:", target_name)
            print("Criticality:", criticality)
            print("Threshold:", alert["threshold"])

            if source_ip in allowed_ips:
                print("POLICY: Trusted IP in allow-list - Do not block")
            elif internal_source:
                print("POLICY: Internal asset - Review manually before blocking")
            else:
                print("POLICY: Untrusted IP - Review for blocking")
                

        print()

if not alerts_found:
    print("No threshold alerts to review.")
