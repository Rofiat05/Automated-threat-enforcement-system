print()
print()
print("NORTHMEN SOC - Security Monitoring Program")
print()
print()
print()
print("Asset inventory:")

inventory_file = "asset_inventory.csv"

asset_inventory = []
file = open(inventory_file, "r")
for line in file:
    asset = line.strip().split(",")
    asset_inventory.append(asset)

for asset in asset_inventory:
    print("Hostname:", asset[0], "\n" + "IP Address:", asset[1], "\n" + "Criticality:", asset[2])
    print()

print()
print()
critical_assets = []
print(f"High criticality assets:") 
for asset in asset_inventory:
    if asset[2] == "High": 
        critical_assets.append(asset)
       
        print("Hostname:", asset[0], "\n" + "IP Address:", asset[1], "\n" + "Criticality:", asset[2])
        print()

print()
print()
print("Processing login attempts...")
print()
print()
print("Failed attempts:")

log_file = "logs/auth.log"


failed_attempts = 0
successful_attempts = 0

file = open(log_file, "r")
for line in file:
    if "Failed password" in line:
        print(line.strip())

    if "Failed password" in line: 
        failed_attempts += 1
                    
    elif "Accepted password" in line:
        successful_attempts += 1

print()
print(f"Failed attempts: {failed_attempts}")
print("Successful attempts:", successful_attempts)
print(f"Total login attempts: {failed_attempts + successful_attempts}")

      
print()

failed_ips = {}

file = open(log_file, "r")
for line in file:
    if "Failed password" in line:
        source_ip = line.split(" – ")[2]
        target_ip = line.split(" – ")[3].split(" ")[0]

        ip = source_ip + "," + target_ip

        if ip in failed_ips:    
            failed_ips[ip] += 1
        else: 
            failed_ips[ip] = 1
print()
print()

print("Suspicious activitty detected(surpassing the threshold of 3): ")
for ip, attempts in failed_ips.items(): 
    if attempts >= 3: #threshold for alerting the SOC team (if it is 3 or more login attempts)
        
        source_ip = ip.split(",")[0]
        target_ip = ip.split(",")[1]
        
        for asset in asset_inventory:
            if asset[1] == target_ip:
                print(f"ALERT: {source_ip} has {attempts} failed login attempts against {asset[0]} ({target_ip})")
                print(f"CRITICALITY: {asset[2]}")
                print(f"Potential cyber attack detected ALERT the SOC team immediately!")
                print()
   
print()
















