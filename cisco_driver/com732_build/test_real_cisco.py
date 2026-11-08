from cisco_driver.iosxe_client import IOSXEClient

try:
    client = IOSXEClient()
    result = client.get_hostname()
    print("Cisco IOS XE connection successful")
    print(result)
except Exception as error:
    print("Connection failed:", error)