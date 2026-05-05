import requests
import urllib3
import json

urllib3.disable_warnings()

NESSUS_URL = "https://localhost:8834"
NESSUS_USER = "admin"                                # ← your Nessus username
NESSUS_PASS = "Admin@123"                            # ← your Nessus password

# Login
r = requests.post(f"{NESSUS_URL}/session",
                  json={"username": NESSUS_USER, "password": NESSUS_PASS},
                  verify=False)
token = r.json()['token']
headers = {"X-Cookie": f"token={token}", "Content-Type": "application/json"}
print("[+] Logged in!\n")

# List all scans
scans = requests.get(f"{NESSUS_URL}/scans", headers=headers, verify=False).json()

print("=" * 50)
print("YOUR NESSUS SCANS:")
print("=" * 50)
for scan in scans.get('scans') or []:
    print(f"  ID: {scan['id']}  |  Name: {scan['name']}  |  Status: {scan['status']}")
print("=" * 50)
