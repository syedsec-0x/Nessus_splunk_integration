import requests
import time
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── CONFIG ───────────────────────────────────────────
NESSUS_URL        = "https://localhost:8834"
NESSUS_USER       = "admin"                         #username
NESSUS_PASS       = "Admin@123"                     #password

SCAN_ID           = 19                              # change to ur scan id after getting list of ids.

SPLUNK_HEC_URL    = "http://localhost:8088/services/collector/event"
SPLUNK_HEC_TOKEN  = "####2986-b267-4e85-ac17-812aca2e####"            # HEC-TOkEN  change to yours by going to splunk enterprises >settings>> data inputs >>html event collector.

INTERVAL_MINS     = 30
SPLUNK_BATCH_SIZE = 25

# This will be set at runtime by asking the user
SPLUNK_INDEX      = None
# ──────────────────────────────────────────────────────

HEADERS = {}

# Persistent session for Splunk — avoids RemoteDisconnected errors
SESSION = requests.Session()
SESSION.verify = False


def choose_splunk_index():
    """
    Ask the user which Splunk index to store logs in.
    Shows a numbered list of common indexes plus a custom option.
    """
    common_indexes = [
        "main",
        "nessus",
        "security",
        "vulnerability",
        "siem",
        "network",
    ]

    print("\n" + "="*55)
    print("  SPLUNK INDEX SELECTION")
    print("="*55)
    print("  Where should Nessus vulnerability logs be stored?\n")

    for i, idx in enumerate(common_indexes, start=1):
        print(f"  [{i}] {idx}")
    print(f"  [{len(common_indexes) + 1}] Custom (type your own index name)")
    print("="*55)

    while True:
        choice = input("  Enter choice number: ").strip()

        if choice.isdigit():
            choice_num = int(choice)
            if 1 <= choice_num <= len(common_indexes):
                selected = common_indexes[choice_num - 1]
                print(f"\n[+] Selected index: '{selected}'")
                return selected
            elif choice_num == len(common_indexes) + 1:
                custom = input("  Enter your custom index name: ").strip()
                if custom:
                    print(f"\n[+] Selected index: '{custom}'")
                    return custom
                else:
                    print("  [!] Index name cannot be empty. Try again.")
            else:
                print(f"  [!] Please enter a number between 1 and {len(common_indexes) + 1}.")
        else:
            print("  [!] Invalid input. Please enter a number.")


def login():
    print("[*] Logging into Nessus...")
    r = requests.post(
        f"{NESSUS_URL}/session",
        json={"username": NESSUS_USER, "password": NESSUS_PASS},
        verify=False,
        timeout=15
    )
    data = r.json()
    if 'token' not in data:
        raise Exception(f"[!] Login failed: {data}")
    print("[+] Login successful!")
    return {
        "X-Cookie": f"token={data['token']}",
        "Content-Type": "application/json"
    }


def is_auth_error(data):
    if isinstance(data, dict):
        err = str(data.get('error', ''))
        if 'Invalid Credentials' in err or 'Invalid token' in err:
            return True
    return False


def api_get(url, retry=True):
    global HEADERS
    try:
        r = requests.get(url, headers=HEADERS, verify=False, timeout=15)
    except Exception as e:
        print(f"    [!] Request error: {e}")
        return {}

    if r.status_code == 401:
        if retry:
            print("[*] HTTP 401 — session expired, re-logging in...")
            HEADERS = login()
            return api_get(url, retry=False)
        else:
            print("[!] Re-login failed, still getting 401.")
            return {}

    try:
        data = r.json()
    except Exception:
        print(f"    [!] Could not parse JSON: {r.text[:300]}")
        return {}

    if is_auth_error(data):
        if retry:
            print("[*] Session expired (body error) — re-logging in...")
            HEADERS = login()
            return api_get(url, retry=False)
        else:
            print("[!] Re-login failed, still getting auth error.")
            return {}

    return data


def test_splunk():
    print(f"[*] Testing Splunk HEC connectivity (index: '{SPLUNK_INDEX}')...")
    splunk_headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = json.dumps({
        "time": time.time(),
        "event": {"test": "hello from nessus script"},
        "sourcetype": "nessus:vuln",
        "index": SPLUNK_INDEX
    })
    try:
        r = SESSION.post(
            SPLUNK_HEC_URL,
            data=payload,
            headers=splunk_headers,
            timeout=10
        )
        if r.status_code == 200:
            print(f"[+] Splunk HEC reachable! Logs will go to index: '{SPLUNK_INDEX}'")
        else:
            print(f"[!] Splunk HEC returned {r.status_code}: {r.text[:500]}")
            print(f"    -> Is index '{SPLUNK_INDEX}' created in Splunk?")
    except Exception as e:
        print(f"[!] Could not reach Splunk HEC: {e}")


def get_scan_status():
    data = api_get(f"{NESSUS_URL}/scans/{SCAN_ID}")
    if not data or 'info' not in data:
        if data:
            print(f"    [!] Unexpected response: {data}")
        return "unknown"
    return data['info']['status']


def wait_for_completed():
    print("[*] Waiting for scan to reach 'completed' status...")
    while True:
        status = get_scan_status()
        print(f"    -> Status: {status}")
        if status == 'completed':
            print("[+] Scan completed!")
            return
        elif status in ['canceled', 'aborted']:
            print(f"[!] Scan ended with status: {status}")
            return
        time.sleep(30)


def wait_for_running_then_complete():
    print(f"\n[*] Monitoring scan ID {SCAN_ID}...")
    print("    ACTION REQUIRED: Please go to Nessus UI and click Launch on your scan.")
    print(f"    URL: {NESSUS_URL}")

    while True:
        status = get_scan_status()
        print(f"    -> Status: {status}")
        if status == 'running':
            print("[+] Scan is running! Waiting for completion...")
            break
        elif status == 'completed':
            print("[+] Scan already completed!")
            return
        elif status in ['canceled', 'aborted']:
            print(f"[!] Scan status: {status}. Please relaunch from Nessus UI.")
        time.sleep(20)

    while True:
        status = get_scan_status()
        print(f"    -> Status: {status}")
        if status == 'completed':
            print("[+] Scan completed!")
            return
        elif status in ['canceled', 'aborted']:
            print(f"[!] Scan ended: {status}")
            return
        time.sleep(30)


def get_vulnerabilities():
    data = api_get(f"{NESSUS_URL}/scans/{SCAN_ID}")
    vulns = []
    hosts = data.get('hosts', [])
    print(f"[*] Processing {len(hosts)} host(s)...")

    for host in hosts:
        host_id  = host['host_id']
        hostname = host['hostname']
        detail   = api_get(f"{NESSUS_URL}/scans/{SCAN_ID}/hosts/{host_id}")
        for vuln in detail.get('vulnerabilities', []):
            vuln['target_host'] = hostname
            vulns.append(vuln)

    return vulns


def send_to_splunk(vulnerabilities):
    splunk_headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json"
    }
    severity_map = ["Info", "Low", "Medium", "High", "Critical"]
    sent   = 0
    errors = 0
    total  = len(vulnerabilities)

    for batch_start in range(0, total, SPLUNK_BATCH_SIZE):
        batch         = vulnerabilities[batch_start: batch_start + SPLUNK_BATCH_SIZE]
        batch_num     = (batch_start // SPLUNK_BATCH_SIZE) + 1
        total_batches = (total + SPLUNK_BATCH_SIZE - 1) // SPLUNK_BATCH_SIZE

        payload_lines = []
        for vuln in batch:
            sev = vuln.get('severity', 0)
            if sev > 4:
                sev = 4

            event_obj = {
                "time": time.time(),
                "event": {
                    "scan_id":        SCAN_ID,
                    "host":           vuln.get('target_host'),
                    "plugin_id":      vuln.get('plugin_id'),
                    "plugin_name":    vuln.get('plugin_name'),
                    "severity":       sev,
                    "severity_label": severity_map[sev],
                    "count":          vuln.get('count'),
                    "family":         vuln.get('plugin_family')
                },
                "sourcetype": "nessus:vuln",
                "index":      SPLUNK_INDEX      # ← uses chosen index
            }
            payload_lines.append(json.dumps(event_obj))

        batch_payload = "\n".join(payload_lines)

        try:
            r = SESSION.post(
                url=SPLUNK_HEC_URL,
                data=batch_payload,
                headers=splunk_headers,
                timeout=30
            )
            if r.status_code == 200:
                sent += len(batch)
                print(f"    [+] Batch {batch_num}/{total_batches} sent ({len(batch)} events) ✓")
            else:
                print(f"    [!] Batch {batch_num}/{total_batches} failed — Splunk {r.status_code}: {r.text[:500]}")
                errors += len(batch)
        except Exception as e:
            print(f"    [!] Batch {batch_num}/{total_batches} exception: {e}")
            errors += len(batch)

        time.sleep(0.5)

    print(f"[+] Splunk: {sent}/{total} sent to index '{SPLUNK_INDEX}', {errors} errors")


def collect_and_send():
    vulns = get_vulnerabilities()
    if not vulns:
        print("[!] No vulnerabilities found — scan may have no results or hosts.")
    else:
        print(f"[+] Found {len(vulns)} vulnerabilities across all hosts")
        send_to_splunk(vulns)


def run():
    global HEADERS, SPLUNK_INDEX

    # Ask user which Splunk index to use before anything else
    SPLUNK_INDEX = choose_splunk_index()

    HEADERS = login()
    test_splunk()

    print(f"\n[+] Monitoring Scan ID : {SCAN_ID}")
    print(f"[+] Splunk Index       : {SPLUNK_INDEX}")
    print(f"[+] Batch size         : {SPLUNK_BATCH_SIZE} events per request")
    print(f"[+] Repeat interval    : {INTERVAL_MINS} minutes")

    print("\n[*] Checking scan status on startup...")
    initial_status = get_scan_status()
    print(f"[*] Startup scan status: {initial_status}")

    if initial_status == 'completed':
        print("[+] Scan already completed — sending existing results to Splunk now...")
        collect_and_send()
        print(f"\n[*] Done. Sleeping {INTERVAL_MINS} min then monitoring for next scan.")
        print(f"[*] ACTION: Launch the scan again from Nessus UI when ready.")
        time.sleep(INTERVAL_MINS * 60)

    elif initial_status == 'running':
        print("[+] Scan is currently running — waiting for it to finish...")
        wait_for_completed()
        collect_and_send()
        print(f"\n[*] Sleeping {INTERVAL_MINS} minutes before next cycle...")
        time.sleep(INTERVAL_MINS * 60)

    cycle = 1
    while True:
        print(f"\n{'='*55}")
        print(f"[*] Cycle #{cycle}")
        print(f"{'='*55}")

        status = get_scan_status()
        print(f"[*] Current scan status: {status}")

        if status == 'completed':
            print("[*] New scan results found — collecting and sending...")
            collect_and_send()
            print(f"\n[*] ACTION: Go to Nessus UI and launch scan again in ~{INTERVAL_MINS} mins")
            print(f"[*] Sleeping {INTERVAL_MINS} minutes...")
            time.sleep(INTERVAL_MINS * 60)

        elif status == 'running':
            wait_for_completed()
            collect_and_send()
            print(f"\n[*] ACTION: Go to Nessus UI and launch scan again in ~{INTERVAL_MINS} mins")
            print(f"[*] Sleeping {INTERVAL_MINS} minutes...")
            time.sleep(INTERVAL_MINS * 60)

        else:
            wait_for_running_then_complete()
            collect_and_send()
            print(f"[*] Sleeping {INTERVAL_MINS} minutes...")
            time.sleep(INTERVAL_MINS * 60)

        cycle += 1


if __name__ == "__main__":
    run()
