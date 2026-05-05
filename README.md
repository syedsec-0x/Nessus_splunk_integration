# Nessus_splunk_integration

# 🔐 Nessus → Splunk: Automated Vulnerability Scanning & Alerting

> Automated vulnerability scanning of Metasploitable 2 every 30 minutes with real-time Splunk alerting.

---

## 📌 Overview

This project integrates **Nessus Expert** with **Splunk Enterprise** to automate vulnerability scanning and security alerting. A Python script authenticates to Nessus via session token, launches scans on a schedule, fetches all vulnerability findings, and forwards them to Splunk via HTTP Event Collector (HEC) — enabling real-time dashboards and automated critical vulnerability alerts.

**Why this matters:** Manual vulnerability reviews are slow and error-prone. This pipeline ensures every scan cycle's findings are immediately visible in a SOC dashboard, with automated alerts firing the moment a Critical severity vulnerability is detected.

---

## 🏗️ Architecture

```
┌─────────────────────┐        ┌─────────────────────┐
│   Metasploitable 2  │◄──────►│   Nessus Expert     │
│   VirtualBox VM     │  Scan  │   localhost:8834    │
│   (Target Host)     │        └────────┬────────────┘
└─────────────────────┘                 │ API (Session Auth)
                                        ▼
                               ┌─────────────────────┐
                               │   Python Script     │
                               │  nessus_to_splunk   │
                               │   Every 30 mins     │
                               └────────┬────────────┘
                                        │ JSON via HEC
                                        ▼
                               ┌─────────────────────┐
                               │  Splunk Enterprise  │
                               │   localhost:8000    │
                               │  Alerts + Dashboard │
                               └─────────────────────┘
```

**Data Flow:**
1. Metasploitable 2 VM runs on VirtualBox (Bridged networking) and gets its own IP
2. Python script authenticates to Nessus using session-based login (username/password)
3. Script launches the pre-configured scan and polls every 30 seconds until `status = completed`
4. All vulnerability findings are fetched from the Nessus API
5. Each vulnerability is sent as a JSON event to Splunk HEC (port 8088)
6. Splunk indexes events, triggers alerts for Critical findings, and displays dashboards

---

## ⚙️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Vulnerability Scanner | Nessus Expert (Trial) |
| SIEM Platform | Splunk Enterprise |
| Integration Script | Python 3.x |
| Data Transport | Splunk HTTP Event Collector (HEC) |
| Scan Target | Metasploitable 2 (VirtualBox VM) |
| Python Libraries | `requests`, `urllib3` |
| Auth Method | Nessus session token (username/password) |

---

## 📋 Prerequisites

- **VirtualBox** — to run the Metasploitable 2 target VM
- **Metasploitable 2** — intentionally vulnerable Linux VM (scan target)
- **Nessus Expert** (Trial) — [download from tenable.com](https://www.tenable.com/products/nessus)
- **Splunk Enterprise** (Free trial) — [download from splunk.com](https://www.splunk.com)
- **Python 3.x** with pip

Install Python dependencies:
```bash
pip install requests urllib3
```

---

## 🚀 Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/nessus-splunk-integration.git
cd nessus-splunk-integration
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Network Setup
Set the VirtualBox network adapter to **Bridged Adapter**, boot Metasploitable 2, then verify connectivity:
```bash
# On Metasploitable 2 VM
ifconfig eth0

# From Windows host
ping 192.168.1.106   # replace with your VM's IP
```

> **Tip:** If Metasploitable 2 doesn't get an IP automatically, run `sudo dhclient eth0` on the VM.

---

## 🔧 Configuration

Open `nessus_to_splunk_final.py` and update the CONFIG section:

```python
NESSUS_URL       = "https://localhost:8834"
NESSUS_USER      = "admin"                   # your Nessus username
NESSUS_PASS      = "YourPassword"            # your Nessus password
SCAN_ID          = 8                         # get this from list_scans.py
SPLUNK_HEC_URL   = "https://localhost:8088/services/collector/event"
SPLUNK_HEC_TOKEN = "your-hec-token"          # from Splunk HEC setup
INTERVAL_MINS    = 30                        # scan interval
```

### Get Your Scan ID
```bash
python list_scans.py
# Output: ID: 8  |  Name: meta1  |  Status: completed
```

### Splunk HEC Setup
1. Go to **Settings → Data Inputs → HTTP Event Collector → New Token**
2. Name: `nessus_hec` | Source type: `nessus:vuln` | Index: `main`
3. Copy the generated token into your config

> **Note:** Nessus Expert trial blocks scan creation via API keys (returns 412). This script uses session-based login instead — which works fully.

---

## ▶️ Usage

```bash
python nessus_to_splunk_final.py
```

**Expected output:**
```
[*] Logging into Nessus...
[+] Login successful!
[+] Using existing Scan ID: 8
[*] Cycle #1 starting...
[+] Scan 8 launched successfully!
[*] Waiting for scan to complete...
    -> Status: running
    -> Status: completed
[+] Scan completed!
[*] Processing 1 host(s)...
[+] Found 143 vulnerabilities
[+] Splunk: 143 sent, 0 errors
[*] Cycle #1 done. Sleeping 30 mins...
```

### Run as a Background Service (Windows)
Using [NSSM](https://nssm.cc/):
```bash
nssm install NessusSplunkBridge
# Path: C:\Python311\python.exe
# Arguments: C:\path\to\nessus_to_splunk_final.py
nssm start NessusSplunkBridge
```

---

## 📊 Results & Splunk Queries

### Verify Data in Splunk
```
index=main sourcetype="nessus:vuln"
```

### Useful SPL Queries

```spl
# All vulnerabilities by severity
index=main sourcetype="nessus:vuln"
| stats count by severity_label
| sort severity

# Top 10 most common vulnerabilities
index=main sourcetype="nessus:vuln"
| top limit=10 plugin_name

# Critical and High findings only
index=main sourcetype="nessus:vuln" severity>=3
| table host plugin_name severity_label family

# Vulnerability trend over time
index=main sourcetype="nessus:vuln"
| timechart count by severity_label
```

### Splunk Dashboard Panels
| Panel | Chart Type | Query |
|-------|-----------|-------|
| Severity Breakdown | Pie Chart | `stats count by severity_label` |
| Top Vulnerabilities | Bar Chart | `top limit=10 plugin_name` |
| Vulnerability Trend | Line Chart | `timechart count by severity_label` |
| Critical Findings | Table | `severity=4 \| table host plugin_name family` |

---

## 🎯 Key Findings on Metasploitable 2

| Severity | Score | Examples Found |
|----------|-------|----------------|
| Critical | 4 | VSFTPd 2.3.4 Backdoor, UnrealIRCd Backdoor |
| High | 3 | Apache Tomcat Default Creds, Outdated Apache |
| Medium | 2 | SSL issues, Weak ciphers |
| Low/Info | 0–1 | Open ports, Service banners |

**Notable Critical CVEs detected:**
- `VSFTPd 2.3.4 Backdoor` (Port 21) — Remote code execution
- `UnrealIRCd Backdoor` (Port 6667) — Arbitrary command execution
- `Samba "username map script"` (Port 445) — Unauthenticated RCE
- `Distcc Daemon RCE` (Port 3632) — Command injection
- `Apache Tomcat Default Credentials` (Port 8180)
- `MySQL No Root Password` (Port 3306)

---

## ⚠️ Errors Encountered & Fixes

Real errors faced during implementation and how they were resolved.

---

### ❌ Error 1 — `pip` Not Recognized

**Error:**
```
'pip' is not recognized as an internal or external command,
operable program or batch file.
```

**Cause:** Python was installed but not added to the Windows system PATH, so CMD could not find the `pip` command.

**Fix:**
1. Search for **Environment Variables** in Windows Start Menu
2. Click **Edit the system environment variables → Environment Variables**
3. Under **System Variables**, find and select **Path → Edit**
4. Click **New** and add:
   ```
   C:\Python3x\
   C:\Python3x\Scripts\
   ```
   *(replace `3x` with your actual Python version e.g. `311` for Python 3.11)*
5. Click OK, close CMD, reopen and run again:
   ```bash
   pip install requests urllib3
   ```

---

### ❌ Error 2 — Splunk Not Receiving Events (HEC Misconfiguration)

**Error:** Script ran successfully but no events appeared in Splunk search. `0 sent` or connection refused on port 8088.

**Cause:** Splunk HEC was either not enabled, SSL was on (causing HTTP requests to fail), wrong port, or index mismatch between script and HEC token.

**Fix:**
1. Go to **Splunk → Settings → Data Inputs → HTTP Event Collector → Global Settings**
2. Set **Enable SSL → OFF**
3. Confirm port is **8088**
4. When creating the HEC token, set **Index → main** (must match `index=main` in the script)
5. Update script config:
   ```python
   SPLUNK_HEC_URL   = "http://localhost:8088/services/collector/event"  # http not https
   SPLUNK_HEC_TOKEN = "your-correct-token"
   ```
> **Note:** If you want alerts going to a different index, create a new index in Splunk and update both the HEC token and the script config to match.

---

### ❌ Error 3 — Metasploitable 2 Not Reachable / No IP Assigned

**Error:** Nessus scan completes but finds 0 hosts, or script cannot reach target. `ping` from Windows host fails.

**Cause:** VirtualBox network adapter was set to **Bridged Adapter** instead of **Host-Only Adapter**, causing the VM to not get a proper IP reachable from the host.

**Fix:**
1. Shut down Metasploitable 2 VM
2. In VirtualBox → Select VM → **Settings → Network**
3. Change **Attached to: Host-Only Adapter**
4. Start the VM and run:
   ```bash
   ifconfig eth0
   ```
5. Note the IP (e.g., `192.168.56.101`)
6. From Windows CMD, verify:
   ```bash
   ping 192.168.56.101
   ```
7. Update Nessus scan target to this new IP

---

### ❌ Error 4 — 412 Error When Creating Scan via API Keys

**Error:**
```
412 Client Error: Precondition Failed
API is not available with this license
```

**Cause:** Nessus Expert trial license restricts scan creation via API keys. Attempting to create scans programmatically using Access Key + Secret Key returns a 412 error.

**Fix:** Use **session-based authentication** (username + password) instead of API keys. The script handles this automatically:
```python
# Script logs in with username/password to get a session token
NESSUS_USER = "admin"
NESSUS_PASS = "yourpassword"
# Do NOT use API keys for scan creation on trial license
```
Also, **create the scan manually** in the Nessus UI first, then let the script launch it by Scan ID.

---

### ❌ Error 5 — Script Authentication Failing

**Error:**
```
[!] Login failed!
401 Unauthorized
```

**Cause:** Wrong username or password entered in the script config, or Nessus session had expired.

**Fix:**
1. Double-check credentials in the script CONFIG section:
   ```python
   NESSUS_USER = "admin"       # exact username used during Nessus setup
   NESSUS_PASS = "yourpassword"  # case-sensitive
   ```
2. Verify you can log in manually at `https://localhost:8834`
3. If Nessus was restarted, the session token resets — just re-run the script to get a fresh token
4. Make sure Nessus service is running (check `https://localhost:8834` in browser)

---

### ❌ Error 6 — Scan Not Starting Automatically

**Error:** Script launches but scan stays in `pending` or doesn't trigger at all.

**Cause:** Nessus trial sometimes does not auto-trigger scans via API on the first call, or a previous scan was still running.

**Fix:**
1. Go to **Nessus UI → My Scans**
2. Manually click **Launch** on your scan
3. Wait for it to complete once manually
4. After that, the script can take over for subsequent automated cycles
5. Also ensure no other scan is already running — Nessus trial allows only one scan at a time

---

## 🔐 Security Notes

- ⚠️ Metasploitable 2 is **intentionally vulnerable** — never expose it to the internet
- Store credentials as **environment variables**, not hardcoded in scripts (for production)
- Rotate HEC tokens regularly
- Restrict Splunk dashboard access to authorized personnel only

> This project is designed for **lab and educational purposes**. For production SOC environments, consider the official [Tenable App for Splunk](https://splunkbase.splunk.com/app/4061/) on Splunkbase.

---

## 🛣️ Future Improvements

- [ ] Schedule scans using Windows Task Scheduler or cron
- [ ] Add Slack/email alerting on new Critical findings
- [ ] Enrich events with CVE data from NVD API
- [ ] Containerize the script with Docker
- [ ] Expand targets beyond a single Metasploitable VM
- [ ] Build Splunk correlation rules for chained attack patterns


## 👤 Author

**Your Name**
- LinkedIn: [linkedin.com/in/yourprofile]([https://linkedin.com/in/yourprofile](https://www.linkedin.com/in/syed-ahmed-914b692ab/))

---

*Version 1.0 | 2026*
