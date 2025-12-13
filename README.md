# 🛡️ NET-SENTRY Framework
> **The Ultimate Automated Red Teaming & Vulnerability Assessment System**

![Version](https://img.shields.io/badge/God_Mode-FF0055?style=for-the-badge&logo=hackthebox&logoColor=white)
![Security](https://img.shields.io/badge/Security-Offensive-red?style=for-the-badge&logo=security)
![Status](https://img.shields.io/badge/Status-OPERATIONAL-success?style=for-the-badge&logo=activity)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Offensive-red?style=for-the-badge&logo=kali-linux&logoColor=white)
![Maintenance](https://img.shields.io/badge/Maintenance-Active-chartreuse?style=for-the-badge&logo=github)
![MadeIn](https://img.shields.io/badge/MADE%20IN-INDIA-orange?style=for-the-badge&logo=india&logoColor=white)

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Backend-000000?style=for-the-badge&logo=flask&logoColor=white)
![Nmap](https://img.shields.io/badge/Nmap-Engine-blue?style=for-the-badge&logo=nmap&logoColor=white)
![Database](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white)

![Code Size](https://img.shields.io/github/languages/code-size/trmxvibs/NetSentry-Framework?style=for-the-badge&color=blueviolet)
![Issues](https://img.shields.io/github/issues/trmxvibs/NetSentry-Framework?style=for-the-badge&color=yellow)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=open-source-initiative&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=for-the-badge&logo=linux)

![Stars](https://img.shields.io/github/stars/trmxvibs/NetSentry-Framework?style=for-the-badge&logo=github&color=gold)
![Forks](https://img.shields.io/github/forks/trmxvibs/NetSentry-Framework?style=for-the-badge&logo=github&color=silver)
![Follow](https://img.shields.io/github/followers/trmxvibs?style=for-the-badge&logo=github&label=Follow&color=181717)

**Net-Sentry** is a military-grade offensive security framework designed to automate the reconnaissance and vulnerability assessment phase. It replaces manual grunt work with a **Unified Command Console**, allowing security researchers to focus on strategy while the AI handles the execution.

Now powered by a **Concurrent Scanning Engine**, Net-Sentry delivers deep intelligence, cloud analysis, and actionable reports at 15x speed.

---



##  Key Features 

Net-Sentry operates on a modular architecture, deploying specialized engines for every stage of the kill chain.

###  1. Active Intelligence & AI
* **The Oracle:** Queries **Shodan/InternetDB** for cached open ports and CVEs without sending active packets to the target.
* **Tech Stack Detective:** Identifies server technologies (CMS, Frameworks, WAFs) to tailor attacks.

###  2. Deep Reconnaissance
* **Multi-Threaded Scanning:** Runs Nmap, SSL, and Spider modules simultaneously for hyper-speed results.
* **Geo-Tactical Tracking:** Live **Satellite Geolocation** of the target server visualized on a world map.
* **Topology Mapper:** Visualizes network nodes, ports, and attack vectors in an interactive graph.
* **Subdomain Spy:** Passive subdomain enumeration via Certificate Transparency logs.

###  3. Offensive Capabilities
* **The Key Reaper:** Scrapes HTML & JavaScript files to harvest leaked **API Keys** (Google, AWS, Stripe) and hidden endpoints.
* **WAF Detector & Bypass:** Identifies Firewalls (Cloudflare/AWS) and attempts 403 bypass using header poisoning techniques.
* **Directory Buster:** Brute-forces hidden paths (`/admin`, `/.env`, `/backup`) to find exposed panels.

###  4. Analysis & Interface
* **Live Terminal:** A fully functional command-line interface within the browser.
* **Executive Reporting:** Generates professional PDF reports separated by modules for client delivery.
* **System Bridge:** Execute host OS commands directly from the dashboard.

---
##  Visual Gallery
[![Daily Auto-Update](https://github.com/trmxvibs/Net-Sentry/actions/workflows/daily_update.yml/badge.svg)](https://github.com/trmxvibs/Net-Sentry/actions/workflows/daily_update.yml)

<img width="1911" height="930" alt="image" src="https://github.com/user-attachments/assets/14deb141-ed8a-496c-8cf4-19dc90df9532" />

---
##  Prerequisites

Before deploying Net-Sentry, ensure your system meets the following requirements.

### 1. Core Engine
* **Python 3.8+**: The backbone of the framework.
* **Nmap**: Essential for port scanning and service detection.
    * *Windows:* [Download Installer](https://nmap.org/download.html)
    * *Linux:* `sudo apt install nmap`
    * *MacOS:* `brew install nmap`

### 2. Offensive Tools (Optional but Recommended)
* **Metasploit Framework**: Required to execute the auto-generated `.rc` attack scripts.
    * *Kali Linux:* Pre-installed.
    * *Windows:* [Download Metasploit](https://windows.metasploit.com/)

### 3. Browser Support
* **Modern Web Browser**: Chrome, Firefox, or Edge (Required for the visual topology map and live terminal).

> **Note:** For the best experience, running Net-Sentry on **Kali Linux** or a specialized pentesting distro is recommended.

---

##  Installation
###  Built With
![Flask](https://img.shields.io/badge/Flask-000000?style=flat&logo=flask&logoColor=white)
![Nmap](https://img.shields.io/badge/Nmap-Engine-blue?style=flat&logo=nmap&logoColor=white)
![Leaflet](https://img.shields.io/badge/Leaflet-Maps-199900?style=flat&logo=leaflet&logoColor=white)
![Vis.js](https://img.shields.io/badge/Vis.js-Topology-orange?style=flat)
![Metasploit](https://img.shields.io/badge/Metasploit-Ready-black?style=flat&logo=metasploit&logoColor=white)
<div align="center">
  
  <br>
  <a href="https://git.io/typing-svg">
    <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&weight=600&size=25&pause=1000&color=00FF00&center=true&vCenter=true&width=600&lines=System+Initializing...;Target+Locked+%3A+Scanning+Ports...;Brute-Forcing+Directories...;Bypassing+WAF+Firewall...;NET-SENTRY+OPERATIONAL" alt="Typing SVG" />
  </a>
  <br>

  ![Modules](https://img.shields.io/badge/Modules-15%2B_Loaded-purple?style=flat-square&logo=component)
  ![Speed](https://img.shields.io/badge/Speed-Hyper_Threaded-orange?style=flat-square&logo=speedtest)
  ![AI](https://img.shields.io/badge/AI-Neural_Network-blue?style=flat-square&logo=openai)
  ![Database](https://img.shields.io/badge/Logs-Encrypted-critical?style=flat-square&logo=sqlite)

</div>
Follow these steps to deploy the framework on your local machine or VPS.

### 1. Clone the Repository
Get the latest source code from GitHub.
```bash
git clone https://github.com/trmxvibs/NetSentry-Framework
cd NetSentry-Framework
```
### 2. Install Dependencies
Install the required Python libraries (Flask, Requests, Vis.js support, etc.).
```
pip install -r requirements.txt
```
### 3. Initialize the Neural Core (Database)
Run the setup script to create the SQLite database and the default admin user.
```
python database_setup.py
```

### **Success Check:** You should see the message: 
[+] Default User Created: lokesh/lokesh
- Default user/pass ==> lokesh/lokesh
## Change your login data 
```
python cli_tool.py --config
```
<img width="738" height="281" alt="image" src="https://github.com/user-attachments/assets/de773bb9-dd9d-4854-a608-062101889c08" />

## Show HelpMenu
```
python cli_tool.py -h
```
```html
usage: cli_tool.py [-h] [-t TARGET] [-m {basic,medium,advance,custom}] [--flags FLAGS] [-o] [--config]

Net-Sentry Professional CLI

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Target IP or Domain
  -m, --mode {basic,medium,advance,custom}
                        Scan Profile
  --flags FLAGS         Custom Nmap Flags
  -o, --output          Save report to file
  --config              Reset Admin Username/Password
```

---

##  Usage: Web Command Console (GUI)


### 1. Launch the System
Start the web server:
```bash
python app.py
```
### Console Output: [+] Net-Sentry Online. Access: http://127.0.0.1:(port)

### 2. Access & Login
Open your browser and navigate to http://127.0.0.1:(port)

Default Username: `lokesh`

Default Password: `lokesh`

**Security Note: Change your password immediately using the ⚙️ SETTINGS button in the dashboard header.**

### 3. Dashboard Operations
Live Terminal: Type commands directly into the browser console.

scan google.com advance (Initiates full spectrum scan)

man nmap (View cheat sheets)

ping 8.8.8.8 (Execute system commands)

`Tactical Maps: Toggle between [TOPO] (Network Graph) and [WORLD] (Geo-Map) using the buttons in the top-right panel.`

Intelligence: View real-time WAF status, CVE alerts, and harvested keys in the "Active Intel" box.

`Reports: Click the PDF button in the Mission Logs table to download a professional client report.`

---
##  Usage: CLI Tool (Terminal)

For security researchers who prefer a headless environment or need to integrate Net-Sentry into automated pipelines, the CLI tool offers full capabilities.

### 1. Basic Scan (Fast)
Performs a quick port scan and basic intel gathering.
```bash
python cli_tool.py -t example.com
```
### 2. Advance Mode (Full Power)
Activates all engines including Fuzzing, Spidering, Zone Transfer, and Vulnerability Checks.
```
python cli_tool.py -t example.com -m advance
```
### 3. Custom Operations
Define your own Nmap flags for specific targeting.
```
python cli_tool.py -t example.com -m custom --flags "-p 80,443,8080 -sV --script=vuln"
```
### 4. Save Output
Save the scan results to a text file for documentation.
```
python cli_tool.py -t example.com -m medium -o
```
<img width="1255" height="658" alt="image" src="https://github.com/user-attachments/assets/21ffcd5d-7f48-4784-8087-b37fa6cae323" />

**Tip: The CLI tool uses the exact same engine as the web dashboard, ensuring consistent results across interfaces.**

# Results
```python

 [★] RISK SCORE: 100/100 (CRITICAL)

----------------------------------------

 [*] TARGET: google.com

 [*] MODE: ADVANCE

--- GEO-INTEL REPORT ---
[+] Org: Google LLC
[+] Country: India (IN)
[+] ISP: Google LLC
[COORDS] 28.6139,77.2088
------------------------



 [*] THE ORACLE (SHODAN DB):
   [+] Ports: [80, 443]
   [✓] Clean record.
[✓] NO WAF DETECTED.


 [*] SSL ILLUMINATOR:
   [+] Issued: WR2
   [SCOPE] Found 137 hidden domains:
       > *.google.com
       > *.appengine.google.com
       > *.bdn.dev
       > *.origin-test.bdn.dev
       > *.cloud.google.com
       > *.crowdsource.google.com
       > *.datacompute.google.com
       > *.google.ca
       > *.google.cl
       > *.google.co.in
       ...and 127 more.


 [*] PASSIVE SUBDOMAINS:
   [+] Found 189 subdomains:
       > aarjav-b480g7k2ab9@checkout.google.com
       > accounts.flexpack.google.com
       > accounts.freezone.google.com
       > accounts.google.com
       > admin@google.com
       > ads-compare.eem.corp.google.com
       > adwords.google.com
       > adwords.google.com.ar
       > adwords.google.com.au
       > adwords.google.com.br
       > adwords.google.com.cn
       > adwords.google.com.gr
       > adwords.google.com.hk
       > adwords.google.com.ly
       > adwords.google.com.mx
       > adwords.google.com.my
       > adwords.google.com.pe
       > adwords.google.com.ph
       > adwords.google.com.pk
       > adwords.google.com.ru
       ...and 169 more.


 [*] ACTIVE SUBDOMAIN DISCOVERY:
   [⚡] Discovered 11 HIDDEN active subdomains:
       > www.google.com
       > mail.google.com
       > blog.google.com
       > ns1.google.com
       > ns2.google.com
       > smtp.google.com
       > vpn.google.com
       > m.google.com
       > shop.google.com
       > admin.google.com
       > api.google.com


 [*] MASS TAKEOVER SCANNER:
   [✓] No dangling subdomains found.


 [*] DNS ZONE TRANSFER:
   [✓] DNS Secure.

 [*] DEEP VULNERABILITY SCAN (LFI/CONFIG):
   [✓] No config backups exposed.
   [✓] LFI check passed.


 [*] DIRECTORY BUSTER:
   [200] FOUND: /robots.txt
   [200] FOUND: /dashboard


 [*] CMS HUNTER (WORDPRESS):
   [✓] WP API secure or not WordPress.


 [*] GIT SOURCE HUNTER:
   [✓] .git is secure.


 [*] SPRING BOOT ACTUATOR SCAN:
   [✓] Spring Boot Actuators secured.


 [*] BROKEN LINK HIJACKING:
   [✓] External links resolve correctly.


 [*] FIREBASE DATABASE HUNTER:
   [✓] No open Firebase databases found.


 [*] MOBILE APP ASSET SCANNER:
   [+] Found Mobile Config: /apple-app-site-association
       [⚠️] LEAK: Internal domains found in /apple-app-site-association


 [*] HOST HEADER INJECTION:
   [✓] Server ignores spoofed Host headers.


 [*] CRLF INJECTION (HEADER SPLITTING):
   [✓] Header Splitting protected.


 [*] CORS CONFIG CHECK:
   [✓] CORS policy secure.


 [*] CLICKJACKING CHECK:
   [✓] Protected against Clickjacking.


 [*] PROTOTYPE POLLUTION FUZZER:
   [✓] Server appears resilient.


 [*] DESERIALIZATION SCAN:
   [✓] No serialized objects found in cookies.


 [*] VERB TAMPERING:
   [✓] Verbs restricted.


 [*] HTTP REQUEST SMUGGLING (CL.TE/TE.CL):
   [✓] No smuggling anomalies detected.


 [*] WEBSOCKET SECURITY (CSWSH):
   [✓] No open WebSocket found.


 [*] API RATE LIMIT BYPASS:
   [✓] Rate limiting appears robust (or not triggered).


 [*] GRAPHQL INSPECTOR:


 [*] WEB CACHE POISONING DETECTOR:
   [✓] Cache headers appear secure.


 [*] JS MINER & DOM HUNTER:
   [i] Analyzing 2 JavaScript files...
   [⚠️] DOM RISK: Found 'innerHTML' in m=cdos,cr,hsm,jsa,mb4ZUb,cEt90b,SNUn3,qddgKe,sTsDMc,dtl0hd,eHDfl,YV5bee,d,csi
   [⚠️] DOM RISK: Found 'eval(' in m=cdos,cr,hsm,jsa,mb4ZUb,cEt90b,SNUn3,qddgKe,sTsDMc,dtl0hd,eHDfl,YV5bee,d,csi
   [⚠️] DOM RISK: Found 'location.search' in m=cdos,cr,hsm,jsa,mb4ZUb,cEt90b,SNUn3,qddgKe,sTsDMc,dtl0hd,eHDfl,YV5bee,d,csi
   [⚠️] DOM RISK: Found 'location.hash' in m=cdos,cr,hsm,jsa,mb4ZUb,cEt90b,SNUn3,qddgKe,sTsDMc,dtl0hd,eHDfl,YV5bee,d,csi
   [⚠️] DOM RISK: Found 'innerHTML' in rs=AA2YrTtMySWmY-EDOJELbz3_ueBB7lVOZQ
   [+] Found 36 crawlable endpoints:
       > /IN?utm_source=hp_header&utm_medium=google_ooo&utm_campaign=GS100042&hl=en-IN
       > /ServiceLogin?hl=en&passive=true&continue=https://www.google.com/%3Fgws_rd%3Dssl&ec=futura_exp_og_so_72776762_e
       > /_/chrome/newtab
       > /aclk
       > /advanced_search?hl=en-IN&fg=1
       > /client_streamz/lens_search/lens_tool_missing_client_adapter_controller
       > /client_streamz/lens_search/lens_tool_missing_dependencies
       > /client_streamz/lens_search/lens_tool_missing_insertion_point
       > /complete/s
       > /complete/search
       ...and 26 more.



 [*] API ZOMBIE (FUZZING):
   [✓] APIs seem resilient.


 [*] DOM EXPLOIT SUGGESTIONS for innerHTML:
   [i] Manual Verification Required. Try these in Browser:
       > http://google.com#<img src=x onerror=alert(1)>
       > http://google.com?q=<svg/onload=alert(1)>
       > http://google.com?q=<iframe src=javascript:alert(1)>


 [*] CLOUD PIERCER (SSRF SCANNER):
   [✓] No SSRF vectors.


 [*] BLIND SQL INJECTION (TIME-BASED):
   [✓] No time delays detected.


 [*] XSS SNIPER (REFLECTED):
   [✓] No Reflected XSS found.


 [*] OS COMMAND INJECTION:
   [✓] No OS injection.


 [*] BACKUP FILE MINER:
   [✓] No backup files exposed.


 [*] XXE INJECTION SCANNER:
   [✓] No XXE found.


 [*] IDOR PATTERN HUNTER:
   [⚠️] POTENTIAL IDOR ENDPOINTS FOUND (10):
       1. /services/?subid=ww-ww-et-g-awa-a-g_hpbfoot1_1!o2&utm_source=google.com&utm_medium=referral&utm_campaign=google_hpbfooter&fg=1
       2. /history/privacyadvisor/search/unauth?utm_source=googlemenu&fg=1&cctld=com
       3. /intl/en_in/ads/?subid=ww-ww-et-g-awa-a-g_hpafoot1_1!o2&utm_source=google.com&utm_medium=referral&utm_campaign=google_hpafooter&fg=1
       4. /history/optout?hl=en-IN&fg=1
       5. /websearch/?p=ws_results_help&hl=en-IN&fg=1
       > Tip: Try changing the ID to access other users' data.


 [*] NOSQL INJECTION SCANNER:
   [✓] No NoSQL vectors.


 [*] LDAP INJECTION SCANNER:
   [✓] No LDAP errors.


 [*] RACE CONDITION HEURISTICS:
   [✓] No race anomalies.


 [*] MASS ASSIGNMENT:
   [✓] No Mass Assignment found.


 [*] PARAMETER TAMPERING (LOGIC):
   [✓] No tampering vectors.


 [*] HTTP PARAMETER POLLUTION (HPP):
   [✓] No obvious HPP vectors.


 [*] SSI INJECTION SCANNER:
   [☠️] CRITICAL: SSI INJECTION FOUND!
       > Target: http://google.com/setprefs?sig=


 [*] XPATH INJECTION SCANNER:
   [✓] No XPath injection errors detected.


 [*] CVE CHECK:
   [✓] No basic signature match.


 [*] KUBERNETES & CLOUD HUNTER:
   [✓] Kubernetes & Cloud endpoints appear secured.


 [*] DARK INTEL (OSINT & LEAKS):
   [i] Generated Intelligence Dorks (Manual Check Recommended):
       > Google Query: site:pastebin.com google.com password
       > Google Query: site:github.com google.com API_KEY
       > Google Query: site:trello.com google.com
       > Google Query: site:s3.amazonaws.com google.com config
   [i] Breach Database Check:
       > Monitoring 3 high-value accounts.
       > Status: [INFO] Use 'H8mail' tool for deep password dumping.


 [*] JWT TOKEN INSPECTOR:
   [-] No JWT tokens found in scan data.


 [*] JWT SECRET CRACKER (HS256):
   [-] No tokens found.


 [*] TECH STACK:


 [*] WEAPONIZER:
   [WEB] nikto -h google.com


 [*] METASPLOIT SCRIPT (RCE):
workspace -a google.com
db_nmap -sV google.com
use auxiliary/scanner/http/dir_scanner
set RHOSTS google.com
run
[i] Save as 'attack.rc' and run: msfconsole -r attack.rc


 [*] CORTEX AI STRATEGY (BLUEPRINT):
   [i] Target is hardened. Recommended: Social Engineering or Phishing.

╔══════════════════════════════════════════════════════╗
║               MISSION DEBRIEF / SUMMARY              ║
╠═════════════════════════════╦════════════════════════╣
║ Target                      ║ google.com             ║
║ Duration                    ║ 245.13s                ║
║ Risk Score                  ║ 100/100                ║
╚═════════════════════════════╩════════════════════════╝
```

---

---
<div align="center">

### Connect with Me

<a href="https://github.com/trmxvibs">
  <img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" />
</a>
<a href="https://www.instagram.com/termuxvibes/">
  <img src="https://img.shields.io/badge/Instagram-E4405F?style=for-the-badge&logo=instagram&logoColor=white" />
</a>


<br><br>

![Visitors](https://visit-count.netlify.app/visits.svg)
![Repo Size](https://img.shields.io/github/repo-size/trmxvibs/NetSentry-Framework?style=flat&color=green)
![Last Commit](https://img.shields.io/github/last-commit/trmxvibs/NetSentry-Framework?style=flat&color=blue)

<br>

![Built With](https://img.shields.io/badge/Built%20With-Caffeine%20%26%20Code-black?style=plastic)

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=00FF00&height=100&section=footer&text=SYSTEM%20OFFLINE&fontSize=20&fontAlign=50&fontColor=000000" width="100%">
</p>

</div>





















