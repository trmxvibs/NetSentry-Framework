#  NET-SENTRY
> **The Ultimate Automated Reconnaissance & Vulnerability Assessment System**


![Version](https://img.shields.io/badge/Version-v29.0_God_Mode-FF0055?style=for-the-badge&logo=hackthebox&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/Status-OPERATIONAL-success?style=for-the-badge&logo=activity)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Maintenance](https://img.shields.io/badge/Maintenance-Active-chartreuse?style=for-the-badge)

**Net-Sentry** is a military-grade offensive security framework designed to automate the reconnaissance and vulnerability assessment phase. It combines the power of multiple scanning engines into a single **Unified Command Console**.

It replaces manual grunt work with automation, allowing security researchers to focus on strategy. Net-Sentry delivers deep intelligence, vulnerability analysis, and actionable reports.

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

Follow these steps to deploy the framework on your local machine or VPS.

### 1. Clone the Repository
Get the latest source code from GitHub.
```bash
git clone https://github.com/trmxvibs/NetSentry-Framework
cd Net-Sentry
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

### **Success Check:** You should see the message: [+] Default User Created: admin / password

---

##  Usage: Web Command Console (GUI)


### 1. Launch the System
Start the web server:
```bash
python app.py
```
### Console Output: [+] Net-Sentry v29.0 Online. Access: http://127.0.0.1:5000

### 2. Access & Login
Open your browser and navigate to http://127.0.0.1:5000.

Default Username: `admin`

Default Password: `password`

**Security Note: Change your password immediately using the ⚙️ SETTINGS button in the dashboard header.**
---
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
##**Tip: The CLI tool uses the exact same engine as the web dashboard, ensuring consistent results across interfaces.**
---


## ⚠️ Legal Disclaimer

> **FOR EDUCATIONAL & AUTHORIZED USE ONLY.**
>
> Net-Sentry is a powerful security research tool. Scanning targets without prior mutual consent is illegal and punishable by law. The developers assume **no liability** and are not responsible for any misuse or damage caused by this program.
>
> * **Do not scan** government, military, or unauthorized corporate networks.
> * **Do not use** for malicious purposes or black-hat hacking.
> * **Always verify** findings manually before reporting to bug bounty programs.

---

## 👨‍💻 Credits
![Stars](https://img.shields.io/github/stars/trmxvibs/Net-Sentry?style=social)
![Forks](https://img.shields.io/github/forks/trmxvibs/Net-Sentry?style=social)
![Issues](https://img.shields.io/github/issues/trmxvibs/Net-Sentry)
![Repo Size](https://img.shields.io/github/repo-size/trmxvibs/Net-Sentry)
**Developed by:** Lokesh kumar
**Version:** 29.0 
**License:** MIT License

---





















