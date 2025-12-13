#cloud_mobile.py
#Date-13/12/2025
#Author- Lokesh Kumar
#github - @trmxvibs
#Madeinindia

import requests
import json
from urllib.parse import urljoin # Safer for joining URLs
from modules.config import get_bypass_headers

def check_firebase(domain):
    report = ["\n[*] FIREBASE DATABASE HUNTER:"]
    base = domain.split('.')[0]
    permutations = [base, f"{base}-app", f"{base}-default-rtdb", f"{base}-prod", domain.replace('.', '')]
    
    vuln_found = False
    for project in permutations:
        url = f"https://{project}.firebaseio.com/.json"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                try:
                    data = r.json()
                    # Null response means empty but open, still a risk but strictly not a leak
                    if data and "error" not in str(data).lower():
                        report.append(f"   [☠️] CRITICAL: FIREBASE DATABASE LEAK!")
                        report.append(f"       > Target: {url}")
                        vuln_found = True
                        break
                except ValueError: pass # Not a JSON response
        except: pass
        
    if not vuln_found:
        report.append("   [✓] No open Firebase databases found.")
    return "\n".join(report)

def check_mobile_configs(domain):
    report = ["\n[*] MOBILE APP ASSET SCANNER:"]
    # Ensure protocol is present
    if not domain.startswith("http"):
        base_url = f"http://{domain}"
    else:
        base_url = domain
        
    files = [
        "/.well-known/apple-app-site-association",
        "/.well-known/assetlinks.json",
        "/apple-app-site-association",
        "/mobile-config.json"
    ]
    
    found = False
    for f in files:
        try:
            # urljoin handles slashes automatically
            target_url = urljoin(base_url, f)
            r = requests.get(target_url, headers=get_bypass_headers(), timeout=3)
            if r.status_code == 200 and ("appID" in r.text or "package_name" in r.text):
                report.append(f"   [+] Found Mobile Config: {f}")
                found = True
                if "staging" in r.text or "dev" in r.text:
                    report.append(f"       [⚠️] LEAK: Internal domains found in {f}")
        except: pass
        
    if not found: report.append("   [-] No mobile configuration files found.")

    return "\n".join(report)
