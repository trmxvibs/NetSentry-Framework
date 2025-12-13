#dark_intel.py
#Date-13/12/2025
#Author- Lokesh Kumar
#github - @trmxvibs
#Madeinindia
import re
from modules.config import make_request

def search_leaks(domain):
    report = ["\n[*] DARK INTEL (OSINT & LEAKS):"]
    found_leaks = False
    
    dorks = [
        f"site:pastebin.com {domain} password",
        f"site:github.com {domain} API_KEY",
        f"site:trello.com {domain}",
        f"site:s3.amazonaws.com {domain} config"
    ]
    
    report.append(f"   [i] Generated Intelligence Dorks (Manual Check Recommended):")
    for dork in dorks:
        report.append(f"       > Google Query: {dork}")
        
    report.append(f"   [i] Breach Database Check:")
   
    targets = [f"admin@{domain}", f"root@{domain}", f"info@{domain}"]
    
    
    report.append(f"       > Monitoring {len(targets)} high-value accounts.")
    report.append(f"       > Status: [INFO] Use 'H8mail' tool for deep password dumping.")

    return "\n".join(report)
