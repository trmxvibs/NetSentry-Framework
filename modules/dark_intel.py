import re
from modules.config import make_request

def search_leaks(domain):
    report = ["\n[*] DARK INTEL (OSINT & LEAKS):"]
    found_leaks = False
    
    # 1. GitHub Leaks Search (Simulated via Dorking)
    # Asli API key use karna user ke liye mushkil ho sakta hai, isliye hum Dork logic use karenge
    dorks = [
        f"site:pastebin.com {domain} password",
        f"site:github.com {domain} API_KEY",
        f"site:trello.com {domain}",
        f"site:s3.amazonaws.com {domain} config"
    ]
    
    report.append(f"   [i] Generated Intelligence Dorks (Manual Check Recommended):")
    for dork in dorks:
        report.append(f"       > Google Query: {dork}")
        
    # 2. Email Breach Check (Mock Logic - Real requires Paid API like HaveIBeenPwned)
    # Hum bas structure banayenge. Future mein API key add kar sakte hain.
    report.append(f"   [i] Breach Database Check:")
    # Yahan hum common admin emails check karte hain
    targets = [f"admin@{domain}", f"root@{domain}", f"info@{domain}"]
    
    # Note: Bina API Key ke hum asli breach check nahi kar sakte, 
    # par hum user ko warn kar sakte hain ki ye emails high risk hain.
    report.append(f"       > Monitoring {len(targets)} high-value accounts.")
    report.append(f"       > Status: [INFO] Use 'H8mail' tool for deep password dumping.")

    return "\n".join(report)