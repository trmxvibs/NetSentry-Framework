#intel.py
#Date-13/12/2025
#Author- Lokesh Kumar
#github - @trmxvibs
#Madeinindia

import socket
import requests
import whois
import json

def get_domain_intel(domain):
    intel = "\n--- GEO-INTEL REPORT ---\n"
    try:
        w = whois.whois(domain)
        if w.org: intel += f"[+] Org: {w.org}\n"
    except: pass
    try:
        ip = socket.gethostbyname(domain)
        if ip.startswith("192.168") or ip.startswith("10."):
             intel += f"[+] Location: LOCAL LAN ({ip})\n"
        else:
            url = f"http://ip-api.com/json/{ip}"
            geo = requests.get(url, timeout=5).json()
            if geo['status'] == 'success':
                intel += f"[+] Country: {geo['country']} ({geo['countryCode']})\n"
                intel += f"[+] ISP: {geo['isp']}\n"
                intel += f"[COORDS] {geo['lat']},{geo['lon']}\n"
    except: pass
    intel += "------------------------\n"
    return intel

def consult_oracle(domain):
    report = ["\n[*] THE ORACLE (SHODAN DB):"]
    try:
        ip = socket.gethostbyname(domain)
        url = f"https://internetdb.shodan.io/{ip}"
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            data = res.json()
            report.append(f"   [+] Ports: {data.get('ports', 'None')}")
            vulns = data.get('vulns', [])
            if vulns:
                report.append(f"   [☠️] KNOWN VULNS: {len(vulns)} FOUND!")
                for v in vulns: report.append(f"       > {v}")
            else: report.append("   [✓] Clean record.")
    except: pass
    return "\n".join(report)

def fetch_wayback_urls(domain):
    report = ["\n[*] TIME TRAVELER (WAYBACK MINING):"]
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=100"
        
        # Increased timeout to 15s because Archive.org is slow
        res = requests.get(url, timeout=15)
        
        if res.status_code == 200:
            data = res.json()
            urls = [row[0] for row in data[1:]]
            
            keywords = ["admin", "login", "api", "dev", "test", "config", "dashboard", "v1", "auth"]
            interesting = [u for u in urls if any(k in u for k in keywords)]
            
            if interesting:
                report.append(f"   [⚡] Recovered {len(interesting)} 'Ghost' URLs from history:")
                unique_urls = list(set(interesting))
                for link in unique_urls[:15]: 
                    report.append(f"       > {link}")
                return "\n".join(report), unique_urls 
            else:
                report.append("   [✓] History seems clean (No sensitive URLs found).")
                return "\n".join(report), []
        else:
            report.append("   [-] Wayback Machine unavailable/busy.")
    except Exception as e:
        report.append(f"   [-] Time travel failed: {str(e)}")
        

    return "\n".join(report), []
