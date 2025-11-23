#lokesh kumar
#github.com/trmxvibs
import subprocess
import socket
import requests
import shutil
import shlex
import re
import ssl
import whois
import dns.resolver
import dns.zone
import dns.query
import random
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

# --- 1. UTILITIES ---
def clean_target(target):
    target = target.strip()
    if "://" in target: return urlparse(target).hostname
    return target.split('/')[0]

def get_random_agent():
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    ]
    return random.choice(agents)

def get_bypass_headers():
    return {
        'User-Agent': get_random_agent(),
        'X-Forwarded-For': '127.0.0.1',
        'Referer': 'https://google.com'
    }

def get_system_info():
    info = {'local_ip': 'Unknown', 'public_ip': 'Offline'}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info['local_ip'] = s.getsockname()[0]
        s.close()
    except: info['local_ip'] = "127.0.0.1"
    return info

# --- 2. INTELLIGENCE ---
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
                intel += f"[+] Country: {geo['country']}\n"
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
                for v in vulns: report.append(f"       > {v}") # UNRESTRICTED
            else: report.append("   [✓] Clean record.")
    except: pass
    return "\n".join(report)

def check_zone_transfer(domain):
    report = ["\n[*] DNS ZONE TRANSFER:"]
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        vuln = False
        for ns in ns_records:
            try:
                ns_ip = socket.gethostbyname(str(ns))
                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=2))
                if z:
                    report.append(f"   [!!!] CRITICAL: ZONE TRANSFER OPEN on {ns}")
                    report.append("   [+] Dumping Records:")
                    for name, node in z.nodes.items(): # UNRESTRICTED
                        report.append(f"       > {name}.{domain}")
                    vuln = True; break
            except: continue
        if not vuln: report.append("   [✓] DNS Secure.")
    except: report.append("   [-] NS Lookup Failed.")
    return "\n".join(report)

# --- 3. DEFENSE ---
def detect_waf(domain):
    report = []
    waf_sigs = {"Cloudflare": "cf-ray", "AWS": "x-amz-cf-id", "Akamai": "x-akamai"}
    detected = None
    try:
        res = requests.get(f"http://{domain}", headers=get_bypass_headers(), timeout=3)
        headers = str(res.headers).lower()
        for name, sig in waf_sigs.items():
            if sig in headers: detected = name; break
    except: pass
    if detected: report.append(f"[🛡️] WAF DETECTED: {detected}")
    else: report.append("[✓] NO WAF DETECTED.")
    return "\n".join(report)

def analyze_ssl_cert(domain):
    report = ["\n[*] SSL ILLUMINATOR:"]
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            issuer = dict(x[0] for x in cert['issuer']).get('commonName', 'Unknown')
            report.append(f"   [+] Issued: {issuer}")
            sans = [x[1] for x in cert.get('subjectAltName', []) if x[0] == 'DNS']
            extras = [d for d in sans if d != domain]
            if extras:
                report.append(f"   [SCOPE] Found {len(extras)} hidden domains:")
                for d in extras: report.append(f"       > {d}") # UNRESTRICTED
    except: report.append("   [-] SSL Handshake Failed.")
    return "\n".join(report)

def find_subdomains(domain):
    report = ["\n[*] PASSIVE SUBDOMAINS:"]
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        data = requests.get(url, timeout=10).json()
        subs = set(entry['name_value'].split('\n')[0] for entry in data)
        valid = [s for s in subs if domain in s]
        if valid:
            report.append(f"   [+] Found {len(valid)} subdomains (FULL LIST):")
            for s in sorted(list(valid)): report.append(f"       > {s}") # UNRESTRICTED
        else: report.append("   [-] No subdomains found.")
    except: report.append("   [-] Passive recon failed.")
    return "\n".join(report)

# --- 4. OFFENSE ---
def run_nmap_scan(domain, mode, custom_flags):
    if shutil.which("nmap") is None: return "[-] CRITICAL: Nmap not installed."
    try: ip = socket.gethostbyname(domain)
    except: return "[-] DNS Failed."

    if mode == "basic": flags = "-F -T4" 
    elif mode == "medium": flags = "-sV -T4 --top-ports 1000"
    elif mode == "advance": flags = "-A -T4 -v"
    elif mode == "custom": flags = custom_flags
    else: flags = "-F"

    cmd = ["nmap"] + shlex.split(flags) + [ip]
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        return process.stdout
    except Exception as e: return f"[-] Nmap Error: {e}"

def deep_vuln_scanner(domain):
    report = ["\n[*] DEEP VULNERABILITY SCAN (LFI/CONFIG):"]
    base_url = f"http://{domain}"
    
    critical_files = [".env", ".git/config", ".vscode/sftp.json", "docker-compose.yml", "wp-config.php.bak"]
    found = False
    for f in critical_files:
        try:
            r = requests.get(f"{base_url}/{f}", headers=get_bypass_headers(), timeout=2)
            if r.status_code == 200 and "html" not in r.text.lower():
                report.append(f"   [☠️] CRITICAL LEAK: {f} FOUND!")
                found = True
        except: pass
    if not found: report.append("   [✓] No config backups exposed.")

    try:
        r = requests.get(base_url, headers=get_bypass_headers(), timeout=3)
        soup = BeautifulSoup(r.text, 'html.parser')
        vuln_lfi = False
        for a in soup.find_all('a', href=True):
            if "=" in a['href']:
                base, param = urljoin(base_url, a['href']).split('=', 1)
                fuzz_url = f"{base}=../../../../etc/passwd"
                try:
                    fr = requests.get(fuzz_url, timeout=3)
                    if "root:x:0:0" in fr.text:
                        report.append(f"   [☠️] LFI DETECTED: {fuzz_url}")
                        vuln_lfi = True; break
                except: pass
        if not vuln_lfi: report.append("   [✓] LFI check passed.")
    except: pass
    return "\n".join(report)

def crawl_website_data(domain):
    report = ["\n[*] JS MINER & KEY REAPER:"]
    url = f"http://{domain}"
    try:
        res = requests.get(url, headers=get_bypass_headers(), timeout=10)
        html = res.text
        
        secrets = {"AWS": r"(AKIA[0-9A-Z]{16})", "Google": r"(AIza[0-9A-Za-z-_]{35})"}
        for name, pat in secrets.items():
            keys = re.findall(pat, html)
            for k in keys: report.append(f"   [$$$] KEY LEAK ({name}): {k}")

        soup = BeautifulSoup(html, 'html.parser')
        scripts = []
        for s in soup.find_all('script'):
            if s.get('src'): scripts.append(s.get('src'))
            elif s.get('data-src'): scripts.append(s.get('data-src'))
            
        report.append(f"   [i] Analyzing {len(scripts)} JavaScript files (FULL SCAN)...")
        
        endpoints = set()
        # UNRESTRICTED: Scan up to 50 scripts now
        for script in scripts[:50]:
            if not script.startswith("http"): 
                if script.startswith("//"): script = "https:" + script
                else: script = urljoin(url, script)
            try:
                js_code = requests.get(script, headers=get_bypass_headers(), timeout=5).text
                
                paths = re.findall(r"['\"](\/[a-zA-Z0-9_/-]+)['\"]", js_code)
                for p in paths:
                    if len(p) > 4 and "//" not in p: endpoints.add(p)
                
                for name, pat in secrets.items():
                    keys = re.findall(pat, js_code)
                    for k in keys: report.append(f"   [$$$] KEY LEAK ({name}) in JS: {k}")
            except: pass
            
        if endpoints:
            report.append(f"   [+] Found {len(endpoints)} hidden API endpoints (FULL LIST):")
            for ep in sorted(list(endpoints)): report.append(f"       > {ep}") # UNRESTRICTED
    except: report.append("   [-] Spider failed.")
    return "\n".join(report)

def check_cve_vulnerabilities(text):
    report = ["\n[*] CVE CHECK:"]
    exploits = {"vsftpd 2.3.4": "CVE-2011-2523", "Apache 2.4.49": "CVE-2021-41773"}
    found = False
    for soft, cve in exploits.items():
        if soft in text:
            report.append(f"   [☠️] VULNERABLE: {soft} -> {cve}")
            found = True
    if not found: report.append("   [✓] No signature match.")
    return "\n".join(report)

def detect_tech_stack(domain):
    report = ["\n[*] TECH STACK:"]
    detected = []
    try:
        res = requests.get(f"http://{domain}", headers=get_bypass_headers(), timeout=3)
        sigs = {"WordPress": "wp-content", "PHP": "php", "React": "react", "AWS": "aws"}
        for tech, sig in sigs.items():
            if sig in res.text.lower() or sig in str(res.headers): detected.append(tech)
        if detected: report.append(f"   [+] Stack: {', '.join(detected)}")
    except: pass
    return "\n".join(report), detected

def generate_attack_commands(domain, scan_text, tech_list):
    cmds = ["\n[*] WEAPONIZER:"]
    if "80/tcp" in scan_text: cmds.append(f"   [WEB] nikto -h {domain}")
    return "\n".join(cmds)

def generate_metasploit_script(domain, scan_text):
    msf = ["\n[*] METASPLOIT SCRIPT (RCE):"]
    script = [f"workspace -a {domain}", f"db_nmap -sV {domain}"]
    if "80/tcp" in scan_text:
        script.append("use auxiliary/scanner/http/dir_scanner")
        script.append(f"set RHOSTS {domain}")
        script.append("run")
    msf.append("\n".join(script))
    msf.append("[i] Save as 'attack.rc' and run: msfconsole -r attack.rc")
    return "\n".join(msf)

def calculate_risk_score(scan_result):
    score = 0
    score += len(re.findall(r"\d+/tcp\s+open", scan_result)) * 5
    if "[☠️]" in scan_result: score += 50
    if "[$$$]" in scan_result: score += 40
    if "403 BYPASSED" in scan_result: score += 30
    if "hidden API endpoints" in scan_result: score += 15
    if score > 100: score = 100
    return score

# --- MASTER ORCHESTRATOR ---
def scan_target(domain, mode="basic", custom_flags="", previous_result=None, webhook=""):
    clean_host = clean_target(domain)
    results_dict = {}
    
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            "intel": executor.submit(get_domain_intel, clean_host),
            "oracle": executor.submit(consult_oracle, clean_host),
            "nmap": executor.submit(run_nmap_scan, clean_host, mode, custom_flags),
            "waf": executor.submit(detect_waf, clean_host),
            "ssl": executor.submit(analyze_ssl_cert, clean_host)
        }
        if mode != "basic":
            futures["spider"] = executor.submit(crawl_website_data, clean_host)
            futures["tech"] = executor.submit(detect_tech_stack, clean_host)
            futures["vuln"] = executor.submit(deep_vuln_scanner, clean_host)
            futures["subdomain"] = executor.submit(find_subdomains, clean_host) # Added explicit call
        
        if mode == "advance":
            futures["zone"] = executor.submit(check_zone_transfer, clean_host)

        for key, future in futures.items():
            try: results_dict[key] = future.result()
            except: results_dict[key] = ""

    final = []
    final.append(f"[*] TARGET: {clean_host}")
    final.append(f"[*] MODE: {mode.upper()}")
    
    final.append(results_dict.get("intel",""))
    final.append(results_dict.get("oracle",""))
    final.append(results_dict.get("waf",""))
    final.append(results_dict.get("ssl",""))
    if "subdomain" in results_dict: final.append(results_dict["subdomain"])
    if "zone" in results_dict: final.append(results_dict["zone"])
    
    scan_out = results_dict.get("nmap","")
    final.append(scan_out)
    
    if "vuln" in results_dict: final.append(results_dict["vuln"])
    if "spider" in results_dict: final.append(results_dict["spider"])
    
    tech_res = results_dict.get("tech", ("", []))
    if isinstance(tech_res, tuple): final.append(tech_res[0])
    
    final.append(generate_attack_commands(clean_host, scan_out, []))
    final.append(generate_metasploit_script(clean_host, scan_out))
    
    full_text = "\n".join(final)
    score = calculate_risk_score(full_text)
    label = "CRITICAL" if score > 70 else "MEDIUM" if score > 30 else "LOW"
    
    return f"\n[★] RISK SCORE: {score}/100 ({label})\n" + "-"*40 + "\n" + full_text
