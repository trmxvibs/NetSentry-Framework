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

# --- 1. UTILITIES & STEALTH ---
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
                for v in vulns[:3]: report.append(f"       > {v}")
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
                for d in extras[:5]: report.append(f"       > {d}")
    except: report.append("   [-] SSL Handshake Failed.")
    return "\n".join(report)

# --- 4. OFFENSE & VULNERABILITY ---
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

# --- NEW: DEEP VULNERABILITY SCANNER ---
def deep_vuln_scanner(domain):
    report = ["\n[*] DEEP VULNERABILITY SCAN (LFI/CONFIG):"]
    base_url = f"http://{domain}"
    
    # 1. CONFIG & BACKUP FILES (High Impact)
    critical_files = [
        ".env", ".git/config", ".vscode/sftp.json", "docker-compose.yml",
        "wp-config.php.bak", "config.php.bak", "id_rsa", "backup.sql"
    ]
    
    found_config = False
    for f in critical_files:
        try:
            url = f"{base_url}/{f}"
            r = requests.get(url, headers=get_bypass_headers(), timeout=2)
            if r.status_code == 200 and len(r.text) > 0:
                # Verify it's not a fake 200 page
                if "html" not in r.text.lower():
                    report.append(f"   [☠️] CRITICAL LEAK: {f} FOUND!")
                    report.append(f"       > Content Snippet: {r.text[:50]}...")
                    found_config = True
        except: pass
    
    if not found_config: report.append("   [✓] No config backups exposed.")

    # 2. LFI (Local File Inclusion) CHECK
    # Look for URL params and fuzz them
    try:
        r = requests.get(base_url, headers=get_bypass_headers(), timeout=3)
        soup = BeautifulSoup(r.text, 'html.parser')
        lfi_payloads = ["../../../../etc/passwd", "c:/windows/win.ini"]
        
        vuln_lfi = False
        for a in soup.find_all('a', href=True):
            if "=" in a['href']:
                target_param_url = urljoin(base_url, a['href'])
                # Replace param value with payload
                # Simple check: assume param is at the end
                base, param = target_param_url.split('=', 1)
                
                for pay in lfi_payloads:
                    fuzz_url = f"{base}={pay}"
                    try:
                        fr = requests.get(fuzz_url, timeout=3)
                        if "root:x:0:0" in fr.text or "[extensions]" in fr.text:
                            report.append(f"   [☠️] LFI VULNERABILITY DETECTED!")
                            report.append(f"       > URL: {fuzz_url}")
                            vuln_lfi = True
                            break
                    except: pass
            if vuln_lfi: break
            
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
            
        report.append(f"   [i] Analyzing {len(scripts)} JavaScript files...")
        
        for script in scripts[:5]:
            if not script.startswith("http"): 
                if script.startswith("//"): script = "https:" + script
                else: script = urljoin(url, script)
            try:
                js_code = requests.get(script, headers=get_bypass_headers(), timeout=5).text
                for name, pat in secrets.items():
                    keys = re.findall(pat, js_code)
                    for k in keys: report.append(f"   [$$$] KEY LEAK ({name}) in JS: {k}")
            except: pass
    except: report.append("   [-] Spider failed.")
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
    if "CRITICAL LEAK" in scan_result: score += 60 # High impact
    if "LFI VULNERABILITY" in scan_result: score += 70 # Critical
    if "WAF DETECTED" in scan_result: score -= 10
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
            # NEW VULN SCANNER (Runs in all modes except basic)
            futures["vuln"] = executor.submit(deep_vuln_scanner, clean_host)
        
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
    
    scan_out = results_dict.get("nmap","")
    final.append(scan_out)
    
    # Vuln Results
    if "vuln" in results_dict: final.append(results_dict["vuln"])
    if "spider" in results_dict: final.append(results_dict["spider"])
    if "zone" in results_dict: final.append(results_dict["zone"])
    
    tech_res = results_dict.get("tech", ("", []))
    if isinstance(tech_res, tuple): final.append(tech_res[0])
    
    final.append(generate_attack_commands(clean_host, scan_out, []))
    final.append(generate_metasploit_script(clean_host, scan_out))
    
    full_text = "\n".join(final)
    score = calculate_risk_score(full_text)
    label = "CRITICAL" if score > 70 else "MEDIUM" if score > 30 else "LOW"
    
    return f"\n[★] RISK SCORE: {score}/100 ({label})\n" + "-"*40 + "\n" + full_text