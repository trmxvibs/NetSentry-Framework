import socket
import ssl
import shutil
import shlex
import subprocess
import requests
import dns.resolver
import dns.zone
import dns.query
from concurrent.futures import ThreadPoolExecutor

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
                for d in extras[:10]: # Limit output to avoid spam
                    report.append(f"       > {d}")
                if len(extras) > 10: report.append(f"       ...and {len(extras)-10} more.")
    except: report.append("   [-] SSL Handshake Failed.")
    return "\n".join(report)

def find_subdomains(domain):
    report = ["\n[*] PASSIVE SUBDOMAINS:"]
    subdomains_found = []
    try:
        # User-Agent added to avoid 403 blocks
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; NetSentry/1.0)'}
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        r = requests.get(url, headers=headers, timeout=20)
        
        if r.status_code != 200:
             report.append(f"   [-] crt.sh Service Unavailable (Status: {r.status_code})")
             return "\n".join(report), []

        try:
            data = r.json()
        except ValueError:
            report.append("   [-] crt.sh returned invalid JSON (API Overload).")
            return "\n".join(report), []

        subs = set()
        for entry in data:
            name_value = entry.get('name_value', '')
            for sub in name_value.split('\n'):
                subs.add(sub)
        
        # Filter valid subdomains and remove wildcards
        valid = [s for s in subs if domain in s and "*" not in s]
        
        if valid:
            report.append(f"   [+] Found {len(valid)} subdomains:")
            for s in sorted(list(valid))[:20]: 
                report.append(f"       > {s}")
            if len(valid) > 20: report.append(f"       ...and {len(valid)-20} more.")
            subdomains_found = list(valid)
        else: report.append("   [-] No subdomains found.")
    except Exception as e: report.append(f"   [-] Passive recon failed: {str(e)}")
    return "\n".join(report), subdomains_found

def active_subdomain_enum(domain):
    report = ["\n[*] ACTIVE SUBDOMAIN DISCOVERY:"]
    common_subs = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure", "vpn", "m", "shop", "ftp", "hr", "dev", "test", "staging", "admin", "portal", "api", "beta", "jenkins"]
    found = []
    
    def check_sub(sub):
        target = f"{sub}.{domain}"
        try:
            # Using DNS resolver is faster than requests
            dns.resolver.resolve(target, 'A')
            return target
        except: return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_sub, sub) for sub in common_subs]
        for f in futures:
            if f.result(): found.append(f.result())
            
    if found:
        report.append(f"   [⚡] Discovered {len(found)} HIDDEN active subdomains:")
        for f in found: report.append(f"       > {f}")
    else: report.append("   [✓] No common hidden subdomains found.")
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

def run_nmap_scan(domain, mode, custom_flags):
    # Check if Nmap exists
    if shutil.which("nmap") is None: 
        return "[-] CRITICAL: Nmap is not installed on the server. Please install it."
        
    try: ip = socket.gethostbyname(domain)
    except: return "[-] DNS Resolution Failed."
    
    if mode == "basic": flags = "-F -T4" 
    elif mode == "medium": flags = "-sV -T4 --top-ports 1000"
    elif mode == "advance": flags = "-A -T4 -v"
    elif mode == "custom": flags = custom_flags
    else: flags = "-F"
    
    cmd = ["nmap"] + shlex.split(flags) + [ip]
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        return process.stdout
    except subprocess.TimeoutExpired: return "[-] Nmap Scan Timed Out."
    except Exception as e: return f"[-] Nmap Error: {e}"