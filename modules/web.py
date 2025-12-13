import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from modules.config import get_bypass_headers
from modules.validator import validate_found_key
import dns.resolver

# --- DEFENSE MODULES ---
def detect_waf(domain):
    report = []
    waf_sigs = {"Cloudflare": "cf-ray", "AWS": "x-amz-cf-id", "Akamai": "x-akamai", "Imperva": "x-iinfo"}
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

def detect_tech_stack(domain):
    report = ["\n[*] TECH STACK:"]
    detected = []
    try:
        res = requests.get(f"http://{domain}", headers=get_bypass_headers(), timeout=3)
        sigs = {
            "WordPress": "wp-content", 
            "PHP": "php", 
            "React": "react", 
            "AWS": "aws", 
            "Angular": "ng-version", 
            "Vue": "vue",
            "Laravel": "laravel_session"
        }
        for tech, sig in sigs.items():
            if sig in res.text.lower() or sig in str(res.headers).lower(): detected.append(tech)
        if detected: report.append(f"   [+] Stack: {', '.join(detected)}")
    except: pass
    return "\n".join(report), detected

def audit_cloud_buckets(html_content):
    report = []
    # Regex for S3 buckets
    buckets = set(re.findall(r'([\w-]+\.s3\.amazonaws\.com)', html_content))
    buckets.update(set(re.findall(r's3://([\w-]+)', html_content)))
    if not buckets: return ""
    
    report.append("\n[*] CLOUD AUDITOR:")
    for bucket in buckets:
        b_url = bucket if "http" in bucket else f"http://{bucket}"
        try:
            res = requests.get(b_url, timeout=3)
            if res.status_code == 200 and "ListBucketResult" in res.text:
                report.append(f"   [☠️] CRITICAL: PUBLIC READ ACCESS on {bucket}")
            elif res.status_code == 403: report.append(f"   [✓] {bucket} is Private.")
        except: pass
    return "\n".join(report)

# --- DOM & KEY HUNTER ---
def crawl_website_data(domain):
    report = ["\n[*] JS MINER & DOM HUNTER:"]
    url = f"http://{domain}"
    html = ""
    endpoints = set()
    
    try:
        res = requests.get(url, headers=get_bypass_headers(), timeout=10)
        html = res.text
        
        # 1. Secrets in HTML
        secrets = {
            "AWS": r"(AKIA[0-9A-Z]{16})", 
            "Google": r"(AIza[0-9A-Za-z-_]{35})",
            "Stripe": r"(pk_live_[0-9a-zA-Z]{24})",
            "Mailgun": r"(pubkey-[0-9a-f]{32})"
        }
        for name, pat in secrets.items():
            keys = re.findall(pat, html)
            for k in keys: 
                status = validate_found_key(name, k)
                report.append(f"   [$$$] KEY LEAK ({name}): {k}")
                report.append(f"       └── STATUS: {status}")

        soup = BeautifulSoup(html, 'html.parser')

        # --- [NEW] HTML ANCHOR EXTRACTION ---
        # Standard links (e.g. <a href="artists.php?artist=1">)
        for a in soup.find_all('a', href=True):
            href = a['href']
            # Filter junk
            if href.startswith(('#', 'javascript', 'mailto')): continue
            
            full_url = urljoin(url, href)
            parsed = urlparse(full_url)
            
            # Sirf wahi links lo jo same domain ke hain aur jisme parameters hain
            if domain in parsed.netloc:
                # Store relative path + query (e.g., /artists.php?artist=1)
                path_query = f"{parsed.path}"
                if parsed.query:
                    path_query += f"?{parsed.query}"
                
                if len(path_query) > 1:
                    endpoints.add(path_query)

        # 2. JavaScript Analysis
        scripts = []
        for s in soup.find_all('script'):
            if s.get('src'): scripts.append(s.get('src'))
            elif s.get('data-src'): scripts.append(s.get('data-src'))
            
        report.append(f"   [i] Analyzing {len(scripts)} JavaScript files...")
        
        # Dangerous DOM Sinks
        dom_sinks = {
            "innerHTML": "DOM XSS (Unsafe HTML rendering)",
            "document.write": "DOM XSS (Old school injection)",
            "eval(": "RCE/XSS (Dangerous execution)",
            "location.search": "Unsafe Source (URL Parameter)",
            "location.hash": "Unsafe Source (Fragment)"
        }

        for script in scripts[:20]: 
            if not script.startswith("http"): 
                if script.startswith("//"): script = "https:" + script
                else: script = urljoin(url, script)
            try:
                js_code = requests.get(script, headers=get_bypass_headers(), timeout=5).text
                
                # Find Endpoints in JS (Regex)
                paths = re.findall(r"['\"](\/[a-zA-Z0-9_/-]+)['\"]", js_code)
                for p in paths:
                    if len(p) > 4 and "//" not in p: endpoints.add(p)
                
                # DOM Sink Check
                for sink, desc in dom_sinks.items():
                    if sink in js_code:
                        report.append(f"   [⚠️] DOM RISK: Found '{sink}' in {script.split('/')[-1]}")

            except: pass
            
        if endpoints:
            report.append(f"   [+] Found {len(endpoints)} crawlable endpoints:")
            # Sirf top 10 dikhao report mein taaki spam na ho
            for ep in sorted(list(endpoints))[:10]: 
                report.append(f"       > {ep}")
            if len(endpoints) > 10:
                report.append(f"       ...and {len(endpoints)-10} more.")
            
    except Exception as e: report.append(f"   [-] Spider failed: {str(e)}")
    
    # Return HTML for cloud check, and endpoints set for vulnerability scanning
    report.append(audit_cloud_buckets(html))
    return "\n".join(report), endpoints

def check_security_headers(domain):
    report = ["\n[*] DEFENSE GAP ANALYSIS (HEADERS):"]
    url = f"http://{domain}"
    try:
        res = requests.get(url, headers=get_bypass_headers(), timeout=5)
        headers = {k.lower(): v for k, v in res.headers.items()}
        missing = []
        if 'strict-transport-security' not in headers: missing.append("HSTS")
        if 'content-security-policy' not in headers: missing.append("CSP")
        if 'x-content-type-options' not in headers: missing.append("No-Sniff")
        if missing:
            report.append("   [⚠️] MISSING HEADERS:")
            for h in missing: report.append(f"       > {h}")
        else: report.append("   [✓] Core security headers present.")
    except: report.append("   [-] Header check failed.")
    return "\n".join(report)

def check_spring_boot(domain):
    report = ["\n[*] SPRING BOOT ACTUATOR SCAN:"]
    base_url = f"http://{domain}"
    endpoints = {"/actuator/env": "Environment Variables", "/actuator/heapdump": "Memory Dump", "/actuator/health": "Health"}
    found = False
    for ep, desc in endpoints.items():
        try:
            r = requests.get(base_url + ep, headers=get_bypass_headers(), timeout=3)
            if r.status_code == 200 and ("activeProfiles" in r.text or "spring" in r.text or "UP" in r.text):
                report.append(f"   [☠️] CRITICAL: {desc} EXPOSED! {ep}")
                found = True
        except: pass
    if not found: report.append("   [✓] Spring Boot Actuators secured.")
    return "\n".join(report)

def check_broken_links(domain):
    report = ["\n[*] BROKEN LINK HIJACKING:"]
    url = f"http://{domain}"
    try:
        res = requests.get(url, headers=get_bypass_headers(), timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        links = set(a['href'] for a in soup.find_all('a', href=True) if "http" in a['href'] and domain not in a['href'])
        
        if not links: return ""
        vuln = False
        
        for link in list(links)[:10]:
            try: 
                hostname = urlparse(link).hostname
                # If domain doesn't resolve, it's hijackable
                dns.resolver.resolve(hostname, 'A')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                report.append(f"   [☠️] HIJACKABLE DOMAIN: {link}")
                vuln = True
            except: pass
            
        if not vuln: report.append("   [✓] External links resolve correctly.")
    except: report.append("   [-] BLH check failed.")
    return "\n".join(report)