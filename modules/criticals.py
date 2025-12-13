import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from modules.config import get_bypass_headers

def check_cors(domain):
    report = ["\n[*] CORS MISCONFIGURATION SCANNER:"]
    url = f"http://{domain}"
    origin_payload = "https://example.com" # WAF Friendly
    
    try:
        headers = get_bypass_headers()
        headers['Origin'] = origin_payload
        
        res = requests.get(url, headers=headers, timeout=5)
        
        if origin_payload in res.headers.get('Access-Control-Allow-Origin', ''):
            report.append(f"   [☠️] CRITICAL: CORS MISCONFIGURATION FOUND!")
            report.append(f"       > Server accepts arbitrary origin: {origin_payload}")
            if 'true' in str(res.headers.get('Access-Control-Allow-Credentials')).lower():
                 report.append("       > [!!!] HIGH IMPACT: Credentials Allowed (Account Takeover Risk)")
        else:
            report.append("   [✓] CORS Policy appears secure.")
    except: report.append("   [-] CORS check failed.")
    return "\n".join(report)

def check_open_redirect(domain, endpoints):
    if not endpoints: return ""
    report = ["\n[*] OPEN REDIRECT HUNTER:"]
    payload = "http://google.com"
    
    found = False
    # Check max 15 endpoints to save time
    for ep in list(endpoints)[:15]:
        if "=" in ep:
            try:
                # Intelligent Parameter Replacement
                parsed = urlparse(ep)
                params = parse_qs(parsed.query)
                
                # Try injecting payload into EVERY parameter one by one
                for param in params:
                    temp_params = params.copy()
                    temp_params[param] = payload # Inject here
                    
                    # Rebuild URL
                    new_query = urlencode(temp_params, doseq=True)
                    target_url = urlunparse(parsed._replace(query=new_query))
                    
                    if not target_url.startswith("http"):
                        target_url = urljoin(f"http://{domain}", target_url)

                    res = requests.get(target_url, headers=get_bypass_headers(), allow_redirects=False, timeout=3)
                    
                    if res.status_code in [301, 302, 307]:
                        loc = res.headers.get('Location', '')
                        if "google.com" in loc:
                            report.append(f"   [☠️] OPEN REDIRECT FOUND: {target_url}")
                            found = True
                            break # Stop checking parameters for this URL if one worked
            except: pass
            
    if not found: report.append("   [✓] No open redirects found in sample.")
    return "\n".join(report)

# Check Clickjacking same as before (it was fine)
def check_clickjacking(domain):
    report = ["\n[*] CLICKJACKING (IFRAME) TEST:"]
    url = f"http://{domain}"
    try:
        res = requests.get(url, headers=get_bypass_headers(), timeout=5)
        headers = {k.lower(): v for k, v in res.headers.items()}
        
        x_frame = headers.get('x-frame-options', '')
        csp = headers.get('content-security-policy', '')
        
        if 'deny' in x_frame or 'sameorigin' in x_frame or 'frame-ancestors' in csp:
            report.append("   [✓] Protected against Clickjacking.")
        else:
            report.append(f"   [⚠️] VULNERABLE: X-Frame-Options missing!")
    except: report.append("   [-] Clickjacking check failed.")
    return "\n".join(report)