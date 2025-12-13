#validtor.py
#Date-13/12/2025
#Author- Lokesh Kumar
#github - @trmxvibs
#Madeinindia
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def validate_google_key(api_key):
    test_url = f"https://maps.googleapis.com/maps/api/staticmap?center=40.7,-73.9&zoom=12&size=400x400&key={api_key}"
    try:
        r = requests.get(test_url, timeout=5, verify=False)
        if r.status_code == 200: return "[CRITICAL] ACTIVE & BILLABLE"
        elif r.status_code == 403: return "[SAFE] Restricted/Inactive"
        else: return f"[?] Status: {r.status_code}"
    except: return "[-] Validation Error"

def validate_stripe_key(api_key):
    try:
        r = requests.post("https://api.stripe.com/v1/tokens", headers={"Authorization": f"Bearer {api_key}"}, timeout=5)
        if r.status_code == 200 or "error" in r.text: return "[HIGH] Key is LIVE"
    except: pass
    return "[-] Connection Failed"

def validate_mailgun_key(api_key):
    try:
        r = requests.get("https://api.mailgun.net/v4/address/validate", auth=("api", api_key), params={"address": "test@test.com"}, timeout=5)
        if r.status_code == 200: return "[CRITICAL] ACTIVE Mailgun Key"
    except: pass
    return "[SAFE] Invalid Key"

def validate_found_key(platform, key):
    if platform == "Google": return validate_google_key(key)
    elif platform == "Stripe": return validate_stripe_key(key)
    elif platform == "Mailgun": return validate_mailgun_key(key)

    return "[i] No auto-validation available."
