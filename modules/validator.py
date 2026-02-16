#validator.py
#Date-13/12/2025
#Author- Lokesh Kumar
#update-on--16/02/2026
#github - @trmxvibs

import requests
import urllib3
import difflib
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ContextEngine:
    """
    Simulated AI Engine for Contextual Analysis and False Positive Reduction.
    Uses Sequence Matching and Heuristic Logic instead of heavy LLMs for speed.
    """
    
    @staticmethod
    def calculate_similarity(text1, text2):
        """Returns a similarity score between 0.0 and 1.0"""
        return difflib.SequenceMatcher(None, text1, text2).ratio()

    @staticmethod
    def analyze_js_risk(snippet):
        """
        Analyzes a JavaScript snippet to determine if 'innerHTML' or 'eval' 
        is actually dangerous based on context.
        """
        snippet = snippet.lower()
        
        # 1. Safe Patterns (Frameworks usually sanitize these)
        safe_indicators = ["react.createelement", "dompurify", "sanitize", "escapehtml", "innertext", "textcontent"]
        for safe in safe_indicators:
            if safe in snippet:
                return False  # Likely Safe

        # 2. Dangerous Contexts (Direct user input)
        danger_indicators = ["location.search", "location.hash", "input.value", "event.target.value"]
        for danger in danger_indicators:
            if danger in snippet:
                return True   # High Risk

        # 3. If it's just a hardcoded string, it's safe.
        # Regex to find if innerHTML is assigned a fixed string like innerHTML = "<div>"
        if re.search(r'innerhtml\s*=\s*["\']', snippet):
            return False 

        return True # Default to potential risk if unsure, but filtered "Fixed Strings"

    @staticmethod
    def is_response_dynamic(url):
        """Checks if a page returns random data (timestamps/nonces) that confuse scanners."""
        try:
            r1 = requests.get(url, timeout=5, verify=False).text
            r2 = requests.get(url, timeout=5, verify=False).text
            similarity = difflib.SequenceMatcher(None, r1, r2).ratio()
            return similarity < 0.95 # If less than 95% similar, it's dynamic
        except: return False

# --- EXISTING KEY VALIDATORS ---

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
