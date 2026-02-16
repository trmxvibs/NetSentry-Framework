#risk.py
#Date-13/12/2025
#Author- Lokesh Kumar 
#update-on-16/02/2026
#github - @trmxvibs
#Madeinindia
import re

def calculate_risk_score(scan_result):
    score = 0
    lines = scan_result.split('\n')
    
    # 1. Base Score (Attack Surface)
    # Google jaise sites par open ports hona normal hai. Iska weight kam kar rahe hain.
    open_ports = len(re.findall(r"\d+/tcp\s+open", scan_result))
    score += min(open_ports, 10) # Max 10 points for open ports base
    
    has_critical_vuln = False

    for line in lines:
        # Stop scoring at the Strategy section (Summary shouldn't double count)
        if "CORTEX AI STRATEGY" in line:
            break

        # --- CRITICAL FINDINGS (The Skull) ---
        if "[☠️]" in line:
            if "CRITICAL" in line or "RCE" in line or "SQLi" in line:
                score = 100 # Game Over. Direct 100.
                has_critical_vuln = True
            else:
                score += 20 # High severity finding (e.g. LFI detected)
            
        # --- SENSITIVE DATA ([$$$]) ---
        elif "[$$$]" in line:
            # API Keys ke liye hum 'STATUS' line ka wait karenge (niche logic hai)
            if "KEY LEAK" in line:
                continue 
            
            # Subdomain Takeover wagarah ke liye direct points
            if "POTENTIAL TAKEOVER" in line:
                score += 30

        # --- VALIDATED KEY STATUS (The Game Changer) ---
        # Ye check karega ki Key active hai ya inactive
        elif "STATUS:" in line:
            if "[CRITICAL]" in line or "ACTIVE" in line:
                score += 50 # Validated Live Key -> High Risk
                has_critical_vuln = True
            elif "[HIGH]" in line:
                score += 30
            elif "[SAFE]" in line or "Restricted" in line:
                score += 0 # Inactive Key -> 0 Points (Ignored)
        
        # --- WARNINGS ([⚠️]) ---
        elif "[⚠️]" in line:
            if "DOM RISK (CONFIRMED)" in line:
                score += 10 # Verified DOM XSS risk
            elif "POTENTIAL" in line:
                score += 5  # Low confidence / IDOR warnings
            else:
                score += 5  # Generic warning (headers, internal IPs)

    # Final Adjustment
    # Agar koi Critical vuln nahi mili, to score ko 90 se upar mat jaane do
    if not has_critical_vuln:
        score = min(score, 85)
        
    return min(score, 100)
