import re

def calculate_risk_score(scan_result):
    score = 0
    # Base Score based on Open Ports (Attack Surface)
    open_ports = len(re.findall(r"\d+/tcp\s+open", scan_result))
    score += open_ports * 2
    
    # Severity Weights
    # Agar Critical mila to game over, score high hona hi chahiye
    if "[☠️] CRITICAL" in scan_result or "RCE DETECTED" in scan_result:
        score = max(score, 90) # Minimum 90 if critical found
    elif "[☠️]" in scan_result: # High Severity
        score += 40
    
    if "[$$$]" in scan_result: # Sensitive Data Leak
        score += 30
        
    if "[⚠️]" in scan_result: # Medium/Low Severity
        score += 15
        
    if "DOM RISK" in scan_result:
        score += 10
        
    # Cap score at 100
    if score > 100: score = 100
    
    # Return 0 if nothing significant found but ensure low score isn't misleading
    if score == 0 and open_ports > 0: score = 10
    
    return score