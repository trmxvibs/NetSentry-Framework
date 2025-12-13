import re

def analyze_attack_strategy(scan_result, tech_list):
    strategy = ["\n[*] CORTEX AI STRATEGY (BLUEPRINT):"]
    
    # 1. OSINT Analysis
    if "Country: Russia" in scan_result or "Country: China" in scan_result:
        strategy.append("   [!] CAUTION: Target is in a high-surveillance region. Use Proxychains.")
    
    # 2. Port-Specific Strategies
    if "445/tcp open" in scan_result:
        strategy.append("   [⚡] SMB FOUND: Check for EternalBlue (MS17-010).")
        strategy.append("       > Cmd: nmap --script smb-vuln* -p 445 <target>")
        
    if "3389/tcp open" in scan_result:
        strategy.append("   [⚡] RDP EXPOSED: Try BlueKeep exploit check.")
        
    if "53/tcp open" in scan_result:
        strategy.append("   [⚡] DNS FOUND: Attempt Zone Transfer manually if automated failed.")
        strategy.append("       > Cmd: dig axfr @<target_ip> <domain>")

    # 3. Web App Strategies
    if "WordPress" in str(tech_list):
        strategy.append("   [⚡] WORDPRESS DETECTED:")
        strategy.append("       > 1. Enumerate Plugins: wpscan --url <url> --enumerate p")
        strategy.append("       > 2. XML-RPC Attack: Check if /xmlrpc.php is active.")
        
    if "Apache" in str(tech_list):
        strategy.append("   [⚡] APACHE SERVER:")
        strategy.append("       > Check for Path Traversal (CVE-2021-41773) if version < 2.4.50.")
        
    if "Tomcat" in scan_result or "8080/tcp" in scan_result:
        strategy.append("   [⚡] TOMCAT/JENKINS:")
        strategy.append("       > Try default creds (tomcat/s3cret, admin/admin).")
        strategy.append("       > Check /manager/html access.")

    # 4. Critical Logic
    if "[$$$]" in scan_result:
        strategy.append("   [☠️] SECRETS FOUND: Validating keys... Use them to access Cloud/APIs.")
    
    if "LFI DETECTED" in scan_result:
        strategy.append("   [☠️] LFI CONFIRMED: Try converting to RCE using Log Poisoning or /proc/self/environ.")

    if len(strategy) == 1:
        strategy.append("   [i] Target is hardened. Recommended: Social Engineering or Phishing.")
        
    return "\n".join(strategy)