import re

def get_exploit_db():
    return {
        "vsftpd 2.3.4": {"cve": "CVE-2011-2523", "name": "Backdoor Command Execution", "severity": "CRITICAL"},
        "Apache/2.4.49": {"cve": "CVE-2021-41773", "name": "Path Traversal & RCE", "severity": "CRITICAL"},
        "Apache/2.4.50": {"cve": "CVE-2021-42013", "name": "Path Traversal & RCE", "severity": "CRITICAL"},
        "Microsoft-IIS/6.0": {"cve": "CVE-2017-7269", "name": "WebDAV Buffer Overflow", "severity": "HIGH"},
        "ProFTPD 1.3.3c": {"cve": "CVE-2010-4227", "name": "ProFTPD IAC Buffer Overflow", "severity": "HIGH"},
        "OpenSSL 1.0.1": {"cve": "CVE-2014-0160", "name": "Heartbleed", "severity": "CRITICAL"},
        "Samba 3.0.20": {"cve": "CVE-2007-2447", "name": "Username Map Script RCE", "severity": "CRITICAL"},
        "Struts 2": {"cve": "CVE-2017-5638", "name": "Apache Struts RCE", "severity": "CRITICAL"},
        "Drupal 7": {"cve": "CVE-2014-3704", "name": "Drupalgeddon SQLi", "severity": "HIGH"},
        "WebLogic 10.3.6": {"cve": "CVE-2017-10271", "name": "Oracle WebLogic WLS RCE", "severity": "CRITICAL"},
        "Tomcat/9.0.0": {"cve": "CVE-2017-12615", "name": "Tomcat PUT JSP Upload RCE", "severity": "HIGH"},
        "Exim 4.92": {"cve": "CVE-2019-10149", "name": "The Return of the WIZard", "severity": "CRITICAL"}
    }

def analyze_services_for_cve(nmap_output):
    report = ["\n[*] INTELLIGENT EXPLOIT MAPPING (CVE):"]
    db = get_exploit_db()
    found_cve = False
    
    # Normalize Nmap output for better matching
    nmap_lower = nmap_output.lower()
    
    for signature, info in db.items():
        # Clean signature: "Apache/2.4.49" -> "apache 2.4.49"
        sig_clean = signature.lower().replace("/", " ").replace("-", " ")
        
        # Check both exact and cleaned versions
        if signature.lower() in nmap_lower or sig_clean in nmap_lower:
            report.append(f"   [☠️] {info['severity']}: {info['name']}")
            report.append(f"       > Detected: {signature}")
            report.append(f"       > CVE ID: {info['cve']}")
            found_cve = True
            
    if not found_cve:
        report.append("   [✓] No widely known legacy exploits matched in local DB.")
        
    return "\n".join(report), found_cve