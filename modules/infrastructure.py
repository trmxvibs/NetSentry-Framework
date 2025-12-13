import socket
import requests
from modules.config import get_bypass_headers

def check_redis_open(ip):
    report = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        if s.connect_ex((ip, 6379)) == 0:
            s.send(b"INFO\r\n")
            if "redis_version" in s.recv(1024).decode():
                report.append(f"   [☠️] CRITICAL: REDIS UNPROTECTED! (Port 6379)")
        s.close()
    except: pass
    if report: return "\n[*] INFRA: REDIS CHECK:\n" + "\n".join(report)
    return ""

def check_memcached_open(ip):
    report = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        if s.connect_ex((ip, 11211)) == 0:
            s.send(b"stats\r\n")
            if "STAT pid" in s.recv(1024).decode():
                report.append(f"   [☠️] CRITICAL: MEMCACHED OPEN! (Port 11211)")
        s.close()
    except: pass
    if report: return "\n[*] INFRA: MEMCACHED CHECK:\n" + "\n".join(report)
    return ""

def grab_service_banners(ip, ports):
    report = ["\n[*] INFRA: SERVICE BANNERS:"]
    found = False
    targets = {21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP"}
    
    # Merge custom ports if needed, for now using standard list
    for port, name in targets.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((ip, port)) == 0:
                try: banner = s.recv(1024).decode().strip()
                except: banner = "No Banner"
                report.append(f"   [+] {name} ({port}): {banner}")
                found = True
                if port == 21 and "220" in banner:
                    s.send(b"USER anonymous\r\n")
                    if "331" in s.recv(1024).decode():
                        s.send(b"PASS anon\r\n")
                        if "230" in s.recv(1024).decode(): report.append(f"       └── [☠️] FTP ANONYMOUS ALLOWED!")
            s.close()
        except: pass
    if not found: return ""
    return "\n".join(report)

def check_elastic_kibana(domain):
    report = []
    try:
        r = requests.get(f"http://{domain}:9200/_cat/indices?v", headers=get_bypass_headers(), timeout=3)
        if r.status_code == 200 and ("health" in r.text or "status" in r.text):
            report.append(f"   [☠️] CRITICAL: ELASTICSEARCH OPEN! (Port 9200)")
    except: pass
    try:
        r = requests.get(f"http://{domain}:2375/version", headers=get_bypass_headers(), timeout=3)
        if r.status_code == 200 and "ApiVersion" in r.text:
            report.append(f"   [☠️] DEFCON 1: DOCKER API EXPOSED! (Port 2375)")
    except: pass
    if report: return "\n[*] CLOUD & CONTAINER:\n" + "\n".join(report)
    return ""

def check_messaging_services(ip, scan_text):
    report = []
    # Always check MQTT if Nmap hinted at it OR just to be safe
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)
        if s.connect_ex((ip, 1883)) == 0:
            s.send(b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00")
            resp = s.recv(1024)
            if len(resp) >= 4 and resp[0] == 0x20: report.append(f"   [☠️] CRITICAL: MQTT BROKER OPEN!")
        s.close()
    except: pass
    if report: return "\n[*] MESSAGING:\n" + "\n".join(report)
    return ""

def scan_infrastructure(domain, scan_text):
    try: ip = socket.gethostbyname(domain)
    except: return ""
    results = []
    
    # IMPROVED: Independent Checks (Don't rely 100% on Nmap text)
    results.append(check_redis_open(ip))
    results.append(check_memcached_open(ip))
    results.append(grab_service_banners(ip, []))
    results.append(check_messaging_services(ip, scan_text))
    
    if "2375" in scan_text or "9200" in scan_text or "Docker" in scan_text:
        results.append(check_elastic_kibana(domain))
        
    return "\n".join([r for r in results if r])