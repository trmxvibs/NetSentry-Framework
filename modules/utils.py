#utils.py
#Date-13/12/2025
#Author- Lokesh Kumar
#github - @trmxvibs
#Madeinindia
import socket
from urllib.parse import urlparse
import requests # Make sure requests is imported

def clean_target(target):
    target = target.strip()
    if "://" in target: return urlparse(target).hostname
    return target.split('/')[0]

def get_system_info():
    info = {'local_ip': 'Unknown', 'public_ip': 'Scanning...'}
    
    # 1. Get Local LAN IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info['local_ip'] = s.getsockname()[0]
        s.close()
    except: info['local_ip'] = "127.0.0.1"

    # 2. Get Public WAN IP 
    try:
        # Ipify API se Public IP maang rahe hain (Timeout 3 sec rakha hai taaki slow na ho)
        pub = requests.get('https://api.ipify.org', timeout=3).text
        info['public_ip'] = pub
    except: 
        info['public_ip'] = "Offline"
        

    return info
