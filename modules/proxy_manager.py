#proxy_manager.py
#Date-13/12/2025
#Author- Lokesh Kumar
#github - @trmxvibs
#Madeinindia

import requests
import random
import time

class ProxyManager:
    def __init__(self):
        self.tor_proxy = "socks5://127.0.0.1:9050"
        self.use_tor = True
        # Free Proxy List (Demo ke liye - Production mein Premium use karein)
        self.proxies = [
            "http://20.206.106.192:80",
            "http://20.210.113.32:8123",
            "http://144.24.113.197:80",
            "http://144.217.101.245:3128"
        ]
        self.current_index = 0

    def set_tor_mode(self, enabled=True):
        self.use_tor = enabled
        print(f"[*] PROXY MODE: {'TOR NETWORK (ON)' if enabled else 'ROTATING PROXIES'}")

    def get_proxy(self):
        """Returns a proxy dictionary for requests"""
        if self.use_tor:
            return {"http": self.tor_proxy, "https": self.tor_proxy}
        
        # Round Robin Rotation
        proxy = self.proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxies)
        return {"http": proxy, "https": proxy}

    def verify_ip(self):
        """Checks actual outgoing IP"""
        try:
            p = self.get_proxy()
            ip = requests.get("http://api.ipify.org", proxies=p, timeout=5).text
            return ip
        except:
            return "Connection Failed"

# Global Instance

proxy_rotator = ProxyManager()
