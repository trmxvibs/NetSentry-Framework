#proxy_manager.py
#Date-13/12/2025
#Author- Lokesh Kumar (Updated: Identity Rotation & Fail-safe)
#update-on-16/02/2026
#github - @trmxvibs
#Madeinindia

import requests
import random
import time

class ProxyManager:
    def __init__(self):
        self.use_proxies = False # Default off unless configured
        self.proxies = []
        self.current_index = 0
        
        # Professional User-Agent List (Mix of OS and Browsers)
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0"
        ]

    def load_proxies_from_file(self, filepath="proxies.txt"):
        """Loads proxies from a text file (Format: ip:port or user:pass@ip:port)"""
        try:
            with open(filepath, "r") as f:
                self.proxies = [line.strip() for line in f if line.strip()]
            if self.proxies:
                self.use_proxies = True
                print(f"[*] ProxyManager: Loaded {len(self.proxies)} proxies.")
            else:
                print("[!] ProxyManager: File is empty.")
        except FileNotFoundError:
            print("[!] ProxyManager: proxies.txt not found. Running in Direct Mode.")

    def get_headers(self):
        """Returns headers with a random User-Agent to avoid detection"""
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

    def get_proxy(self):
        """Returns the next proxy in the rotation or None"""
        if not self.use_proxies or not self.proxies:
            return None
        
        # Round Robin Selection
        proxy_url = self.proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxies)
        
        # Support for HTTP/HTTPS
        # Ensure your proxy string format is correct (e.g., http://1.2.3.4:8080)
        if not proxy_url.startswith("http"):
             proxy_url = f"http://{proxy_url}"
             
        return {"http": proxy_url, "https": proxy_url}

    def verify_connection(self):
        """Self-test to check if current configuration works"""
        try:
            proxy = self.get_proxy()
            headers = self.get_headers()
            print("[*] Testing connection...")
            
            start = time.time()
            ip = requests.get("http://api.ipify.org", proxies=proxy, headers=headers, timeout=10).text
            latency = round(time.time() - start, 2)
            
            return f"Connected! IP: {ip} (Latency: {latency}s)"
        except Exception as e:
            return f"Connection Failed: {str(e)}"

# Global Instance
proxy_rotator = ProxyManager()
# Optional: Auto-load on import if file exists
# proxy_rotator.load_proxies_from_file()
