import urllib3
from modules.config import make_request

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_k8s_exposure(domain):
    report = ["\n[*] KUBERNETES & CLOUD HUNTER:"]
    vuln_found = False
    
    # Common K8s Ports & Endpoints
    # 6443: API Server | 10250: Kubelet API | 2379: etcd
    checks = [
        {"port": 6443, "path": "/version", "name": "K8s API Server"},
        {"port": 10250, "path": "/pods", "name": "Kubelet API (RCE Risk)"},
        {"port": 2379, "path": "/version", "name": "etcd Database"},
        {"port": 443, "path": "/api/v1/namespaces/kube-system/secrets", "name": "K8s Secrets Exposure"}
    ]

    for check in checks:
        url = f"https://{domain}:{check['port']}{check['path']}"
        try:
            # Using our new Stealth Proxy Request
            res = make_request(url, timeout=4)
            
            if res and res.status_code == 200:
                # Analyze response to confirm it's actually K8s
                if "major" in res.text or "items" in res.text or "etcd" in res.text:
                    report.append(f"   [☠️] CRITICAL: {check['name']} EXPOSED!")
                    report.append(f"       > URL: {url}")
                    report.append(f"       > Access: ANONYMOUS (No Auth needed)")
                    vuln_found = True
            elif res and res.status_code == 403:
                report.append(f"   [⚠️] DETECTED: {check['name']} is live (Access Denied).")
        except: pass

    # Cloud Metadata Check (For AWS/GCP/Azure) if hosted on cloud
    cloud_url = f"http://{domain}/latest/meta-data/"
    try:
        res = make_request(cloud_url, timeout=2)
        if res and res.status_code == 200 and "ami-id" in res.text:
             report.append(f"   [☠️] CRITICAL: AWS METADATA LEAKED via HTTP!")
             vuln_found = True
    except: pass

    if not vuln_found:
        report.append("   [✓] Kubernetes & Cloud endpoints appear secured.")
        
    return "\n".join(report)