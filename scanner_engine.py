#MainEngineHere
#Date-13/12/2025
#Author- Lokesh Kumar
#github - @trmxvibs
#Madeinindia

import requests
import socket
from concurrent.futures import ThreadPoolExecutor
from modules.utils import clean_target, get_system_info 
from modules.intel import get_domain_intel, consult_oracle
from modules.network import run_nmap_scan, analyze_ssl_cert, find_subdomains, check_zone_transfer, active_subdomain_enum
from modules.web import detect_waf, detect_tech_stack, crawl_website_data, check_spring_boot, check_broken_links
from modules.infrastructure import scan_infrastructure, check_messaging_services, check_elastic_kibana
from modules.cloud_mobile import check_firebase, check_mobile_configs
from modules.exploit import api_zombie_fuzzer, generate_attack_commands, generate_metasploit_script, generate_dom_payloads
from modules.risk import calculate_risk_score
from modules.ai_strategist import analyze_attack_strategy
from modules.k8s_hunter import check_k8s_exposure
from modules.dark_intel import search_leaks
from modules.vulnerability import (
    deep_vuln_scanner, check_cve_vulnerabilities, directory_buster, 
    check_mass_takeover, enumerate_cms_users, check_ssrf, 
    check_time_based_sqli, check_host_header_injection, 
    check_git_exposure, check_reflected_xss, check_crlf_injection, analyze_jwt_tokens,
    check_ssti, check_graphql, check_nosql_injection, check_ldap_injection,
    check_race_condition, check_mass_assignment, check_parameter_tampering, check_rate_limit_bypass,
    check_cors, check_clickjacking, check_open_redirect, check_prototype_pollution,
    check_deserialization, check_verb_tampering, check_os_injection, check_backup_files,
    check_request_smuggling, check_websocket_security, 
    check_hpp, check_cache_poisoning, 
    check_ssi_injection, check_xpath_injection,
    check_xxe, check_idor_patterns,  
    crack_jwt_secret                  
)

def scan_target(domain, mode="basic", custom_flags="", previous_result=None, webhook=""):
    clean_host = clean_target(domain)
    results_dict = {}
    
    # --- PHASE 1: PARALLEL SCANNING ---
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {
            "intel": executor.submit(get_domain_intel, clean_host),
            "oracle": executor.submit(consult_oracle, clean_host),
            "nmap": executor.submit(run_nmap_scan, clean_host, mode, custom_flags),
            "waf": executor.submit(detect_waf, clean_host),
            "ssl": executor.submit(analyze_ssl_cert, clean_host)
        }
        
        if mode != "basic":
            futures["spider"] = executor.submit(crawl_website_data, clean_host) 
            futures["tech"] = executor.submit(detect_tech_stack, clean_host)
            futures["vuln"] = executor.submit(deep_vuln_scanner, clean_host)
            futures["subdomain"] = executor.submit(find_subdomains, clean_host) 
            futures["dir"] = executor.submit(directory_buster, clean_host)
            futures["cms"] = executor.submit(enumerate_cms_users, clean_host)
            futures["spring"] = executor.submit(check_spring_boot, clean_host)
            futures["blh"] = executor.submit(check_broken_links, clean_host)
            futures["firebase"] = executor.submit(check_firebase, clean_host)
            futures["mobile"] = executor.submit(check_mobile_configs, clean_host)
            
            # Protocols & Headers
            futures["host_inject"] = executor.submit(check_host_header_injection, clean_host)
            futures["crlf"] = executor.submit(check_crlf_injection, clean_host)
            futures["cors"] = executor.submit(check_cors, clean_host)
            futures["clickjack"] = executor.submit(check_clickjacking, clean_host)
            futures["cache"] = executor.submit(check_cache_poisoning, clean_host)
        
        if mode == "advance":
            futures["zone"] = executor.submit(check_zone_transfer, clean_host)
            futures["git"] = executor.submit(check_git_exposure, clean_host)
            futures["active_subs"] = executor.submit(active_subdomain_enum, clean_host)
            futures["graphql"] = executor.submit(check_graphql, clean_host)
            futures["proto"] = executor.submit(check_prototype_pollution, clean_host)
            futures["serial"] = executor.submit(check_deserialization, clean_host)
            futures["verb"] = executor.submit(check_verb_tampering, clean_host)
            futures["smuggle"] = executor.submit(check_request_smuggling, clean_host)
            futures["ws"] = executor.submit(check_websocket_security, clean_host)
            futures["rate"] = executor.submit(check_rate_limit_bypass, clean_host)
            futures["k8s"] = executor.submit(check_k8s_exposure, clean_host)
            futures["dark"] = executor.submit(search_leaks, clean_host)

        for key, future in futures.items():
            try: results_dict[key] = future.result()
            except Exception as e: results_dict[key] = f"[-] Module {key} error: {str(e)}"

    # --- PHASE 2: ASSEMBLY ---
    final = []
    final.append(f"[*] TARGET: {clean_host}")
    final.append(f"[*] MODE: {mode.upper()}")
    
    # 1. Recon & Intel
    final.append(results_dict.get("intel",""))
    final.append(results_dict.get("oracle",""))
    final.append(results_dict.get("waf",""))
    final.append(results_dict.get("ssl",""))
    
    sub_res = results_dict.get("subdomain", ("", []))
    sub_text = sub_res[0] if isinstance(sub_res, tuple) else sub_res
    sub_list = sub_res[1] if isinstance(sub_res, tuple) else []
    final.append(sub_text)
    
    if "active_subs" in results_dict: final.append(results_dict["active_subs"])
    if sub_list and mode == "advance": final.append(check_mass_takeover(sub_list))
    if "zone" in results_dict: final.append(results_dict["zone"])
    
    # 2. Scanning
    scan_out = results_dict.get("nmap","")
    final.append(scan_out)
    
    if "open" in scan_out:
        final.append(scan_infrastructure(clean_host, scan_out))
        try: final.append(check_messaging_services(socket.gethostbyname(clean_host), scan_out))
        except: pass
    final.append(check_elastic_kibana(clean_host))

    # 3. Vulnerabilities
    if "vuln" in results_dict: final.append(results_dict["vuln"])
    if "dir" in results_dict: final.append(results_dict["dir"])
    if "cms" in results_dict: final.append(results_dict["cms"])
    if "git" in results_dict: final.append(results_dict["git"])
    if "spring" in results_dict: final.append(results_dict["spring"])
    if "blh" in results_dict: final.append(results_dict["blh"])
    
    # Cloud & Mobile
    if "firebase" in results_dict: final.append(results_dict["firebase"])
    if "mobile" in results_dict: final.append(results_dict["mobile"])

    # Protocols
    if "host_inject" in results_dict: final.append(results_dict["host_inject"])
    if "crlf" in results_dict: final.append(results_dict["crlf"])
    if "cors" in results_dict: final.append(results_dict["cors"])
    if "clickjack" in results_dict: final.append(results_dict["clickjack"])
    if "proto" in results_dict: final.append(results_dict["proto"])
    if "serial" in results_dict: final.append(results_dict["serial"])
    if "verb" in results_dict: final.append(results_dict["verb"])
    if "smuggle" in results_dict: final.append(results_dict["smuggle"])
    if "ws" in results_dict: final.append(results_dict["ws"])
    if "rate" in results_dict: final.append(results_dict["rate"])
    if "graphql" in results_dict: final.append(results_dict["graphql"])
    if "cache" in results_dict: final.append(results_dict["cache"])

    # 4. Web Data & API
    spider_res = results_dict.get("spider", ("", set()))
    spider_text = spider_res[0] if isinstance(spider_res, tuple) else spider_res
    endpoints = spider_res[1] if isinstance(spider_res, tuple) else set()
    
    final.append(spider_text)
    final.append(api_zombie_fuzzer(endpoints, clean_host))
    if "DOM RISK" in spider_text:
        if "innerHTML" in spider_text:
            final.append(generate_dom_payloads(f"http://{clean_host}", "innerHTML"))
        elif "eval" in spider_text:
            final.append(generate_dom_payloads(f"http://{clean_host}", "eval"))
            
    
    # Post-Scan Attacks (Sequential)
    if mode == "advance" and endpoints:
        final.append(check_ssrf(clean_host, endpoints))
        final.append(check_time_based_sqli(clean_host, endpoints))
        final.append(check_reflected_xss(clean_host, endpoints))
        final.append(check_os_injection(clean_host, endpoints))
        final.append(check_backup_files(clean_host, endpoints))
        final.append(check_xxe(clean_host, endpoints))
        final.append(check_idor_patterns(clean_host, endpoints))
        final.append(check_nosql_injection(clean_host, endpoints))
        final.append(check_ldap_injection(clean_host, endpoints))
        final.append(check_race_condition(clean_host, endpoints))
        final.append(check_mass_assignment(clean_host, endpoints))
        final.append(check_parameter_tampering(clean_host, endpoints))
        final.append(check_hpp(clean_host, endpoints))
        final.append(check_ssi_injection(clean_host, endpoints))
        final.append(check_xpath_injection(clean_host, endpoints))
    
    final.append(check_cve_vulnerabilities(scan_out))
    if "k8s" in results_dict: final.append(results_dict["k8s"])
    if "dark" in results_dict: final.append(results_dict["dark"])
    
    # 5. JWT Analysis & Cracking
    full_raw_text = "\n".join(final)
    final.append(analyze_jwt_tokens(full_raw_text))
    final.append(crack_jwt_secret(full_raw_text))

    # 6. Strategy & Exploits
    tech_res = results_dict.get("tech", ("", []))
    tech_text = tech_res[0] if isinstance(tech_res, tuple) else tech_res
    tech_list = tech_res[1] if isinstance(tech_res, tuple) else []
    final.append(tech_text)
    
    final.append(generate_attack_commands(clean_host, scan_out, []))
    final.append(generate_metasploit_script(clean_host, scan_out))
    
    # 7. AI & Scoring
    ai_blueprint = analyze_attack_strategy(full_raw_text, tech_list)
    final.append(ai_blueprint)
    
    full_text = "\n".join(final)
    score = calculate_risk_score(full_text)
    label = "CRITICAL" if score > 70 else "MEDIUM" if score > 30 else "LOW"
    
    final_report = f"\n[★] RISK SCORE: {score}/100 ({label})\n" + "-"*40 + "\n" + full_text
    
    if webhook:
        try: requests.post(webhook, json={"content": f"Scan Finished: {clean_host}\nRisk: {score}"})
        except: pass
    

    return final_report
