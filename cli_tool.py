import argparse
import os
import time
import sys
import re
# Ensure modules can be found
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner_engine import scan_target

# --- ADVANCED COLOR ENGINE ---
# Windows CMD me colors enable karne ke liye
os.system('')

class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    
    # Text Colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Neon/Bright Colors
    NEON_RED = '\033[91m'
    NEON_GREEN = '\033[92m'
    NEON_YELLOW = '\033[93m'
    NEON_BLUE = '\033[94m'
    NEON_PURPLE = '\033[95m'
    NEON_CYAN = '\033[96m'
    NEON_WHITE = '\033[97m'

    # Backgrounds
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_BLUE = '\033[44m'

def print_banner():
    banner = f"""{Colors.NEON_CYAN}{Colors.BOLD}
    ███╗   ██╗███████╗████████╗      ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
    ████╗  ██║██╔════╝╚══██╔══╝      ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
    ██╔██╗ ██║█████╗     ██║   █████╗███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
    ██║╚██╗██║██╔══╝     ██║   ╚════╝╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  
    ██║ ╚████║███████╗   ██║         ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   
    ╚═╝  ╚═══╝╚══════╝   ╚═╝         ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   
    {Colors.RESET}
    {Colors.NEON_PURPLE}    [ v64.0 - GOD MODE ] {Colors.RESET} | {Colors.NEON_GREEN} [ SYSTEM ONLINE ] {Colors.RESET} | {Colors.NEON_YELLOW} [ AUTHORIZED USE ONLY ] {Colors.RESET}
    {Colors.DIM}    --------------------------------------------------------------------------{Colors.RESET}
    """
    print(banner)

def loading_effect(task):
    sys.stdout.write(f"{Colors.NEON_BLUE}[*] {task}{Colors.RESET}")
    for _ in range(3):
        sys.stdout.write(f"{Colors.NEON_BLUE}.{Colors.RESET}")
        sys.stdout.flush()
        time.sleep(0.2)
    print(f" {Colors.NEON_GREEN}[DONE]{Colors.RESET}")

def colorize_output(raw_text):
    lines = raw_text.split('\n')
    colored_lines = []

    for line in lines:
        processed = line
        
        # HEADERS (Modules)
        if "[*]" in line and "REPORT" not in line:
            processed = f"\n{Colors.BG_BLUE}{Colors.NEON_WHITE}{Colors.BOLD} {line.strip()} {Colors.RESET}"
        
        # TARGET HEADER
        elif "[*] TARGET" in line or "[*] MODE" in line:
             processed = f"{Colors.NEON_CYAN}{Colors.BOLD}{line}{Colors.RESET}"

        # CRITICAL THREATS (Red Blinking)
        elif "[☠️]" in line or "CRITICAL" in line or "RCE" in line or "SQLi" in line:
            processed = f"{Colors.NEON_RED}{Colors.BOLD}{line}{Colors.RESET}"
        
        # LOOT / MONEY (Gold)
        elif "[$$$]" in line or "KEY LEAK" in line:
            processed = f"{Colors.NEON_YELLOW}{Colors.BOLD}{line}{Colors.RESET}"

        # WARNINGS (Orange)
        elif "[⚠️]" in line or "POTENTIAL" in line or "Warning" in line:
             processed = f"{Colors.YELLOW}{line}{Colors.RESET}"
        
        # SUCCESS / SAFE (Green)
        elif "[✓]" in line or "[+]" in line or "Safe" in line or "Secure" in line:
             processed = f"{Colors.NEON_GREEN}{line}{Colors.RESET}"
        
        # INFO (Blue)
        elif "[i]" in line:
             processed = f"{Colors.NEON_BLUE}{line}{Colors.RESET}"
        
        # WAF (Purple)
        elif "WAF DETECTED" in line:
             processed = f"{Colors.NEON_PURPLE}{Colors.BOLD}{line}{Colors.RESET}"
        
        # RISK SCORE (Dynamic Background)
        elif "RISK SCORE" in line:
             score_match = re.search(r"RISK SCORE: (\d+)", line)
             score = int(score_match.group(1)) if score_match else 0
             
             if score > 70:
                 color = Colors.BG_RED + Colors.NEON_WHITE + Colors.BOLD + Colors.BLINK
             elif score > 30:
                 color = Colors.YELLOW + Colors.BOLD
             else:
                 color = Colors.NEON_GREEN + Colors.BOLD
                 
             processed = f"\n{color} {line.strip()} {Colors.RESET}\n"

        colored_lines.append(processed)
    
    return "\n".join(colored_lines)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description=f"{Colors.NEON_CYAN}Net-Sentry CLI{Colors.RESET}")
    parser.add_argument("target", help="Target IP or Domain")
    parser.add_argument("-m", "--mode", choices=['basic', 'medium', 'advance', 'custom'], default='basic', help="Scan Mode")
    parser.add_argument("--flags", help="Custom Nmap Flags", default="")
    parser.add_argument("-o", "--output", help="Save report to file", action="store_true")
    
    args = parser.parse_args()

    print(f"{Colors.NEON_WHITE}--------------------------------------------------------------------------{Colors.RESET}")
    print(f"{Colors.NEON_GREEN}[+] TARGET LOCKED :{Colors.RESET} {Colors.BOLD}{args.target}{Colors.RESET}")
    print(f"{Colors.NEON_YELLOW}[+] SCAN PROFILE  :{Colors.RESET} {Colors.BOLD}{args.mode.upper()}{Colors.RESET}")
    print(f"{Colors.NEON_WHITE}--------------------------------------------------------------------------{Colors.RESET}\n")

    loading_effect("Initializing Neural Network")
    if args.mode == 'advance':
        loading_effect("Activating Offensive Modules (Fuzzers, Exploits)")
    loading_effect("Engaging Target")

    try:
        start_time = time.time()
        # Call the Engine
        result_text = scan_target(args.target, args.mode, args.flags)
        end_time = time.time()
        
        # Print Colored Result
        print(colorize_output(result_text))
        
        # Footer
        duration = round(end_time - start_time, 2)
        print(f"\n{Colors.NEON_WHITE}--------------------------------------------------------------------------{Colors.RESET}")
        print(f"{Colors.NEON_GREEN}[✓] MISSION ACCOMPLISHED in {duration}s{Colors.RESET}")
        
        # Save to File (Clean text, no colors)
        if args.output:
            filename = f"report_{args.target}.txt"
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            clean_text = ansi_escape.sub('', result_text)
            
            with open(filename, "w", encoding="utf-8") as f:
                f.write(clean_text)
            print(f"{Colors.NEON_CYAN}[+] Intelligence saved to: {Colors.BOLD}{filename}{Colors.RESET}")

    except KeyboardInterrupt:
        print(f"\n\n{Colors.NEON_RED}[!] MISSION ABORTED BY USER{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.BG_RED}[!] CRITICAL SYSTEM FAILURE: {e}{Colors.RESET}")

if __name__ == "__main__":
    main()