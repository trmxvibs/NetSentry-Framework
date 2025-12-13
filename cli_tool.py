#cli_tool.py
#Date-13/12/2025
#Author- Lokesh Kumar 
#github - @trmxvibs

import argparse
import os
import time
import sys
import re
import threading
import itertools
import getpass
import json
import hashlib
from datetime import datetime

# --- SYSTEM SETUP ---
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# File Paths
SESSION_FILE = os.path.join(current_dir, ".net_sentry_session")
SECRETS_FILE = os.path.join(current_dir, ".net_sentry_secrets.json")
SESSION_TIMEOUT = 1800  # 30 Minutes

# Default Credentials (Initial Setup)
DEFAULT_USER = "lokesh"
DEFAULT_PASS = "lokesh"

# Try importing scanner engine safely
try:
    from scanner_engine import scan_target
except ImportError:
    def scan_target(t, m, f): return "Error: Engine not found."

os.system('') # Enable colors

class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    CYAN = '\033[36m'
    NEON_RED = '\033[91m'
    NEON_GREEN = '\033[92m'
    NEON_YELLOW = '\033[93m'
    NEON_BLUE = '\033[94m'
    NEON_CYAN = '\033[96m'
    NEON_WHITE = '\033[97m'
    BG_RED = '\033[41m'
    BG_BLUE = '\033[44m'

# --- UTILITIES ---

def clear_console():
    if os.name == 'nt':
        _ = os.system('cls')
    else:
        _ = os.system('clear')

def get_time():
    return datetime.now().strftime("%H:%M:%S")

def log(type_tag, message):
    time_str = f"{Colors.DIM}[{get_time()}]{Colors.RESET}"
    if type_tag == "INFO": prefix = f"{Colors.NEON_BLUE}[*]{Colors.RESET}"
    elif type_tag == "SUCCESS": prefix = f"{Colors.NEON_GREEN}[+]{Colors.RESET}"
    elif type_tag == "WARN": prefix = f"{Colors.YELLOW}[!]{Colors.RESET}"
    elif type_tag == "ERROR": prefix = f"{Colors.NEON_RED}[-]{Colors.RESET}"
    elif type_tag == "LOCKED": prefix = f"{Colors.NEON_CYAN}[TARGET]{Colors.RESET}"
    else: prefix = f"[{type_tag}]"
    print(f"{time_str} {prefix} {message}")

def hash_password(password):
    """Securely hash passwords using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

# --- CREDENTIAL MANAGEMENT ---

def load_credentials():
    """Load credentials from file or return defaults"""
    if os.path.exists(SECRETS_FILE):
        try:
            with open(SECRETS_FILE, 'r') as f:
                return json.load(f)
        except:
            pass # Fallback if file corrupted
    
    # Return Default (Hashed)
    return {
        "username": DEFAULT_USER,
        "password_hash": hash_password(DEFAULT_PASS)
    }

def save_credentials(username, password):
    """Save new credentials securely"""
    data = {
        "username": username,
        "password_hash": hash_password(password)
    }
    with open(SECRETS_FILE, 'w') as f:
        json.dump(data, f)
    print(f"\n{Colors.NEON_GREEN}[✓] SYSTEM CREDENTIALS UPDATED SUCCESSFULLY.{Colors.RESET}")
    # Clear session to force re-login
    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)

def change_password_wizard():
    """Interactive wizard to change login details"""
    clear_console()
    print(f"{Colors.NEON_YELLOW}")
    print("╔════════════════════════════════════════════╗")
    print("║        ADMINISTRATIVE CONFIGURATION        ║")
    print("╚════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")
    
    creds = load_credentials()
    
    # Verify Old Password
    print(f"{Colors.DIM}[Security Check] Please enter current credentials.{Colors.RESET}")
    user_input = input(f"{Colors.BOLD} [?] Current User:{Colors.RESET} ")
    pass_input = getpass.getpass(f"{Colors.BOLD} [?] Current Pass:{Colors.RESET} ")
    
    if user_input != creds['username'] or hash_password(pass_input) != creds['password_hash']:
        print(f"\n{Colors.NEON_RED}[!] SECURITY CHECK FAILED. ABORTING.{Colors.RESET}")
        sys.exit(1)
        
    print(f"\n{Colors.NEON_CYAN}[*] Identity Verified. Enter NEW credentials.{Colors.RESET}")
    
    new_user = input(f"{Colors.BOLD} [?] New Username:{Colors.RESET} ")
    new_pass = getpass.getpass(f"{Colors.BOLD} [?] New Password:{Colors.RESET} ")
    confirm_pass = getpass.getpass(f"{Colors.BOLD} [?] Confirm Pass:{Colors.RESET} ")
    
    if new_pass != confirm_pass:
        print(f"\n{Colors.NEON_RED}[!] Passwords do not match! Try again.{Colors.RESET}")
        sys.exit(1)
        
    save_credentials(new_user, new_pass)
    sys.exit(0)

# --- SESSION & AUTH SYSTEM ---

def update_session():
    with open(SESSION_FILE, 'w') as f:
        f.write(str(time.time()))

def check_session():
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, 'r') as f:
                last_active = float(f.read().strip())
            if time.time() - last_active < SESSION_TIMEOUT:
                return True
        except:
            return False
    return False

def authenticate_user():
    if check_session():
        update_session() 
        return

    clear_console()
    print(f"\n{Colors.NEON_BLUE}")
    print("╔════════════════════════════════════════════╗")
    print("║          NET-SENTRY ACCESS CONTROL         ║")
    print("╚════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")
    
    creds = load_credentials()

    try:
        user_input = input(f"{Colors.BOLD} [?] IDENTITY :{Colors.RESET} ")
        pass_input = getpass.getpass(f"{Colors.BOLD} [?] AUTH CODE:{Colors.RESET} ")

        print(f"\n{Colors.DIM}[*] Verifying biometric signature...{Colors.RESET}")
        time.sleep(0.8) 

        # Validate Hash
        if user_input == creds['username'] and hash_password(pass_input) == creds['password_hash']:
            print(f"{Colors.NEON_GREEN}[✓] ACCESS GRANTED.{Colors.RESET}")
            time.sleep(0.5)
            update_session() 
            clear_console()
            return
        else:
            print(f"{Colors.NEON_RED}[X] ACCESS DENIED.{Colors.RESET}")
            sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)

# --- ANIMATED SPINNER ---
class Spinner:
    def __init__(self, message="Scanning"):
        self.spinner = itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'])
        self.running = False
        self.message = message
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._animate, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
        sys.stdout.write('\r' + ' ' * (len(self.message) + 10) + '\r')
        sys.stdout.flush()

    def _animate(self):
        while self.running:
            sys.stdout.write(f'\r{Colors.NEON_CYAN}{next(self.spinner)}{Colors.RESET} {self.message}...')
            sys.stdout.flush()
            time.sleep(0.1)

def print_banner():
    NAME = "LOKESH KUMAR"

    banner = f"""{Colors.NEON_CYAN}{Colors.BOLD}
    ███╗   ██╗███████╗████████╗      ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
    ████╗  ██║██╔════╝╚══██╔══╝      ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
    ██╔██╗ ██║█████╗     ██║   █████╗███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
    ██║╚██╗██║██╔══╝     ██║   ╚════╝╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  
    ██║ ╚████║███████╗   ██║         ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   
    ╚═╝  ╚═══╝╚══════╝   ╚═╝         ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   
    {Colors.RESET}
    {Colors.NEON_GREEN}  [ SYSTEM ONLINE ]{Colors.RESET} | {Colors.NEON_RED}  [ GOD MODE ]{Colors.RESET} | {Colors.NEON_YELLOW} {NAME} {Colors.RESET}
    """
    print(banner)


def print_summary_table(target, duration, risk_score):
    print(f"\n{Colors.NEON_WHITE}╔══════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.NEON_WHITE}║               MISSION DEBRIEF / SUMMARY              ║{Colors.RESET}")
    print(f"{Colors.NEON_WHITE}╠═════════════════════════════╦════════════════════════╣{Colors.RESET}")
    print(f"║ {Colors.BOLD}Target{Colors.RESET}                      ║ {str(target).ljust(22)} ║")
    print(f"║ {Colors.BOLD}Duration{Colors.RESET}                    ║ {str(duration).ljust(22)} ║")
    
    if risk_score > 70: r_color = Colors.NEON_RED
    elif risk_score > 30: r_color = Colors.YELLOW
    else: r_color = Colors.NEON_GREEN
    
    score_display = f"{r_color}{str(risk_score)}/100{Colors.RESET}"
    visible_length = len(f"{risk_score}/100") 
    padding = 22 - visible_length
    print(f"║ {Colors.BOLD}Risk Score{Colors.RESET}                  ║ {score_display}{' ' * padding} ║")
    print(f"{Colors.NEON_WHITE}╚═════════════════════════════╩════════════════════════╝{Colors.RESET}")

def colorize_output(raw_text):
    if not raw_text: return f"{Colors.RED}[!] No data.{Colors.RESET}", 0
    lines = raw_text.split('\n')
    colored_lines = []
    risk_score = 0
    for line in lines:
        processed = line
        if "RISK SCORE" in line:
            score_match = re.search(r"RISK SCORE: (\d+)", line)
            if score_match: risk_score = int(score_match.group(1))
            if risk_score > 70: processed = f"\n{Colors.BG_RED}{Colors.NEON_WHITE}{Colors.BOLD} {line.strip()} {Colors.RESET}\n"
            else: processed = f"\n{Colors.NEON_GREEN}{Colors.BOLD} {line.strip()} {Colors.RESET}\n"
        elif "[☠️]" in line or "CRITICAL" in line: processed = f"{Colors.NEON_RED}{Colors.BOLD}{line}{Colors.RESET}"
        elif "[$$$]" in line: processed = f"{Colors.NEON_YELLOW}{Colors.BOLD}{line}{Colors.RESET}"
        elif "[✓]" in line or "[+]" in line: processed = f"{Colors.NEON_GREEN}{line}{Colors.RESET}"
        elif "[i]" in line: processed = f"{Colors.NEON_BLUE}{line}{Colors.RESET}"
        elif "[*]" in line and "REPORT" not in line: processed = f"\n{Colors.BG_BLUE}{Colors.NEON_WHITE}{Colors.BOLD} {line.strip()} {Colors.RESET}"
        colored_lines.append(processed)
    return "\n".join(colored_lines), risk_score

def main():
    # Parse arguments first to check for Configuration Mode
    parser = argparse.ArgumentParser(description="Net-Sentry Professional CLI")
    
    # Optional args
    parser.add_argument("-t", "--target", help="Target IP or Domain")
    parser.add_argument("-m", "--mode", choices=['basic', 'medium', 'advance', 'custom'], default='basic', help="Scan Profile")
    parser.add_argument("--flags", help="Custom Nmap Flags", default="")
    parser.add_argument("-o", "--output", help="Save report to file", action="store_true")
    
    # New Admin Switch
    parser.add_argument("--config", help="Reset Admin Username/Password", action="store_true")
    
    args = parser.parse_args()

    # CHECK FOR CONFIG MODE
    if args.config:
        change_password_wizard()
        return

    # Normal Flow: Authenticate -> Scan
    if not args.target:
        # Manually clear and show help if no target provided (since required=True is removed for --config support)
        clear_console()
        print_banner()
        print(f"\n{Colors.NEON_RED}[!] Error: Target is required unless using --config{Colors.RESET}")
        print(f"{Colors.YELLOW}Usage: python cli_tool.py -t <target> [-m mode] [--config]{Colors.RESET}")
        sys.exit(1)

    clear_console()
    authenticate_user()

    print_banner()
    
    print(f"{Colors.NEON_WHITE}--------------------------------------------------------------------------{Colors.RESET}")
    log("LOCKED", f"{Colors.BOLD}{args.target}{Colors.RESET}")
    log("INFO",   f"Profile: {Colors.BOLD}{args.mode.upper()}{Colors.RESET}")
    print(f"{Colors.NEON_WHITE}--------------------------------------------------------------------------{Colors.RESET}\n")

    spinner = Spinner(f"Engaging {args.target}")
    spinner.start()

    try:
        start_time = time.time()
        result_text = scan_target(args.target, args.mode, args.flags)
        spinner.stop()
        
        colored_text, risk_score = colorize_output(result_text)
        print("\n" + colored_text)
        print_summary_table(args.target, f"{round(time.time() - start_time, 2)}s", risk_score)

        if args.output:
            filename = f"report_{args.target}.txt"
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            clean_text = ansi_escape.sub('', result_text if result_text else "")
            with open(filename, "w", encoding="utf-8") as f: f.write(clean_text)
            log("SUCCESS", f"Intelligence saved to: {Colors.BOLD}{filename}{Colors.RESET}")

    except KeyboardInterrupt:
        spinner.stop()
        print(f"\n\n{Colors.NEON_RED}[!] MISSION ABORTED{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        spinner.stop()
        log("ERROR", f"System Failure: {e}")

if __name__ == "__main__":
    main()
