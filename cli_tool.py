import argparse
import os
import time
import sys
from scanner_engine import scan_target

# --- COLOR CODES ---
os.system('')  # Windows Compatibility

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'  # Orange/Gold
    FAIL = '\033[91m'     # Red
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    print(fr"""{Colors.CYAN}
    ======================================================
      _   _      _      ____             _7ry v29.0
     | \ | | ___| |_   / ___|  ___ _ __ | |_7ry
     |  \| |/ _ \ __|  \___ \ / _ \ '_ \| __|7ry
     | |\  |  __/ |_    ___) |  __/ | | | |_ 
     |_| \_|\___|\__|  |____/ \___|_| |_|\__|
    
     [ NET-SENTRY COMMAND LINE INTERFACE ]
     [ INTELLIGENCE | OFFENSE | DEFENSE  ]
    ======================================================{Colors.ENDC}
    """)

def loading_animation(text):
    # Fixed: Added 'r' to make it a raw string to handle backslash
    chars = r"/-\|" 
    for _ in range(10):
        for char in chars:
            sys.stdout.write(f'\r{Colors.WARNING}[{char}] {text}...{Colors.ENDC}')
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write('\r' + ' ' * 50 + '\r') # Clear line

def format_output(raw_text):
    """Parses the raw text and applies color coding for CLI"""
    lines = raw_text.split('\n')
    formatted_lines = []
    
    for line in lines:
        # 1. Critical Threats (Red)
        if "[☠️]" in line or "[!!!]" in line or "CRITICAL" in line:
            formatted_lines.append(f"{Colors.FAIL}{Colors.BOLD}{line}{Colors.ENDC}")
        
        # 2. Success / Safe (Green)
        elif "[✓]" in line or "[+]" in line or "Safe" in line:
            formatted_lines.append(f"{Colors.GREEN}{line}{Colors.ENDC}")
        
        # 3. Loot / Money (Gold)
        elif "[$$$]" in line or "KEY LEAK" in line:
            formatted_lines.append(f"{Colors.WARNING}{Colors.BOLD}{line}{Colors.ENDC}")
        
        # 4. Info / Headers (Blue)
        elif "[*]" in line or "REPORT" in line:
            formatted_lines.append(f"{Colors.BLUE}{Colors.BOLD}{line}{Colors.ENDC}")
        
        # 5. WAF (Purple/Cyan)
        elif "WAF DETECTED" in line:
            formatted_lines.append(f"{Colors.HEADER}{Colors.BOLD}{line}{Colors.ENDC}")
            
        # 6. Risk Score (Highlight)
        elif "RISK SCORE" in line:
            score_line = line
            if "CRITICAL" in line: color = Colors.FAIL
            elif "MEDIUM" in line: color = Colors.WARNING
            else: color = Colors.GREEN
            formatted_lines.append(f"\n{color}{Colors.BOLD}{'='*40}")
            formatted_lines.append(f" {score_line} ")
            formatted_lines.append(f"{'='*40}{Colors.ENDC}\n")
            
        # Default
        else:
            formatted_lines.append(line)
            
    return "\n".join(formatted_lines)

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Net-Sentry CLI: Advanced Recon Framework")
    # Target is mandatory positional argument
    parser.add_argument("target", help="Target Domain or IP (e.g. google.com)")
    parser.add_argument("-m", "--mode", 
                        choices=['basic', 'medium', 'advance', 'custom'], 
                        default='basic',
                        help="Scan Mode: basic (Fast), medium (Standard), advance (Full Power)")
    parser.add_argument("--flags", help="Custom Nmap flags (use with -m custom)", default="")
    
    # Optional: Save to file via CLI
    parser.add_argument("-o", "--output", help="Save report to text file", action="store_true")

    args = parser.parse_args()

    if args.mode == 'custom' and not args.flags:
        print(f"{Colors.FAIL}[!] Error: 'custom' mode requires --flags argument.{Colors.ENDC}")
        return

    print(f"{Colors.BLUE}[*] Target Locked: {Colors.BOLD}{args.target}{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Mode Selected: {Colors.BOLD}{args.mode.upper()}{Colors.ENDC}")
    
    loading_animation("Initializing Modules")
    
    if args.mode == 'advance':
        print(f"{Colors.WARNING}[i] Note: Advance mode includes Fuzzing & Spidering. This may take time.{Colors.ENDC}")

    # --- EXECUTE SCAN ---
    try:
        # Calling the same powerful engine used by the Web UI
        result_text = scan_target(args.target, args.mode, args.flags)
        
        # Print colorful output
        print(format_output(result_text))
        
        # Save to file if requested
        if args.output:
            filename = f"scan_{args.target}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(result_text)
            print(f"\n{Colors.CYAN}[+] Report saved to {filename}{Colors.ENDC}")

    except KeyboardInterrupt:
        print(f"\n{Colors.FAIL}[!] Scan Aborted by User.{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] System Error: {e}{Colors.ENDC}")

if __name__ == "__main__":
    main()