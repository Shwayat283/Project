import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import warnings
from urllib3.exceptions import InsecureRequestWarning
import re
import html

# Suppress SSL warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

# ANSI Color Codes
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_WHITE = "\033[97m"
COLOR_RESET = "\033[0m"

class BaseLabScenario:
    """Base class for all lab scenarios with common functionality"""
    def detect(cls, response_text):
        """Check if this scenario matches the target"""
        raise NotImplementedError("Child classes must implement detect()")
        
    @property
    def lab_name(self):
        """Return human-readable lab name"""
        raise NotImplementedError("Child classes must implement lab_name")
        
    def solve(self):
        """Main method to solve the lab"""
        raise NotImplementedError("Child classes must implement solve()")
    
    def __init__(self, target_url, session):  # Accept session parameter
        self.target_url = target_url
        self.session = session  # Use existing session
        self.session.verify = False
        
        
    def get_csrf_token(self, text):
        """Extract CSRF token from HTML response"""
        soup = BeautifulSoup(text, 'html.parser')
        csrf_input = soup.find('input', {'name': 'csrf'})
        return csrf_input['value'] if csrf_input else None
    
    def login(self, username, password):
        """Common login functionality"""
        try:
            login_page = self.session.get(urljoin(self.target_url, "/login"))
            csrf_token = self.get_csrf_token(login_page.text)
            
            if not csrf_token:
                print("[-] Could not find CSRF token on login page")
                return False
            
            login_data = {
                "csrf": csrf_token,
                "username": username,
                "password": password
            }
            
            response = self.session.post(
                urljoin(self.target_url, "/login"),
                data=login_data
            )
            
            return "Log out" in response.text
            
        except Exception as e:
            print(f"[-] Login error: {str(e)}")
            return False
    
    def get_account_csrf(self):
        """Get CSRF token from account page"""
        try:
            account_page = self.session.get(urljoin(self.target_url, "/my-account"))
            return self.get_csrf_token(account_page.text)
        except Exception as e:
            print(f"[-] Error getting account CSRF: {str(e)}")
            return None

    def interactive_shell(self):
        """Provide interactive command execution interface"""
        print(f"\n{COLOR_GREEN}[+] Entering interactive shell{COLOR_RESET}")
        print(f"{COLOR_YELLOW}[!] Type 'exit' to quit{COLOR_RESET}")
        print(f"{COLOR_YELLOW}[!] Commands will be executed on the target server\n{COLOR_RESET}")
        
        while True:
            try:
                cmd = input(f"{COLOR_RED}shell{COLOR_RESET}{COLOR_WHITE}» {COLOR_RESET}").strip()
                if not cmd or cmd.lower() == "exit":
                    break
                    
                result = self.execute_command(cmd)
                print(f"{COLOR_WHITE}{result}{COLOR_RESET}" if result else f"{COLOR_RED}[-] No response{COLOR_RESET}")
                    
            except KeyboardInterrupt:
                print(f"\n{COLOR_RED}[-] Terminating session...{COLOR_RESET}")
                break
            except Exception as e:
                print(f"{COLOR_RED}[-] Error: {str(e)}{COLOR_RESET}")

    def execute_command(self, command):
        raise NotImplementedError("Child classes must implement execute_command")
