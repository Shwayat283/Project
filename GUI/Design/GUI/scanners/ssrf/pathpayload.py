import concurrent.futures, subprocess, re, time, ipaddress
from urllib.parse import quote, urljoin, urlparse, parse_qs, urlunparse
import requests, urllib3
from bs4 import BeautifulSoup
from colorama import Fore, Style
import shutil
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
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
def path_payload(url, pay,param,payloads):
    payload = {
        param: pay
    }
    session = requests.Session()


    response = session.get(url)
    default_headers = response.request.headers
    headers = {
        "Host": response.url.split("/")[2],  
        "Cookie": response.headers.get("Set-Cookie", ""),   
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": default_headers.get("User-Agent", "Mozilla/5.0"),
        "Referer": response.url
    }
    try:
        r = session.post(url, data=payload, headers=headers, verify=False, timeout=5)
    except requests.exceptions.RequestException as e:
        return
    if payloads in r.text.lower():
        print("true")
        return
        
def fetch_content(url):
    try:
        return requests.get(url, verify=False, timeout=5).text
    except requests.exceptions.RequestException:
        return ""       
def fetch_content(url: str, timeout: float = 5.0) -> str:

    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()   # يرفع استثناء إذا كان رمز الحالة >= 400
        return response.text
    except requests.RequestException:
        return ""
  
def extract_fields(pattern, content):
    return re.findall(pattern, content, re.IGNORECASE) or []
  
extract_actions = lambda content: extract_fields(r'action=["\'](.*?)["\']', content)
extract_values  = lambda content: extract_fields(r'value=["\'](.*?)["\']', content)
extract_names   = lambda content: extract_fields(r'name=["\'](.*?)["\']', content)
def load_payloads(filename):
    payloads = []
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):  
                payloads.append(line)
    return payloads
def url_encode(original_url):
    encoded = quote(original_url, safe="/")
    return re.sub(r"%([0-9A-F]{2})", lambda m: f"%{m.group(1).lower()}", encoded)

def filter_similar_urls(urls):
    unique, seen = [], set()
    for url in urls:
        base = urljoin(url, urlparse(url).path)
        if base not in seen:
            unique.append(url)
            seen.add(base)
    return unique
print("SSRF SCANNER STARTING")

base_url = input(f"▶ Enter target URL :").strip()

if base_url.endswith('/'):
    base_url = base_url[:-1]

main_page_content = fetch_content(base_url)
raw_links = set(re.findall(r'href=["\'](.*?)["\']', main_page_content))
absolute_links = {urljoin(base_url, link) for link in raw_links}
actions_list, value_fields_list, name_fields_list = [], [], []
for link in absolute_links:
    page_content = fetch_content(link)
    for func in (extract_actions, extract_values, extract_names):
        for item in func(page_content):
            if func == extract_actions and item not in actions_list:
                actions_list.append(item)
            elif func == extract_values and item not in value_fields_list:
                value_fields_list.append(item)
            elif func == extract_names and item not in name_fields_list:
                name_fields_list.append(item)

result_links = filter_similar_urls(absolute_links)

target_urls = [f"{base_url}{action}" for action in actions_list]


ssrf_payloads = load_payloads("payload.txt")
tar = []
for k in result_links:
    p = extract_links(k)
    p_cleaned = [url.replace(base_url, "") for url in p]
    tar.extend(p_cleaned)

with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    futures = []
    for target_url in target_urls:
        for payload in ssrf_payloads:
            for u in tar:
                combined = u + payload
                encoded_text = url_encode(combined)
                for n in name_fields_list:
                    futures.append(executor.submit(path_payload, target_url, encoded_text, n,payload))

    concurrent.futures.wait(futures)
