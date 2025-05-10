# Server-Side Request Forgery (SSRF) Scanner Documentation

## Table of Contents
1. [Introduction](#introduction)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Core Components](#core-components)
5. [Detailed Code Analysis](#detailed-code-analysis)
6. [Usage Examples](#usage-examples)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)

## Introduction

The Server-Side Request Forgery (SSRF) Scanner is a sophisticated tool designed to detect and analyze SSRF vulnerabilities in web applications. This documentation provides a comprehensive explanation of the scanner's architecture, components, and functionality.

### What is SSRF?
Server-Side Request Forgery (SSRF) is a web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing. In typical SSRF examples, the attacker might cause the server to make a connection to internal-only services within the organization's infrastructure.

## System Requirements

- Python 3.6 or higher
- Required Python packages:
  - requests
  - beautifulsoup4
  - colorama
  - urllib3
  - concurrent.futures

## Installation

1. Clone the repository
2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Core Components

### 1. Main Scanner Class
The `SSRFScanner` class is the primary interface for the scanner. It handles:
- URL processing
- Payload management
- Thread management
- Proxy configuration
- Result collection

### 2. Payload Management
The scanner uses two types of payloads:
- SSRF payloads (stored in payload.txt)
- Path payloads (stored in pathpayload.txt)

### 3. Request Handling
The scanner implements multiple request methods:
- GET requests
- POST requests
- Custom header manipulation
- Proxy support

## Detailed Code Analysis

### 1. Import Statements and Dependencies
```python
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
from datetime import datetime
```

Each import serves a specific purpose:
- `concurrent.futures`: Enables parallel processing
- `requests`: Handles HTTP requests
- `BeautifulSoup`: Parses HTML content
- `colorama`: Provides colored terminal output
- `urllib3`: Manages HTTP connections
- `datetime`: Timestamps for results

### 2. Core Functions

#### 2.1 OS Detection
```python
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
```

This function analyzes server response headers to determine the underlying operating system.

#### 2.2 SSRF POST Request
```python
def ssrf_post(url, payload, param, session=None, return_bool=False, proxies=None):
    global results
    params = {param: payload}
    s = session or requests.Session()
    try:
        r = s.post(url, data=params, verify=False, timeout=5, proxies=proxies)
    except requests.exceptions.RequestException:
        return False
```

This function:
- Constructs POST requests with SSRF payloads
- Handles session management
- Processes responses
- Records results

#### 2.3 Payload Loading
```python
def load_payloads(filename):
    payloads = []
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):  
                payloads.append(line)
    return payloads
```

This function:
- Reads payload files
- Filters comments
- Returns clean payload list

### 3. URL Processing

#### 3.1 Content Fetching
```python
def fetch_content(url, timeout=5.0, proxies=None):
    try:
        response = requests.get(url, timeout=timeout, verify=False, proxies=proxies)
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        return ""
```

This function:
- Retrieves web page content
- Handles timeouts
- Manages proxy settings

#### 3.2 Link Extraction
```python
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
```

This function:
- Parses HTML content
- Extracts links
- Processes URL parameters
- Handles relative URLs

### 4. Result Management

#### 4.1 JSON Output
```python
def save_to_json(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
```

#### 4.2 CSV Output
```python
def save_to_csv(data, filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Payload", "Parameter"])
        for entry in data:
            writer.writerow([entry["URL"], entry["Payload"], entry["Parameter"]])
```

## Usage Examples

### Basic Usage
```python
scanner = SSRFScanner(
    url="http://example.com",
    output="json",
    threads=20
)
results = scanner.scan()
```

### Advanced Usage with Proxy
```python
scanner = SSRFScanner(
    url="http://example.com",
    output="csv",
    threads=50,
    proxy="127.0.0.1:8080",
    collaborator="your-collaborator-domain.com"
)
results = scanner.scan()
```

## Security Considerations

1. **Legal Compliance**
   - Always obtain proper authorization before scanning
   - Respect rate limits and scanning policies
   - Document all scanning activities

2. **Resource Management**
   - Monitor system resources during scanning
   - Implement proper timeout handling
   - Use appropriate thread limits

3. **Data Protection**
   - Secure storage of scan results
   - Proper handling of sensitive information
   - Regular cleanup of temporary files

## Troubleshooting

### Common Issues

1. **Connection Timeouts**
   - Check network connectivity
   - Verify proxy settings
   - Adjust timeout values

2. **Memory Issues**
   - Reduce thread count
   - Implement batch processing
   - Monitor system resources

3. **False Positives**
   - Verify results manually
   - Adjust detection thresholds
   - Update payload lists

### Best Practices

1. **Scanning Strategy**
   - Start with low thread count
   - Gradually increase scanning intensity
   - Monitor system performance

2. **Result Validation**
   - Cross-reference findings
   - Document false positives
   - Maintain result history

3. **Maintenance**
   - Regular payload updates
   - Code optimization
   - Documentation updates

## Conclusion

This SSRF scanner provides a comprehensive solution for detecting server-side request forgery vulnerabilities. By understanding and properly utilizing its components, security professionals can effectively identify and mitigate SSRF risks in web applications.

Remember to:
- Keep the tool updated
- Follow security best practices
- Document all scanning activities
- Respect target systems and policies

For additional support or feature requests, please refer to the project's issue tracker or documentation repository. 