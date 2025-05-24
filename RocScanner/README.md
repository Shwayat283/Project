# Vulnerability Scanner GUI

A modern GUI application for scanning web applications for various vulnerabilities including LFI, XSS, SSRF, and SSTI.

## Features

- **LFI Scanner**: Scan for Local File Inclusion vulnerabilities
- **XSS Scanner**: Detect Cross-Site Scripting vulnerabilities
- **SSRF Scanner**: Identify Server-Side Request Forgery vulnerabilities
- **SSTI Scanner**: Find Server-Side Template Injection vulnerabilities
- **Modern UI**: Clean and intuitive user interface with dark theme
- **Multiple Output Formats**: Export results in JSON, CSV, or XML
- **Configurable Scanning**: Customize scan parameters for each vulnerability type
- **Progress Tracking**: Real-time scan progress and results display

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/vulnerability-scanner-gui.git
cd vulnerability-scanner-gui
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
python GUI.py
```

2. Select the type of vulnerability scan you want to perform from the main menu.

3. Configure the scan parameters:
   - Target URL or URL list
   - Proxy settings (optional)
   - Thread count
   - Output format
   - Additional scanner-specific options

4. Click "Start Scan" to begin the vulnerability scan.

5. View the results in the "Scan Results" tab.

## Project Structure

```
vulnerability-scanner-gui/
├── GUI.py                 # Main application entry point
├── BaseScannerWindow.py   # Base class for scanner windows
├── LFIScannerWindow.py    # LFI scanner interface
├── XSSScannerWindow.py    # XSS scanner interface
├── SSRFScannerWindow.py   # SSRF scanner interface
├── SSTIScannerWindow.py   # SSTI scanner interface
├── scanners/             # Scanner modules
│   ├── lfi/             # LFI scanner implementation
│   ├── xss/             # XSS scanner implementation
│   ├── ssrf/            # SSRF scanner implementation
│   └── ssti/            # SSTI scanner implementation
├── requirements.txt      # Project dependencies
└── README.md            # Project documentation
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning any systems. The authors are not responsible for any misuse or damage caused by this program. 