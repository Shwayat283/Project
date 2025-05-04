import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk
import json
import csv
import io
import concurrent.futures
import requests
import urllib3
from urllib.parse import quote, urljoin, urlparse, parse_qs, urlunparse
from bs4 import BeautifulSoup
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Vulnerability Scanner")
        self.geometry("1000x750")
        self.current_bg = "#1a1a1a"
        self.configure(bg=self.current_bg)
        self.style = ttk.Style(self)
        self.style.theme_use('alt')
        self._setup_styles()
        self._create_settings_button()
        self._create_main_menu()
    
    # ... [جميع الدوال السابقة تبقى كما هي حتى _open_scanner] ...

    def _open_scanner(self, vuln_type):
        self._saved_geometry = self.geometry()
        self._saved_state = self.state()
        self.withdraw()
        if vuln_type == "LFI":
            win = LFIScannerWindow(self)
        elif vuln_type == "SSRF":
            win = SSRFScannerWindow(self)  # إضافة نافذة SSRF
        elif vuln_type == "ColorTheme":
            win = ColorThemeWindow(self)
        else:
            win = GenericWindow(self, vuln_type)
        if 'zoomed' in self._saved_state:
            win.state('zoomed')
        else:
            win.geometry(self._saved_geometry)
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_child_close(win))
        win.mainloop()

class SSRFScannerWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("SSRF Scanner")
        self.configure(bg=self.parent.current_bg)
        self.style = ttk.Style(self)
        self.style.configure('Custom.TEntry', 
                             fieldbackground='#3d3d3d',
                             foreground='white',
                             insertcolor='white')
        self.style.configure('Accent.TButton', 
                             background='#ff9900',
                             foreground='black',
                             font=('Segoe UI', 11, 'bold'))
        self.style.map('Accent.TButton',
                       background=[('active', '#ffaa00'), ('pressed', '#ff8800')])
        self._create_widgets()
        self.results = []

    def _create_widgets(self):
        container = ttk.Frame(self, padding=15)
        container.pack(fill=tk.BOTH, expand=True)
        notebook = ttk.Notebook(container)
        notebook.pack(fill=tk.BOTH, expand=True)

        # إطار الإدخال
        input_frame = ttk.Frame(notebook)
        notebook.add(input_frame, text="Scan Configuration")
        
        ttk.Label(input_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=8)
        self.url_entry = ttk.Entry(input_frame, width=60, style='Custom.TEntry')
        self.url_entry.grid(row=0, column=1, columnspan=3, padx=5)
        
        ttk.Label(input_frame, text="URL List File:").grid(row=1, column=0, sticky=tk.W, pady=8)
        self.url_list_entry = ttk.Entry(input_frame, width=50, style='Custom.TEntry')
        self.url_list_entry.grid(row=1, column=1, columnspan=2, padx=5)
        ttk.Button(input_frame, text="Browse", command=self._browse_urllist).grid(row=1, column=3)
        
        ttk.Label(input_frame, text="Proxy:").grid(row=2, column=0, sticky=tk.W, pady=8)
        self.proxy_entry = ttk.Entry(input_frame, width=30, style='Custom.TEntry')
        self.proxy_entry.grid(row=2, column=1)
        
        ttk.Label(input_frame, text="Threads:").grid(row=2, column=2, sticky=tk.W)
        self.threads_entry = ttk.Entry(input_frame, width=10, style='Custom.TEntry')
        self.threads_entry.insert(0, "20")
        self.threads_entry.grid(row=2, column=3)
        
        ttk.Label(input_frame, text="Payload File:").grid(row=3, column=0, sticky=tk.W, pady=8)
        self.payload_entry = ttk.Entry(input_frame, width=50, style='Custom.TEntry')
        self.payload_entry.grid(row=3, column=1, columnspan=2)
        ttk.Button(input_frame, text="Browse", command=self._browse_payload).grid(row=3, column=3)
        
        # أزرار التحكم
        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill=tk.X, pady=10)
        self.back_button = ttk.Button(btn_frame, text="← Back", style='TButton', command=self._on_back)
        self.back_button.pack(side=tk.LEFT, padx=10)
        self.scan_button = ttk.Button(btn_frame, text="Start Scan ▶", style='Accent.TButton', command=self._start_scan)
        self.scan_button.pack(side=tk.RIGHT, padx=10)

        # نتائج الفحص
        result_frame = ttk.Frame(notebook)
        notebook.add(result_frame, text="Scan Results")
        self.result_text = scrolledtext.ScrolledText(result_frame, 
                                                    bg='#3d3d3d',
                                                    fg='#ffffff',
                                                    insertbackground='white',
                                                    relief='flat',
                                                    font=('Consolas', 10),
                                                    state='disabled')
        self.result_text.pack(fill=tk.BOTH, expand=True)

    def _browse_urllist(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            self.url_list_entry.delete(0, tk.END)
            self.url_list_entry.insert(0, path)

    def _browse_payload(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            self.payload_entry.delete(0, tk.END)
            self.payload_entry.insert(0, path)

    def _on_back(self):
        self.parent._on_child_close(self)

    def _start_scan(self):
        urls = []
        if self.url_list_entry.get().strip():
            try:
                with open(self.url_list_entry.get()) as f:
                    urls = [line.strip() for line in f if line.strip()]
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read URL list: {e}")
                return
        elif self.url_entry.get().strip():
            urls = [self.url_entry.get().strip()]
        else:
            messagebox.showerror("Error", "Please provide target URL(s)")
            return
        
        try:
            with open(self.payload_entry.get()) as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load payloads: {e}")
            return
        
        proxies = {}
        if self.proxy_entry.get().strip():
            proxies = {
                "http": f"http://{self.proxy_entry.get().strip()}",
                "https": f"http://{self.proxy_entry.get().strip()}"
            }
        
        self.scan_button.config(state='disabled')
        self._append_text("[*] Starting SSRF scan...\n")
        threading.Thread(target=self._run_scan, args=(urls, payloads, proxies), daemon=True).start()

    def _run_scan(self, urls, payloads, proxies):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=int(self.threads_entry.get())) as executor:
                futures = []
                for url in urls:
                    for payload in payloads:
                        futures.append(executor.submit(self._test_ssrf, url, payload, proxies))
                concurrent.futures.wait(futures)
            
            self._append_text(f"\n[+] Scan completed! Found {len(self.results)} vulnerabilities\n")
            self._display_results()
        except Exception as e:
            self._append_text(f"[!] Error: {str(e)}\n")
        finally:
            self.scan_button.config(state='normal')

    def _test_ssrf(self, url, payload, proxies):
        try:
            session = requests.Session()
            response = session.post(url, data={"url": payload}, verify=False, proxies=proxies, timeout=10)
            if response.status_code in [200, 302] and "ssrf" in response.text.lower():
                result = {
                    "url": url,
                    "payload": payload,
                    "status": response.status_code,
                    "length": len(response.text),
                    "timestamp": datetime.now().isoformat()
                }
                self.results.append(result)
                self._append_text(f"[+] Vulnerable: {url} | Payload: {payload}\n")
        except Exception as e:
            self._append_text(f"[!] Error testing {url}: {str(e)}\n")

    def _display_results(self):
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        for result in self.results:
            self.result_text.insert(tk.END, json.dumps(result, indent=2) + "\n")
        self.result_text.config(state='disabled')

    def _append_text(self, text):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state='disabled')

# ... [بقية الفئات (ColorThemeWindow, LFIScannerWindow, إلخ) تبقى كما هي] ...
class GenericWindow(tk.Toplevel):
    def __init__(self, parent, vuln_type):
        super().__init__(parent)
        self.parent = parent
        self.title(f"{vuln_type} Scanner")
        self.configure(bg=self.parent.current_bg)  # استخدام لون الخلفية الرئيسي
        frame = ttk.Frame(self, padding=20)
        frame.pack(expand=True)
        ttk.Label(frame, 
                  text=f"{vuln_type} scanner not implemented yet.", 
                  font=("Segoe UI", 14),
                  foreground="white").pack(pady=20)
        ttk.Button(frame, 
                   text="← Back", 
                   style='TButton',
                   command=self._on_back).pack(pady=10)

    def _on_back(self):
        self.parent._on_child_close(self)

class LFIScannerWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("LFI Scanner")
        self.configure(bg=self.parent.current_bg)  # استخدام لون الخلفية الرئيسي
        self.style = ttk.Style(self)
        self.style.configure('Custom.TEntry', 
                             fieldbackground='#3d3d3d',
                             foreground='white',
                             insertcolor='white',
                             bordercolor='#4d4d4d',
                             lightcolor='#4d4d4d',
                             darkcolor='#4d4d4d')
        self.style.configure('Accent.TButton', 
                             background='#ff9900',
                             foreground='black',
                             font=('Segoe UI', 11, 'bold'))
        self.style.map('Accent.TButton',
                       background=[('active', '#ffaa00'), ('pressed', '#ff8800')])
        self._create_widgets()

    def _create_widgets(self):
        container = ttk.Frame(self, padding=15)
        container.pack(fill=tk.BOTH, expand=True)
        notebook = ttk.Notebook(container)
        notebook.pack(fill=tk.BOTH, expand=True)
        input_frame = ttk.Frame(notebook)
        notebook.add(input_frame, text="Scan Configuration")
        ttk.Label(input_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=8)
        self.url_entry = ttk.Entry(input_frame, width=60, style='Custom.TEntry')
        self.url_entry.grid(row=0, column=1, columnspan=3, padx=5)
        ttk.Label(input_frame, text="URL-List File:").grid(row=1, column=0, sticky=tk.W, pady=8)
        self.url_list_entry = ttk.Entry(input_frame, width=50, style='Custom.TEntry')
        self.url_list_entry.grid(row=1, column=1, columnspan=2, padx=5)
        ttk.Button(input_frame, text="Browse", command=self._browse_urllist).grid(row=1, column=3)
        ttk.Label(input_frame, text="Auth URL:").grid(row=2, column=0, sticky=tk.W, pady=8)
        self.auth_url_entry = ttk.Entry(input_frame, width=60, style='Custom.TEntry')
        self.auth_url_entry.grid(row=2, column=1, columnspan=3, padx=5)
        ttk.Label(input_frame, text="Proxy:").grid(row=3, column=0, sticky=tk.W, pady=8)
        self.proxy_entry = ttk.Entry(input_frame, width=30, style='Custom.TEntry')
        self.proxy_entry.grid(row=3, column=1)
        ttk.Label(input_frame, text="Threads:").grid(row=3, column=2, sticky=tk.W)
        self.threads_entry = ttk.Entry(input_frame, width=10, style='Custom.TEntry')
        self.threads_entry.insert(0, "10")
        self.threads_entry.grid(row=3, column=3)
        ttk.Label(input_frame, text="Wordlist:").grid(row=4, column=0, sticky=tk.W, pady=8)
        self.wordlist_entry = ttk.Entry(input_frame, width=50, style='Custom.TEntry')
        self.wordlist_entry.grid(row=4, column=1, columnspan=2)
        ttk.Button(input_frame, text="Browse", command=self._browse_wordlist).grid(row=4, column=3)
        ttk.Label(input_frame, text="Username:").grid(row=5, column=0, sticky=tk.W, pady=8)
        self.user_entry = ttk.Entry(input_frame, width=20, style='Custom.TEntry')
        self.user_entry.grid(row=5, column=1)
        ttk.Label(input_frame, text="Password:").grid(row=5, column=2)
        self.pass_entry = ttk.Entry(input_frame, show="*", width=20, style='Custom.TEntry')
        self.pass_entry.grid(row=5, column=3)
        ttk.Label(input_frame, text="Cookies:").grid(row=6, column=0, sticky=tk.W, pady=8)
        self.cookies_entry = ttk.Entry(input_frame, width=60, style='Custom.TEntry')
        self.cookies_entry.grid(row=6, column=1, columnspan=3)
        ttk.Label(input_frame, text="Output Format:").grid(row=7, column=0, sticky=tk.W)
        self.output_var = tk.StringVar(value="json")
        ttk.OptionMenu(input_frame, self.output_var, "json", "json", "csv").grid(row=7, column=1, sticky=tk.W)
        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill=tk.X, pady=10)
        self.back_button = ttk.Button(btn_frame, 
                                      text="← Back", 
                                      style='TButton',
                                      command=self._on_back)
        self.back_button.pack(side=tk.LEFT, padx=10)
        self.scan_button = ttk.Button(btn_frame, 
                                       text="Start Scan ▶", 
                                       style='Accent.TButton',
                                       command=self._start_scan)
        self.scan_button.pack(side=tk.RIGHT, padx=10)
        result_frame = ttk.Frame(notebook)
        notebook.add(result_frame, text="Scan Results")
        self.result_text = scrolledtext.ScrolledText(result_frame, 
                                                     bg='#3d3d3d',
                                                     fg='#ffffff',
                                                     insertbackground='white',
                                                     relief='flat',
                                                     font=('Consolas', 10),
                                                     state='disabled')
        self.result_text.pack(fill=tk.BOTH, expand=True)

    def _browse_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, path)

    def _browse_urllist(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            self.url_list_entry.delete(0, tk.END)
            self.url_list_entry.insert(0, path)

    def _on_back(self):
        self.parent._on_child_close(self)

    def _start_scan(self):
        urls = []
        single = self.url_entry.get().strip()
        listfile = self.url_list_entry.get().strip()
        if not single and not listfile:
            messagebox.showerror("Input Error", "Target URL or URL-List file is required.")
            return
        if listfile:
            try:
                with open(listfile) as f:
                    urls = [line.strip() for line in f if line.strip()]
            except Exception as e:
                messagebox.showerror("File Error", f"Unable to read URL list: {e}")
                return
        else:
            urls = [single]
        params = {
            'proxy': self.proxy_entry.get().strip() or None,
            'threads': int(self.threads_entry.get()),
            'wordlist': self.wordlist_entry.get().strip() or None,
            'username': self.user_entry.get().strip() or None,
            'password': self.pass_entry.get().strip() or None,
            'cookies': self.cookies_entry.get().strip() or None,
            'auth_url': self.auth_url_entry.get().strip() or None
        }
        self.scan_button.config(state='disabled')
        self._append_text("Starting scan...\n")
        threading.Thread(target=self._run_scan, args=(urls, params), daemon=True).start()

    def _run_scan(self, urls, params):
        try:
            scanner = scanner_module.LFIScanner(
                proxy=params['proxy'], threads=params['threads'],
                wordlist=params['wordlist'], username=params['username'],
                password=params['password'], cookies=params['cookies']
            )
            if params['auth_url']:
                scanner.login_url = params['auth_url']
            all_results = []
            for url in urls:
                self._append_text(f"Scanning {url}...\n")
                results = scanner.scan(url)
                all_results.extend(results)
                scanner.visited_urls.clear()
                scanner.tested_combinations.clear()
                scanner.vulnerabilities.clear()
                scanner.exploitation_results.clear()
                scanner.base_domain = None
            self._display_results(all_results)
        except Exception as e:
            self._append_text(f"Error: {e}\n")
        finally:
            self.scan_button.config(state='normal')

    def _display_results(self, results):
        self._append_text(f"Scan complete. Found {len(results)} issues.\n")
        if self.output_var.get() == 'json':
            for item in results:
                self._append_text(json.dumps(item, indent=2) + "\n")
        else:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['url', 'parameter', 'payload', 'status', 'length', 'timestamp'])
            for item in results:
                writer.writerow([item.get(k, '') for k in ['url', 'parameter', 'payload', 'status', 'length', 'timestamp']])
            self._append_text(output.getvalue() + "\n")

    def _append_text(self, text):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state='disabled')

class ColorThemeWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Color Theme")
        self.configure(bg=self.parent.current_bg)
        self.style = ttk.Style(self)
        self.style.configure('Custom.TButton', 
                             background='#ff9900',
                             foreground='black',
                             font=('Segoe UI', 11, 'bold'))
        self.style.map('Custom.TButton',
                       background=[('active', '#ffaa00'), ('pressed', '#ff8800')])
        self._create_widgets()

    def _create_widgets(self):
        container = ttk.Frame(self, padding=15)
        container.pack(fill=tk.BOTH, expand=True)
        label = ttk.Label(container, 
                          text="Select a color theme:", 
                          font=("Segoe UI", 14),
                          foreground="white",
                          background=self.parent.current_bg)
        label.pack(pady=(20, 10))
        themes = [
            ("Dark Theme", "#1a1a1a"),
            ("Light Theme", "#f0f0f0"),
            ("Blue Theme", "#0078d4"),
            ("Green Theme", "#2ecc71")
        ]
        for text, color in themes:
            btn = ttk.Button(container, 
                             text=text,
                             style='Custom.TButton',
                             command=lambda c=color: self._apply_theme(c))
            btn.pack(fill=tk.X, pady=5)

        back_button = ttk.Button(container, 
                                 text="← Back", 
                                 style='Custom.TButton',
                                 command=self._on_back)
        back_button.pack(side=tk.BOTTOM, pady=10)

    def _apply_theme(self, color):
        self.parent.update_theme(color)  # استدعاء دالة التحديث في النافذة الرئيسية

    def _on_back(self):
        self.parent._on_child_close(self)

if __name__ == '__main__':
    app = ScannerApp()
    app.mainloop()