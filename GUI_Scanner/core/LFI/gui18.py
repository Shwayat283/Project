import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk
import json
import csv
import io
import PathTraversalWithComment as scanner_module

class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Vulnerability Scanner")
        self.geometry("1000x750")
        self.current_bg = "#1a1a1a"  # متغير لتخزين اللون الحالي
        self.configure(bg=self.current_bg)
        self.style = ttk.Style(self)
        self.style.theme_use('alt')
        self._setup_styles()
        self._create_settings_button()
        self._create_main_menu()
    
    def _setup_styles(self):
        """تحديث الأنماط مع اللون الحالي"""
        self.style.configure('TFrame', background=self.current_bg)
        self.style.configure('TLabel', background=self.current_bg, foreground='#ffffff', font=('Segoe UI', 12))
        self.style.configure('TButton', font=('Segoe UI', 12, 'bold'), 
                             borderwidth=1, relief='flat',
                             background='#2d2d2d', foreground='#ffffff')
        self.style.map('TButton',
               background=[('active', '#3d3d3d'), ('pressed', '#4d4d4d')])
        self.style.configure('TLabelframe', background=self.current_bg, 
                             relief='flat', borderwidth=5,
                             foreground='#ff9900', font=('Segoe UI', 12, 'bold'))
        self.style.configure('TLabelframe.Label', background=self.current_bg, foreground='#ff9900')

    def _create_settings_button(self):
        self.settings_btn = tk.Menubutton(self, text='⚙', font=('Segoe UI', 16), bg=self.current_bg, fg='white', bd=0, relief='flat')
        settings_menu = tk.Menu(self.settings_btn, tearoff=0)
        settings_menu.add_command(label='Color Theme', command=self._open_color_theme)
        settings_menu.add_command(label='Help', command=self._open_help)
        settings_menu.add_separator()
        settings_menu.add_command(label='About', command=self._open_about)
        self.settings_btn.config(menu=settings_menu)
        self.settings_btn.place(x=10, y=10)

    def _open_color_theme(self):
        self._saved_geometry = self.geometry()
        self._saved_state = self.state()
        self.withdraw()
        win = ColorThemeWindow(self)
        if 'zoomed' in self._saved_state:
            win.state('zoomed')
        else:
            win.geometry(self._saved_geometry)
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_child_close(win))
        win.mainloop()

    def _open_help(self):
        messagebox.showinfo("Help", "مساعدة: اشرح كيفية استخدام الماسح هنا.")

    def _open_about(self):
        messagebox.showinfo("About", "Vulnerability Scanner v1.0\nDeveloped by YourName.")

    def _lighten_color(self, hex_color, factor=0.2):
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        new_rgb = [min(int(c + (255 - c) * factor), 255) for c in rgb]
        return f'#{new_rgb[0]:02x}{new_rgb[1]:02x}{new_rgb[2]:02x}'

    def _create_main_menu(self):
        frame = ttk.Frame(self)
        frame.pack(expand=True, fill=tk.BOTH, padx=50, pady=50)
        title = ttk.Label(frame, 
                          text="Vulnerability Scanner", 
                          font=("Segoe UI", 24, "bold"),
                          foreground="#ff9900")
        title.pack(pady=(30, 50))
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X)
        buttons = [
            ("SSRF", "#4CAF50"),
            ("SSTI", "#2196F3"),
            ("LFI", "#FF5722"),
            ("XSS", "#9C27B0")
        ]
        for text, color in buttons:
            btn = tk.Button(button_frame, 
                              text=text,
                              font=("Segoe UI", 16, "bold"),
                              bg=color,
                              fg="white",
                              activebackground=color,
                              activeforeground="white",
                              relief='flat',
                              width=25,
                              height=2,
                              bd=0,
                              command=lambda v=text: self._open_scanner(v))
            btn.pack(side=tk.TOP, fill=tk.X, pady=10)
            btn.bind("<Enter>", lambda e, b=btn, c=color: b.config(bg=self._lighten_color(c)))
            btn.bind("<Leave>", lambda e, b=btn, c=color: b.config(bg=c))

    def _open_scanner(self, vuln_type):
        self._saved_geometry = self.geometry()
        self._saved_state = self.state()
        self.withdraw()
        if vuln_type == "LFI":
            win = LFIScannerWindow(self)
        elif vuln_type == "SSRF":
            win = SSRFScannerWindow(self)
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

    def _on_child_close(self, window):
        if hasattr(self, '_saved_geometry'):
            self.geometry(self._saved_geometry)
        if hasattr(self, '_saved_state') and 'zoomed' in self._saved_state:
            self.state('zoomed')
        window.destroy()
        self.deiconify()

    def update_theme(self, color):
        """تحديث السمة الرئيسية"""
        self.current_bg = color
        self.configure(bg=color)
        self.settings_btn.config(bg=color)
        self._setup_styles()

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
        ttk.Label(input_frame, text="Proxy:").grid(row=2, column=0, sticky=tk.W, pady=8)
        self.proxy_entry = ttk.Entry(input_frame, width=30, style='Custom.TEntry')
        self.proxy_entry.grid(row=2, column=1)
        ttk.Label(input_frame, text="Threads:").grid(row=2, column=2, sticky=tk.W)
        self.threads_entry = ttk.Entry(input_frame, width=10, style='Custom.TEntry')
        self.threads_entry.insert(0, "10")
        self.threads_entry.grid(row=2, column=3)
        ttk.Label(input_frame, text="Payload List:").grid(row=3, column=0, sticky=tk.W, pady=8)
        self.payload_entry = ttk.Entry(input_frame, width=50, style='Custom.TEntry')
        self.payload_entry.grid(row=3, column=1, columnspan=2)
        ttk.Button(input_frame, text="Browse", command=self._browse_payload).grid(row=3, column=3)
        ttk.Label(input_frame, text="Path Payload List:").grid(row=4, column=0, sticky=tk.W, pady=8)
        self.path_payload_entry = ttk.Entry(input_frame, width=50, style='Custom.TEntry')
        self.path_payload_entry.grid(row=4, column=1, columnspan=2)
        ttk.Button(input_frame, text="Browse", command=self._browse_path_payload).grid(row=4, column=3)
        ttk.Label(input_frame, text="Collaborator Domain:").grid(row=5, column=0, sticky=tk.W, pady=8)
        self.collab_entry = ttk.Entry(input_frame, width=30, style='Custom.TEntry')
        self.collab_entry.grid(row=5, column=1)
        ttk.Label(input_frame, text="Bruteforce Attack (yes/no):").grid(row=5, column=2)
        self.brute_entry = ttk.Entry(input_frame, width=10, style='Custom.TEntry')
        self.brute_entry.insert(0, "no")
        self.brute_entry.grid(row=5, column=3)
        ttk.Label(input_frame, text="Output Format:").grid(row=6, column=0, sticky=tk.W)
        self.output_var = tk.StringVar(value="json")
        ttk.OptionMenu(input_frame, self.output_var, "json", "json", "csv", "xml").grid(row=6, column=1, sticky=tk.W)
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

    def _browse_path_payload(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            self.path_payload_entry.delete(0, tk.END)
            self.path_payload_entry.insert(0, path)

    def _on_back(self):
        self.parent._on_child_close(self)

    def _start_scan(self):
        from project30 import SSRFScanner
        url = self.url_entry.get().strip()
        url_list = self.url_list_entry.get().strip()
        threads = int(self.threads_entry.get()) if self.threads_entry.get().isdigit() else 10
        proxy = self.proxy_entry.get().strip() or None
        payload_list = self.payload_entry.get().strip() or None
        path_payload_list = self.path_payload_entry.get().strip() or None
        collaborator = self.collab_entry.get().strip() or None
        bruteforceattack = self.brute_entry.get().strip() or None
        output = self.output_var.get()
        self.scan_button.config(state='disabled')
        self._append_text("Starting SSRF scan...\n")
        import threading
        threading.Thread(target=self._run_scan, args=(url, url_list, threads, proxy, payload_list, path_payload_list, collaborator, bruteforceattack, output), daemon=True).start()

    def _run_scan(self, url, url_list, threads, proxy, payload_list, path_payload_list, collaborator, bruteforceattack, output):
        try:
            from project30 import SSRFScanner
            scanner = SSRFScanner(
                url=url or None,
                url_list=url_list or None,
                output=output,
                threads=threads,
                payload_list=payload_list,
                path_payload_list=path_payload_list,
                collaborator=collaborator,
                bruteforceattack=bruteforceattack,
                proxy=proxy
            )
            results = scanner.scan()
            self._display_results(results, output)
        except Exception as e:
            self._append_text(f"Error: {e}\n")
        finally:
            self.scan_button.config(state='normal')

    def _display_results(self, results, output):
        self._append_text(f"Scan complete. Found {len(results)} issues.\n")
        import json, csv, io
        if output == 'json':
            for item in results:
                self._append_text(json.dumps(item, indent=2) + "\n")
        elif output == 'xml':
            import xml.etree.ElementTree as ET
            root = ET.Element('results')
            for item in results:
                entry = ET.SubElement(root, 'entry')
                for k, v in item.items():
                    child = ET.SubElement(entry, k)
                    child.text = str(v)
            xml_str = ET.tostring(root, encoding='utf-8').decode('utf-8')
            self._append_text(xml_str + "\n")
        else:
            output_io = io.StringIO()
            writer = csv.writer(output_io)
            if results:
                writer.writerow(results[0].keys())
                for item in results:
                    writer.writerow([item.get(k, '') for k in results[0].keys()])
            self._append_text(output_io.getvalue() + "\n")

    def _append_text(self, text):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state='disabled')

if __name__ == '__main__':
    app = ScannerApp()
    app.mainloop()