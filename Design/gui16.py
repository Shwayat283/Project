import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk
import json
import csv
import io
import PathTraversalWithComment as scanner_module
import FinalLFI as scanner_module
import XSS as xss_module
import SSRF as ssrf_module

class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Vulnerability Scanner")
        self.geometry("1200x800")
        self.current_bg = "#1E1E2E"  # Dark theme background
        self.configure(bg=self.current_bg)
        self.style = ttk.Style(self)
        self.style.theme_use('alt')
        self._setup_styles()
        self._create_settings_button()
        self._create_main_menu()
    
    def _setup_styles(self):
        """تحديث الأنماط مع اللون الحالي"""
        self.style.configure('TFrame', background=self.current_bg)
        self.style.configure('TLabel', background=self.current_bg, foreground='#E0E0E0', font=('Segoe UI', 12))
        self.style.configure('TButton', font=('Segoe UI', 12, 'bold'), 
                             borderwidth=0, relief='flat',
                             background='#2D2D44', foreground='#E0E0E0')
        self.style.map('TButton',
               background=[('active', '#3D3D54'), ('pressed', '#4D4D64')])
        self.style.configure('TLabelframe', background=self.current_bg, 
                             relief='flat', borderwidth=5,
                             foreground='#89B4FA', font=('Segoe UI', 12, 'bold'))
        self.style.configure('TLabelframe.Label', background=self.current_bg, foreground='#89B4FA')
        self.style.configure('Accent.TButton', 
                             background='#89B4FA',
                             foreground='#1E1E2E',
                             font=('Segoe UI', 12, 'bold'))
        self.style.map('Accent.TButton',
                       background=[('active', '#A5C8FF'), ('pressed', '#7BA4F7')])

    def _create_settings_button(self):
        self.settings_btn = tk.Menubutton(self, text='⚙', font=('Segoe UI', 16), bg=self.current_bg, fg='#E0E0E0', bd=0, relief='flat')
        settings_menu = tk.Menu(self.settings_btn, tearoff=0, bg='#2D2D44', fg='#E0E0E0', activebackground='#3D3D54', activeforeground='#E0E0E0')
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
                          font=("Segoe UI", 40, "bold"),
                          foreground="#38bdf8")
        title.pack(pady=(0, 0))
        subtitle = ttk.Label(frame,
                           text="Advanced Security Testing Platform",
                           font=("Segoe UI", 18),
                           foreground="#94a3b8")
        subtitle.pack(pady=(0, 30))

        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X)
        buttons = [
            ("SSRF", "#89B4FA","🌐"),
            ("SSTI", "#89B4FA", "📝"),
            ("LFI", "#89B4FA", "📂"),
            ("XSS", "#89B4FA", "⚠️")
        ]
        for text, color, emoji in buttons:
            btn = tk.Button(button_frame, 
                              text=f"{emoji} {text}",
                              font=("Segoe UI", 16, "bold"),
                              bg=color,
                              fg="#1E1E2E",
                              activebackground=self._lighten_color(color),
                              activeforeground="#1E1E2E",
                              relief='flat',
                              width=35,
                              height=2,
                              bd=0,
                              command=lambda v=text: self._open_scanner(v))
            btn.pack(side=tk.TOP, fill=tk.X, pady=15)
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
        elif vuln_type == "XSS":
            win = XSSScannerWindow(self)
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
        self.configure(bg=self.parent.current_bg)
        self.style = ttk.Style(self)
        self.style.configure('Custom.TEntry', 
                             fieldbackground='#2D2D44',
                             foreground='#000000',
                             insertcolor='#000000',
                             bordercolor='#3D3D54',
                             lightcolor='#3D3D54',
                             darkcolor='#3D3D54',
                             font=('Segoe UI', 12))
        self.style.configure('Accent.TButton', 
                             background='#89B4FA',
                             foreground='#1E1E2E',
                             font=('Segoe UI', 12, 'bold'))
        self.style.map('Accent.TButton',
                       background=[('active', '#A5C8FF'), ('pressed', '#7BA4F7')])
        self._create_widgets()

    def _create_widgets(self):
        container = ttk.Frame(self, padding=15)
        container.pack(fill=tk.BOTH, expand=True)
        notebook = ttk.Notebook(container)
        notebook.pack(fill=tk.BOTH, expand=True)
        input_frame = ttk.Frame(notebook)
        notebook.add(input_frame, text="Scan Configuration")

        # Header Frame
        header_frame = ttk.Frame(input_frame)
        header_frame.grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 20))
        
        # Title
        title_label = ttk.Label(header_frame, 
                               text="📂 LFI Scanner",
                               font=("Segoe UI", 24, "bold"),
                               foreground="#89B4FA")
        title_label.pack(side=tk.TOP, padx=(0, 10), anchor=tk.W)
        
        # Subtitle
        subtitle_label = ttk.Label(header_frame,
                                 text=" Input Configuration",
                                 font=("Segoe UI", 12),
                                 foreground="#94a3b8")
        subtitle_label.pack(side=tk.TOP, pady=(5, 0), anchor=tk.W)

        # Create a frame for input fields with consistent width
        input_container = ttk.Frame(input_frame)
        input_container.grid(row=1, column=0, columnspan=3, sticky=tk.EW, padx=20)
        input_container.grid_columnconfigure(1, weight=1)

        row = 0
        # Target URL
        ttk.Label(input_container, text="🌐 Target URL:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.url_entry = ttk.Entry(input_container, width=70)
        self.url_entry.grid(row=row, column=1, sticky=tk.EW, padx=5)

        row += 1
        # URL List
        ttk.Label(input_container, text="📋 URL List:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.url_list_entry = ttk.Entry(input_container, width=55)
        self.url_list_entry.grid(row=row, column=1, sticky=tk.EW, padx=5)
        ttk.Button(input_container, text="Browse", style='Accent.TButton', command=self._browse_urllist).grid(row=row, column=2, padx=5)

        row += 1
        # Wordlist
        ttk.Label(input_container, text="📚 Wordlist:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.wordlist_entry = ttk.Entry(input_container, width=55)
        self.wordlist_entry.grid(row=row, column=1, sticky=tk.EW, padx=5)
        ttk.Button(input_container, text="Browse", style='Accent.TButton', command=self._browse_wordlist).grid(row=row, column=2, padx=5)

        row += 1
        # Proxy
        ttk.Label(input_container, text="🔒 Proxy:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.proxy_entry = ttk.Entry(input_container, width=70)
        self.proxy_entry.grid(row=row, column=1, columnspan=1, sticky=tk.EW, padx=5)

        row += 1
        # Threads
        ttk.Label(input_container, text="⚡ Threads:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.threads_entry = ttk.Entry(input_container, width=10)
        self.threads_entry.insert(0, "10")
        self.threads_entry.grid(row=row, column=1, sticky=tk.W, padx=5)

        row += 1
        # Cookies
        ttk.Label(input_container, text="🍪 Cookies:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.cookies_entry = ttk.Entry(input_container, width=70)
        self.cookies_entry.grid(row=row, column=1, columnspan=1, sticky=tk.EW, padx=5)

        row += 1
        # Output Format
        ttk.Label(input_container, text="📄 Output Format:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.output_var = tk.StringVar(value="json")
        output_menu = ttk.OptionMenu(input_container, self.output_var, "json", "json", "csv", "xml")
        output_menu.grid(row=row, column=1, sticky=tk.W, padx=5)

        row += 1
        # Exploit Categories
        ttk.Label(input_container, text="🎯 Exploit Categories:", font=("Segoe UI", 12, "bold")).grid(row=row, column=0, columnspan=3, sticky=tk.W, pady=8)
        
        row += 1
        # Create a frame for the checkbuttons with a border
        check_frame = ttk.LabelFrame(input_container, text="Select Categories", padding=5)
        check_frame.grid(row=row, column=0, columnspan=3, sticky=tk.EW, pady=5)
        check_frame.configure(style='Categories.TLabelframe')
        
        self.style.configure('Categories.TLabelframe', background=self.parent.current_bg)
        self.style.configure('Categories.TLabelframe.Label', background=self.parent.current_bg, foreground='#89B4FA')
        self.style.configure('White.TCheckbutton', foreground='#FFFFFF', background=self.parent.current_bg, font=('Segoe UI', 12))
        
        self.category_vars = {}
        categories = [
            ("linux_users", "Linux User Files"),
            ("linux_system", "Linux System Files"),
            ("linux_network", "Linux Network Files"),
            ("windows_common", "Windows Files"),
            ("log_rce", "Log-based RCE"),
            ("web_servers", "Web Server Configs"),
            ("cron_jobs", "Scheduled Tasks"),
            ("database", "Database Configs"),
            ("ftp_configs", "FTP Server Configs"),
            ("ssh_keys", "SSH Authentication"),
            ("boot_files", "System Boot Configs")
        ]
        
        # Add checkbuttons in a grid layout
        for i, (cat_id, cat_name) in enumerate(categories):
            var = tk.BooleanVar()
            self.category_vars[cat_id] = var
            cb = tk.Checkbutton(check_frame,
                               text=cat_name,
                               variable=var,
                               bg=self.parent.current_bg,
                               fg='#FFFFFF',
                               selectcolor=self.parent.current_bg,
                               activebackground=self.parent.current_bg,
                               activeforeground='#FFFFFF',
                               font=('Segoe UI', 12),
                               highlightthickness=0,
                               bd=0)
            cb.grid(row=i//3, column=i%3, padx=10, pady=2, sticky=tk.W)

        # Buttons
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

        # Results
        result_frame = ttk.Frame(notebook)
        notebook.add(result_frame, text="Scan Results")
        self.result_text = scrolledtext.ScrolledText(result_frame, 
                                                     bg='#2D2D44',
                                                     fg='#E0E0E0',
                                                     insertbackground='#E0E0E0',
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

        # Get selected categories
        selected_categories = [
            cat_id for cat_id, var in self.category_vars.items()
            if var.get()
        ]

        params = {
            'proxy': self.proxy_entry.get().strip() or None,
            'threads': int(self.threads_entry.get()),
            'wordlist': self.wordlist_entry.get().strip() or None,
            'cookies': self.cookies_entry.get().strip() or None,
            'selected_categories': selected_categories,
            'exploit_enabled': bool(selected_categories)
        }

        self.scan_button.config(state='disabled')
        self._append_text("Starting scan...\n")
        threading.Thread(target=self._run_scan, args=(urls, params), daemon=True).start()

    def _run_scan(self, urls, params):
        try:
            scanner = scanner_module.LFIScanner(
                proxy=params['proxy'],
                threads=params['threads'],
                wordlist=params['wordlist'],
                cookies=params['cookies'],
                selected_categories=params['selected_categories'],
                exploit_enabled=params['exploit_enabled']
            )
            
            all_results = []
            for url in urls:
                self._append_text(f"Scanning {url}...\n")
                results = scanner.scan(url)
                all_results.extend(results)
                
                # Reset scanner state between URLs
                scanner.reset_scanner()
                
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
        elif self.output_var.get() == 'xml':
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
                             background='#89B4FA',
                             foreground='#1E1E2E',
                             font=('Segoe UI', 12, 'bold'))
        self.style.map('Custom.TButton',
                       background=[('active', '#A5C8FF'), ('pressed', '#7BA4F7')])
        self._create_widgets()

    def _create_widgets(self):
        container = ttk.Frame(self, padding=15)
        container.pack(fill=tk.BOTH, expand=True)
        label = ttk.Label(container, 
                          text="Select a color theme:", 
                          font=("Segoe UI", 18, "bold"),
                          foreground="#89B4FA",
                          background=self.parent.current_bg)
        label.pack(pady=(20, 10))
        themes = [
            ("Dark Theme", "#1E1E2E"),
            ("Light Theme", "#F5F5F5"),
            ("Blue Theme", "#1E3A8A"),
            ("Purple Theme", "#2E1065")
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
                             fieldbackground='#2D2D44',
                             foreground='#000000',
                             insertcolor='#000000',
                             bordercolor='#3D3D54',
                             lightcolor='#3D3D54',
                             darkcolor='#3D3D54',
                             font=('Segoe UI', 12))
        self.style.configure('Accent.TButton', 
                             background='#89B4FA',
                             foreground='#1E1E2E',
                             font=('Segoe UI', 12, 'bold'))
        self.style.map('Accent.TButton',
                       background=[('active', '#A5C8FF'), ('pressed', '#7BA4F7')])
        self._create_widgets()

    def _create_widgets(self):
        container = ttk.Frame(self, padding=15)
        container.pack(fill=tk.BOTH, expand=True)
        notebook = ttk.Notebook(container)
        notebook.pack(fill=tk.BOTH, expand=True)
        input_frame = ttk.Frame(notebook)
        notebook.add(input_frame, text="Scan Configuration")

        # Header Frame
        header_frame = ttk.Frame(input_frame)
        header_frame.grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 20))
        
        # Title
        title_label = ttk.Label(header_frame, 
                               text="🌐 SSRF Scanner",
                               font=("Segoe UI", 24, "bold"),
                               foreground="#89B4FA")
        title_label.pack(side=tk.TOP, padx=(0, 10), anchor=tk.W)
        
        # Subtitle
        subtitle_label = ttk.Label(header_frame,
                                 text=" Input Configuration",
                                 font=("Segoe UI", 12),
                                 foreground="#94a3b8")
        subtitle_label.pack(side=tk.TOP, pady=(5, 0), anchor=tk.W)

        # Create a frame for input fields with consistent width
        input_container = ttk.Frame(input_frame)
        input_container.grid(row=1, column=0, columnspan=3, sticky=tk.EW, padx=20)
        input_container.grid_columnconfigure(1, weight=1)

        row = 0
        # Target URL
        ttk.Label(input_container, text="🌐 Target URL:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.url_entry = ttk.Entry(input_container, width=70)
        self.url_entry.grid(row=row, column=1, sticky=tk.EW, padx=5)

        row += 1
        # URL List
        ttk.Label(input_container, text="📋 URL List:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.url_list_entry = ttk.Entry(input_container, width=55)
        self.url_list_entry.grid(row=row, column=1, sticky=tk.EW, padx=5)
        ttk.Button(input_container, text="Browse", style='Accent.TButton', command=self._browse_urllist).grid(row=row, column=2, padx=5)

        row += 1
        # Payload List
        ttk.Label(input_container, text="🎯 Payload List:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.payload_entry = ttk.Entry(input_container, width=55)
        self.payload_entry.grid(row=row, column=1, sticky=tk.EW, padx=5)
        ttk.Button(input_container, text="Browse", style='Accent.TButton', command=self._browse_payload).grid(row=row, column=2, padx=5)

        row += 1
        # Path Payload List
        ttk.Label(input_container, text="📂 Path Payload List:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.path_payload_entry = ttk.Entry(input_container, width=55)
        self.path_payload_entry.grid(row=row, column=1, sticky=tk.EW, padx=5)
        ttk.Button(input_container, text="Browse", style='Accent.TButton', command=self._browse_path_payload).grid(row=row, column=2, padx=5)

        row += 1
        # Collaborator Domain
        ttk.Label(input_container, text="🔗 Collaborator Domain:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.collab_entry = ttk.Entry(input_container, width=70)
        self.collab_entry.grid(row=row, column=1, columnspan=1, sticky=tk.EW, padx=5)

        row += 1
        # Bruteforce Attack
        ttk.Label(input_container, text="🔓 Bruteforce Attack:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.brute_var = tk.StringVar(value="no")
        brute_frame = ttk.Frame(input_container)
        brute_frame.grid(row=row, column=1, sticky=tk.W, columnspan=2)
        ttk.Radiobutton(brute_frame, text="Yes", value="yes", variable=self.brute_var).pack(side=tk.LEFT, padx=(6, 30))
        ttk.Radiobutton(brute_frame, text="No", value="no", variable=self.brute_var).pack(side=tk.LEFT)

        row += 1
        # Output Format
        ttk.Label(input_container, text="📄 Output Format:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.output_var = tk.StringVar(value="json")
        output_menu = ttk.OptionMenu(input_container, self.output_var, "json", "json", "csv", "xml")
        output_menu.grid(row=row, column=1, sticky=tk.W, padx=5)

        row += 1
        # Proxy
        ttk.Label(input_container, text="🔒 Proxy:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.proxy_entry = ttk.Entry(input_container, width=70)
        self.proxy_entry.grid(row=row, column=1, columnspan=1, sticky=tk.EW, padx=5)

        row += 1
        # Threads
        ttk.Label(input_container, text="⚡ Threads:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.threads_entry = ttk.Entry(input_container, width=10)
        self.threads_entry.insert(0, "20")
        self.threads_entry.grid(row=row, column=1, sticky=tk.W, padx=5)

        # Buttons
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

        # Results
        result_frame = ttk.Frame(notebook)
        notebook.add(result_frame, text="Scan Results")
        self.result_text = scrolledtext.ScrolledText(result_frame, 
                                                     bg='#2D2D44',
                                                     fg='#E0E0E0',
                                                     insertbackground='#E0E0E0',
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
        url = self.url_entry.get().strip()
        url_list = self.url_list_entry.get().strip()
        threads = int(self.threads_entry.get()) if self.threads_entry.get().isdigit() else 20
        proxy = self.proxy_entry.get().strip() or None
        payload_list = self.payload_entry.get().strip() or None
        path_payload_list = self.path_payload_entry.get().strip() or None
        collaborator = self.collab_entry.get().strip() or None
        bruteforceattack = self.brute_var.get()
        output_format = self.output_var.get()

        if not url and not url_list:
            messagebox.showerror("Input Error", "Target URL or URL-List file is required.")
            return

        self.scan_button.config(state='disabled')
        self._append_text("Starting SSRF scan...\n")
        threading.Thread(target=self._run_scan, args=(url, url_list, threads, proxy, payload_list, path_payload_list, collaborator, bruteforceattack, output_format), daemon=True).start()

    def _run_scan(self, url, url_list, threads, proxy, payload_list, path_payload_list, collaborator, bruteforceattack, output_format):
        try:
            scanner = ssrf_module.SSRFScanner(
                url=url or None,
                url_list=url_list or None,
                output=output_format,
                threads=threads,
                payload_list=payload_list,
                path_payload_list=path_payload_list,
                collaborator=collaborator,
                bruteforceattack=bruteforceattack,
                proxy=proxy
            )
            results = scanner.scan()
            self._display_results(results, output_format)
        except Exception as e:
            self._append_text(f"Error: {e}\n")
        finally:
            self.scan_button.config(state='normal')

    def _display_results(self, results, output_format):
        self._append_text(f"Scan complete. Found {len(results)} issues.\n")
        if output_format == 'json':
            for item in results:
                self._append_text(json.dumps(item, indent=2) + "\n")
        elif output_format == 'xml':
            import xml.etree.ElementTree as ET
            root = ET.Element('results')
            for item in results:
                entry = ET.SubElement(root, 'entry')
                for k, v in item.items():
                    child = ET.SubElement(entry, k)
                    child.text = str(v)
            xml_str = ET.tostring(root, encoding='utf-8').decode('utf-8')
            self._append_text(xml_str + "\n")
        else:  # csv
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['URL', 'Payload', 'Parameter', 'OS', 'Status', 'Length', 'Timestamp'])
            for item in results:
                writer.writerow([
                    item.get('URL', ''),
                    item.get('Payload', ''),
                    item.get('Parameter', ''),
                    item.get('os', ''),
                    item.get('Status', ''),
                    item.get('length', ''),
                    item.get('timestamp', '')
                ])
            self._append_text(output.getvalue() + "\n")

    def _append_text(self, text):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state='disabled')

class XSSScannerWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("XSS Scanner")
        self.configure(bg=self.parent.current_bg)
        self.style = ttk.Style(self)
        self.style.configure('Custom.TEntry', 
                             fieldbackground='#2D2D44',
                             foreground='#000000',
                             insertcolor='#000000',
                             bordercolor='#3D3D54',
                             lightcolor='#3D3D54',
                             darkcolor='#3D3D54',
                             font=('Segoe UI', 12))
        self.style.configure('Accent.TButton', 
                             background='#89B4FA',
                             foreground='#1E1E2E',
                             font=('Segoe UI', 12, 'bold'))
        self.style.map('Accent.TButton',
                       background=[('active', '#A5C8FF'), ('pressed', '#7BA4F7')])
        self._create_widgets()

    def _create_widgets(self):
        container = ttk.Frame(self, padding=15)
        container.pack(fill=tk.BOTH, expand=True)
        notebook = ttk.Notebook(container)
        notebook.pack(fill=tk.BOTH, expand=True)
        input_frame = ttk.Frame(notebook)
        notebook.add(input_frame, text="Scan Configuration")

        # Header Frame
        header_frame = ttk.Frame(input_frame)
        header_frame.grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 20))
        
        # Title
        title_label = ttk.Label(header_frame, 
                               text="⚠️ XSS Scanner",
                               font=("Segoe UI", 24, "bold"),
                               foreground="#89B4FA")
        title_label.pack(side=tk.TOP, padx=(0, 10), anchor=tk.W)
        
        # Subtitle
        subtitle_label = ttk.Label(header_frame,
                                 text=" Input Configuration",
                                 font=("Segoe UI", 12),
                                 foreground="#94a3b8")
        subtitle_label.pack(side=tk.TOP, pady=(5, 0), anchor=tk.W)

        # Create a frame for input fields with consistent width
        input_container = ttk.Frame(input_frame)
        input_container.grid(row=1, column=0, columnspan=3, sticky=tk.EW, padx=20)
        input_container.grid_columnconfigure(1, weight=1)

        row = 0
        # Target URL
        ttk.Label(input_container, text="🌐 Target URL:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.url_entry = ttk.Entry(input_container, width=70)
        self.url_entry.grid(row=row, column=1, sticky=tk.EW, padx=5)

        row += 1
        # Proxy
        ttk.Label(input_container, text="🔒 Proxy:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.proxy_entry = ttk.Entry(input_container, width=70)
        self.proxy_entry.grid(row=row, column=1, columnspan=1, sticky=tk.EW, padx=5)

        row += 1
        # Workers
        ttk.Label(input_container, text="⚡ Workers:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.workers_entry = ttk.Entry(input_container, width=10)
        self.workers_entry.insert(0, "3")
        self.workers_entry.grid(row=row, column=1, sticky=tk.W, padx=5)

        row += 1
        # Output Format
        ttk.Label(input_container, text="📄 Output Format:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.output_var = tk.StringVar(value="json")
        output_menu = ttk.OptionMenu(input_container, self.output_var, "json", "json", "csv", "xml")
        output_menu.grid(row=row, column=1, sticky=tk.W, padx=5)

        row += 1
        # Output Filename
        ttk.Label(input_container, text="💾 Output File:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.output_file_entry = ttk.Entry(input_container, width=70)
        self.output_file_entry.insert(0, "xss_report")
        self.output_file_entry.grid(row=row, column=1, columnspan=1, sticky=tk.EW, padx=5)

        # Buttons
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

        # Results
        result_frame = ttk.Frame(notebook)
        notebook.add(result_frame, text="Scan Results")
        self.result_text = scrolledtext.ScrolledText(result_frame, 
                                                     bg='#2D2D44',
                                                     fg='#E0E0E0',
                                                     insertbackground='#E0E0E0',
                                                     relief='flat',
                                                     font=('Consolas', 10),
                                                     state='disabled')
        self.result_text.pack(fill=tk.BOTH, expand=True)

    def _on_back(self):
        self.parent._on_child_close(self)

    def _start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Input Error", "Target URL is required.")
            return

        # Get selected output formats
        output_formats = [self.output_var.get()]

        params = {
            'url': url,
            'proxy': self.proxy_entry.get().strip() or None,
            'workers': int(self.workers_entry.get()),
            'output_formats': output_formats,
            'output_file': self.output_file_entry.get().strip()
        }

        self.scan_button.config(state='disabled')
        self._append_text("Starting XSS scan...\n")
        threading.Thread(target=self._run_scan, args=(params,), daemon=True).start()

    def _run_scan(self, params):
        try:
            scanner = xss_module.XSSHunter(
                target_url=params['url'],
                output_formats=params['output_formats'],
                output_file=params['output_file'],
                proxy_url=params['proxy']
            )
            scanner.max_workers = params['workers']
            
            # Override the print function to capture output
            def custom_print(*args, **kwargs):
                text = ' '.join(str(arg) for arg in args)
                self._append_text(text + '\n')
            
            # Store original print function
            original_print = print
            # Replace print with custom function
            import builtins
            builtins.print = custom_print
            
            try:
                scanner.start_scan()
            finally:
                # Restore original print function
                builtins.print = original_print
            
            self._append_text("\nScan complete!\n")
            
        except Exception as e:
            self._append_text(f"Error: {e}\n")
        finally:
            self.scan_button.config(state='normal')

    def _append_text(self, text):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state='disabled')

if __name__ == '__main__':
    app = ScannerApp()
    app.mainloop()