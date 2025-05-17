import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json
import csv
import io
import threading
from scanners.lfi.LFI import LFIScanner

class LFIScannerWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("LFI Scanner")
        self.state('zoomed')  # Start maximized
        self.configure(bg=self.parent.current_bg)
        self.style = ttk.Style(self)
        self.style.configure('Custom.TEntry', 
                             fieldbackground='#2D2D44',
                             foreground='#FFFFFF',
                             insertcolor='#FFFFFF',
                             bordercolor='#3D3D54',
                             lightcolor='#3D3D54',
                             darkcolor='#3D3D54',
                             font=('Segoe UI', 12, 'bold'))
        self.style.configure('Placeholder.TEntry',
                             foreground='#666666',
                             font=('Segoe UI', 12))
        self.style.configure('Accent.TButton', 
                             background='#89B4FA',
                             foreground='#1E1E2E',
                             font=('Segoe UI', 12, 'bold'))
        self.style.map('Accent.TButton',
                        background=[('active', '#A5C8FF'), ('pressed', '#7BA4F7')])
        
        # Create main frame with scrollbars
        self.main_frame = ttk.Frame(self)
        self.vsb = ttk.Scrollbar(self.main_frame, orient="vertical")
        self.hsb = ttk.Scrollbar(self.main_frame, orient="horizontal")
        
        # Configure main frame
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.vsb.pack(side="right", fill="y")
        self.hsb.pack(side="bottom", fill="x")
        
        self._create_widgets()

    def _create_widgets(self):
        container = ttk.Frame(self.main_frame, padding=15)
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
        # Add placeholder handling methods
        def on_focus_in(event):
            widget = event.widget
            if widget.get() == widget.placeholder:
                widget.delete(0, tk.END)
                widget.configure(style='Custom.TEntry')

        def on_focus_out(event):
            widget = event.widget
            if not widget.get():
                widget.insert(0, widget.placeholder)
                widget.configure(style='Placeholder.TEntry')

        # Target URL
        ttk.Label(input_container, text="🌐 Target URL:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.url_entry = ttk.Entry(input_container, width=70, style='Placeholder.TEntry')
        self.url_entry.placeholder = "Enter target URL (e.g., http://example.com/page.php?file=)"
        self.url_entry.insert(0, self.url_entry.placeholder)
        self.url_entry.bind('<FocusIn>', on_focus_in)
        self.url_entry.bind('<FocusOut>', on_focus_out)
        self.url_entry.grid(row=row, column=1, sticky=tk.EW, padx=5)

        row += 1
        # URL List
        ttk.Label(input_container, text="📋 URL List:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.url_list_entry = ttk.Entry(input_container, width=55, style='Placeholder.TEntry')
        self.url_list_entry.placeholder = "Enter path to URL list file"
        self.url_list_entry.insert(0, self.url_list_entry.placeholder)
        self.url_list_entry.bind('<FocusIn>', on_focus_in)
        self.url_list_entry.bind('<FocusOut>', on_focus_out)
        self.url_list_entry.grid(row=row, column=1, sticky=tk.EW, padx=5)
        ttk.Button(input_container, text="Browse", style='Accent.TButton', command=self._browse_urllist).grid(row=row, column=2, padx=5)

        row += 1
        # Wordlist
        ttk.Label(input_container, text="📚 Wordlist:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.wordlist_entry = ttk.Entry(input_container, width=55, style='Placeholder.TEntry')
        self.wordlist_entry.placeholder = "Enter path to wordlist file"
        self.wordlist_entry.insert(0, self.wordlist_entry.placeholder)
        self.wordlist_entry.bind('<FocusIn>', on_focus_in)
        self.wordlist_entry.bind('<FocusOut>', on_focus_out)
        self.wordlist_entry.grid(row=row, column=1, sticky=tk.EW, padx=5)
        ttk.Button(input_container, text="Browse", style='Accent.TButton', command=self._browse_wordlist).grid(row=row, column=2, padx=5)

        row += 1
        # Proxy
        ttk.Label(input_container, text="🔒 Proxy:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.proxy_entry = ttk.Entry(input_container, width=70, style='Placeholder.TEntry')
        self.proxy_entry.placeholder = "Enter proxy (e.g., http://127.0.0.1:8080)"
        self.proxy_entry.insert(0, self.proxy_entry.placeholder)
        self.proxy_entry.bind('<FocusIn>', on_focus_in)
        self.proxy_entry.bind('<FocusOut>', on_focus_out)
        self.proxy_entry.grid(row=row, column=1, columnspan=1, sticky=tk.EW, padx=5)

        row += 1
        # Threads
        ttk.Label(input_container, text="⚡ Threads:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.threads_entry = ttk.Entry(input_container, width=10)
        self.threads_entry.insert(0, "20")
        self.threads_entry.grid(row=row, column=1, sticky=tk.W, padx=5)

        row += 1
        # Cookies
        ttk.Label(input_container, text="🍪 Cookies:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.cookies_entry = ttk.Entry(input_container, width=70, style='Placeholder.TEntry')
        self.cookies_entry.placeholder = "Enter cookies (e.g., session=abc123)"
        self.cookies_entry.insert(0, self.cookies_entry.placeholder)
        self.cookies_entry.bind('<FocusIn>', on_focus_in)
        self.cookies_entry.bind('<FocusOut>', on_focus_out)
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

        # Add Select All checkbox
        self.select_all_var = tk.BooleanVar()
        select_all_cb = tk.Checkbutton(check_frame,
                                     text="Select All",
                                     variable=self.select_all_var,
                                     bg=self.parent.current_bg,
                                     fg='#FFFFFF',
                                     selectcolor=self.parent.current_bg,
                                     activebackground=self.parent.current_bg,
                                     activeforeground='#FFFFFF',
                                     font=('Segoe UI', 12),
                                     highlightthickness=0,
                                     bd=0,
                                     command=self._toggle_all_categories)
        select_all_cb.grid(row=len(categories)//3, column=len(categories)%3, padx=10, pady=2, sticky=tk.W)

        # Buttons
        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill=tk.X, pady=3)
        self.back_button = ttk.Button(btn_frame, 
                                      text="← Back", 
                                      style='TButton',
                                      command=self._on_back)
        self.back_button.pack(side=tk.LEFT, padx=4)
        
        # Add Stop Scan button
        self.stop_button = ttk.Button(btn_frame,
                                    text="Stop Scan ⏹",
                                    style='TButton',
                                    command=self._stop_scan,
                                    state='disabled')
        self.stop_button.pack(side=tk.RIGHT, padx=4)
        
        self.scan_button = ttk.Button(btn_frame, 
                                       text="Start Scan ▶", 
                                       style='Accent.TButton',
                                       command=self._start_scan)
        self.scan_button.pack(side=tk.RIGHT, padx=3)

        # Results
        result_frame = ttk.Frame(notebook)
        notebook.add(result_frame, text="Scan Results")
        
        # Add Save Output button
        save_btn_frame = ttk.Frame(result_frame)
        save_btn_frame.pack(fill=tk.X, pady=5)
        self.save_button = ttk.Button(save_btn_frame,
                                    text="Save Output 💾",
                                    style='Accent.TButton',
                                    command=self._save_output)
        self.save_button.pack(side=tk.RIGHT, padx=10)
        
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
        
        # Check if the input is just the placeholder text
        if single == self.url_entry.placeholder:
            single = ""
        if listfile == self.url_list_entry.placeholder:
            listfile = ""
        
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

        # Get other parameters, ignoring placeholder text
        proxy = self.proxy_entry.get().strip()
        if proxy == self.proxy_entry.placeholder:
            proxy = None
            
        wordlist = self.wordlist_entry.get().strip()
        if wordlist == self.wordlist_entry.placeholder:
            wordlist = None
            
        cookies = self.cookies_entry.get().strip()
        if cookies == self.cookies_entry.placeholder:
            cookies = None

        params = {
            'proxy': proxy,
            'threads': int(self.threads_entry.get()),
            'wordlist': wordlist,
            'cookies': cookies,
            'selected_categories': selected_categories,
            'exploit_enabled': bool(selected_categories)
        }

        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self._append_text("Starting scan...\n")
        self.scanner = LFIScanner(
            proxy=params['proxy'],
            threads=params['threads'],
            wordlist=params['wordlist'],
            cookies=params['cookies'],
            selected_categories=params['selected_categories'],
            exploit_enabled=params['exploit_enabled']
        )
        threading.Thread(target=self._run_scan, args=(urls, params), daemon=True).start()

    def _stop_scan(self):
        if hasattr(self, 'scanner'):
            self.scanner.stop_scan = True
            self._append_text("\nStopping scan...\n")
            self.stop_button.config(state='disabled')
            self.scan_button.config(state='normal')

    def _save_output(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.result_text.get('1.0', tk.END))
                messagebox.showinfo("Success", "Output saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save output: {str(e)}")

    def _run_scan(self, urls, params):
        try:
            all_results = []
            for url in urls:
                if hasattr(self, 'scanner') and self.scanner.stop_scan:
                    break
                self._append_text(f"Scanning {url}...\n")
                results = self.scanner.scan(url)
                all_results.extend(results)
                
                # Reset scanner state between URLs
                self.scanner.reset_scanner()
                
            self._display_results(all_results)
            
        except Exception as e:
            self._append_text(f"Error: {e}\n")
        finally:
            self.scan_button.config(state='normal')
            self.stop_button.config(state='disabled')

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

    def _toggle_all_categories(self):
        """Toggle all category checkboxes based on Select All checkbox state"""
        state = self.select_all_var.get()
        for var in self.category_vars.values():
            var.set(state) 