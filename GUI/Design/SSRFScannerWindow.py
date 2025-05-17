import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json
import csv
import io
import threading
from scanners.ssrf.SSRF import SSRFScanner, display_xml

class SSRFScannerWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("SSRF Scanner")
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
        self.style.configure('Accent.TButton', 
                             background='#89B4FA',
                             foreground='#1E1E2E',
                             font=('Segoe UI', 12, 'bold'))
        self.style.map('Accent.TButton',
                        background=[('active', '#A5C8FF'), ('pressed', '#7BA4F7')])
        self.style.configure('Placeholder.TEntry',
                             foreground='#666666',
                             font=('Segoe UI', 12))
        
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
        self.url_entry.placeholder = "Enter target URL (e.g., http://example.com/api?url=)"
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
        # Payload List
        ttk.Label(input_container, text="🎯 Payload List:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.payload_entry = ttk.Entry(input_container, width=55, style='Placeholder.TEntry')
        self.payload_entry.placeholder = "Enter path to SSRF payload list file"
        self.payload_entry.insert(0, self.payload_entry.placeholder)
        self.payload_entry.bind('<FocusIn>', on_focus_in)
        self.payload_entry.bind('<FocusOut>', on_focus_out)
        self.payload_entry.grid(row=row, column=1, sticky=tk.EW, padx=5)
        ttk.Button(input_container, text="Browse", style='Accent.TButton', command=self._browse_payload).grid(row=row, column=2, padx=5)

        row += 1
        # Path Payload List
        ttk.Label(input_container, text="📂 Path Payload List:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.path_payload_entry = ttk.Entry(input_container, width=55, style='Placeholder.TEntry')
        self.path_payload_entry.placeholder = "Enter path to SSRF path payload list file"
        self.path_payload_entry.insert(0, self.path_payload_entry.placeholder)
        self.path_payload_entry.bind('<FocusIn>', on_focus_in)
        self.path_payload_entry.bind('<FocusOut>', on_focus_out)
        self.path_payload_entry.grid(row=row, column=1, sticky=tk.EW, padx=5)
        ttk.Button(input_container, text="Browse", style='Accent.TButton', command=self._browse_path_payload).grid(row=row, column=2, padx=5)

        row += 1
        # Collaborator Domain
        ttk.Label(input_container, text="🔗 Collaborator Domain:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.collab_entry = ttk.Entry(input_container, width=70, style='Placeholder.TEntry')
        self.collab_entry.placeholder = "Enter collaborator domain (e.g., xyz.burpcollaborator.net)"
        self.collab_entry.insert(0, self.collab_entry.placeholder)
        self.collab_entry.bind('<FocusIn>', on_focus_in)
        self.collab_entry.bind('<FocusOut>', on_focus_out)
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

        # Buttons
        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill=tk.X, pady=10)
        self.back_button = ttk.Button(btn_frame, 
                                      text="← Back", 
                                      style='TButton',
                                      command=self._on_back)
        self.back_button.pack(side=tk.LEFT, padx=10)
        
        # Add Stop Scan button
        self.stop_button = ttk.Button(btn_frame,
                                    text="Stop Scan ⏹",
                                    style='TButton',
                                    command=self._stop_scan,
                                    state='disabled')
        self.stop_button.pack(side=tk.RIGHT, padx=10)
        
        self.scan_button = ttk.Button(btn_frame, 
                                       text="Start Scan ▶", 
                                       style='Accent.TButton',
                                       command=self._start_scan)
        self.scan_button.pack(side=tk.RIGHT, padx=10)

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

    def _browse_urllist(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            self.url_list_entry.delete(0, tk.END)
            self.url_list_entry.insert(0, path)
            self.url_list_entry.configure(style='Custom.TEntry')

    def _browse_payload(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            self.payload_entry.delete(0, tk.END)
            self.payload_entry.insert(0, path)
            self.payload_entry.configure(style='Custom.TEntry')

    def _browse_path_payload(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            self.path_payload_entry.delete(0, tk.END)
            self.path_payload_entry.insert(0, path)
            self.path_payload_entry.configure(style='Custom.TEntry')

    def _on_back(self):
        self.parent._on_child_close(self)

    def _start_scan(self):
        def get_value(entry):
            value = entry.get().strip()
            return None if value == entry.placeholder or not value else value

        url = get_value(self.url_entry)
        url_list = get_value(self.url_list_entry)
        threads = int(self.threads_entry.get()) if self.threads_entry.get().isdigit() else 20
        proxy = get_value(self.proxy_entry)
        payload_list = get_value(self.payload_entry)
        path_payload_list = get_value(self.path_payload_entry)
        collaborator = get_value(self.collab_entry)
        bruteforceattack = self.brute_var.get()
        output_format = self.output_var.get()

        if not url and not url_list:
            messagebox.showerror("Input Error", "Target URL or URL-List file is required.")
            return

        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self._append_text("Starting SSRF scan...\n")
        threading.Thread(target=self._run_scan, args=(url, url_list, threads, proxy, payload_list, path_payload_list, collaborator, bruteforceattack, output_format), daemon=True).start()

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

    def _run_scan(self, url, url_list, threads, proxy, payload_list, path_payload_list, collaborator, bruteforceattack, output_format):
        try:
            self.scanner = SSRFScanner(
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
            results = self.scanner.scan()
            self._display_results(results, output_format)
        except Exception as e:
            self._append_text(f"Error: {e}\n")
        finally:
            self.scan_button.config(state='normal')
            self.stop_button.config(state='disabled')

    def _display_results(self, results, output_format):
        self._append_text(f"Scan complete. Found {len(results)} issues.\n")
        if output_format == 'json':
            for item in results:
                self._append_text(json.dumps(item, indent=2) + "\n")
        elif output_format == 'xml':
            xml_str = display_xml(results)
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