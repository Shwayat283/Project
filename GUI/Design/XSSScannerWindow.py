import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json
import csv
import io
import threading
from scanners.xss.XsScanner import XSScanner
import xml.etree.ElementTree as ET
import os

class XSSScannerWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("XSS Scanner")
        self.state('zoomed')
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
        self.url_entry.placeholder = "Enter target URL (e.g., http://example.com/search?q=)(required)"
        self.url_entry.insert(0, self.url_entry.placeholder)
        self.url_entry.bind('<FocusIn>', on_focus_in)
        self.url_entry.bind('<FocusOut>', on_focus_out)
        self.url_entry.grid(row=row, column=1, sticky=tk.EW, padx=5)

        row += 1
        # URL List
        ttk.Label(input_container, text="📋 URL List:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        url_list_frame = ttk.Frame(input_container)
        url_list_frame.grid(row=row, column=1, sticky=tk.EW, padx=5)
        self.url_list_entry = ttk.Entry(url_list_frame, style='Placeholder.TEntry')
        self.url_list_entry.placeholder = "Enter path to URL list file "
        self.url_list_entry.insert(0, self.url_list_entry.placeholder)
        self.url_list_entry.bind('<FocusIn>', on_focus_in)
        self.url_list_entry.bind('<FocusOut>', on_focus_out)
        self.url_list_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(url_list_frame, text="Browse", style='Accent.TButton', command=self._browse_urllist).pack(side=tk.RIGHT, padx=5)

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
        # Workers
        ttk.Label(input_container, text="⚡ Threads:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.workers_entry = ttk.Entry(input_container, width=10)
        self.workers_entry.insert(0, "20")
        self.workers_entry.grid(row=row, column=1, sticky=tk.W, padx=5)

        row += 1
        # Crawl Depth
        ttk.Label(input_container, text="🔍 Crawl Depth:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.depth_entry = ttk.Entry(input_container, width=10)
        self.depth_entry.insert(0, "2")
        self.depth_entry.grid(row=row, column=1, sticky=tk.W, padx=5)

        row += 1
        # Report Format
        ttk.Label(input_container, text="📄 Report Format:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.report_var = tk.StringVar(value="json")
        report_menu = ttk.OptionMenu(input_container, self.report_var, "json", "json", "csv", "xml", "all")
        report_menu.grid(row=row, column=1, sticky=tk.W, padx=5)

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
        
        # Add button frame for results
        result_btn_frame = ttk.Frame(result_frame)
        result_btn_frame.pack(fill=tk.X, pady=5)
        
        # Add Copy button
        self.copy_button = ttk.Button(result_btn_frame,
                                    text="Copy Selected 📋",
                                    style='Accent.TButton',
                                    command=self._copy_selected)
        self.copy_button.pack(side=tk.RIGHT, padx=10)
        
        # Add Save Output button
        self.save_button = ttk.Button(result_btn_frame,
                                    text="Save Output 💾",
                                    style='Accent.TButton',
                                    command=self._save_output)
        self.save_button.pack(side=tk.RIGHT, padx=10)
        
        # Add Clear Results button
        self.clear_button = ttk.Button(result_btn_frame,
                                    text="Clear Results 🗑",
                                    style='Accent.TButton',
                                    command=self._clear_results)
        self.clear_button.pack(side=tk.RIGHT, padx=10)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, 
                                                     bg='#2D2D44',
                                                     fg='#E0E0E0',
                                                     insertbackground='#E0E0E0',
                                                     relief='flat',
                                                     font=('Consolas', 10))
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # Create right-click menu
        self.context_menu = tk.Menu(self.result_text, tearoff=0)
        self.context_menu.add_command(label="Copy", command=self._copy_selected)
        self.context_menu.add_command(label="Copy All", command=self._copy_all)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Clear", command=self._clear_results)
        
        # Bind right-click event
        self.result_text.bind("<Button-3>", self._show_context_menu)
        
        # Bind Ctrl+C to copy
        self.result_text.bind("<Control-c>", lambda e: self._copy_selected())
        self.result_text.bind("<Control-a>", lambda e: self._select_all())

    def _browse_urllist(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            self.url_list_entry.delete(0, tk.END)
            self.url_list_entry.insert(0, path)
            self.url_list_entry.configure(style='Custom.TEntry')

    def _on_back(self):
        self.parent._on_child_close(self)

    def _start_scan(self):
        url = self.url_entry.get().strip()
        url_list = self.url_list_entry.get().strip()
        
        # Check if URL is placeholder
        if url == self.url_entry.placeholder:
            url = None
            
        # Check if URL list is empty or placeholder
        if not url_list or url_list == self.url_list_entry.placeholder:
            url_list = None
            
        if not url and not url_list:
            messagebox.showerror("Input Error", "Either Target URL or URL List is required.")
            return

        # Get proxy if not placeholder
        proxy = self.proxy_entry.get().strip()
        if proxy == self.proxy_entry.placeholder:
            proxy = None

        try:
            threads = int(self.workers_entry.get())
            depth = int(self.depth_entry.get())
        except ValueError:
            messagebox.showerror("Input Error", "Threads and Depth must be valid numbers.")
            return

        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')
        
        # Clear previous results
        self._clear_results()
        
        # Configure text tags for colored output
        self.result_text.tag_configure('error', foreground='red')
        self.result_text.tag_configure('vulnerability', foreground='#ff9800')  # Orange for vulnerabilities
        
        self._append_text("Starting XSS scan...\n")

        # Initialize scanner with parameters and callback
        self.scanner = XSScanner(
            target_url=url,
            proxy_url=proxy,
            threads=threads,
            depth=depth,
            report_format=self.report_var.get(),
            callback=self._on_scan_result  # Add callback for real-time results
        )

        # Start scan in a separate thread
        threading.Thread(target=self._run_scan, args=(url_list,), daemon=True).start()

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

    def _clear_results(self):
        """Clear the results text area"""
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.config(state='disabled')

    def _run_scan(self, url_list=None):
        try:
            if url_list and url_list != self.url_list_entry.placeholder and os.path.isfile(url_list):
                with open(url_list) as f:
                    urls = f.read().splitlines()
                for url in urls:
                    if hasattr(self, 'scanner') and self.scanner.stop_scan:
                        break
                    self._append_text(f"\nScanning {url}...\n")
                    # Create a new scanner instance for each URL
                    self.scanner = XSScanner(
                        target_url=url,
                        proxy_url=self.proxy_entry.get().strip() if self.proxy_entry.get().strip() != self.proxy_entry.placeholder else None,
                        threads=int(self.workers_entry.get()),
                        depth=int(self.depth_entry.get()),
                        report_format=self.report_var.get(),
                        callback=self._on_scan_result
                    )
                    self.scanner.start_scan()
            else:
                self.scanner.start_scan()

        except Exception as e:
            self._append_text(f"Error: {e}\n")
        finally:
            self.scan_button.config(state='normal')
            self.stop_button.config(state='disabled')

    def _on_scan_result(self, result):
        """Callback function to handle real-time scan results"""
        if result.get('type') == 'info':
            # For info messages, just append them
            self._append_text(f"{result['message']}\n")
        elif result.get('type') == 'error':
            # For error messages, append them in red (using a tag)
            self._append_text(f"ERROR: {result['message']}\n", tag='error')
        else:
            # For vulnerability findings, format them nicely
            vuln_text = f"""
Found {result['type']} XSS!
URL: {result['source']}
Parameter: {result['parameter']}
Payload: {result['payload']}
Timestamp: {result['timestamp']}
{'='*50}
"""
            self._append_text(vuln_text, tag='vulnerability')

    def _append_text(self, text, tag=None):
        """Append text to the result text widget with optional tag"""
        self.result_text.config(state='normal')
        if tag:
            self.result_text.insert(tk.END, text, tag)
        else:
            self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state='disabled')

    def _show_context_menu(self, event):
        """Show the context menu on right click"""
        self.context_menu.tk_popup(event.x_root, event.y_root)

    def _copy_selected(self):
        """Copy selected text to clipboard"""
        try:
            selected_text = self.result_text.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.clipboard_clear()
            self.clipboard_append(selected_text)
        except tk.TclError:  # No selection
            pass

    def _copy_all(self):
        """Copy all text to clipboard"""
        text = self.result_text.get(1.0, tk.END)
        self.clipboard_clear()
        self.clipboard_append(text)

    def _select_all(self, event=None):
        """Select all text in the result area"""
        self.result_text.tag_add(tk.SEL, "1.0", tk.END)
        self.result_text.mark_set(tk.INSERT, "1.0")
        self.result_text.see(tk.INSERT)
        return 'break' 