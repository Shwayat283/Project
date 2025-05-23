import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json
import csv
import io
import threading
from scanners.ssti.SSTI import SSTIScanner, SSTIExploiter
import time
from datetime import datetime
import os

class SSTIScannerWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("SSTI Scanner")
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
        self.scanner = None
        self.flow_update_thread = None
        self.is_scanning = False

    def _create_widgets(self):
        container = ttk.Frame(self.main_frame, padding=15)
        container.pack(fill=tk.BOTH, expand=True)
        notebook = ttk.Notebook(container)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Add Scan Configuration tab first
        input_frame = ttk.Frame(notebook)
        notebook.add(input_frame, text="Scan Configuration")

        # Header Frame
        header_frame = ttk.Frame(input_frame)
        header_frame.grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 20))
        
        # Title
        title_label = ttk.Label(header_frame, 
                               text="📝 SSTI Scanner",
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
        self.url_entry.placeholder = "Enter target URL (e.g., http://example.com/page?name=) (required)"
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
        # Output Format
        ttk.Label(input_container, text="📄 Output Format:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.output_var = tk.StringVar(value="json")
        output_menu = ttk.OptionMenu(input_container, self.output_var, "json", "json", "csv", "xml")
        output_menu.grid(row=row, column=1, sticky=tk.W, padx=5)

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

        # Add Scan Results tab second
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
        
        # Add Clear Results button
        self.clear_button = ttk.Button(save_btn_frame,
                                    text="Clear Results 🗑",
                                    style='Accent.TButton',
                                    command=self._clear_results)
        self.clear_button.pack(side=tk.RIGHT, padx=10)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, 
                                                     bg='#2D2D44',
                                                     fg='#E0E0E0',
                                                     insertbackground='#E0E0E0',
                                                     relief='flat',
                                                     font=('Consolas', 10),
                                                     state='disabled')
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # Add Interactive Shell tab third
        shell_frame = ttk.Frame(notebook)
        notebook.add(shell_frame, text="Interactive Shell")
        
        # Create shell interface
        shell_container = ttk.Frame(shell_frame)
        shell_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Output area
        self.shell_output = scrolledtext.ScrolledText(
            shell_container,
            wrap=tk.WORD,
            bg='#2D2D44',
            fg='#E0E0E0',
            font=('Consolas', 10),
            height=20
        )
        self.shell_output.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Input area
        input_frame = ttk.Frame(shell_container)
        input_frame.pack(fill=tk.X)
        
        self.shell_input = ttk.Entry(
            input_frame,
            font=('Consolas', 10),
            style='Custom.TEntry'
        )
        self.shell_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.shell_input.bind('<Return>', self._execute_shell_command)
        
        send_button = ttk.Button(
            input_frame,
            text="Send",
            style='Accent.TButton',
            command=lambda: self._execute_shell_command(None)
        )
        send_button.pack(side=tk.RIGHT)

    def _browse_urllist(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            self.url_list_entry.delete(0, tk.END)
            self.url_list_entry.insert(0, path)

    def _on_back(self):
        self.parent._on_child_close(self)

    def _start_scan(self):
        # Get values and remove placeholders
        url = self.url_entry.get().strip()
        if url == self.url_entry.placeholder:
            url = ""

        url_list = self.url_list_entry.get().strip()
        if url_list == self.url_list_entry.placeholder:
            url_list = ""

        proxy = self.proxy_entry.get().strip()
        if proxy == self.proxy_entry.placeholder:
            proxy = ""

        threads = int(self.threads_entry.get()) if self.threads_entry.get().isdigit() else 20
        output_format = self.output_var.get()

        # Convert empty strings to None
        url_list = url_list or None
        proxy = proxy or None

        if not url and not url_list:
            messagebox.showerror("Input Error", "Target URL or URL-List file is required.")
            return

        # Validate URL list file if provided
        if url_list and not os.path.isfile(url_list):
            messagebox.showerror("Input Error", f"URL list file not found: {url_list}")
            return

        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self._append_text("Starting SSTI scan...\n")
        threading.Thread(target=self._run_scan, args=(url, url_list, threads, proxy, output_format), daemon=True).start()

    def _stop_scan(self):
        if hasattr(self, 'scanner'):
            self.scanner.stop_scan = True
            self._append_text("\nStopping scan...\n")
            self.stop_button.config(state='disabled')
            self.scan_button.config(state='normal')
            self.is_scanning = False

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

    def _run_scan(self, url, url_list, threads, proxy, output_format):
        """Run the SSTI scan"""
        try:
            # Initialize scanner with proper parameters
            self.scanner = SSTIScanner()
            self.scanner.stop_scan = False  # Initialize stop_scan flag
            self.is_scanning = True
            self.target_url = url  # Store the target URL
            
            # First check if this is a scenario
            initial_response = self.scanner.session.get(url, verify=False)
            if self.scanner.scenario_handler.detect_scenario(initial_response.text):
                self._append_text("Detected known SSTI scenario. Attempting scenario-specific exploitation...\n")
                success, exploiter = self.scanner.scenario_handler.execute_scenario_exploit(url)
                if success:
                    self._append_text("Scenario exploitation successful!\n")
                    self.shell_output.config(state='normal')
                    self.shell_output.insert(tk.END, "Scenario exploitation successful! Interactive shell is now available.\n")
                    self.shell_output.insert(tk.END, "Type 'exit' to quit the shell.\n")
                    self.shell_output.config(state='disabled')
                    self.shell_input.config(state='normal')
                    self.exploiter = exploiter
                    return
                else:
                    self._append_text("Scenario exploitation failed, falling back to standard scan...\n")
            
            # Run the standard scan
            results = self.scanner.scan(
                url=url,
                url_list=url_list,
                threads=threads,
                proxy=proxy
            )
            
            # Check if scan was stopped
            if self.scanner.stop_scan:
                self._append_text("Scan stopped by user.\n")
                return
            
            # Display results
            self._display_results(results, output_format)
            
            # Check if we found any vulnerabilities
            if results and len(results) > 0:
                self.shell_output.config(state='normal')
                self.shell_output.insert(tk.END, "Vulnerability found! Interactive shell is now available.\n")
                self.shell_output.insert(tk.END, "Type 'exit' to quit the shell.\n")
                self.shell_output.config(state='disabled')
                self.shell_input.config(state='normal')
                
                # Create exploiter for the first vulnerable parameter
                vuln = results[0]
                self.exploiter = SSTIExploiter(
                    self.scanner.session,
                    self.target_url,  # Use the stored target URL
                    vuln['parameter'],
                    vuln['engine']
                )
            else:
                self.shell_output.config(state='normal')
                self.shell_output.insert(tk.END, "No vulnerabilities found. Interactive shell is not available.\n")
                self.shell_output.config(state='disabled')
                self.shell_input.config(state='disabled')
                
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.shell_output.config(state='normal')
            self.shell_output.insert(tk.END, f"Error: {str(e)}\n")
            self.shell_output.config(state='disabled')
        finally:
            self.is_scanning = False
            self.scan_button.config(state='normal')
            self.stop_button.config(state='disabled')

    def _display_results(self, results, output_format):
        """Display scan results in the specified format"""
        if not results:
            self._append_text("No vulnerabilities found.\n")
            return
            
        self._append_text(f"Scan complete. Found {len(results)} issues.\n")
        
        try:
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
                writer.writerow(['URL', 'Payload', 'Parameter', 'Status', 'Length', 'Timestamp'])
                for item in results:
                    writer.writerow([
                        item.get('URL', ''),
                        item.get('Payload', ''),
                        item.get('Parameter', ''),
                        item.get('Status', ''),
                        item.get('length', ''),
                        item.get('timestamp', '')
                    ])
                self._append_text(output.getvalue() + "\n")
        except Exception as e:
            self._append_text(f"Error displaying results: {str(e)}\n")

    def _append_text(self, text):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state='disabled')

    def _execute_shell_command(self, event):
        """Execute a command in the interactive shell"""
        command = self.shell_input.get().strip()
        if not command:
            return
            
        if command.lower() == 'exit':
            self.shell_output.config(state='normal')
            self.shell_output.insert(tk.END, "Exiting shell...\n")
            self.shell_output.config(state='disabled')
            self.shell_input.delete(0, tk.END)
            return
            
        # Send command to exploiter
        if hasattr(self, 'exploiter') and self.exploiter:
            try:
                self.shell_output.config(state='normal')
                self.shell_output.insert(tk.END, f"> {command}\n")
                
                response = self.exploiter.execute_command(command)
                if response:
                    self.shell_output.insert(tk.END, f"{response}\n")
                else:
                    self.shell_output.insert(tk.END, "No response received from server\n")
                    
                self.shell_output.config(state='disabled')
            except Exception as e:
                self.shell_output.config(state='normal')
                self.shell_output.insert(tk.END, f"Error: {str(e)}\n")
                self.shell_output.config(state='disabled')
        else:
            self.shell_output.config(state='normal')
            self.shell_output.insert(tk.END, "Shell not available. Please run a scan first.\n")
            self.shell_output.config(state='disabled')
            
        self.shell_input.delete(0, tk.END)
        self.shell_output.see(tk.END) 