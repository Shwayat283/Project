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
        self.scanner = None
        self.flow_update_thread = None
        self.is_scanning = False

    def _create_widgets(self):
        container = ttk.Frame(self.main_frame, padding=15)
        container.pack(fill=tk.BOTH, expand=True)
        self.notebook = ttk.Notebook(container)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Add Scan Configuration tab first
        input_frame = ttk.Frame(self.notebook)
        self.notebook.add(input_frame, text="Scan Configuration")

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
        result_frame = ttk.Frame(self.notebook)
        self.notebook.add(result_frame, text="Scan Results")
        
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
        shell_frame = ttk.Frame(self.notebook)
        self.notebook.add(shell_frame, text="Interactive Shell")
        
        # Create shell interface with better styling
        shell_container = ttk.Frame(shell_frame)
        shell_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add a header frame with gradient-like effect
        header_frame = ttk.Frame(shell_container, style='Header.TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Configure header style
        self.style.configure('Header.TFrame', background='#1E1E2E')
        
        # Add a header label with icon
        header_label = ttk.Label(header_frame,
                               text="📝 Interactive SSTI Shell",
                               font=("Segoe UI", 16, "bold"),
                               foreground="#89B4FA",
                               background='#1E1E2E')
        header_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Add a subtitle with status
        subtitle_label = ttk.Label(header_frame,
                                 text="Ready to execute commands",
                                 font=("Segoe UI", 10),
                                 foreground="#94a3b8",
                                 background='#1E1E2E')
        subtitle_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Create a frame for the output area with a border and gradient-like effect
        output_frame = ttk.LabelFrame(shell_container, text="Output", padding=5, style='Output.TLabelframe')
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Configure output frame style
        self.style.configure('Output.TLabelframe', background='#1E1E2E', foreground='#89B4FA')
        self.style.configure('Output.TLabelframe.Label', background='#1E1E2E', foreground='#89B4FA')
        
        # Output area with better styling
        self.shell_output = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.WORD,
            bg='#2D2D44',
            fg='#E0E0E0',
            font=('Consolas', 11),
            height=20,
            padx=10,
            pady=10,
            insertbackground='#89B4FA'  # Cursor color
        )
        self.shell_output.pack(fill=tk.BOTH, expand=True)
        
        # Add a decorative separator
        separator_frame = ttk.Frame(shell_container, height=2, style='Separator.TFrame')
        separator_frame.pack(fill=tk.X, pady=10)
        self.style.configure('Separator.TFrame', background='#89B4FA')
        
        # Input area with better styling
        input_frame = ttk.Frame(shell_container, style='Input.TFrame')
        input_frame.pack(fill=tk.X)
        self.style.configure('Input.TFrame', background='#1E1E2E')
        
        # Add a prompt label with custom styling
        prompt_label = ttk.Label(input_frame,
                               text=">",
                               font=("Consolas", 12, "bold"),
                               foreground="#89B4FA",
                               background='#1E1E2E')
        prompt_label.pack(side=tk.LEFT, padx=(0, 5))
        
        # Style for the input field
        self.style.configure('Shell.TEntry',
                           fieldbackground='#2D2D44',
                           foreground='#E0E0E0',
                           insertcolor='#89B4FA',
                           bordercolor='#3D3D54',
                           lightcolor='#3D3D54',
                           darkcolor='#3D3D54',
                           font=('Consolas', 11))
        
        self.shell_input = ttk.Entry(
            input_frame,
            font=('Consolas', 11),
            style='Shell.TEntry'
        )
        self.shell_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.shell_input.bind('<Return>', self._execute_shell_command)
        self.shell_input.bind('<Up>', self._history_up)
        self.shell_input.bind('<Down>', self._history_down)
        
        # Style for the send button
        self.style.configure('Shell.TButton',
                           background='#89B4FA',
                           foreground='#1E1E2E',
                           font=('Segoe UI', 11, 'bold'))
        self.style.map('Shell.TButton',
                      background=[('active', '#A5C8FF'), ('pressed', '#7BA4F7')])
        
        send_button = ttk.Button(
            input_frame,
            text="Send",
            style='Shell.TButton',
            command=lambda: self._execute_shell_command(None)
        )
        send_button.pack(side=tk.RIGHT)
        
        # Add status bar with gradient-like effect
        status_frame = ttk.Frame(shell_container, style='Status.TFrame')
        status_frame.pack(fill=tk.X, pady=(5, 0))
        self.style.configure('Status.TFrame', background='#1E1E2E')
        
        self.status_bar = ttk.Label(status_frame,
                                  text="Ready",
                                  font=("Segoe UI", 10),
                                  foreground="#94a3b8",
                                  background='#1E1E2E')
        self.status_bar.pack(side=tk.LEFT, padx=5, pady=2)
        
        # Initialize command history
        self.command_history = []
        self.history_index = 0

    def _browse_urllist(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            self.url_list_entry.delete(0, tk.END)
            self.url_list_entry.insert(0, path)

    def _on_back(self):
        self.parent._on_child_close(self)

    def _start_scan(self):
        command = self.shell_input.get().strip()
        if not command:
            return
            
        if command.lower() == 'exit':
            self.shell_output.config(state='normal')
            self.shell_output.insert(tk.END, "Exiting shell...\n", "exit")
            self.shell_output.config(state='disabled')
            self.shell_input.delete(0, tk.END)
            return

        # Switch to results tab
        self.notebook.select(1)

        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')

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
            
        self._append_text(f"Scan complete. Found {len(results)} issues.\n\n")
        
        try:
            # Display detailed information for each finding
            for idx, item in enumerate(results, 1):
                self._append_text(f"=== Finding #{idx} ===\n")
                self._append_text(f"Target URL: {item.get('url', 'N/A')}\n")
                self._append_text(f"Vulnerable Parameter: {item.get('parameter', 'N/A')}\n")
                self._append_text(f"Template Engine: {item.get('engine', 'N/A')}\n")
                self._append_text(f"Detection Method: {item.get('method', 'N/A')}\n")
                self._append_text(f"Evidence: {item.get('evidence', 'N/A')}\n")
                
                # Add payload information if available
                if 'payload' in item:
                    self._append_text("\nPayload Information:\n")
                    self._append_text(f"Payload Type: {item.get('payload_type', 'N/A')}\n")
                    self._append_text(f"Payload Used: {item.get('payload', 'N/A')}\n")
                
                # Add template engine details
                engine = item.get('engine', '').lower()
                if engine:
                    self._append_text("\nTemplate Engine Details:\n")
                    if engine == 'jinja2':
                        self._append_text("• Jinja2 is a modern and designer-friendly templating language for Python\n")
                        self._append_text("• Common payload pattern: {{7*'7'}} or {{self.__init__.__globals__.__builtins__}}\n")
                    elif engine == 'twig':
                        self._append_text("• Twig is a modern template engine for PHP\n")
                        self._append_text("• Common payload pattern: {{_self.env.registerUndefinedFilterCallback('exec')}}\n")
                    elif engine == 'freemarker':
                        self._append_text("• FreeMarker is a template engine for Java\n")
                        self._append_text("• Common payload pattern: ${7*7} or <#assign ex=\"freemarker.template.utility.Execute\">\n")
                    elif engine == 'velocity':
                        self._append_text("• Velocity is a Java-based template engine\n")
                        self._append_text("• Common payload pattern: #set($str=$class.inspect(\"java.lang.String\"))\n")
                    elif engine == 'handlebars':
                        self._append_text("• Handlebars is a JavaScript templating engine\n")
                        self._append_text("• Common payload pattern: {{#with \"s\" as |string|}} or {{this.constructor.constructor}}\n")
                    elif engine == 'erb':
                        self._append_text("• ERB is Ruby's templating engine\n")
                        self._append_text("• Common payload pattern: <%= 7*7 %> or <%= system('command') %>\n")
                
                self._append_text("\n" + "="*50 + "\n\n")
            
            # Display the formatted output as requested
            self._append_text("\nFormatted Output:\n")
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
            self.shell_output.insert(tk.END, "Exiting shell...\n", "exit")
            self.shell_output.config(state='disabled')
            self.shell_input.delete(0, tk.END)
            return
            
        # Add clear command
        if command.lower() == 'clear':
            self.shell_output.config(state='normal')
            self.shell_output.delete('1.0', tk.END)
            self.shell_output.config(state='disabled')
            self.shell_input.delete(0, tk.END)
            return
            
        # Add command to history
        self.command_history.append(command)
        self.history_index = len(self.command_history)
            
        # Send command to exploiter
        if hasattr(self, 'exploiter') and self.exploiter:
            try:
                self.shell_output.config(state='normal')
                self.shell_output.insert(tk.END, f"> {command}\n", "command")
                
                # Update status
                self.status_bar.config(text="Executing command...", foreground="#89B4FA")
                self.update_idletasks()
                
                response = self.exploiter.execute_command(command)
                if response:
                    self.shell_output.insert(tk.END, f"{response}\n", "response")
                else:
                    self.shell_output.insert(tk.END, "No response received from server\n", "error")
                    
                self.shell_output.config(state='disabled')
                self.status_bar.config(text="Command executed successfully", foreground="#4ADE80")  # Green color for success
            except Exception as e:
                self.shell_output.config(state='normal')
                self.shell_output.insert(tk.END, f"Error: {str(e)}\n", "error")
                self.shell_output.config(state='disabled')
                self.status_bar.config(text="Error executing command", foreground="#F87171")  # Red color for error
        else:
            self.shell_output.config(state='normal')
            self.shell_output.insert(tk.END, "Shell not available. Please run a scan first.\n", "error")
            self.shell_output.config(state='disabled')
            self.status_bar.config(text="Shell not available", foreground="#F87171")
            
        self.shell_input.delete(0, tk.END)
        self.shell_output.see(tk.END)
        
        # Configure tags for syntax highlighting with more colors
        self.shell_output.tag_configure("command", foreground="#89B4FA")  # Blue
        self.shell_output.tag_configure("response", foreground="#E0E0E0")  # White
        self.shell_output.tag_configure("error", foreground="#F87171")  # Red
        self.shell_output.tag_configure("exit", foreground="#94a3b8")  # Gray
        self.shell_output.tag_configure("success", foreground="#4ADE80")  # Green
        self.shell_output.tag_configure("warning", foreground="#FBBF24")  # Yellow

    def _history_up(self, event):
        """Navigate up through command history"""
        if self.command_history and self.history_index > 0:
            self.history_index -= 1
            self.shell_input.delete(0, tk.END)
            self.shell_input.insert(0, self.command_history[self.history_index])

    def _history_down(self, event):
        """Navigate down through command history"""
        if self.command_history and self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.shell_input.delete(0, tk.END)
            self.shell_input.insert(0, self.command_history[self.history_index])
        elif self.history_index == len(self.command_history) - 1:
            self.history_index += 1
            self.shell_input.delete(0, tk.END) 