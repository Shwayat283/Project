import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json
import csv
import io
import threading
from scanners.ssti.SSTI import SSTIScanner
import time

class AttackFlowCanvas(tk.Canvas):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.configure(bg='#2D2D44')
        self.phase_nodes = {}
        self.step_nodes = {}
        self.connections = []
        self.node_radius = 30
        self.vertical_spacing = 100
        self.horizontal_spacing = 200
        self.current_y = 50
        
    def add_phase(self, phase_name, status='in_progress'):
        """Add a new phase node to the canvas"""
        x = 100
        y = self.current_y
        
        # Create phase node
        node_id = self.create_oval(
            x - self.node_radius, y - self.node_radius,
            x + self.node_radius, y + self.node_radius,
            fill='#89B4FA' if status == 'in_progress' else '#A6E3A1',
            outline='#E0E0E0'
        )
        
        # Add phase name
        text_id = self.create_text(
            x, y,
            text=phase_name,
            fill='#E0E0E0',
            font=('Segoe UI', 10, 'bold')
        )
        
        self.phase_nodes[phase_name] = (node_id, text_id)
        self.current_y += self.vertical_spacing
        return node_id
        
    def add_step(self, phase_name, step_type, details, status='completed'):
        """Add a step node to the canvas"""
        if phase_name not in self.phase_nodes:
            return
            
        phase_x = 100
        phase_y = self.current_y - self.vertical_spacing
        
        # Calculate step position
        step_x = phase_x + self.horizontal_spacing
        step_y = phase_y
        
        # Create step node
        node_id = self.create_oval(
            step_x - self.node_radius, step_y - self.node_radius,
            step_x + self.node_radius, step_y + self.node_radius,
            fill='#89B4FA' if status == 'in_progress' else '#A6E3A1',
            outline='#E0E0E0'
        )
        
        # Add step details
        text_id = self.create_text(
            step_x, step_y,
            text=f"{step_type}\n{details}",
            fill='#E0E0E0',
            font=('Segoe UI', 8),
            width=150,
            justify=tk.CENTER
        )
        
        # Create connection
        line_id = self.create_line(
            phase_x + self.node_radius, phase_y,
            step_x - self.node_radius, step_y,
            fill='#E0E0E0',
            width=2,
            arrow=tk.LAST
        )
        
        self.step_nodes[step_type] = (node_id, text_id)
        self.connections.append(line_id)
        
    def update_phase_status(self, phase_name, status):
        """Update the status of a phase node"""
        if phase_name in self.phase_nodes:
            node_id, _ = self.phase_nodes[phase_name]
            self.itemconfig(
                node_id,
                fill='#89B4FA' if status == 'in_progress' else '#A6E3A1'
            )
            
    def clear(self):
        """Clear all nodes and connections"""
        self.delete('all')
        self.phase_nodes.clear()
        self.step_nodes.clear()
        self.connections.clear()
        self.current_y = 50

class SSTIScannerWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("SSTI Scanner")
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
        self.scanner = None
        self.flow_update_thread = None
        self.is_scanning = False

    def _create_widgets(self):
        container = ttk.Frame(self, padding=15)
        container.pack(fill=tk.BOTH, expand=True)
        notebook = ttk.Notebook(container)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Add Attack Flow tab
        flow_frame = ttk.Frame(notebook)
        notebook.add(flow_frame, text="Attack Flow")
        
        # Add Interactive Shell tab
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
        
        # Create canvas with scrollbar
        canvas_frame = ttk.Frame(flow_frame)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        
        self.flow_canvas = AttackFlowCanvas(
            canvas_frame,
            width=800,
            height=600,
            highlightthickness=0
        )
        self.flow_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(canvas_frame, orient=tk.VERTICAL, command=self.flow_canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.flow_canvas.configure(yscrollcommand=scrollbar.set)
        
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

    def _on_back(self):
        self.parent._on_child_close(self)

    def _start_scan(self):
        url = self.url_entry.get().strip()
        url_list = self.url_list_entry.get().strip()
        threads = int(self.threads_entry.get()) if self.threads_entry.get().isdigit() else 10
        proxy = self.proxy_entry.get().strip() or None
        payload_list = self.payload_entry.get().strip() or None
        output_format = self.output_var.get()

        if not url and not url_list:
            messagebox.showerror("Input Error", "Target URL or URL-List file is required.")
            return

        self.scan_button.config(state='disabled')
        self._append_text("Starting SSTI scan...\n")
        threading.Thread(target=self._run_scan, args=(url, url_list, threads, proxy, payload_list, output_format), daemon=True).start()

    def _run_scan(self, url, url_list, threads, proxy, payload_list, output_format):
        """Run the SSTI scan"""
        try:
            self.scanner = SSTIScanner()
            self.is_scanning = True
            
            # Start flow visualization update thread
            self.flow_update_thread = threading.Thread(target=self._update_flow_visualization)
            self.flow_update_thread.daemon = True
            self.flow_update_thread.start()
            
            # Run the scan
            results = self.scanner.scan(
                url=url,
                url_list=url_list,
                threads=threads,
                proxy=proxy,
                payload_list=payload_list
            )
            
            # Display results
            self._display_results(results, output_format)
            
            # If vulnerability found, enable shell
            if results and any(r.get('vulnerable', False) for r in results):
                self.shell_output.insert(tk.END, "Vulnerability found! Interactive shell is now available.\n")
                self.shell_output.insert(tk.END, "Type 'exit' to quit the shell.\n")
                self.shell_input.config(state='normal')
            else:
                self.shell_output.insert(tk.END, "No vulnerabilities found. Interactive shell is not available.\n")
                self.shell_input.config(state='disabled')
                
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        finally:
            self.is_scanning = False
            self.scan_button.config(state='normal')

    def _update_flow_visualization(self):
        """Update the attack flow visualization in real-time"""
        while self.is_scanning and self.scanner:
            try:
                flow_data = self.scanner.get_flow_data()
                self.flow_canvas.clear()
                
                for phase in flow_data:
                    # Add phase node
                    self.flow_canvas.add_phase(phase['phase'], phase['status'])
                    
                    # Add step nodes
                    for step in phase['steps']:
                        details = step['details']
                        if isinstance(details, dict):
                            details = f"{details.get('parameter', '')} - {details.get('engine', '')}"
                        self.flow_canvas.add_step(
                            phase['phase'],
                            step['type'],
                            str(details),
                            step['status']
                        )
                
                time.sleep(0.5)  # Update every 500ms
            except Exception as e:
                print(f"Flow update error: {e}")
                break

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
            self.shell_output.insert(tk.END, "Exiting shell...\n")
            self.shell_input.delete(0, tk.END)
            return
            
        # Send command to scanner
        if self.scanner and hasattr(self.scanner, 'execute_shell_command'):
            try:
                response = self.scanner.execute_shell_command(command)
                self.shell_output.insert(tk.END, f"> {command}\n{response}\n")
            except Exception as e:
                self.shell_output.insert(tk.END, f"Error: {str(e)}\n")
        else:
            self.shell_output.insert(tk.END, "Scanner not initialized or shell not available\n")
            
        self.shell_input.delete(0, tk.END)
        self.shell_output.see(tk.END) 