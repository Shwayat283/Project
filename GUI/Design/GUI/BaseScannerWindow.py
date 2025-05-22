import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import json
import csv
import io

class BaseScannerWindow(tk.Toplevel):
    def __init__(self, parent, title, icon):
        super().__init__(parent)
        self.parent = parent
        self.title(title)
        self.configure(bg=self.parent.current_bg)
        self._setup_styles()
        self._create_widgets(icon)

    def _setup_styles(self):
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

    def _create_widgets(self, icon):
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
                               text=f"{icon} {self.title()}",
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
        self.input_container = ttk.Frame(input_frame)
        self.input_container.grid(row=1, column=0, columnspan=3, sticky=tk.EW, padx=20)
        self.input_container.grid_columnconfigure(1, weight=1)

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

    def _on_back(self):
        self.parent._on_child_close(self)

    def _start_scan(self):
        """To be implemented by child classes"""
        raise NotImplementedError("Child classes must implement _start_scan")

    def _append_text(self, text):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state='disabled')

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