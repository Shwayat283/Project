import threading

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk
import json
import csv
import io
import LFI as scanner_module
import XSS as xss_module
import SSTI as ssti_module
from PIL import Image, ImageTk
import os

class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Vulnerability Scanner")
        self.geometry("1200x900")
        # Minimal color scheme
        self.current_bg = "#1a1a1a"  # Dark background
        self.accent_color = "#4a90e2"  # Soft blue accent
        self.text_color = "#ffffff"  # White text
        self.error_color = "#e74c3c"  # Soft red for errors
        self.success_color = "#2ecc71"  # Soft green for success
        self.configure(bg=self.current_bg)
        self.style = ttk.Style(self)
        self.style.theme_use('alt')
        
        # Initialize icons
        self.icons = {
            "LFI": "📁",  # File icon
            "SSRF": "🔄",  # Refresh icon
            "SSTI": "📝",  # Document icon
            "XSS": "⚠️"   # Warning icon
        }
        
        self._setup_styles()
        self._create_settings_button()
        self._create_main_menu()
    
    def _setup_styles(self):
        """Setup minimal theme styles"""
        # Configure base styles
        self.style.configure('TFrame', background=self.current_bg)
        self.style.configure('TLabel', 
                           background=self.current_bg, 
                           foreground=self.text_color,
                           font=('Segoe UI', 12))
        self.style.configure('TButton', 
                           font=('Segoe UI', 12, 'bold'),
                           borderwidth=0,
                           relief='flat',
                           background='#2d2d2d',
                           foreground=self.text_color,
                           padding=(20, 10))
        self.style.map('TButton',
                      background=[('active', '#3d3d3d'), ('pressed', '#4d4d4d')])
        
        # Configure accent button style
        self.style.configure('Accent.TButton', 
                           background=self.accent_color,
                           foreground=self.text_color,
                           font=('Segoe UI', 12, 'bold'),
                           padding=(20, 10))
        self.style.map('Accent.TButton',
                      background=[('active', '#5a9ae2'), ('pressed', '#4a90e2')])
        
        # Configure danger button style
        self.style.configure('Danger.TButton',
                           background=self.error_color,
                           foreground=self.text_color,
                           font=('Segoe UI', 12, 'bold'),
                           padding=(20, 10))
        self.style.map('Danger.TButton',
                      background=[('active', '#f55c4c'), ('pressed', '#e74c3c')])
        
        # Configure success button style
        self.style.configure('Success.TButton',
                           background=self.success_color,
                           foreground=self.text_color,
                           font=('Segoe UI', 12, 'bold'),
                           padding=(20, 10))
        self.style.map('Success.TButton',
                      background=[('active', '#3ecc81'), ('pressed', '#2ecc71')])
        
        # Configure entry style
        self.style.configure('Custom.TEntry',
                           fieldbackground='#2d2d2d',
                           foreground=self.text_color,
                           insertcolor=self.text_color,
                           bordercolor='#3d3d3d',
                           lightcolor='#3d3d3d',
                           darkcolor='#3d3d3d')
        
        # Configure notebook style
        self.style.configure('TNotebook',
                           background=self.current_bg,
                           tabmargins=[2, 5, 2, 0])
        self.style.configure('TNotebook.Tab',
                           background='#24283b',
                           foreground=self.text_color,
                           padding=[10, 5],
                           font=('Segoe UI', 10))
        self.style.map('TNotebook.Tab',
                      background=[('selected', self.accent_color)],
                      foreground=[('selected', '#1a1b26')])

    def _create_settings_button(self):
        """Create modern settings button"""
        self.settings_btn = tk.Button(
            self, text='⚙', font=('Segoe UI', 22, 'bold'),
            bg=self.current_bg, fg=self.text_color, bd=0, relief='flat',
            cursor='hand2', activebackground='#24283b',
            activeforeground=self.accent_color
        )
        self.settings_btn.place(x=10, y=10, width=44, height=44)

        # Modern settings menu
        self.settings_menu = tk.Menu(self, tearoff=0,
                                   bg='#24283b', fg=self.text_color,
                                   activebackground=self.accent_color,
                                   activeforeground='#1a1b26',
                                   font=('Segoe UI', 10))
        self.settings_menu.add_command(label='Color Theme', command=self._open_color_theme)
        self.settings_menu.add_command(label='Help', command=self._open_help)
        self.settings_menu.add_separator()
        self.settings_menu.add_command(label='About', command=self._open_about)
        self.settings_btn.bind('<Button-1>', self._show_settings_menu)

    def _show_settings_menu(self, event):
        """Show the settings menu at the button's position"""
        try:
            self.settings_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.settings_menu.grab_release()

    def _open_color_theme(self):
        """Open color theme window with modern design"""
        theme_window = tk.Toplevel(self)
        theme_window.title("Color Theme")
        theme_window.geometry("400x500")
        theme_window.configure(bg=self.current_bg)
        
        # Create main container
        main_frame = ttk.Frame(theme_window)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)
        
        # Title
        title = ttk.Label(main_frame,
                         text="🎨 Color Theme",
                         font=("Segoe UI", 20, "bold"),
                         foreground="#00BFFF")
        title.pack(pady=(0, 20))
        
        # Theme options
        themes = [
            ("Dark Theme", "#1E1E1E"),
            ("Light Theme", "#F5F5F5"),
            ("Blue Theme", "#1A237E"),
            ("Green Theme", "#1B5E20")
        ]
        
        for theme_name, theme_color in themes:
            theme_frame = ttk.Frame(main_frame)
            theme_frame.pack(fill=tk.X, pady=5)
            
            theme_btn = ttk.Button(theme_frame,
                                 text=theme_name,
                                 style='Accent.TButton',
                                 command=lambda c=theme_color: self._change_theme(c))
            theme_btn.pack(fill=tk.X)

    def _change_theme(self, color):
        """Change the application theme with smooth transition"""
        self.current_bg = color
        self.configure(bg=color)
        self._setup_styles()
        # Update all child windows
        for child in self.winfo_children():
            if isinstance(child, (tk.Toplevel, ttk.Frame)):
                child.configure(bg=color)

    def _open_help(self):
        """Open help window with modern design"""
        help_window = tk.Toplevel(self)
        help_window.title("Help")
        help_window.geometry("600x400")
        help_window.configure(bg=self.current_bg)
        
        # Create main container
        main_frame = ttk.Frame(help_window)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)
        
        # Title
        title = ttk.Label(main_frame,
                         text="❓ Help & Documentation",
                         font=("Segoe UI", 20, "bold"),
                         foreground="#00BFFF")
        title.pack(pady=(0, 20))
        
        # Help content
        help_text = scrolledtext.ScrolledText(main_frame,
                                            font=("Segoe UI", 11),
                                            bg='#2d2d2d',
                                            fg='white',
                                            insertbackground='white')
        help_text.pack(fill=tk.BOTH, expand=True)
        
        help_content = """
        Vulnerability Scanner Help
        
        1. Getting Started
        - Select a scanner type from the main menu
        - Enter the target URL
        - Configure scan options
        - Click Start Scan
        
        2. Scanner Types
        - SSRF: Server-Side Request Forgery
        - SSTI: Server-Side Template Injection
        - LFI: Local File Inclusion
        - XSS: Cross-Site Scripting
        
        3. Configuration
        - Headers: Add custom HTTP headers
        - Data: Add POST data for POST requests
        - Threads: Number of concurrent scans
        - Timeout: Request timeout in seconds
        
        4. Results
        - Real-time scan results
        - Progress indicator
        - Status updates
        """
        
        help_text.insert("1.0", help_content)
        help_text.config(state=tk.DISABLED)

    def _open_about(self):
        """Open about window with modern design"""
        about_window = tk.Toplevel(self)
        about_window.title("About")
        about_window.geometry("400x300")
        about_window.configure(bg=self.current_bg)
        
        # Create main container
        main_frame = ttk.Frame(about_window)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)
        
        # Title
        title = ttk.Label(main_frame,
                         text="ℹ️ About",
                         font=("Segoe UI", 20, "bold"),
                         foreground="#00BFFF")
        title.pack(pady=(0, 20))
        
        # Version
        version = ttk.Label(main_frame,
                          text="Version 1.0.0",
                          font=("Segoe UI", 12),
                          foreground="#888888")
        version.pack()
        
        # Description
        description = ttk.Label(main_frame,
                              text="A comprehensive vulnerability scanner\nfor web applications",
                              font=("Segoe UI", 12),
                              foreground="#ffffff",
                              justify=tk.CENTER)
        description.pack(pady=20)
        
        # Copyright
        copyright = ttk.Label(main_frame,
                            text="© 2024 All rights reserved",
                            font=("Segoe UI", 10),
                            foreground="#888888")
        copyright.pack(side=tk.BOTTOM)

    def _create_main_menu(self):
        """Create minimal main menu"""
        menu_frame = ttk.Frame(self, padding=20)
        menu_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title with minimal styling
        title_label = ttk.Label(menu_frame, 
                               text="Vulnerability Scanner",
                               font=('Segoe UI', 32, 'bold'),
                               foreground=self.accent_color)
        title_label.pack(pady=(0, 30))
        
        # Scanner buttons with icons and minimal layout
        scanners = [
            ("LFI Scanner", "LFI"),
            ("SSRF Scanner", "SSRF"),
            ("SSTI Scanner", "SSTI"),
            ("XSS Scanner", "XSS")
        ]
        
        for text, scanner_type in scanners:
            btn = ttk.Button(menu_frame,
                            text=f"{self.icons.get(scanner_type, '')} {text}",
                            style='Accent.TButton',
                            command=lambda t=scanner_type: self._show_scanner(t))
            btn.pack(fill=tk.X, pady=5, padx=50)
            
        # Version label with minimal styling
        version_label = ttk.Label(menu_frame,
                                 text="Version 1.0",
                                 font=('Segoe UI', 10),
                                 foreground='#666666')
        version_label.pack(side=tk.BOTTOM, pady=10)

    def _show_scanner(self, scanner_type):
        """Show scanner window with modern styling"""
        if scanner_type == "LFI":
            if hasattr(self, 'lfi_window') and self.lfi_window.winfo_exists():
                self.lfi_window.lift()
                return
            self.lfi_window = LFIScannerWindow(self)
            self.lfi_window.protocol("WM_DELETE_WINDOW", lambda: self._on_child_close(self.lfi_window))
            self.lfi_window.grab_set()
        elif scanner_type == "SSRF":
            if hasattr(self, 'ssrf_window') and self.ssrf_window.winfo_exists():
                self.ssrf_window.lift()
                return
            self.ssrf_window = SSRFScannerWindow(self)
            self.ssrf_window.protocol("WM_DELETE_WINDOW", lambda: self._on_child_close(self.ssrf_window))
            self.ssrf_window.grab_set()
        elif scanner_type == "SSTI":
            if hasattr(self, 'ssti_window') and self.ssti_window.winfo_exists():
                self.ssti_window.lift()
                return
            self.ssti_window = SSTIScannerWindow(self)
            self.ssti_window.protocol("WM_DELETE_WINDOW", lambda: self._on_child_close(self.ssti_window))
            self.ssti_window.grab_set()
        elif scanner_type == "XSS":
            if hasattr(self, 'xss_window') and self.xss_window.winfo_exists():
                self.xss_window.lift()
                return
            self.xss_window = XSSScannerWindow(self)
            self.xss_window.protocol("WM_DELETE_WINDOW", lambda: self._on_child_close(self.xss_window))
            self.xss_window.grab_set()
        else:
            messagebox.showerror("Error", f"Unknown scanner type: {scanner_type}")

    def _show_main_menu(self):
        """Show the main menu and hide scanner interface"""
        if hasattr(self, 'scanner_frame'):
            self.scanner_frame.pack_forget()
        self.main_frame.pack(expand=True, fill=tk.BOTH, padx=50, pady=50)
        # Show settings button
        self.settings_btn.place(x=10, y=10, width=44, height=44)
        self.settings_btn.lift()

    def _browse_file(self, entry_widget):
        """Browse for a file and update the entry widget"""
        filename = filedialog.askopenfilename(
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)

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

    def _start_scan(self, scanner_type):
        """Start the scanning process with modern UI feedback"""
        try:
            # Get input values
            url = self.url_entry.get().strip()
            if not url:
                messagebox.showerror("Error", "Please enter a target URL")
                return
            
            # Create progress bar and status label if they don't exist
            if not hasattr(self, 'progress_var'):
                self.progress_var = tk.DoubleVar()
                self.progress_bar = ttk.Progressbar(self.scanner_frame, 
                                                  variable=self.progress_var,
                                                  maximum=100)
                self.progress_bar.pack(fill=tk.X, padx=20, pady=10)
                
                self.status_label = ttk.Label(self.scanner_frame,
                                            text="Ready to scan",
                                            foreground="#00BFFF")
                self.status_label.pack(pady=5)
            
            # Clear previous results
            self.results_text.delete("1.0", tk.END)
            self.progress_var.set(0)
            self.status_label.config(text="Scanning in progress...", foreground="#00BFFF")
            
            # Get scanner options
            try:
                threads = int(self.threads_entry.get())
            except ValueError:
                messagebox.showerror("Error", "Threads must be a number")
                return
            
            # Start scan in a separate thread
            self.scan_thread = threading.Thread(
                target=self._run_scan,
                args=(scanner_type, url, threads)
            )
            self.scan_thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            if hasattr(self, 'status_label'):
                self.status_label.config(text="Error occurred", foreground="#FF4444")

    def _run_scan(self, scanner_type, url, threads):
        """Run the actual scan with modern progress updates"""
        try:
            # Initialize scanner based on type
            if scanner_type == "LFI":
                try:
                    scanner = scanner_module.LFIScanner(threads=threads)
                    # Run LFI scan without callbacks
                    results = scanner.scan(url)
                    # Display results
                    for result in results:
                        self._append_text(f"{json.dumps(result, indent=2)}\n")
                    self.status_label.config(text="Scan completed", foreground="#00C851")
                    self.progress_var.set(100)
                    return
                except ImportError:
                    self._append_text("Error: LFI scanner module not found. Please ensure LFI.py exists.\n")
                    return
            elif scanner_type == "SSRF":
                try:
                    from project30 import SSRFScanner
                    scanner = SSRFScanner(url=url, threads=threads)
                    # Run SSRF scan without callbacks
                    results = scanner.scan()
                    # Display results
                    for result in results:
                        self._append_text(f"{json.dumps(result, indent=2)}\n")
                    self.status_label.config(text="Scan completed", foreground="#00C851")
                    self.progress_var.set(100)
                    return
                except ImportError:
                    self._append_text("Error: SSRF scanner module not found. Please ensure project30.py exists.\n")
                    return
            elif scanner_type == "SSTI":
                try:
                    from SSTI import SSTIScanner
                    scanner = SSTIScanner(verbose=True, crawl=True)
                    results = scanner.scan(url)
                    for result in results:
                        self._append_text(f"{json.dumps(result, indent=2)}\n")
                    self.status_label.config(text="Scan completed", foreground="#00C851")
                    self.progress_var.set(100)
                    return
                except ImportError:
                    self._append_text("Error: SSTI scanner module not found. Please ensure SSTI.py exists.\n")
                    return
            elif scanner_type == "XSS":
                try:
                    scanner = xss_module.XSSHunter(url, threads=threads)
                except ImportError:
                    self._append_text("Error: XSS scanner module not found. Please ensure XSS.py exists.\n")
                    return
            else:
                self._append_text(f"Error: Unknown scanner type: {scanner_type}\n")
                return
            
            # Set up progress callback
            def progress_callback(current, total):
                progress = (current / total) * 100
                self.progress_var.set(progress)
                self.status_label.config(
                    text=f"Scanning... {current}/{total} ({progress:.1f}%)",
                    foreground="#00BFFF"
                )
            
            # Set up result callback
            def result_callback(result):
                self._append_text(f"{result}\n")
            
            # Run the scan
            scanner.scan(progress_callback, result_callback)
            
            # Update UI when done
            self.status_label.config(text="Scan completed", foreground="#00C851")
            self.progress_var.set(100)
            
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}", foreground="#FF4444")
            self._append_text(f"\nError: {str(e)}\n")

    def _append_text(self, text):
        """Append text to the results text widget"""
        self.results_text.config(state='normal')
        self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END)
        self.results_text.config(state='disabled')

    def _stop_scan(self):
        """Stop the current scan with modern UI feedback"""
        if hasattr(self, 'scan_thread') and self.scan_thread.is_alive():
            self.status_label.config(text="Stopping scan...", foreground="#FF4444")
            # Implement actual stop logic here
            self.status_label.config(text="Scan stopped", foreground="#FF4444")
        else:
            self.status_label.config(text="No scan in progress", foreground="#888888")

    def _clear_placeholder(self, event, placeholder_text):
        """Clear placeholder text when entry gets focus"""
        widget = event.widget
        if widget.get() == placeholder_text:
            widget.delete(0, tk.END)
            widget.config(foreground='#000000')  # Black color for user input

    def _restore_placeholder(self, event, placeholder_text):
        """Restore placeholder text if entry is empty"""
        widget = event.widget
        if not widget.get():
            widget.insert(0, placeholder_text)
            widget.config(foreground='#808080')  # Light gray color for placeholder

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
        
        # إعداد نمط زر Browse الأزرق
        style = ttk.Style()
        style.configure('Blue.TButton', background='#38bdf8', foreground='#0f172a', font=('Segoe UI', 11, 'bold'))
        style.map('Blue.TButton', background=[('active', '#7dd3fc'), ('pressed', '#0284c7')])

        # Target URL
        row = 0
        ttk.Label(input_frame, text="🌐 Target URL:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.url_entry = ttk.Entry(input_frame, width=60, style='Custom.TEntry')
        self.url_entry.insert(0, "Enter target URL (e.g., http://example.com)")
        self.url_entry.grid(row=row, column=1, columnspan=2, padx=5)

        # URL List
        row += 1
        ttk.Label(input_frame, text="📋 URL List:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.url_list_entry = ttk.Entry(input_frame, width=50, style='Custom.TEntry')
        self.url_list_entry.insert(0, "Enter path to URL list file (optional)")
        self.url_list_entry.grid(row=row, column=1)
        ttk.Button(input_frame, text="Browse", style='Blue.TButton', command=self._browse_urllist).grid(row=row, column=2, padx=5)

        # Proxy Input
        row += 1
        ttk.Label(input_frame, text="🔒 Proxy:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.proxy_entry = ttk.Entry(input_frame, width=30, style='Custom.TEntry')
        self.proxy_entry.grid(row=row, column=1)
        
        # Threads Input
        row += 1
        ttk.Label(input_frame, text="⚡ Threads:", font=("Segoe UI", 12)).grid(row=row, column=2, sticky=tk.W)
        self.threads_entry = ttk.Entry(input_frame, width=10, style='Custom.TEntry')
        self.threads_entry.insert(0, "10")
        self.threads_entry.grid(row=row, column=3)
        
        # Wordlist Input
        row += 1
        ttk.Label(input_frame, text="📚 Wordlist:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.wordlist_entry = ttk.Entry(input_frame, width=50, style='Custom.TEntry')
        self.wordlist_entry.grid(row=row, column=1, columnspan=2)
        ttk.Button(input_frame, text="Browse", style='Blue.TButton', command=self._browse_wordlist).grid(row=row, column=3, padx=5)
        
        # Cookies Input
        row += 1
        ttk.Label(input_frame, text="Cookies:").grid(row=row, column=0, sticky=tk.W, pady=8)
        self.cookies_entry = ttk.Entry(input_frame, width=60, style='Custom.TEntry')
        self.cookies_entry.grid(row=row, column=1, columnspan=3)
        
        # Exploit Categories
        row += 1
        ttk.Label(input_frame, text="Exploit Categories:").grid(row=row, column=0, columnspan=4, sticky=tk.W, pady=8)
        self.categories_frame = ttk.Frame(input_frame)
        self.categories_frame.grid(row=row+1, column=0, columnspan=4, sticky=tk.W)
        
        self.category_vars = {}
        categories = [
            ("linux_users", "Linux User Files"),
            ("linux_system", "Linux System Files"),
            ("linux_network", "Linux Network Files"),
            ("windows_common", "Windows Files"),
            ("log_rce", "Log-based RCE")
        ]
        
        # Create a frame for the checkbuttons with a border
        check_frame = ttk.LabelFrame(self.categories_frame, text="Select Categories", padding=5)
        check_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add checkbuttons vertically
        for cat_id, cat_name in categories:
            var = tk.BooleanVar()
            self.category_vars[cat_id] = var
            cb = ttk.Checkbutton(check_frame, 
                               text=cat_name,
                               variable=var)
            cb.pack(anchor=tk.W, pady=2)
        
        # Output Format
        row += 1
        ttk.Label(input_frame, text="Output Format:").grid(row=row, column=0, sticky=tk.W)
        self.output_var = tk.StringVar(value="json")
        ttk.OptionMenu(input_frame, self.output_var, "json", "json", "csv", "xml").grid(row=row, column=1, sticky=tk.W)
        
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
        self._append_text("Starting LFI scan...\n")
        threading.Thread(target=self._run_scan, args=(urls, params), daemon=True).start()

    def _run_scan(self, urls, params):
        try:
            from LFI import LFIScanner
            scanner = LFIScanner(
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
        if not results:
            self._append_text("No vulnerabilities found.\n")
            return
            
        self._append_text(f"Scan complete. Found {len(results)} issues.\n")
        
        if self.output_var.get() == 'json':
            self._append_text(json.dumps(results, indent=2) + "\n")
        elif self.output_var.get() == 'xml':
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
            writer.writerow(['URL', 'Parameter', 'Payload', 'Status', 'Length', 'Timestamp'])
            for item in results:
                writer.writerow([
                    item.get('url', ''),
                    item.get('parameter', ''),
                    item.get('payload', ''),
                    item.get('status', ''),
                    item.get('length', ''),
                    item.get('timestamp', '')
                ])
            self._append_text(output.getvalue() + "\n")

    def _append_text(self, text):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state='disabled')

    def _clear_placeholder(self, event, placeholder_text):
        """Clear placeholder text when entry gets focus"""
        widget = event.widget
        if widget.get() == placeholder_text:
            widget.delete(0, tk.END)
            widget.config(foreground='#000000')  # Black color for user input

    def _restore_placeholder(self, event, placeholder_text):
        """Restore placeholder text if entry is empty"""
        widget = event.widget
        if not widget.get():
            widget.insert(0, placeholder_text)
            widget.config(foreground='#808080')  # Light gray color for placeholder

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
        
        # إعداد نمط زر Browse الأزرق
        style = ttk.Style()
        style.configure('Blue.TButton', background='#38bdf8', foreground='#0f172a', font=('Segoe UI', 11, 'bold'))
        style.map('Blue.TButton', background=[('active', '#7dd3fc'), ('pressed', '#0284c7')])

        # Target URL
        row = 0
        ttk.Label(input_frame, text="🌐 Target URL:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.url_entry = ttk.Entry(input_frame, width=60, style='Custom.TEntry')
        self.url_entry.insert(0, "Enter target URL (e.g., http://example.com)")
        self.url_entry.grid(row=row, column=1, columnspan=2, padx=5)

        # URL List
        row += 1
        ttk.Label(input_frame, text="📋 URL List:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.url_list_entry = ttk.Entry(input_frame, width=50, style='Custom.TEntry')
        self.url_list_entry.insert(0, "Enter path to URL list file (optional)")
        self.url_list_entry.grid(row=row, column=1)
        ttk.Button(input_frame, text="Browse", style='Blue.TButton', command=self._browse_urllist).grid(row=row, column=2, padx=5)

        # Payload List
        row += 1
        ttk.Label(input_frame, text="🎯 Payload List:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.payload_entry = ttk.Entry(input_frame, width=50, style='Custom.TEntry')
        self.payload_entry.insert(0, "Enter path to payload list file")
        self.payload_entry.grid(row=row, column=1)
        ttk.Button(input_frame, text="Browse", style='Blue.TButton', command=self._browse_payload).grid(row=row, column=2, padx=5)

        # Path Payload List
        row += 1
        ttk.Label(input_frame, text="📂 Path Payload List:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.path_payload_entry = ttk.Entry(input_frame, width=50, style='Custom.TEntry')
        self.path_payload_entry.insert(0, "Enter path to path payload list file")
        self.path_payload_entry.grid(row=row, column=1)
        ttk.Button(input_frame, text="Browse", style='Blue.TButton', command=self._browse_path_payload).grid(row=row, column=2, padx=5)

        # Collaborator
        row += 1
        ttk.Label(input_frame, text="🔗 Collaborator:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.collab_entry = ttk.Entry(input_frame, width=50, style='Custom.TEntry')
        self.collab_entry.insert(0, "Enter collaborator domain (optional)")
        self.collab_entry.grid(row=row, column=1, columnspan=2, padx=5)

        # Brute Force Attack
        row += 1
        ttk.Label(input_frame, text="🔓 Bruteforce Attack:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.brute_var = tk.StringVar(value="no")
        ttk.Radiobutton(input_frame, text="Yes", value="yes", variable=self.brute_var).grid(row=row, column=1, sticky=tk.W)
        ttk.Radiobutton(input_frame, text="No", value="no", variable=self.brute_var).grid(row=row, column=2, sticky=tk.W)

        # Proxy
        row += 1
        ttk.Label(input_frame, text="🔒 Proxy:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.proxy_entry = ttk.Entry(input_frame, width=50, style='Custom.TEntry')
        self.proxy_entry.insert(0, "Enter proxy (e.g., 127.0.0.1:8080)")
        self.proxy_entry.grid(row=row, column=1, columnspan=2, padx=5)

        # Threads
        row += 1
        ttk.Label(input_frame, text="⚡ Threads:", font=("Segoe UI", 12)).grid(row=row, column=0, sticky=tk.W, pady=8)
        self.threads_entry = ttk.Entry(input_frame, width=10, style='Custom.TEntry')
        self.threads_entry.insert(0, "10")
        self.threads_entry.grid(row=row, column=1, sticky=tk.W)

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
        url = self.url_entry.get().strip()
        url_list = self.url_list_entry.get().strip()
        threads = int(self.threads_entry.get()) if self.threads_entry.get().isdigit() else 20
        proxy = self.proxy_entry.get().strip() or None
        payload_list = self.payload_entry.get().strip() or None
        path_payload_list = self.path_payload_entry.get().strip() or None
        collaborator = self.collab_entry.get().strip() or None
        bruteforceattack = self.brute_var.get()
        output = self.output_var.get()
        
        if not url and not url_list:
            messagebox.showerror("Input Error", "Target URL or URL-List file is required.")
            return
            
        self.scan_button.config(state='disabled')
        self._append_text("Starting SSRF scan...\n")
        threading.Thread(target=self._run_scan, 
                        args=(url, url_list, threads, proxy, payload_list, 
                              path_payload_list, collaborator, bruteforceattack, output), 
                        daemon=True).start()

    def _run_scan(self, url, url_list, threads, proxy, payload_list, path_payload_list, collaborator, bruteforceattack, output):
        try:
            from SSRF import SSRFScanner
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

    def _display_results(self, results, output_format):
        if not results:
            self._append_text("No vulnerabilities found.\n")
            return
            
        self._append_text(f"Scan complete. Found {len(results)} issues.\n")
        
        if output_format == 'json':
            self._append_text(json.dumps(results, indent=2) + "\n")
        elif output_format == 'xml':
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

    def _clear_placeholder(self, event, placeholder_text):
        """Clear placeholder text when entry gets focus"""
        widget = event.widget
        if widget.get() == placeholder_text:
            widget.delete(0, tk.END)
            widget.config(foreground='#000000')  # Black color for user input

    def _restore_placeholder(self, event, placeholder_text):
        """Restore placeholder text if entry is empty"""
        widget = event.widget
        if not widget.get():
            widget.insert(0, placeholder_text)
            widget.config(foreground='#808080')  # Light gray color for placeholder

class XSSScannerWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("XSS Scanner")
        self.geometry("800x600")
        self.configure(bg=parent.current_bg)
        self._create_widgets()
        
        # Protocol handler for window close
        self.protocol("WM_DELETE_WINDOW", self._on_back)
        
        # Store button reference
        self.scan_running = False
        
    def _create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)
        
        # Input frame
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        # URL Entry
        url_label = ttk.Label(input_frame, text="Target URL:")
        url_label.pack(anchor=tk.W)
        
        self.url_entry = ttk.Entry(input_frame, width=50)
        self.url_entry.pack(fill=tk.X, pady=(5, 10))
        
        # Parameters Entry
        params_label = ttk.Label(input_frame, text="Parameters (comma-separated):")
        params_label.pack(anchor=tk.W)
        
        self.params_entry = ttk.Entry(input_frame, width=50)
        self.params_entry.pack(fill=tk.X, pady=(5, 10))
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        # Back button
        back_btn = ttk.Button(button_frame, text="Back", command=self._on_back)
        back_btn.pack(side=tk.LEFT, padx=5)
        
        # Scan button
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self._start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        # Output Text
        self.output_text = scrolledtext.ScrolledText(main_frame, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
    def _on_back(self):
        self.parent._show_main_menu()
        self.destroy()
        
    def _start_scan(self):
        if self.scan_running:
            return
            
        url = self.url_entry.get().strip()
        params = self.params_entry.get().strip()
        
        if not url or not params:
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        # Disable scan button
        self.scan_running = True
        self.scan_button.config(state='disabled')
        
        # Clear output
        self.output_text.delete(1.0, tk.END)
        
        # Start scan in a separate thread
        params_dict = {
            'url': url,
            'params': params.split(',')
        }
        
        scan_thread = threading.Thread(target=self._run_scan, args=(params_dict,))
        scan_thread.daemon = True
        scan_thread.start()
        
    def _run_scan(self, params):
        try:
            # Redirect print to the text widget
            original_print = print
            def custom_print(*args, **kwargs):
                # Get the message
                output = " ".join(map(str, args))
                # Schedule the UI update in the main thread
                self.after(0, self._append_text, output + "\n")
            
            # Replace the print function
            print = custom_print
            
            # Run the scan
            scanner = xss_module.XSSScanner()
            scanner.scan(params['url'], params['params'])
            
        except Exception as e:
            self.after(0, messagebox.showerror, "Error", str(e))
        finally:
            # Restore the original print function
            print = original_print
            # Re-enable the scan button in the main thread
            self.after(0, self._enable_scan_button)
            
    def _enable_scan_button(self):
        self.scan_running = False
        self.scan_button.config(state='normal')
            
    def _append_text(self, text):
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)

class SSTIScannerWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("SSTI Scanner")
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
        
        # URL Input
        ttk.Label(input_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=8)
        self.url_entry = ttk.Entry(input_frame, width=60, style='Custom.TEntry')
        self.url_entry.grid(row=0, column=1, columnspan=3, padx=5)
        
        # Proxy Input
        ttk.Label(input_frame, text="Proxy:").grid(row=1, column=0, sticky=tk.W, pady=8)
        self.proxy_entry = ttk.Entry(input_frame, width=30, style='Custom.TEntry')
        self.proxy_entry.grid(row=1, column=1)
        
        # Threads Input
        ttk.Label(input_frame, text="Threads:").grid(row=1, column=2, sticky=tk.W)
        self.threads_entry = ttk.Entry(input_frame, width=10, style='Custom.TEntry')
        self.threads_entry.insert(0, "10")
        self.threads_entry.grid(row=1, column=3)
        
        # Crawl Option
        ttk.Label(input_frame, text="Crawl:").grid(row=2, column=0, sticky=tk.W, pady=8)
        self.crawl_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(input_frame, variable=self.crawl_var).grid(row=2, column=1, sticky=tk.W)
        
        # Crawl Depth
        ttk.Label(input_frame, text="Crawl Depth:").grid(row=2, column=2, sticky=tk.W)
        self.depth_entry = ttk.Entry(input_frame, width=10, style='Custom.TEntry')
        self.depth_entry.insert(0, "2")
        self.depth_entry.grid(row=2, column=3)
        
        # Verbose Output
        ttk.Label(input_frame, text="Verbose:").grid(row=3, column=0, sticky=tk.W, pady=8)
        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(input_frame, variable=self.verbose_var).grid(row=3, column=1, sticky=tk.W)
        
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
                                                     bg='#3d3d3d',
                                                     fg='#ffffff',
                                                     insertbackground='white',
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

        params = {
            'url': url,
            'proxy': self.proxy_entry.get().strip() or None,
            'threads': int(self.threads_entry.get()),
            'crawl': self.crawl_var.get(),
            'crawl_depth': int(self.depth_entry.get()),
            'verbose': self.verbose_var.get()
        }

        self.scan_button.config(state='disabled')
        self._append_text("Starting SSTI scan...\n")
        threading.Thread(target=self._run_scan, args=(params,), daemon=True).start()

    def _run_scan(self, params):
        try:
            from SSTI import SSTIScanner
            scanner = SSTIScanner(
                proxies=params['proxy'],
                verbose=params['verbose'],
                crawl=params['crawl'],
                crawl_depth=params['crawl_depth']
            )
            
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
                results = scanner.scan(params['url'])
                if results:
                    self._append_text("\nVulnerabilities found:\n")
                    for result in results:
                        self._append_text(f"{json.dumps(result, indent=2)}\n")
                else:
                    self._append_text("\nNo vulnerabilities found.\n")
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

    def _clear_placeholder(self, event, placeholder_text):
        """Clear placeholder text when entry gets focus"""
        widget = event.widget
        if widget.get() == placeholder_text:
            widget.delete(0, tk.END)
            widget.config(foreground='#000000')  # Black color for user input

    def _restore_placeholder(self, event, placeholder_text):
        """Restore placeholder text if entry is empty"""
        widget = event.widget
        if not widget.get():
            widget.insert(0, placeholder_text)
            widget.config(foreground='#808080')  # Light gray color for placeholder

if __name__ == '__main__':
    app = ScannerApp()
    app.mainloop()