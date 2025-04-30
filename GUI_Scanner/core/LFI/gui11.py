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
        self.configure(bg="#1a1a1a")
        self.style = ttk.Style(self)
        self.style.theme_use('alt')
        
        # تخصيص الأنماط
        self.style.configure('TFrame', background='#1a1a1a')
        self.style.configure('TLabel', background='#1a1a1a', foreground='#ffffff', font=('Segoe UI', 12))
        self.style.configure('TButton', font=('Segoe UI', 12, 'bold'), 
                             borderwidth=1, relief='flat',
                             background='#2d2d2d', foreground='#ffffff')
        self.style.map('TButton',
               background=[('active', '#3d3d3d'), ('pressed', '#4d4d4d')])
        
        self.style.configure('TLabelframe', background='#2d2d2d', 
                             relief='flat', borderwidth=5,
                             foreground='#ff9900', font=('Segoe UI', 12, 'bold'))
        self.style.configure('TLabelframe.Label', background='#2d2d2d', foreground='#ff9900')
        
        self._create_main_menu()

    def _lighten_color(self, hex_color, factor=0.2):
        """تفتيح اللون بنسبة معينة"""
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

class GenericWindow(tk.Toplevel):
    def __init__(self, parent, vuln_type):
        super().__init__(parent)
        self.parent = parent
        self.title(f"{vuln_type} Scanner")
        self.configure(bg="#2d2d2d")
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
        self.configure(bg="#2d2d2d")
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

        input_frame = ttk.LabelFrame(container, 
                                     text=" Scan Configuration ",
                                     padding=15,
                                     style='TLabelframe')
        input_frame.pack(fill=tk.X, padx=5, pady=10, ipady=10)

        ttk.Label(input_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=8)
        self.url_entry = ttk.Entry(input_frame, 
                                   width=60, 
                                   style='Custom.TEntry')
        self.url_entry.grid(row=0, column=1, columnspan=3, padx=5)

        ttk.Label(input_frame, text="Auth URL:").grid(row=1, column=0, sticky=tk.W, pady=8)
        self.auth_url_entry = ttk.Entry(input_frame, width=60, style='Custom.TEntry')
        self.auth_url_entry.grid(row=1, column=1, columnspan=3, padx=5)

        ttk.Label(input_frame, text="Proxy:").grid(row=2, column=0, sticky=tk.W, pady=8)
        self.proxy_entry = ttk.Entry(input_frame, width=30, style='Custom.TEntry')
        self.proxy_entry.grid(row=2, column=1)
        ttk.Label(input_frame, text="Threads:").grid(row=2, column=2, sticky=tk.W)
        self.threads_entry = ttk.Entry(input_frame, width=10, style='Custom.TEntry')
        self.threads_entry.insert(0, "10")
        self.threads_entry.grid(row=2, column=3)

        ttk.Label(input_frame, text="Wordlist:").grid(row=3, column=0, sticky=tk.W, pady=8)
        self.wordlist_entry = ttk.Entry(input_frame, width=50, style='Custom.TEntry')
        self.wordlist_entry.grid(row=3, column=1, columnspan=2)
        ttk.Button(input_frame, text="Browse", command=self._browse_wordlist).grid(row=3, column=3)

        ttk.Label(input_frame, text="Username:").grid(row=4, column=0, sticky=tk.W, pady=8)
        self.user_entry = ttk.Entry(input_frame, width=20, style='Custom.TEntry')
        self.user_entry.grid(row=4, column=1)
        ttk.Label(input_frame, text="Password:").grid(row=4, column=2)
        self.pass_entry = ttk.Entry(input_frame, show="*", width=20, style='Custom.TEntry')
        self.pass_entry.grid(row=4, column=3)

        ttk.Label(input_frame, text="Cookies:").grid(row=5, column=0, sticky=tk.W, pady=8)
        self.cookies_entry = ttk.Entry(input_frame, width=60, style='Custom.TEntry')
        self.cookies_entry.grid(row=5, column=1, columnspan=3)
        ttk.Label(input_frame, text="Output Format:").grid(row=6, column=0, sticky=tk.W)
        self.output_var = tk.StringVar(value="json")
        ttk.OptionMenu(input_frame, self.output_var, "json", "json", "csv").grid(row=6, column=1, sticky=tk.W)

        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill=tk.X, padx=5, pady=20)
        
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
        
        result_frame = ttk.LabelFrame(container, 
                                      text=" Scan Results ",
                                      padding=15,
                                      style='TLabelframe')
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, 
                                                     bg='#3d3d3d',
                                                     fg='#ffffff',
                                                     insertbackground='white',
                                                     relief='flat',
                                                     font=('Consolas', 10))
        self.result_text.pack(fill=tk.BOTH, expand=True)

    def _browse_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, path)

    def _on_back(self):
        self.parent._on_child_close(self)

    def _start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Input Error", "Target URL is required.")
            return
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
        threading.Thread(target=self._run_scan, args=(url, params), daemon=True).start()

    def _run_scan(self, url, params):
        try:
            scanner = scanner_module.LFIScanner(
                proxy=params['proxy'], threads=params['threads'],
                wordlist=params['wordlist'], username=params['username'],
                password=params['password'], cookies=params['cookies']
            )
            if params['auth_url']:
                scanner.login_url = params['auth_url']
            results = scanner.scan(url)
            self._display_results(results)
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
            writer.writerow(['url','parameter','payload','status','length','timestamp'])
            for item in results:
                writer.writerow([item.get(k, '') for k in ['url','parameter','payload','status','length','timestamp']])
            self._append_text(output.getvalue() + "\n")

    def _append_text(self, text):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state='disabled')

if __name__ == '__main__':
    app = ScannerApp()
    app.mainloop()
