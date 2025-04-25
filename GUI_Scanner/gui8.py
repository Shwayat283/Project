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
        self.geometry("900x700")
        self.configure(bg="#f0f0f0")
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        self._create_main_menu()

    def _create_main_menu(self):
        frame = ttk.Frame(self, padding=20)
        frame.pack(expand=True)
        title = ttk.Label(frame, text="Select Vulnerability:", font=("Segoe UI", 18))
        title.pack(pady=20)

        button_frame = ttk.Frame(frame)
        button_frame.pack()  
        for vuln in ["SSRF", "SSTI", "LFI", "XSS"]:
            btn = ttk.Button(button_frame, text=vuln, width=15,
                            command=lambda v=vuln: self._open_scanner(v))
            btn.pack(side=tk.LEFT, padx=10, pady=10)

    def _open_scanner(self, vuln_type):
        self.withdraw()
        if vuln_type == "LFI":
            win = LFIScannerWindow(self)
        else:
            win = GenericWindow(self, vuln_type)
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_child_close(win))
        win.mainloop()

    def _on_child_close(self, window):
        window.destroy()
        self.deiconify()


class GenericWindow(tk.Toplevel):
    def __init__(self, parent, vuln_type):
        super().__init__(parent)
        self.parent = parent
        self.title(f"{vuln_type} Scanner")
        self.geometry("400x250")
        self.configure(bg="#fdfdfd")
        frame = ttk.Frame(self, padding=20)
        frame.pack(expand=True)
        ttk.Label(frame, text=f"{vuln_type} scanner not implemented yet.", font=("Segoe UI", 14)).pack(pady=20)
        ttk.Button(frame, text="Back", command=self._on_back).pack(pady=10)

    def _on_back(self):
        self.destroy()
        self.parent.deiconify()


class LFIScannerWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("LFI Scanner")
        self.geometry("900x700")
        self.configure(bg="#f7f7f7")
        self.style = ttk.Style(self)
        self.style.configure('TLabel', font=("Segoe UI", 11))
        self.style.configure('TButton', font=("Segoe UI", 11))
        self._create_widgets()

    def _create_widgets(self):
        container = ttk.Frame(self, padding=15)
        container.pack(fill=tk.BOTH, expand=True)

        # Input frame
        input_frame = ttk.LabelFrame(container, text="Scan Configuration", padding=10)
        input_frame.pack(fill=tk.X, padx=5, pady=5)

        # URL
        ttk.Label(input_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.url_entry = ttk.Entry(input_frame, width=60)
        self.url_entry.grid(row=0, column=1, columnspan=3)

        # Auth URL
        ttk.Label(input_frame, text="Auth URL:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.auth_url_entry = ttk.Entry(input_frame, width=60)
        self.auth_url_entry.grid(row=1, column=1, columnspan=3)

        # Proxy & Threads
        ttk.Label(input_frame, text="Proxy:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.proxy_entry = ttk.Entry(input_frame, width=30)
        self.proxy_entry.grid(row=2, column=1)
        ttk.Label(input_frame, text="Threads:").grid(row=2, column=2, sticky=tk.W)
        self.threads_entry = ttk.Entry(input_frame, width=10)
        self.threads_entry.insert(0, "10")
        self.threads_entry.grid(row=2, column=3)

        # Wordlist
        ttk.Label(input_frame, text="Wordlist:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.wordlist_entry = ttk.Entry(input_frame, width=50)
        self.wordlist_entry.grid(row=3, column=1, columnspan=2)
        ttk.Button(input_frame, text="Browse", command=self._browse_wordlist).grid(row=3, column=3)

        # Credentials
        ttk.Label(input_frame, text="Username:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.user_entry = ttk.Entry(input_frame, width=20)
        self.user_entry.grid(row=4, column=1)
        ttk.Label(input_frame, text="Password:").grid(row=4, column=2)
        self.pass_entry = ttk.Entry(input_frame, show="*", width=20)
        self.pass_entry.grid(row=4, column=3)

        # Cookies & Output
        ttk.Label(input_frame, text="Cookies:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.cookies_entry = ttk.Entry(input_frame, width=60)
        self.cookies_entry.grid(row=5, column=1, columnspan=3)
        ttk.Label(input_frame, text="Output Format:").grid(row=6, column=0, sticky=tk.W)
        self.output_var = tk.StringVar(value="json")
        ttk.OptionMenu(input_frame, self.output_var, "json", "json", "csv").grid(row=6, column=1, sticky=tk.W)

        # Buttons
        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill=tk.X, padx=5, pady=10)
        self.back_button = ttk.Button(btn_frame, text="Back", command=self._on_back)
        self.back_button.pack(side=tk.LEFT)
        self.scan_button = ttk.Button(btn_frame, text="Start Scan", command=self._start_scan)
        self.scan_button.pack(side=tk.RIGHT)

        # Results
        result_frame = ttk.LabelFrame(container, text="Results", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.result_text = scrolledtext.ScrolledText(result_frame, state='disabled', bg='#ffffff')
        self.result_text.pack(fill=tk.BOTH, expand=True)

    def _browse_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*")])
        if path:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, path)

    def _on_back(self):
        self.destroy()
        self.parent.deiconify()

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
