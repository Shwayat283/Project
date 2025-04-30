import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import json
import csv
import io
import PathTraversalWithComment as scanner_module

class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Vulnerability Scanner")
        self.geometry("800x650")
        self._create_main_menu()

    def _create_main_menu(self):
        frame = tk.Frame(self)
        frame.pack(expand=True)
        tk.Label(frame, text="Select Vulnerability:", font=(None, 14)).pack(pady=20)
        for vuln in ["SSRF", "SSTI", "LFI", "XSS"]:
            btn = tk.Button(frame, text=vuln, width=20,
                            command=lambda v=vuln: self._open_scanner(v))
            btn.pack(pady=5)

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
        self.title(f"{vuln_type} Scanner")
        self.geometry("400x200")
        tk.Label(self, text=f"{vuln_type} scanner not implemented yet.").pack(pady=20)
        tk.Button(self, text="Back", command=self._on_back).pack(pady=10)
        self.parent = parent

    def _on_back(self):
        self.destroy()
        self.parent.deiconify()

class LFIScannerWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("LFI Scanner GUI")
        self.geometry("800x650")
        self._create_widgets()

    def _create_widgets(self):
        frame = tk.Frame(self)
        frame.pack(padx=10, pady=10, fill=tk.X)

        # URL input
        tk.Label(frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W)
        self.url_entry = tk.Entry(frame, width=60)
        self.url_entry.grid(row=0, column=1, columnspan=3, sticky=tk.W)

        # Auth URL input
        tk.Label(frame, text="Auth URL:").grid(row=1, column=0, sticky=tk.W)
        self.auth_url_entry = tk.Entry(frame, width=60)
        self.auth_url_entry.grid(row=1, column=1, columnspan=3, sticky=tk.W)

        # Proxy input
        tk.Label(frame, text="Proxy:").grid(row=2, column=0, sticky=tk.W)
        self.proxy_entry = tk.Entry(frame, width=30)
        self.proxy_entry.grid(row=2, column=1, sticky=tk.W)

        # Threads input
        tk.Label(frame, text="Threads:").grid(row=2, column=2, sticky=tk.W)
        self.threads_entry = tk.Entry(frame, width=10)
        self.threads_entry.insert(0, "10")
        self.threads_entry.grid(row=2, column=3, sticky=tk.W)

        # Wordlist selection
        tk.Label(frame, text="Wordlist:").grid(row=3, column=0, sticky=tk.W)
        self.wordlist_entry = tk.Entry(frame, width=50)
        self.wordlist_entry.grid(row=3, column=1, columnspan=2, sticky=tk.W)
        tk.Button(frame, text="Browse", command=self._browse_wordlist).grid(row=3, column=3)

        # Auth credentials
        tk.Label(frame, text="Username:").grid(row=4, column=0, sticky=tk.W)
        self.user_entry = tk.Entry(frame, width=20)
        self.user_entry.grid(row=4, column=1, sticky=tk.W)
        tk.Label(frame, text="Password:").grid(row=4, column=2, sticky=tk.W)
        self.pass_entry = tk.Entry(frame, show="*", width=20)
        self.pass_entry.grid(row=4, column=3, sticky=tk.W)

        # Cookies
        tk.Label(frame, text="Cookies:").grid(row=5, column=0, sticky=tk.W)
        self.cookies_entry = tk.Entry(frame, width=60)
        self.cookies_entry.grid(row=5, column=1, columnspan=3, sticky=tk.W)

        # Output format
        tk.Label(frame, text="Output:").grid(row=6, column=0, sticky=tk.W)
        self.output_var = tk.StringVar(value="json")
        tk.OptionMenu(frame, self.output_var, "json", "csv").grid(row=6, column=1, sticky=tk.W)

        # Buttons
        btn_frame = tk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=10)
        self.back_button = tk.Button(btn_frame, text="Back", command=self._on_back)
        self.back_button.pack(side=tk.LEFT)
        self.scan_button = tk.Button(btn_frame, text="Start Scan", command=self._start_scan)
        self.scan_button.pack(side=tk.RIGHT)

        # Results display
        self.result_text = scrolledtext.ScrolledText(self, state='disabled')
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

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
        auth_url = self.auth_url_entry.get().strip() or None
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
            'auth_url': auth_url
        }
        self.scan_button.config(state='disabled')
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "Starting scan...\n")
        self.result_text.config(state='disabled')
        threading.Thread(target=self._run_scan, args=(url, params), daemon=True).start()

    def _run_scan(self, url, params):
        try:
            scanner = scanner_module.LFIScanner(
                proxy=params['proxy'],
                threads=params['threads'],
                wordlist=params['wordlist'],
                username=params['username'],
                password=params['password'],
                cookies=params['cookies']
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
        fmt = self.output_var.get()
        self._append_text(f"Scan complete. Found {len(results)} issues.\n")
        if fmt == 'json':
            for item in results:
                self._append_text(json.dumps(item, indent=2) + "\n")
        else:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['url','parameter','payload','status','length','timestamp'])
            for item in results:
                writer.writerow([
                    item.get('url',''),
                    item.get('parameter',''),
                    item.get('payload',''),
                    item.get('status',''),
                    item.get('length',''),
                    item.get('timestamp','')
                ])
            self._append_text(output.getvalue() + "\n")

    def _append_text(self, text):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state='disabled')

if __name__ == '__main__':
    app = ScannerApp()
    app.mainloop()
