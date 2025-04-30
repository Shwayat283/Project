import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import json
import PathTraversalWithComment as scanner_module

class LFIScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LFI Scanner GUI")
        self.geometry("800x600")
        self._create_widgets()

    def _create_widgets(self):
        frame = tk.Frame(self)
        frame.pack(padx=10, pady=10, fill=tk.X)

        # URL input
        tk.Label(frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W)
        self.url_entry = tk.Entry(frame, width=60)
        self.url_entry.grid(row=0, column=1, columnspan=3, sticky=tk.W)

        # Proxy input
        tk.Label(frame, text="Proxy:").grid(row=1, column=0, sticky=tk.W)
        self.proxy_entry = tk.Entry(frame, width=30)
        self.proxy_entry.grid(row=1, column=1, sticky=tk.W)

        # Threads input
        tk.Label(frame, text="Threads:").grid(row=1, column=2, sticky=tk.W)
        self.threads_entry = tk.Entry(frame, width=10)
        self.threads_entry.insert(0, "10")
        self.threads_entry.grid(row=1, column=3, sticky=tk.W)

        # Wordlist selection
        tk.Label(frame, text="Wordlist:").grid(row=2, column=0, sticky=tk.W)
        self.wordlist_entry = tk.Entry(frame, width=50)
        self.wordlist_entry.grid(row=2, column=1, columnspan=2, sticky=tk.W)
        tk.Button(frame, text="Browse", command=self._browse_wordlist).grid(row=2, column=3)

        # Auth credentials
        tk.Label(frame, text="Username:").grid(row=3, column=0, sticky=tk.W)
        self.user_entry = tk.Entry(frame, width=20)
        self.user_entry.grid(row=3, column=1, sticky=tk.W)
        tk.Label(frame, text="Password:").grid(row=3, column=2, sticky=tk.W)
        self.pass_entry = tk.Entry(frame, show="*", width=20)
        self.pass_entry.grid(row=3, column=3, sticky=tk.W)

        # Cookies
        tk.Label(frame, text="Cookies:").grid(row=4, column=0, sticky=tk.W)
        self.cookies_entry = tk.Entry(frame, width=60)
        self.cookies_entry.grid(row=4, column=1, columnspan=3, sticky=tk.W)

        # Output format
        tk.Label(frame, text="Output:").grid(row=5, column=0, sticky=tk.W)
        self.output_var = tk.StringVar(value="json")
        tk.OptionMenu(frame, self.output_var, "json", "csv").grid(row=5, column=1, sticky=tk.W)

        # Scan button
        self.scan_button = tk.Button(frame, text="Start Scan", command=self._start_scan)
        self.scan_button.grid(row=6, column=0, columnspan=4, pady=10)

        # Results display
        self.result_text = scrolledtext.ScrolledText(self, state='disabled')
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _browse_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*")])
        if path:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, path)

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
            'cookies': self.cookies_entry.get().strip() or None
        }
        # Disable button
        self.scan_button.config(state='disabled')
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "Starting scan...\n")
        self.result_text.config(state='disabled')
        # Run scan in thread
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
            results = scanner.scan(url)
            self._display_results(results)
        except Exception as e:
            self._append_text(f"Error: {e}\n")
        finally:
            self.scan_button.config(state='normal')

    def _display_results(self, results):
        self._append_text(f"Scan complete. Found {len(results)} issues.\n")
        for item in results:
            self._append_text(json.dumps(item, indent=2) + "\n")

    def _append_text(self, text):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state='disabled')

if __name__ == '__main__':
    app = LFIScannerGUI()
    app.mainloop()
