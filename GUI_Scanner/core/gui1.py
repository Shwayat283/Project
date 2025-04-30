import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PathTraversalWithComment import LFIScanner  # استيراد الكود الأصلي
import argparse
import sys

class LFIScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("LFI Scanner GUI")
        self.setup_ui()
    
    def setup_ui(self):
        # إطار للإدخالات الأساسية
        frame = ttk.LabelFrame(self.root, text="Scan Configuration")
        frame.pack(padx=10, pady=10, fill="x")
        
        # حقل إدخال URL
        ttk.Label(frame, text="Target URL:").grid(row=0, column=0, sticky="w")
        self.url_entry = ttk.Entry(frame, width=50)
        self.url_entry.grid(row=0, column=1, padx=5)
        
        # زر لاختيار ملف URLs
        ttk.Button(frame, text="Browse URL List", command=self.browse_url_list).grid(row=1, column=0, pady=5)
        self.url_list_path = tk.StringVar()
        ttk.Label(frame, textvariable=self.url_list_path).grid(row=1, column=1, sticky="w")
        
        # إعدادات المصادقة
        ttk.Label(frame, text="Username:").grid(row=2, column=0, sticky="w")
        self.username_entry = ttk.Entry(frame)
        self.username_entry.grid(row=2, column=1, padx=5)
        
        ttk.Label(frame, text="Password:").grid(row=3, column=0, sticky="w")
        self.password_entry = ttk.Entry(frame, show="*")
        self.password_entry.grid(row=3, column=1, padx=5)
        
        # خيارات إضافية
        ttk.Label(frame, text="Proxy:").grid(row=4, column=0, sticky="w")
        self.proxy_entry = ttk.Entry(frame)
        self.proxy_entry.grid(row=4, column=1, padx=5)
        
        ttk.Label(frame, text="Threads:").grid(row=5, column=0, sticky="w")
        self.threads_entry = ttk.Entry(frame)
        self.threads_entry.insert(0, "10")
        self.threads_entry.grid(row=5, column=1, padx=5)
        
        # زر تشغيل المسح
        ttk.Button(self.root, text="Start Scan", command=self.start_scan).pack(pady=10)
        
        # منطقة لعرض النتائج
        self.result_area = scrolledtext.ScrolledText(self.root, height=15)
        self.result_area.pack(padx=10, pady=10, fill="both", expand=True)
    
    def browse_url_list(self):
        file_path = filedialog.askopenfilename()
        self.url_list_path.set(file_path)
    
    def start_scan(self):
        # جمع المدخلات من الواجهة
        args = argparse.Namespace(
            url=self.url_entry.get(),
            url_list=self.url_list_path.get() if self.url_list_path.get() else None,
            username=self.username_entry.get(),
            password=self.password_entry.get(),
            proxy=self.proxy_entry.get(),
            threads=int(self.threads_entry.get()),
            wordlist=None,
            output=None,
            auth_url=None,
            cookies=None
        )
        
        # التحقق من المدخلات الأساسية
        if not args.url and not args.url_list:
            messagebox.showerror("Error", "You must provide a URL or URL list!")
            return
        
        try:
            # تهيئة الماسح الضوئي
            scanner = LFIScanner(
                proxy=args.proxy,
                threads=args.threads,
                username=args.username,
                password=args.password
            )
            
            # تنفيذ المسح
            self.result_area.insert(tk.END, "[*] Starting scan...\n")
            self.root.update()
            
            if args.url:
                results = scanner.scan(args.url)
            else:
                with open(args.url_list) as f:
                    urls = [line.strip() for line in f]
                results = []
                for url in urls:
                    results.extend(scanner.scan(url))
            
            # عرض النتائج
            self.result_area.insert(tk.END, f"\n[*] Found {len(results)} vulnerabilities:\n")
            for vuln in results:
                self.result_area.insert(tk.END, f"- URL: {vuln['url']}\n  Parameter: {vuln['parameter']}\n")
            
            messagebox.showinfo("Scan Complete", "Scan finished successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.result_area.insert(tk.END, f"\n[!] Error: {str(e)}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = LFIScannerGUI(root)
    root.mainloop()