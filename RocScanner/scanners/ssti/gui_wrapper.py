import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import threading
import queue
import re
import json
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib
matplotlib.use('TkAgg')

class SSTIGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSTI Scanner GUI")
        self.root.geometry("1200x800")
        
        # Configure dark theme
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#2b2b2b')
        self.style.configure('TLabel', background='#2b2b2b', foreground='white')
        self.style.configure('TButton', background='#404040', foreground='white')
        
        # Create main container
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create top panels
        self.top_frame = ttk.Frame(self.main_frame)
        self.top_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Attack Flow Panel (Top-left)
        self.attack_frame = ttk.LabelFrame(self.top_frame, text="Live Attack Flow")
        self.attack_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        self.attack_list = scrolledtext.ScrolledText(
            self.attack_frame, 
            wrap=tk.WORD,
            bg='#1e1e1e',
            fg='white',
            font=('Consolas', 10)
        )
        self.attack_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Progress Dashboard (Top-right)
        self.dashboard_frame = ttk.LabelFrame(self.top_frame, text="Progress Dashboard")
        self.dashboard_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.dashboard_frame,
            variable=self.progress_var,
            maximum=100
        )
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)
        
        # Pie Chart
        self.fig, self.ax = plt.subplots(figsize=(4, 3))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.dashboard_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Stats Labels
        self.stats_frame = ttk.Frame(self.dashboard_frame)
        self.stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.vuln_label = ttk.Label(self.stats_frame, text="Vulnerable: 0")
        self.vuln_label.pack(side=tk.LEFT, padx=5)
        
        self.safe_label = ttk.Label(self.stats_frame, text="Safe: 0")
        self.safe_label.pack(side=tk.LEFT, padx=5)
        
        self.blocked_label = ttk.Label(self.stats_frame, text="Blocked: 0")
        self.blocked_label.pack(side=tk.LEFT, padx=5)
        
        # Verbose Logs (Bottom)
        self.log_frame = ttk.LabelFrame(self.main_frame, text="Verbose Logs")
        self.log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(
            self.log_frame,
            wrap=tk.WORD,
            bg='#1e1e1e',
            fg='white',
            font=('Consolas', 10)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Control Buttons
        self.control_frame = ttk.Frame(self.main_frame)
        self.control_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.start_button = ttk.Button(
            self.control_frame,
            text="Start Scan",
            command=self.start_scan
        )
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.pause_button = ttk.Button(
            self.control_frame,
            text="Pause",
            command=self.pause_scan,
            state=tk.DISABLED
        )
        self.pause_button.pack(side=tk.LEFT, padx=5)
        
        self.export_button = ttk.Button(
            self.control_frame,
            text="Export Report",
            command=self.export_report
        )
        self.export_button.pack(side=tk.LEFT, padx=5)
        
        # Initialize variables
        self.scan_process = None
        self.is_paused = False
        self.output_queue = queue.Queue()
        self.stats = {
            'vulnerable': 0,
            'safe': 0,
            'blocked': 0,
            'total': 0
        }
        
        # Start output processing thread
        self.process_thread = threading.Thread(target=self.process_output, daemon=True)
        self.process_thread.start()
    
    def start_scan(self):
        """Start the SSTI scanner as a subprocess"""
        if self.scan_process is None:
            self.start_button.config(state=tk.DISABLED)
            self.pause_button.config(state=tk.NORMAL)
            
            # Start scanner process
            self.scan_process = subprocess.Popen(
                ['/bin/python', 'SSTI.py', '--url', 'TARGET_URL'],  # Replace with actual target
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            # Start reading threads
            threading.Thread(target=self.read_output, args=(self.scan_process.stdout,), daemon=True).start()
            threading.Thread(target=self.read_output, args=(self.scan_process.stderr,), daemon=True).start()
    
    def pause_scan(self):
        """Pause/Resume the scanning process"""
        if self.scan_process:
            if not self.is_paused:
                self.scan_process.send_signal(subprocess.SIGSTOP)
                self.pause_button.config(text="Resume")
                self.is_paused = True
            else:
                self.scan_process.send_signal(subprocess.SIGCONT)
                self.pause_button.config(text="Pause")
                self.is_paused = False
    
    def read_output(self, pipe):
        """Read output from scanner process"""
        for line in iter(pipe.readline, ''):
            self.output_queue.put(line)
        pipe.close()
    
    def process_output(self):
        """Process scanner output and update GUI"""
        while True:
            try:
                line = self.output_queue.get(timeout=0.1)
                self.update_gui(line)
            except queue.Empty:
                continue
    
    def update_gui(self, line):
        """Update GUI elements based on scanner output"""
        # Update verbose log
        self.log_text.insert(tk.END, line)
        self.log_text.see(tk.END)
        
        # Parse line for important information
        if "VULNERABLE" in line:
            self.stats['vulnerable'] += 1
            self.add_attack_entry(line, "red")
        elif "blocked by WAF" in line:
            self.stats['blocked'] += 1
            self.add_attack_entry(line, "yellow")
        elif "SAFE" in line:
            self.stats['safe'] += 1
            self.add_attack_entry(line, "green")
        
        self.stats['total'] += 1
        self.update_dashboard()
    
    def add_attack_entry(self, line, color):
        """Add entry to attack flow panel"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.attack_list.insert(tk.END, f"[{timestamp}] {line}\n", color)
        self.attack_list.see(tk.END)
    
    def update_dashboard(self):
        """Update progress dashboard"""
        # Update progress bar
        if self.stats['total'] > 0:
            progress = (self.stats['vulnerable'] + self.stats['safe'] + self.stats['blocked']) / self.stats['total'] * 100
            self.progress_var.set(progress)
        
        # Update pie chart
        self.ax.clear()
        labels = ['Vulnerable', 'Safe', 'Blocked']
        sizes = [self.stats['vulnerable'], self.stats['safe'], self.stats['blocked']]
        colors = ['red', 'green', 'yellow']
        self.ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%')
        self.canvas.draw()
        
        # Update stats labels
        self.vuln_label.config(text=f"Vulnerable: {self.stats['vulnerable']}")
        self.safe_label.config(text=f"Safe: {self.stats['safe']}")
        self.blocked_label.config(text=f"Blocked: {self.stats['blocked']}")
    
    def export_report(self):
        """Export scan results as HTML report"""
        # TODO: Implement HTML report generation
        pass

def main():
    root = tk.Tk()
    app = SSTIGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 