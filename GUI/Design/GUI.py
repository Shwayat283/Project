import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk
import json
import csv
import io
from PIL import Image, ImageTk
import os
import sys


from LFIScannerWindow import LFIScannerWindow
from XSSScannerWindow import XSSScannerWindow
from SSRFScannerWindow import SSRFScannerWindow
from SSTIScannerWindow import SSTIScannerWindow

def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class ScannerApp(tk.Tk):
    def __init__(self): 
        super().__init__()
        self.title("RocScanner")
        self.state('zoomed')
        self.geometry("{0}x{1}+0+0".format(self.winfo_screenwidth(), self.winfo_screenheight()))  # Maximize window
        self.current_bg = "#1E1E2E"  # Dark theme background
        self.configure(bg=self.current_bg)
        self.style = ttk.Style(self)
        self.style.theme_use('alt')
        self._setup_styles()
        
        # Create container frame
        container = ttk.Frame(self)
        container.pack(side="left", fill="both", expand=True)
        
        # Create canvas with scrollbars
        self.canvas = tk.Canvas(container, bg=self.current_bg)
        self.vsb = ttk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        self.hsb = ttk.Scrollbar(container, orient="horizontal", command=self.canvas.xview)
        
        # Configure canvas
        self.canvas.configure(yscrollcommand=self.vsb.set, xscrollcommand=self.hsb.set)
        
        # Grid scrollbars and canvas
        self.hsb.grid(row=1, column=0, sticky="ew")
        self.vsb.grid(row=0, column=1, sticky="ns")
        self.canvas.grid(row=0, column=0, sticky="nsew")
        
        # Create main frame inside canvas
        self.main_frame = ttk.Frame(self.canvas)
        self.canvas_frame = self.canvas.create_window((0, 0), window=self.main_frame, anchor="nw")
        
        # Configure container grid
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        
        # Bind events for scrolling
        self.main_frame.bind("<Configure>", self._on_frame_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        
        # Create settings button after container setup
        self._create_settings_button()
        
        self._create_main_menu()
        
        # Set window icon
        icon_path = resource_path("image.png")
        icon = tk.PhotoImage(file=icon_path)
        self.iconphoto(False, icon)
    
    def _on_frame_configure(self, event=None):
        """Reset the scroll region to encompass the inner frame"""
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
    
    def _on_canvas_configure(self, event):
        """When the canvas is resized, resize the inner frame to match"""
        min_width = self.main_frame.winfo_reqwidth()
        if event.width > min_width:
            # Expand frame to fill canvas
            self.canvas.itemconfig(self.canvas_frame, width=event.width)
        else:
            # Keep minimum width
            self.canvas.itemconfig(self.canvas_frame, width=min_width)

    def _setup_styles(self):
        """تحديث الأنماط مع اللون الحالي"""
        self.style.configure('TFrame', background=self.current_bg)
        self.style.configure('TLabel', background=self.current_bg, foreground='#E0E0E0', font=('Segoe UI', 12))
        self.style.configure('TButton', font=('Segoe UI', 12, 'bold'), 
                             borderwidth=0, relief='flat',
                             background='#2D2D44', foreground='#E0E0E0')
        self.style.map('TButton',
               background=[('active', '#3D3D54'), ('pressed', '#4D4D64')])
        self.style.configure('TLabelframe', background=self.current_bg, 
                             relief='flat', borderwidth=5,
                             foreground='#89B4FA', font=('Segoe UI', 12, 'bold'))
        self.style.configure('TLabelframe.Label', background=self.current_bg, foreground='#89B4FA')
        self.style.configure('Accent.TButton', 
                             background='#89B4FA',
                             foreground='#1E1E2E',
                             font=('Segoe UI', 12, 'bold'))
        self.style.map('Accent.TButton',
                       background=[('active', '#A5C8FF'), ('pressed', '#7BA4F7')])

    def _create_settings_button(self):
        self.settings_btn = tk.Menubutton(self, text='⚙', font=('Segoe UI', 16), bg=self.current_bg, fg='#E0E0E0', bd=0, relief='flat')
        settings_menu = tk.Menu(self.settings_btn, tearoff=0, bg='#2D2D44', fg='#E0E0E0', activebackground='#3D3D54', activeforeground='#E0E0E0')
        settings_menu.add_command(label='Help    ', command=self._open_help)
        settings_menu.add_separator()
        settings_menu.add_command(label='About', command=self._open_about)
        self.settings_btn.config(menu=settings_menu)
        self.settings_btn.place(x=10, y=10)

    def _open_help(self):
        self._saved_geometry = self.geometry()
        self._saved_state = self.state()
        self.withdraw()
        win = HelpWindow(self)
        if 'zoomed' in self._saved_state:
            win.state('zoomed')
        else:
            win.geometry(self._saved_geometry)
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_child_close(win))
        win.mainloop()

    def _open_about(self):
        self._saved_geometry = self.geometry()
        self._saved_state = self.state()
        self.withdraw()
        win = AboutWindow(self)
        if 'zoomed' in self._saved_state:
            win.state('zoomed')
        else:
            win.geometry(self._saved_geometry)
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_child_close(win))
        win.mainloop()

    def _lighten_color(self, hex_color, factor=0.2):
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        new_rgb = [min(int(c + (255 - c) * factor), 255) for c in rgb]
        return f'#{new_rgb[0]:02x}{new_rgb[1]:02x}{new_rgb[2]:02x}'

    def _create_main_menu(self):
        frame = ttk.Frame(self.main_frame)
        frame.pack(expand=True, fill=tk.BOTH, padx=50, pady=50)
        # Load and trim the logo image to remove transparent/white borders, then resize
        icon_path = resource_path("image.png")
        logo_img_raw = Image.open(icon_path)
        # Convert to RGBA if not already
        if logo_img_raw.mode != 'RGBA':
            logo_img_raw = logo_img_raw.convert('RGBA')
        # Get bounding box of non-transparent area
        bbox = logo_img_raw.getbbox()
        if bbox:
            logo_img_raw = logo_img_raw.crop(bbox)
        logo_img = logo_img_raw.resize((100, 100), Image.LANCZOS)
        self.logo_img = ImageTk.PhotoImage(logo_img)
        tight_title_frame = ttk.Frame(frame, style='TFrame')
        tight_title_frame.pack(pady=(0, 0))
        logo_label = ttk.Label(tight_title_frame, image=self.logo_img, style='TLabel')
        logo_label.pack(side=tk.LEFT, padx=(0, 0))
        text_label = ttk.Label(tight_title_frame, text="RocScanner", font=("Segoe UI", 40, "bold"), foreground="#38bdf8", style='TLabel')
        text_label.pack(side=tk.LEFT, padx=(0, 0))
        subtitle = ttk.Label(frame,
                           text="    Advanced Security Testing Platform",
                           font=("Segoe UI", 18),
                           foreground="#94a3b8")
        subtitle.pack(pady=(0, 30))

        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X)
        buttons = [
            ("Server-side request forgery (SSRF)", "#89B4FA","🌐"),
            ("Server-side template injection(SSTI)", "#89B4FA", "📝"),
            ("Local file inclusion (LFI)", "#89B4FA", "📂"),
            ("Cross-site scripting(XSS)", "#89B4FA", "⚠️")
        ]
        for text, color, emoji in buttons:
            btn = tk.Button(button_frame, 
                              text=f"{emoji} {text}",
                              font=("Segoe UI", 16, "bold"),
                              bg=color,
                              fg="#1E1E2E",
                              activebackground=self._lighten_color(color),
                              activeforeground="#1E1E2E",
                              relief='flat',
                              width=35,
                              height=2,
                              bd=0,
                              command=lambda v=text: self._open_scanner(v))
            btn.pack(side=tk.TOP, fill=tk.X, pady=15)
            btn.bind("<Enter>", lambda e, b=btn, c=color: b.config(bg=self._lighten_color(c)))
            btn.bind("<Leave>", lambda e, b=btn, c=color: b.config(bg=c))

    def _open_scanner(self, vuln_type):
        self._saved_state = self.state()
        self.withdraw()
        if vuln_type == "Local file inclusion (LFI)":
            win = LFIScannerWindow(self)
        elif vuln_type == "Server-side request forgery (SSRF)":
            win = SSRFScannerWindow(self)
        elif vuln_type == "Cross-site scripting(XSS)":
            win = XSSScannerWindow(self)
        elif vuln_type == "Server-side template injection(SSTI)":
            win = SSTIScannerWindow(self)
        else:
            win = GenericWindow(self, vuln_type)
        win.state('zoomed')
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_child_close(win))
        win.mainloop()

    def _on_child_close(self, window):
        if hasattr(self, '_saved_state'):
            self.state(self._saved_state)
        window.destroy()
        self.deiconify()

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

class AboutWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("About")
        self.configure(bg=self.parent.current_bg)
        self.style = ttk.Style(self)
        self.style.configure('Custom.TButton', 
                             background='#89B4FA',
                             foreground='#1E1E2E',
                             font=('Segoe UI', 12, 'bold'))
        self.style.map('Custom.TButton',
                       background=[('active', '#A5C8FF'), ('pressed', '#7BA4F7')])
        
        # Create main container with scrollbars
        self.main_container = ttk.Frame(self)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create canvas
        self.canvas = tk.Canvas(self.main_container, bg=self.parent.current_bg)
        self.vsb = ttk.Scrollbar(self.main_container, orient="vertical", command=self.canvas.yview)
        self.hsb = ttk.Scrollbar(self.main_container, orient="horizontal", command=self.canvas.xview)
        
        # Configure canvas
        self.canvas.configure(yscrollcommand=self.vsb.set, xscrollcommand=self.hsb.set)
        
        # Grid layout for scrollbars and canvas
        self.vsb.grid(row=0, column=1, sticky="ns")
        self.hsb.grid(row=1, column=0, sticky="ew")
        self.canvas.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid weights
        self.main_container.grid_rowconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)
        
        # Create frame inside canvas
        self.container = ttk.Frame(self.canvas, padding=15)
        self.canvas_frame = self.canvas.create_window((0, 0), window=self.container, anchor="nw")
        
        # Bind events
        self.container.bind("<Configure>", self._on_frame_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        
        self._create_widgets()

    def _on_frame_configure(self, event=None):
        """Reset the scroll region to encompass the inner frame"""
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        """When the canvas is resized, resize the inner frame to match"""
        min_width = self.container.winfo_reqwidth()
        if event.width > min_width:
            # Expand frame to fill canvas
            self.canvas.itemconfig(self.canvas_frame, width=event.width)
        else:
            # Keep minimum width
            self.canvas.itemconfig(self.canvas_frame, width=min_width)

    def _create_widgets(self):
        # Title
        title = ttk.Label(self.container, 
                          text="RocScanner v1.0", 
                          font=("Segoe UI", 24, "bold"),
                          foreground="#89B4FA",
                          background=self.parent.current_bg)
        title.pack(pady=(20, 10))

        # Description
        description = ttk.Label(self.container,
                              text="A comprehensive security testing platform designed to identify and analyze various web vulnerabilities. This tool helps security professionals and developers identify potential security risks in their web applications through advanced scanning techniques and detailed analysis.",
                              font=("Segoe UI", 12),
                              foreground="#E0E0E0",
                              background=self.parent.current_bg,
                              wraplength=600,
                              anchor="w",
                              justify="left")
        description.pack(pady=(0, 20), fill=tk.X)

        # Features
        features_frame = ttk.LabelFrame(self.container, text="Key Features", padding=10)
        features_frame.pack(fill=tk.X, pady=10)
        
        features = [
            "• Server-side Request Forgery (SSRF) Detection",
            "• Server-side Template Injection (SSTI) Analysis",
            "• Local File Inclusion (LFI) Testing",
            "• Cross-site Scripting (XSS) Vulnerability Scanner",
            "• Modern and Intuitive User Interface",
            "• Detailed Vulnerability Reports"
        ]
        
        for feature in features:
            ttk.Label(features_frame,
                     text=feature,
                     font=("Segoe UI", 11),
                     foreground="#E0E0E0",
                     background=self.parent.current_bg).pack(anchor="w", pady=2)

        # Scanner Capabilities
        capabilities_frame = ttk.LabelFrame(self.container, text="Scanner Capabilities", padding=10)
        capabilities_frame.pack(fill=tk.X, pady=10)
        
        capabilities = [
            "• Advanced SSRF Detection: Identifies potential server-side request forgery vulnerabilities",
            "• SSTI Analysis: Detects template injection vulnerabilities in various frameworks",
            "• LFI Testing: Scans for local file inclusion vulnerabilities with multiple payloads",
            "• XSS Scanner: Comprehensive cross-site scripting vulnerability detection",
            "• Real-time Scanning: Immediate feedback during vulnerability assessment",
            "• Custom Payload Support: Ability to add custom testing payloads",
            "• Detailed Reporting: Generates comprehensive vulnerability reports"
        ]
        
        for capability in capabilities:
            ttk.Label(capabilities_frame,
                     text=capability,
                     font=("Segoe UI", 11),
                     foreground="#E0E0E0",
                     background=self.parent.current_bg).pack(anchor="w", pady=2)

        # Security Features
        security_frame = ttk.LabelFrame(self.container, text="Security Features", padding=10)
        security_frame.pack(fill=tk.X, pady=10)
        
        security_features = [
            "• Safe Testing Environment: Built-in safeguards to prevent accidental damage",
            "• Rate Limiting: Prevents overwhelming target systems",
            "• Session Management: Secure handling of testing sessions",
            "• Error Handling: Graceful handling of scanning errors",
            "• Logging System: Comprehensive activity logging for audit trails"
        ]
        
        for feature in security_features:
            ttk.Label(security_frame,
                     text=feature,
                     font=("Segoe UI", 11),
                     foreground="#E0E0E0",
                     background=self.parent.current_bg).pack(anchor="w", pady=2)

        # Usage Guidelines
        guidelines_frame = ttk.LabelFrame(self.container, text="Usage Guidelines", padding=10)
        guidelines_frame.pack(fill=tk.X, pady=10)
        
        guidelines = [
            "• Always obtain proper authorization before scanning",
            "• Use responsibly and ethically",
            "• Follow security best practices",
            "• Keep the scanner updated",
            "• Review and validate scan results"
        ]
        
        for guideline in guidelines:
            ttk.Label(guidelines_frame,
                     text=guideline,
                     font=("Segoe UI", 11),
                     foreground="#E0E0E0",
                     background=self.parent.current_bg).pack(anchor="w", pady=2)

        # Developers
        dev_frame = ttk.LabelFrame(self.container, text="Developed by", padding=10)
        dev_frame.pack(fill=tk.X, pady=10)
        
        developers = [
            "1) Ahmad Ali Shwaiyat",
            "2) Abdalrahman Reda Albeshtawi",
            "3) Mohammad Abdallah Alzoubi",
            "4) Yousef Mohammad Hjooj"
        ]
        
        for dev in developers:
            ttk.Label(dev_frame,
                     text=dev,
                     font=("Segoe UI", 11),
                     foreground="#E0E0E0",
                     background=self.parent.current_bg).pack(anchor="w", pady=2)

        # Version Info
        version_frame = ttk.LabelFrame(self.container, text="Version Information", padding=10)
        version_frame.pack(fill=tk.X, pady=10)
        
        version_info = [
            "• Version: 1.0",
            "• Release Date: 2025",
            "• Platform: Windows/linux/macOS",
            "• Requirements: Python 3.8+",
            "• License: Educational Use"
        ]
        
        for info in version_info:
            ttk.Label(version_frame,
                     text=info,
                     font=("Segoe UI", 11),
                     foreground="#E0E0E0",
                     background=self.parent.current_bg).pack(anchor="w", pady=2)

        # Back button
        back_button = ttk.Button(self.container, 
                                text="← Back", 
                                style='Custom.TButton',
                                command=self._on_back)
        back_button.pack(side=tk.BOTTOM, pady=20)

    def _on_back(self):
        self.parent._on_child_close(self)

class HelpWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Help")
        self.configure(bg=self.parent.current_bg)
        self.style = ttk.Style(self)
        self.style.configure('Custom.TButton', 
                             background='#89B4FA',
                             foreground='#1E1E2E',
                             font=('Segoe UI', 12, 'bold'))
        self.style.map('Custom.TButton',
                       background=[('active', '#A5C8FF'), ('pressed', '#7BA4F7')])
        
        # Create main container with scrollbars
        self.main_container = ttk.Frame(self)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create canvas
        self.canvas = tk.Canvas(self.main_container, bg=self.parent.current_bg)
        self.vsb = ttk.Scrollbar(self.main_container, orient="vertical", command=self.canvas.yview)
        self.hsb = ttk.Scrollbar(self.main_container, orient="horizontal", command=self.canvas.xview)
        
        # Configure canvas
        self.canvas.configure(yscrollcommand=self.vsb.set, xscrollcommand=self.hsb.set)
        
        # Grid layout for scrollbars and canvas
        self.vsb.grid(row=0, column=1, sticky="ns")
        self.hsb.grid(row=1, column=0, sticky="ew")
        self.canvas.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid weights
        self.main_container.grid_rowconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)
        
        # Create frame inside canvas
        self.container = ttk.Frame(self.canvas, padding=15)
        self.canvas_frame = self.canvas.create_window((0, 0), window=self.container, anchor="nw")
        
        # Bind events
        self.container.bind("<Configure>", self._on_frame_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        
        self._create_widgets()

    def _on_frame_configure(self, event=None):
        """Reset the scroll region to encompass the inner frame"""
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        """When the canvas is resized, resize the inner frame to match"""
        min_width = self.container.winfo_reqwidth()
        if event.width > min_width:
            # Expand frame to fill canvas
            self.canvas.itemconfig(self.canvas_frame, width=event.width)
        else:
            # Keep minimum width
            self.canvas.itemconfig(self.canvas_frame, width=min_width)

    def _create_widgets(self):
        # Title
        title = ttk.Label(self.container, 
                          text="Help Guide", 
                          font=("Segoe UI", 24, "bold"),
                          foreground="#89B4FA",
                          background=self.parent.current_bg)
        title.pack(pady=(20, 10))

        # Getting Started
        getting_started_frame = ttk.LabelFrame(self.container, text="Getting Started", padding=10)
        getting_started_frame.pack(fill=tk.X, pady=10)
        
        getting_started = [
            "• Launch the application and you'll see the main menu with four scanning options",
            "• Select the type of vulnerability you want to scan for",
            "• Enter the target URL or file path in the scanner window",
            "• Configure any additional settings if needed",
            "• Click 'Start Scan' to begin the vulnerability assessment"
        ]
        
        for item in getting_started:
            ttk.Label(getting_started_frame,
                     text=item,
                     font=("Segoe UI", 11),
                     foreground="#E0E0E0",
                     background=self.parent.current_bg).pack(anchor="w", pady=2)

        # Scanner Types
        scanner_types_frame = ttk.LabelFrame(self.container, text="Scanner Types", padding=10)
        scanner_types_frame.pack(fill=tk.X, pady=10)
        
        scanner_types = [
            "1. SSRF Scanner:",
            "   • Detects server-side request forgery vulnerabilities",
            "   • Tests for internal network access",
            "   • Identifies potential data leakage",
            "",
            "2. SSTI Scanner:",
            "   • Tests for template injection vulnerabilities",
            "   • Supports multiple template engines",
            "   • Detects code execution possibilities",
            "",
            "3. LFI Scanner:",
            "   • Tests for local file inclusion vulnerabilities",
            "   • Attempts to access sensitive system files",
            "   • Identifies path traversal issues",
            "",
            "4. XSS Scanner:",
            "   • Detects cross-site scripting vulnerabilities",
            "   • Tests for reflected and stored XSS",
            "   • Identifies DOM-based XSS issues"
        ]
        
        for item in scanner_types:
            ttk.Label(scanner_types_frame,
                     text=item,
                     font=("Segoe UI", 11),
                     foreground="#E0E0E0",
                     background=self.parent.current_bg).pack(anchor="w", pady=2)

        # Best Practices
        best_practices_frame = ttk.LabelFrame(self.container, text="Best Practices", padding=10)
        best_practices_frame.pack(fill=tk.X, pady=10)
        
        best_practices = [
            "• Always obtain proper authorization before scanning",
            "• Start with a small scope and gradually expand",
            "• Monitor system resources during scanning",
            "• Keep the scanner updated to the latest version",
            "• Review and validate scan results carefully",
            "• Document all findings and remediation steps",
            "• Follow responsible disclosure practices"
        ]
        
        for item in best_practices:
            ttk.Label(best_practices_frame,
                     text=item,
                     font=("Segoe UI", 11),
                     foreground="#E0E0E0",
                     background=self.parent.current_bg).pack(anchor="w", pady=2)

        # Troubleshooting
        troubleshooting_frame = ttk.LabelFrame(self.container, text="Troubleshooting", padding=10)
        troubleshooting_frame.pack(fill=tk.X, pady=10)
        
        troubleshooting = [
            "Common Issues:",
            "• Scanner not starting: Check Python version and dependencies",
            "• Connection errors: Verify network connectivity and target accessibility",
            "• False positives: Review scan configuration and adjust sensitivity",
            "• Performance issues: Reduce scan scope or adjust resource limits",
            "",
            "If you encounter any issues:",
            "1. Check the error messages in the console",
            "2. Verify your input parameters",
            "3. Ensure you have proper permissions",
            "4. Contact support if the issue persists"
        ]
        
        for item in troubleshooting:
            ttk.Label(troubleshooting_frame,
                     text=item,
                     font=("Segoe UI", 11),
                     foreground="#E0E0E0",
                     background=self.parent.current_bg).pack(anchor="w", pady=2)

        # Back button
        back_button = ttk.Button(self.container, 
                                text="← Back", 
                                style='Custom.TButton',
                                command=self._on_back)
        back_button.pack(side=tk.BOTTOM, pady=20)

    def _on_back(self):
        self.parent._on_child_close(self)

if __name__ == '__main__':
    app = ScannerApp()
    app.mainloop()