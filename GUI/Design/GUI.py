import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk
import json
import csv
import io

# Import scanner windows
from LFIScannerWindow import LFIScannerWindow
from XSSScannerWindow import XSSScannerWindow
from SSRFScannerWindow import SSRFScannerWindow
from SSTIScannerWindow import SSTIScannerWindow

class ScannerApp(tk.Tk):
    def __init__(self): 
        super().__init__()
        self.title("Vulnerability Scanner")
        self.geometry("1200x800")
        self.current_bg = "#1E1E2E"  # Dark theme background
        self.configure(bg=self.current_bg)
        self.style = ttk.Style(self)
        self.style.theme_use('alt')
        self._setup_styles()
        self._create_settings_button()
        self._create_main_menu()
    
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
        settings_menu.add_command(label='Color Theme', command=self._open_color_theme)
        settings_menu.add_command(label='Help', command=self._open_help)
        settings_menu.add_separator()
        settings_menu.add_command(label='About', command=self._open_about)
        self.settings_btn.config(menu=settings_menu)
        self.settings_btn.place(x=10, y=10)

    def _open_color_theme(self):
        self._saved_geometry = self.geometry()
        self._saved_state = self.state()
        self.withdraw()
        win = ColorThemeWindow(self)
        if 'zoomed' in self._saved_state:
            win.state('zoomed')
        else:
            win.geometry(self._saved_geometry)
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_child_close(win))
        win.mainloop()

    def _open_help(self):
        messagebox.showinfo("Help", "مساعدة: اشرح كيفية استخدام الماسح هنا.")

    def _open_about(self):
        messagebox.showinfo("About", "Vulnerability Scanner v1.0\nDeveloped by YourName.")

    def _lighten_color(self, hex_color, factor=0.2):
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        new_rgb = [min(int(c + (255 - c) * factor), 255) for c in rgb]
        return f'#{new_rgb[0]:02x}{new_rgb[1]:02x}{new_rgb[2]:02x}'

    def _create_main_menu(self):
        frame = ttk.Frame(self)
        frame.pack(expand=True, fill=tk.BOTH, padx=50, pady=50)
        title = ttk.Label(frame, 
                          text="Vulnerability Scanner", 
                          font=("Segoe UI", 40, "bold"),
                          foreground="#38bdf8")
        title.pack(pady=(0, 0))
        subtitle = ttk.Label(frame,
                           text="Advanced Security Testing Platform",
                           font=("Segoe UI", 18),
                           foreground="#94a3b8")
        subtitle.pack(pady=(0, 30))

        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X)
        buttons = [
            ("SSRF", "#89B4FA","🌐"),
            ("SSTI", "#89B4FA", "📝"),
            ("LFI", "#89B4FA", "📂"),
            ("XSS", "#89B4FA", "⚠️")
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
        self._saved_geometry = self.geometry()
        self._saved_state = self.state()
        self.withdraw()
        if vuln_type == "LFI":
            win = LFIScannerWindow(self)
        elif vuln_type == "SSRF":
            win = SSRFScannerWindow(self)
        elif vuln_type == "XSS":
            win = XSSScannerWindow(self)
        elif vuln_type == "SSTI":
            win = SSTIScannerWindow(self)
        elif vuln_type == "ColorTheme":
            win = ColorThemeWindow(self)
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

    def update_theme(self, color):
        """تحديث السمة الرئيسية"""
        self.current_bg = color
        self.configure(bg=color)
        self.settings_btn.config(bg=color)
        self._setup_styles()

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

class ColorThemeWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Color Theme")
        self.configure(bg=self.parent.current_bg)
        self.style = ttk.Style(self)
        self.style.configure('Custom.TButton', 
                             background='#89B4FA',
                             foreground='#1E1E2E',
                             font=('Segoe UI', 12, 'bold'))
        self.style.map('Custom.TButton',
                       background=[('active', '#A5C8FF'), ('pressed', '#7BA4F7')])
        self._create_widgets()

    def _create_widgets(self):
        container = ttk.Frame(self, padding=15)
        container.pack(fill=tk.BOTH, expand=True)
        label = ttk.Label(container, 
                          text="Select a color theme:", 
                          font=("Segoe UI", 18, "bold"),
                          foreground="#89B4FA",
                          background=self.parent.current_bg)
        label.pack(pady=(20, 10))
        themes = [
            ("Dark Theme", "#1E1E2E"),
            ("Light Theme", "#F5F5F5"),
            ("Blue Theme", "#1E3A8A"),
            ("Purple Theme", "#2E1065")
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

if __name__ == '__main__':
    app = ScannerApp()
    app.mainloop()