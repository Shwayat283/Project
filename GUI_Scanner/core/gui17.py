import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk
import json
import csv
import io
import PathTraversalWithComment as scanner_module

class ModernStyle:
    DARK = {
        'bg': '#2D2D2D',
        'fg': '#FFFFFF',
        'accent': '#FF6B6B',
        'secondary': '#4ECDC4',
        'highlight': '#FFE66D',
        'entry_bg': '#404040',
        'text_bg': '#333333'
    }
    
    @classmethod
    def apply_style(cls, style, theme):
        style.theme_use('alt')
        style.configure('.', font=('Segoe UI', 11))
        
        # Base styles
        style.configure('TFrame', background=theme['bg'])
        style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
        style.configure('TButton', 
                       background=theme['secondary'],
                       foreground='black',
                       borderwidth=0,
                       focuscolor=theme['bg'],
                       relief='flat')
        style.map('TButton',
                 background=[('active', theme['highlight']), ('pressed', theme['accent'])])
        
        # Custom styles
        style.configure('Accent.TButton', 
                       background=theme['accent'],
                       foreground='black',
                       font=('Segoe UI', 12, 'bold'))
        style.map('Accent.TButton',
                 background=[('active', '#FF7B7B'), ('pressed', '#FF5555')])
        
        style.configure('Custom.TEntry', 
                       fieldbackground=theme['entry_bg'],
                       foreground=theme['fg'],
                       insertcolor=theme['fg'],
                       bordercolor=theme['secondary'],
                       lightcolor=theme['secondary'],
                       darkcolor=theme['secondary'])
        
        style.configure('Nav.TButton', 
                       background=theme['bg'],
                       foreground=theme['fg'],
                       font=('Segoe UI', 14))

class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Vulnerability Scanner")
        self.geometry("1200x800")
        self.current_theme = ModernStyle.DARK
        self.configure(bg=self.current_theme['bg'])
        self.style = ttk.Style(self)
        ModernStyle.apply_style(self.style, self.current_theme)
        self._create_settings_button()
        self._create_main_menu()
        self._setup_icons()

    def _setup_icons(self):
        try:
            self.iconbitmap('shield_icon.ico')
        except:
            pass

    def _create_settings_button(self):
        self.settings_btn = ttk.Button(self, text='⚙', style='Nav.TButton', command=self._open_settings)
        self.settings_btn.place(x=20, y=20, width=40, height=40)

    def _open_settings(self):
        self._saved_geometry = self.geometry()
        self._saved_state = self.state()
        self.withdraw()
        win = ColorThemeWindow(self)
        self._restore_window_state(win)
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_child_close(win))
        win.mainloop()

    def _create_main_menu(self):
        container = ttk.Frame(self)
        container.pack(expand=True, fill='both', padx=100, pady=80)
        
        header = ttk.Label(container,
                          text="Vulnerability Scanner",
                          font=("Segoe UI", 28, "bold"),
                          foreground=self.current_theme['accent'])
        header.pack(pady=(0, 40))
        
        grid_frame = ttk.Frame(container)
        grid_frame.pack()
        
        buttons = [
            ("SSRF", self.current_theme['secondary']),
            ("SSTI", self.current_theme['accent']),
            ("LFI", "#FF9666"),
            ("XSS", "#C792EA")
        ]
        
        for idx, (text, color) in enumerate(buttons):
            btn = tk.Button(grid_frame,
                           text=text,
                           font=("Segoe UI", 16, "bold"),
                           bg=color,
                           fg="black",
                           activebackground=color,
                           relief='flat',
                           width=18,
                           height=3,
                           command=lambda v=text: self._open_scanner(v))
            btn.grid(row=idx//2, column=idx%2, padx=15, pady=15, sticky='nsew')
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=self._lighten_color(b.cget('bg'))))
            btn.bind("<Leave>", lambda e, b=btn, c=color: b.config(bg=c))

    def _lighten_color(self, hex_color, factor=0.15):
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        new_rgb = [min(int(c + (255 - c) * factor), 255) for c in rgb]
        return f'#{new_rgb[0]:02x}{new_rgb[1]:02x}{new_rgb[2]:02x}'

    def _open_scanner(self, vuln_type):
        self._saved_geometry = self.geometry()
        self._saved_state = self.state()
        self.withdraw()
        win = LFIScannerWindow(self) if vuln_type == "LFI" else GenericWindow(self, vuln_type)
        self._restore_window_state(win)
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_child_close(win))
        win.mainloop()

    def _restore_window_state(self, window):
        if 'zoomed' in self._saved_state:
            window.state('zoomed')
        else:
            window.geometry(self._saved_geometry)

    def _on_child_close(self, window):
        window.destroy()
        self.deiconify()
        if hasattr(self, '_saved_geometry'):
            self.geometry(self._saved_geometry)
        if 'zoomed' in self._saved_state:
            self.state('zoomed')

    def update_theme(self, new_theme):
        self.current_theme = new_theme
        self.configure(bg=new_theme['bg'])
        ModernStyle.apply_style(self.style, new_theme)
        self._update_children()

    def _update_children(self):
        for child in self.winfo_children():
            if isinstance(child, (ColorThemeWindow, LFIScannerWindow)):
                child.destroy()

class GenericWindow(tk.Toplevel):
    def __init__(self, parent, vuln_type):
        super().__init__(parent)
        self.parent = parent
        self.title(f"{vuln_type} Scanner")
        self.configure(bg=self.parent.current_theme['bg'])
        self._create_ui()

    def _create_ui(self):
        container = ttk.Frame(self, padding=30)
        container.pack(expand=True, fill='both')
        
        ttk.Label(container,
                 text=f"{self.title()} under development",
                 font=("Segoe UI", 18),
                 foreground=self.parent.current_theme['accent']).pack(pady=40)
        
        ttk.Button(container,
                  text="← Return to Main Menu",
                  style='Accent.TButton',
                  command=self.destroy).pack()

class LFIScannerWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("LFI Scanner Pro")
        self.configure(bg=self.parent.current_theme['bg'])
        self.style = ttk.Style(self)
        ModernStyle.apply_style(self.style, self.parent.current_theme)
        self._create_ui()
        self._setup_validation()

    def _create_ui(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Configuration Section
        config_frame = ttk.LabelFrame(main_frame, text=" Scan Parameters ", padding=15)
        config_frame.pack(fill='x', pady=10)
        
        self._create_input_row(config_frame, "Target URL:", 0, self._create_url_entry)
        self._create_input_row(config_frame, "URL List File:", 1, self._create_urllist_widgets)
        self._create_input_row(config_frame, "Authentication URL:", 2, self._create_auth_entry)
        self._create_input_row(config_frame, "Proxy Settings:", 3, self._create_proxy_widgets)
        self._create_input_row(config_frame, "Wordlist File:", 4, self._create_wordlist_widgets)
        self._create_input_row(config_frame, "Credentials:", 5, self._create_credential_widgets)
        self._create_input_row(config_frame, "Cookies:", 6, self._create_cookie_entry)
        
        # Results Section
        result_frame = ttk.LabelFrame(main_frame, text=" Scan Results ", padding=15)
        result_frame.pack(fill='both', expand=True, pady=10)
        
        self.result_text = scrolledtext.ScrolledText(result_frame,
                                                    bg=self.parent.current_theme['text_bg'],
                                                    fg=self.parent.current_theme['fg'],
                                                    insertbackground='white',
                                                    font=('Consolas', 10))
        self.result_text.pack(fill='both', expand=True)
        
        # Control Buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill='x', pady=10)
        
        ttk.Button(control_frame,
                  text="◀ Main Menu",
                  style='Nav.TButton',
                  command=self.destroy).pack(side='left')
        
        ttk.Button(control_frame,
                  text="▶ Start Deep Scan",
                  style='Accent.TButton',
                  command=self._start_scan).pack(side='right')

    def _create_input_row(self, parent, label, row, widget_creator):
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=0, sticky='ew', pady=5)
        ttk.Label(frame, text=label, width=15).pack(side='left')
        widget_creator(frame)

    def _create_url_entry(self, parent):
        self.url_entry = ttk.Entry(parent, width=70, style='Custom.TEntry')
        self.url_entry.pack(side='left', fill='x', expand=True)

    def _create_urllist_widgets(self, parent):
        self.url_list_entry = ttk.Entry(parent, width=50, style='Custom.TEntry')
        self.url_list_entry.pack(side='left', fill='x', expand=True)
        ttk.Button(parent, text="Browse...", command=self._browse_urllist).pack(side='left', padx=5)

    def _create_auth_entry(self, parent):
        self.auth_url_entry = ttk.Entry(parent, width=70, style='Custom.TEntry')
        self.auth_url_entry.pack(side='left', fill='x', expand=True)

    def _create_proxy_widgets(self, parent):
        self.proxy_entry = ttk.Entry(parent, width=30, style='Custom.TEntry')
        self.proxy_entry.pack(side='left')
        ttk.Label(parent, text="Threads:").pack(side='left', padx=10)
        self.threads_entry = ttk.Entry(parent, width=5, style='Custom.TEntry')
        self.threads_entry.insert(0, "10")
        self.threads_entry.pack(side='left')

    def _create_wordlist_widgets(self, parent):
        self.wordlist_entry = ttk.Entry(parent, width=50, style='Custom.TEntry')
        self.wordlist_entry.pack(side='left', fill='x', expand=True)
        ttk.Button(parent, text="Browse...", command=self._browse_wordlist).pack(side='left', padx=5)

    def _create_credential_widgets(self, parent):
        ttk.Label(parent, text="Username:").pack(side='left')
        self.user_entry = ttk.Entry(parent, width=20, style='Custom.TEntry')
        self.user_entry.pack(side='left', padx=5)
        ttk.Label(parent, text="Password:").pack(side='left')
        self.pass_entry = ttk.Entry(parent, show="*", width=20, style='Custom.TEntry')
        self.pass_entry.pack(side='left')

    def _create_cookie_entry(self, parent):
        self.cookies_entry = ttk.Entry(parent, width=70, style='Custom.TEntry')
        self.cookies_entry.pack(side='left', fill='x', expand=True)

    def _browse_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if path:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, path)

    def _browse_urllist(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if path:
            self.url_list_entry.delete(0, tk.END)
            self.url_list_entry.insert(0, path)

    def _start_scan(self):
        # ... (Same scanning logic as original, but with improved UI updates)
        pass

class ColorThemeWindow(tk.Toplevel):
    THEMES = {
        "Dark Theme": ModernStyle.DARK,
        "Cyber Theme": {
            'bg': '#1A1A2E',
            'fg': '#E94560',
            'accent': '#E94560',
            'secondary': '#0F3460',
            'highlight': '#533483',
            'entry_bg': '#16213E',
            'text_bg': '#1A1A2E'
        },
        "Nature Theme": {
            'bg': '#2C5F2D',
            'fg': '#FFE77A',
            'accent': '#97BC62',
            'secondary': '#2C5F2D',
            'highlight': '#94B447',
            'entry_bg': '#1E3F20',
            'text_bg': '#234524'
        }
    }

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Theme Selector")
        self.configure(bg=self.parent.current_theme['bg'])
        self._create_ui()

    def _create_ui(self):
        container = ttk.Frame(self, padding=20)
        container.pack(expand=True, fill='both')
        
        ttk.Label(container,
                 text="Select Interface Theme",
                 font=("Segoe UI", 16, "bold"),
                 foreground=self.parent.current_theme['accent']).pack(pady=10)
        
        theme_frame = ttk.Frame(container)
        theme_frame.pack(pady=20)
        
        for idx, (theme_name, theme_data) in enumerate(self.THEMES.items()):
            color_block = tk.Canvas(theme_frame, 
                                  width=200, 
                                  height=80,
                                  bg=theme_data['bg'],
                                  highlightthickness=0)
            color_block.create_text(100, 40, 
                                  text=theme_name,
                                  fill=theme_data['fg'],
                                  font=('Segoe UI', 12, 'bold'))
            color_block.grid(row=idx//2, column=idx%2, padx=15, pady=15)
            color_block.bind("<Button-1>", lambda e, t=theme_data: self._apply_theme(t))
        
        ttk.Button(container,
                  text="◀ Back",
                  style='Nav.TButton',
                  command=self.destroy).pack(pady=20)

    def _apply_theme(self, theme):
        self.parent.update_theme(theme)

if __name__ == '__main__':
    app = ScannerApp()
    app.mainloop()
