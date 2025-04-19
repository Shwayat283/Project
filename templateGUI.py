import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QStackedWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLineEdit, QRadioButton, QLabel,
                             QFileDialog, QCheckBox, QGroupBox, QSpinBox, QTableWidget,
                             QTableWidgetItem, QTextEdit, QSplitter, QProgressBar, QScrollArea)
from PyQt5.QtCore import Qt, pyqtSignal

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Web Vulnerability Scanner")
        self.setMinimumSize(800, 600)
        
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        # Initialize widgets
        self.dashboard = DashboardWidget()
        self.target_input = TargetInputWidget()
        self.configure_scan = ConfigureScanWidget()
        self.scan_progress = ScanProgressWidget()
        self.results = ResultsWidget()

        # Add widgets to stack
        self.stacked_widget.addWidget(self.dashboard)
        self.stacked_widget.addWidget(self.target_input)
        self.stacked_widget.addWidget(self.configure_scan)
        self.stacked_widget.addWidget(self.scan_progress)
        self.stacked_widget.addWidget(self.results)

        # Connect signals
        self.dashboard.new_scan_clicked.connect(self.show_target_input)
        self.target_input.next_clicked.connect(self.show_configure_scan)
        self.configure_scan.start_scan_clicked.connect(self.start_scan)
        self.scan_progress.scan_complete.connect(self.show_results)

    def show_target_input(self):
        self.stacked_widget.setCurrentWidget(self.target_input)

    def show_configure_scan(self):
        self.stacked_widget.setCurrentWidget(self.configure_scan)

    def start_scan(self):
        self.stacked_widget.setCurrentWidget(self.scan_progress)
        # Simulate scan completion after 2 seconds
        self.scan_progress.start_progress()

    def show_results(self):
        self.stacked_widget.setCurrentWidget(self.results)

class DashboardWidget(QWidget):
    new_scan_clicked = pyqtSignal()
    load_scan_clicked = pyqtSignal()
    help_clicked = pyqtSignal()

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.setLayout(layout)

        btn_style = "QPushButton {padding: 15px; font-size: 16px;}"
        
        btn_new = QPushButton("New Scan")
        btn_new.setStyleSheet(btn_style)
        btn_new.clicked.connect(self.new_scan_clicked.emit)
        
        btn_load = QPushButton("Load Previous Scan")
        btn_load.setStyleSheet(btn_style)
        btn_load.clicked.connect(self.load_scan_clicked.emit)
        
        btn_help = QPushButton("Help")
        btn_help.setStyleSheet(btn_style)
        btn_help.clicked.connect(self.help_clicked.emit)

        layout.addWidget(btn_new)
        layout.addWidget(btn_load)
        layout.addWidget(btn_help)
        layout.addStretch()

class TargetInputWidget(QWidget):
    next_clicked = pyqtSignal()

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.setLayout(layout)

        # URL input type
        self.url_type_group = QHBoxLayout()
        self.radio_single = QRadioButton("Single URL")
        self.radio_list = QRadioButton("URL List")
        self.radio_single.setChecked(True)
        self.url_type_group.addWidget(self.radio_single)
        self.url_type_group.addWidget(self.radio_list)
        layout.addLayout(self.url_type_group)

        # Single URL input
        self.single_url_input = QLineEdit()
        self.single_url_input.setPlaceholderText("Enter target URL (e.g., http://example.com)")
        layout.addWidget(self.single_url_input)

        # File input
        self.file_layout = QHBoxLayout()
        self.file_input = QLineEdit()
        self.file_input.setReadOnly(True)
        self.btn_browse = QPushButton("Browse...")
        self.btn_browse.clicked.connect(self.select_file)
        self.file_layout.addWidget(self.file_input)
        self.file_layout.addWidget(self.btn_browse)
        layout.addWidget(QLabel("URL List File:"))
        layout.addLayout(self.file_layout)

        # Toggle visibility
        self.radio_single.toggled.connect(self.toggle_input_mode)
        self.toggle_input_mode(True)

        # Navigation
        btn_next = QPushButton("Next →")
        btn_next.clicked.connect(self.next_clicked.emit)
        layout.addWidget(btn_next, alignment=Qt.AlignRight)

    def toggle_input_mode(self, checked):
        self.single_url_input.setVisible(checked)
        self.file_input.setVisible(not checked)
        self.btn_browse.setVisible(not checked)

    def select_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select URL List", "", "Text Files (*.txt)")
        if filename:
            self.file_input.setText(filename)

class ConfigureScanWidget(QWidget):
    start_scan_clicked = pyqtSignal()

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        self.setLayout(layout)
        layout.addWidget(scroll)
        scroll.setWidget(content)
        content_layout = QVBoxLayout()
        content.setLayout(content_layout)

        # Vulnerability selection
        content_layout.addWidget(QLabel("Select Vulnerabilities to Scan:"))
        self.vuln_checks = {
            'XSS': QCheckBox("Cross-Site Scripting (XSS)"),
            'SSTI': QCheckBox("Server-Side Template Injection (SSTI)"),
            'SQLi': QCheckBox("SQL Injection (SQLi)"),
            'Path': QCheckBox("Path Traversal")
        }
        for cb in self.vuln_checks.values():
            content_layout.addWidget(cb)

        # Configuration options
        self.config_options = {}
        for vuln in self.vuln_checks.keys():
            group = QGroupBox(f"{vuln} Settings")
            group.setVisible(False)
            group_layout = QVBoxLayout()
            
            # Wordlist
            wordlist_layout = QHBoxLayout()
            wordlist_input = QLineEdit()
            btn_wordlist = QPushButton("Browse...")
            btn_wordlist.clicked.connect(lambda _, w=wordlist_input: self.select_wordlist(w))
            wordlist_layout.addWidget(QLabel("Wordlist:"))
            wordlist_layout.addWidget(wordlist_input)
            wordlist_layout.addWidget(btn_wordlist)
            
            # Threads
            threads_spin = QSpinBox()
            threads_spin.setRange(1, 50)
            threads_spin.setValue(10)
            
            # Proxy
            proxy_input = QLineEdit()
            
            group_layout.addLayout(wordlist_layout)
            group_layout.addWidget(QLabel("Threads:"))
            group_layout.addWidget(threads_spin)
            group_layout.addWidget(QLabel("Proxy:"))
            group_layout.addWidget(proxy_input)
            group.setLayout(group_layout)
            
            self.config_options[vuln] = {
                'wordlist': wordlist_input,
                'threads': threads_spin,
                'proxy': proxy_input,
                'group': group
            }
            content_layout.addWidget(group)
        
        # Connect checkboxes to group visibility
        for vuln, cb in self.vuln_checks.items():
            cb.toggled.connect(self.config_options[vuln]['group'].setVisible)

        # Start scan button
        btn_start = QPushButton("Start Scan")
        btn_start.clicked.connect(self.start_scan_clicked.emit)
        content_layout.addWidget(btn_start)

    def select_wordlist(self, widget):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text Files (*.txt)")
        if filename:
            widget.setText(filename)

class ScanProgressWidget(QWidget):
    scan_complete = pyqtSignal()

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.setLayout(layout)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["URL", "Vulnerability", "Severity", "Status"])
        layout.addWidget(self.results_table)

        # Controls
        control_layout = QHBoxLayout()
        self.btn_pause = QPushButton("Pause")
        self.btn_stop = QPushButton("Stop")
        control_layout.addWidget(self.btn_pause)
        control_layout.addWidget(self.btn_stop)
        layout.addLayout(control_layout)

    def start_progress(self):
        # Simulate scan progress
        self.progress.setValue(0)
        for i in range(1, 101):
            QApplication.processEvents()
            self.progress.setValue(i)
            QApplication.processEvents()
            QThread.msleep(50)
        self.scan_complete.emit()

class ResultsWidget(QWidget):
    def __init__(self):
        super().__init__()
        splitter = QSplitter(Qt.Vertical)
        layout = QVBoxLayout()
        self.setLayout(layout)
        layout.addWidget(splitter)

        # Results table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["URL", "Vulnerability", "Severity", "Payload"])
        splitter.addWidget(self.table)

        # Details panel
        details_panel = QWidget()
        details_layout = QVBoxLayout()
        details_panel.setLayout(details_layout)
        
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.poc = QTextEdit()
        self.poc.setReadOnly(True)
        
        details_layout.addWidget(QLabel("Vulnerability Details:"))
        details_layout.addWidget(self.details)
        details_layout.addWidget(QLabel("Proof of Concept:"))
        details_layout.addWidget(self.poc)
        
        splitter.addWidget(details_panel)
        splitter.setSizes([400, 200])

        # Load sample data
        self.load_sample_data()

    def load_sample_data(self):
        self.table.setRowCount(2)
        self.table.setItem(0, 0, QTableWidgetItem("http://test.com/page?q=1"))
        self.table.setItem(0, 1, QTableWidgetItem("XSS"))
        self.table.setItem(0, 2, QTableWidgetItem("High"))
        self.table.setItem(0, 3, QTableWidgetItem("<script>alert(1)</script>"))

        self.table.setItem(1, 0, QTableWidgetItem("http://test.com/profile"))
        self.table.setItem(1, 1, QTableWidgetItem("SSTI"))
        self.table.setItem(1, 2, QTableWidgetItem("Critical"))
        self.table.setItem(1, 3, QTableWidgetItem("{{7*7}}"))

        self.table.itemSelectionChanged.connect(self.show_details)

    def show_details(self):
        selected = self.table.selectedItems()
        if selected:
            row = selected[0].row()
            details = f"URL: {self.table.item(row, 0).text()}\n"
            details += f"Type: {self.table.item(row, 1).text()}\n"
            details += f"Severity: {self.table.item(row, 2).text()}\n"
            details += f"Payload Used:\n{self.table.item(row, 3).text()}"
            self.details.setText(details)
            
            poc = "Proof of Concept:\n"
            if self.table.item(row, 1).text() == "XSS":
                poc += "<script>alert(document.domain)</script>"
            elif self.table.item(row, 1).text() == "SSTI":
                poc += "${7*7}"
            self.poc.setText(poc)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
