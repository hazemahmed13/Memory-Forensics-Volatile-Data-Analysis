from PyQt5.QtWidgets import (
    QWidget,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QFileDialog,
    QTextEdit,
    QLabel,
    QTabWidget,
    QComboBox,
    QMessageBox,
    QLineEdit,
    QDialog,
    QDialogButtonBox,
    QFrame,
)
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QPalette, QColor, QFont

from process_analysis import (
    detect_injection,
    detect_injection_details,
    get_dll_records,
    get_process_records,
    get_processes,
    get_process_tree_records,
    get_thread_records,
)
from network_analysis import get_connections, get_connection_records
from secrets_analysis import detect_keys_and_credentials
from yara_scan import format_yara_matches, scan_memory
from os_profile import detect_os_profile
from report_export import build_report, export_report_json, export_report_txt, export_report_html
from volatility_runner import (
    get_resolved_vol2_script,
    get_volatility_config,
    run_volatility,
    set_volatility_config,
    volatility_any_backend_ok,
    volatility_engine_status,
)
from forensics_logging import setup_forensics_logging
import json
import os


class WorkerThread(QThread):
    progress = pyqtSignal(str)
    step_done = pyqtSignal(str, str, object)
    all_done = pyqtSignal()

    def __init__(self, task, memory_file):
        super().__init__()
        self.task = task
        self.memory_file = memory_file
        self.os_type = "windows"

    def set_os_type(self, os_type):
        self.os_type = os_type

    def _run_one(self, task_name):
        os_type = self.os_type
        try:
            if task_name == "process":
                return get_processes(self.memory_file, os_type=os_type), None

            if task_name == "injection":
                details = detect_injection_details(self.memory_file, os_type=os_type)
                summary = details.get("summary", [])
                entities = details.get("entities", [])
                raw_output = details.get("raw_output", "")

                blocks = []
                if summary:
                    blocks.append("Suspicious findings (summary):")
                    blocks.append("\n".join(summary))
                else:
                    blocks.append("Suspicious findings (summary):")
                    blocks.append("No injection detected")

                if entities:
                    blocks.append("\nExtracted process hints:")
                    blocks.append("\n".join(entities))

                if raw_output:
                    blocks.append("\nRaw malfind output:")
                    blocks.append(raw_output)

                text = "\n".join(blocks)
                return text, summary

            if task_name == "network":
                data = get_connections(self.memory_file, os_type=os_type)
                text = "\n".join(data[:50])
                return text, None

            if task_name == "secrets":
                raw = detect_keys_and_credentials(self.memory_file, os_type=os_type)
                return json.dumps(raw, indent=2), raw

            if task_name == "yara":
                matches = scan_memory(self.memory_file)
                return format_yara_matches(matches), matches

        except Exception as e:
            from forensics_logging import log_exception

            log_exception(f"worker.{task_name}", e)
            return f"[worker error] {e}", None

        return "Unknown task", None

    def run(self):
        if self.task == "full":
            for step in ["process", "injection", "network", "secrets", "yara"]:
                self.progress.emit(f"Running {step}… (full analysis)")
                result, extra = self._run_one(step)
                self.step_done.emit(step, result, extra)
        else:
            self.progress.emit(f"Running {self.task}…")
            result, extra = self._run_one(self.task)
            self.step_done.emit(self.task, result, extra)
        self.all_done.emit()


class MemoryForensicsApp(QWidget):
    def __init__(self):
        super().__init__()
        setup_forensics_logging()

        self.setWindowTitle("Memory Forensics Tool")
        self.setGeometry(200, 200, 900, 600)
        self._apply_theme()

        self.memory_file = None
        self.report_dir = None
        self.completed_tasks = set()
        self.last_profile = {"guessed_os": "windows", "confidence": "low", "scores": {}}
        self.last_process_records = []
        self.last_process_tree_records = []
        self.last_thread_records = []
        self.last_dll_records = []
        self.last_connection_records = []
        self.last_injection = []
        self.last_secrets = {}
        self.last_yara_matches = []

        self.label = QLabel("No memory file selected")
        self.status = QLabel("Status: Idle")
        self.report_folder_label = QLabel("Reports folder: next to memory dump")

        self.tabs = QTabWidget()
        self.process_tab = QTextEdit()
        self.injection_tab = QTextEdit()
        self.network_tab = QTextEdit()
        self.secrets_tab = QTextEdit()
        self.process_deep_tab = QTextEdit()
        self.yara_tab = QTextEdit()
        for tab in [
            self.process_tab,
            self.process_deep_tab,
            self.injection_tab,
            self.network_tab,
            self.secrets_tab,
            self.yara_tab,
        ]:
            tab.setReadOnly(True)
            tab.setProperty("resultsPanel", "true")
            self._configure_results_panel(tab)

        self.tabs.addTab(self.process_tab, "Processes")
        self.tabs.addTab(self.process_deep_tab, "Process Deep Dive")
        self.tabs.addTab(self.injection_tab, "Injection")
        self.tabs.addTab(self.network_tab, "Network")
        self.tabs.addTab(self.secrets_tab, "Keys/Creds")
        self.tabs.addTab(self.yara_tab, "YARA")

        self.btn_load = QPushButton("Load Memory Dump")
        self.btn_export = QPushButton("Export Report (JSON + TXT + HTML)")
        self.btn_report_folder = QPushButton("Set report folder…")
        self.os_selector = QComboBox()
        self.os_selector.addItems(["windows", "linux", "mac"])

        self.engine_combo = QComboBox()
        self.engine_combo.addItem("Volatility 3 (vol)", "3")
        self.engine_combo.addItem("Volatility 2 (vol.py)", "2")
        self.engine_combo.setToolTip("Use Vol 2 for legacy dumps that fail with Volatility 3.")

        self.vol2_profile_edit = QLineEdit()
        self.vol2_profile_edit.setPlaceholderText("Vol2 profile, e.g. Win7SP1x64 (optional for imageinfo)")
        self.vol2_script_edit = QLineEdit()
        self.vol2_script_edit.setPlaceholderText("Path to vol.py — or env VOLATILITY2_VOLPY")
        self.btn_browse_vol2 = QPushButton("Browse vol.py…")
        self.vol2_python_edit = QLineEdit()
        self.vol2_python_edit.setPlaceholderText(
            "Python for Vol 2 — e.g. …\\Python27\\python.exe (official vol.py is Python 2)"
        )
        self.btn_browse_vol2_python = QPushButton("Browse python.exe…")
        self.btn_vol2_imageinfo = QPushButton("Run imageinfo (Vol 2)…")
        self.btn_vol2_imageinfo.setToolTip(
            "Runs imageinfo without a profile so you can copy a Suggested Profile (e.g. Win7SP1x64)."
        )

        self.vol2_hint = QLabel(
            "Vol 2: use Python 2.7 for official vol.py (otherwise you get SyntaxError on print). "
            "Leave profile empty only for imageinfo; then set profile before pslist / full analysis."
        )
        self.vol2_hint.setWordWrap(True)

        self.btn_full = QPushButton("Run full analysis (all steps)")
        self.btn_process = QPushButton("Run Process Analysis")
        self.btn_injection = QPushButton("Detect Injection")
        self.btn_network = QPushButton("Network Scan")
        self.btn_secrets = QPushButton("Detect Keys/Credentials")
        self.btn_yara = QPushButton("YARA Scan")

        primary_buttons = [
            self.btn_load,
            self.btn_export,
            self.btn_full,
            self.btn_process,
            self.btn_injection,
            self.btn_network,
            self.btn_secrets,
            self.btn_yara,
            self.btn_vol2_imageinfo,
        ]
        secondary_buttons = [
            self.btn_report_folder,
            self.btn_browse_vol2,
            self.btn_browse_vol2_python,
        ]
        for button in primary_buttons:
            button.setProperty("variant", "primary")
        for button in secondary_buttons:
            button.setProperty("variant", "secondary")

        self._task_buttons = [
            self.btn_full,
            self.btn_process,
            self.btn_injection,
            self.btn_network,
            self.btn_secrets,
            self.btn_yara,
            self.btn_export,
            self.btn_report_folder,
        ]
        self._config_busy_widgets = [
            self.os_selector,
            self.engine_combo,
            self.vol2_profile_edit,
            self.vol2_script_edit,
            self.btn_browse_vol2,
            self.vol2_python_edit,
            self.btn_browse_vol2_python,
            self.btn_vol2_imageinfo,
        ]

        layout = QVBoxLayout()
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        layout.addWidget(self.label)
        layout.addWidget(self.status)
        layout.addWidget(self.report_folder_label)

        action_row = QHBoxLayout()
        action_row.setSpacing(8)
        action_row.addWidget(self.btn_load)
        action_row.addWidget(self.btn_report_folder)
        action_row.addWidget(self.btn_export)
        action_row.addStretch()
        layout.addLayout(action_row)

        config_sep = QFrame()
        config_sep.setFrameShape(QFrame.HLine)
        layout.addWidget(config_sep)

        layout.addWidget(QLabel("Target OS"))
        layout.addWidget(self.os_selector)
        layout.addWidget(QLabel("Volatility engine"))
        layout.addWidget(self.engine_combo)
        layout.addWidget(QLabel("Volatility 2 — memory profile"))
        layout.addWidget(self.vol2_profile_edit)
        row_vol2 = QHBoxLayout()
        row_vol2.addWidget(self.vol2_script_edit)
        row_vol2.addWidget(self.btn_browse_vol2)
        layout.addLayout(row_vol2)
        layout.addWidget(QLabel("Python interpreter for Vol 2 (Python 2.7 recommended)"))
        row_py2 = QHBoxLayout()
        row_py2.addWidget(self.vol2_python_edit)
        row_py2.addWidget(self.btn_browse_vol2_python)
        layout.addLayout(row_py2)
        layout.addWidget(self.btn_vol2_imageinfo)
        layout.addWidget(self.vol2_hint)

        analyze_sep = QFrame()
        analyze_sep.setFrameShape(QFrame.HLine)
        layout.addWidget(analyze_sep)

        layout.addWidget(QLabel("Analysis"))
        analyze_row_1 = QHBoxLayout()
        analyze_row_1.setSpacing(8)
        analyze_row_1.addWidget(self.btn_full)
        analyze_row_1.addWidget(self.btn_process)
        analyze_row_1.addWidget(self.btn_injection)
        layout.addLayout(analyze_row_1)

        analyze_row_2 = QHBoxLayout()
        analyze_row_2.setSpacing(8)
        analyze_row_2.addWidget(self.btn_network)
        analyze_row_2.addWidget(self.btn_secrets)
        analyze_row_2.addWidget(self.btn_yara)
        layout.addLayout(analyze_row_2)

        results_sep = QFrame()
        results_sep.setFrameShape(QFrame.HLine)
        layout.addWidget(results_sep)
        layout.addWidget(QLabel("Results"))
        layout.addWidget(self.tabs)

        self.setLayout(layout)

        self.btn_load.clicked.connect(self.load_file)
        self.btn_export.clicked.connect(self.export_report)
        self.btn_report_folder.clicked.connect(self.pick_report_folder)
        self.btn_full.clicked.connect(lambda: self.start_task("full"))
        self.btn_process.clicked.connect(lambda: self.start_task("process"))
        self.btn_injection.clicked.connect(lambda: self.start_task("injection"))
        self.btn_network.clicked.connect(lambda: self.start_task("network"))
        self.btn_secrets.clicked.connect(lambda: self.start_task("secrets"))
        self.btn_yara.clicked.connect(lambda: self.start_task("yara"))
        self.btn_browse_vol2.clicked.connect(self.browse_vol2_script)
        self.btn_browse_vol2_python.clicked.connect(self.browse_vol2_python)
        self.btn_vol2_imageinfo.clicked.connect(self.run_vol2_imageinfo)

    def _apply_theme(self):
        self.setStyleSheet(
            """
            QWidget {
                background: #f7f9fc;
                color: #1f2937;
                font-family: "Segoe UI", "Inter", Arial, sans-serif;
                font-size: 13px;
            }
            QLabel {
                font-size: 13px;
            }
            QLineEdit, QComboBox, QTextEdit {
                background: #ffffff;
                border: 1px solid #d8dee9;
                border-radius: 6px;
                padding: 6px;
                color: #111827;
            }
            QTextEdit, QPlainTextEdit {
                font-family: "Consolas", "Cascadia Mono", "Courier New", monospace;
                font-size: 14px;
                selection-color: #111827;
                selection-background-color: #bfdbfe;
            }
            QTextEdit[resultsPanel="true"], QPlainTextEdit[resultsPanel="true"] {
                background: #ffffff;
                color: #0f172a;
                border: 1px solid #b6c2d2;
            }
            QTextEdit[resultsPanel="true"]:read-only, QPlainTextEdit[resultsPanel="true"]:read-only {
                background: #ffffff;
                color: #0f172a;
            }
            QTextEdit:disabled, QPlainTextEdit:disabled {
                background: #f8fafc;
                color: #1f2937;
            }
            QPushButton {
                background: #ffffff;
                border: 1px solid #d8dee9;
                border-radius: 6px;
                padding: 7px 12px;
                min-height: 30px;
                color: #1f2937;
            }
            QPushButton[variant="primary"] {
                background: #2563eb;
                border: 1px solid #1d4ed8;
                color: #ffffff;
                font-weight: 600;
            }
            QPushButton[variant="primary"]:hover {
                background: #1d4ed8;
                border: 1px solid #1e40af;
            }
            QPushButton[variant="primary"]:pressed {
                background: #1e40af;
                border: 1px solid #1e3a8a;
            }
            QPushButton[variant="secondary"] {
                background: #ffffff;
                border: 1px solid #d1d5db;
                color: #374151;
            }
            QPushButton[variant="secondary"]:hover {
                background: #f0f4f8;
            }
            QPushButton[variant="secondary"]:pressed {
                background: #e5eaf1;
            }
            QPushButton:disabled {
                color: #9ca3af;
                background: #f3f4f6;
                border: 1px solid #e5e7eb;
            }
            QPushButton[variant="primary"]:disabled {
                background: #93c5fd;
                border: 1px solid #93c5fd;
                color: #eff6ff;
            }
            QTabWidget::pane {
                border: 1px solid #cbd5e1;
                background: #ffffff;
                border-radius: 6px;
            }
            QTabBar::tab {
                background: #e5e7eb;
                border: 1px solid #cbd5e1;
                color: #374151;
                padding: 9px 14px;
                margin-right: 4px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }
            QTabBar::tab:selected {
                background: #ffffff;
                color: #0f172a;
                font-weight: 600;
                border-bottom-color: #ffffff;
            }
            QTabBar::tab:hover {
                background: #dbeafe;
                color: #1e3a8a;
            }
            QScrollBar:vertical {
                background: #f1f5f9;
                width: 12px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #94a3b8;
                min-height: 28px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background: #64748b;
            }
            QScrollBar:horizontal {
                background: #f1f5f9;
                height: 12px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background: #94a3b8;
                min-width: 28px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #64748b;
            }
            QFrame {
                color: #d8dee9;
            }
            """
        )

    def _configure_results_panel(self, widget):
        # Explicit palette prevents washed-out text on some system themes/read-only states.
        palette = widget.palette()
        base = QColor("#ffffff")
        text = QColor("#0f172a")
        highlight = QColor("#bfdbfe")
        highlighted_text = QColor("#0f172a")

        for group in (QPalette.Active, QPalette.Inactive, QPalette.Disabled):
            palette.setColor(group, QPalette.Base, base)
            palette.setColor(group, QPalette.Text, text)
            palette.setColor(group, QPalette.Highlight, highlight)
            palette.setColor(group, QPalette.HighlightedText, highlighted_text)
            palette.setColor(group, QPalette.PlaceholderText, QColor("#64748b"))

        widget.setPalette(palette)
        widget.setAutoFillBackground(True)
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.Monospace)
        mono.setPointSize(10)
        widget.setFont(mono)

    def run_vol2_imageinfo(self):
        if not self.memory_file:
            QMessageBox.warning(self, "imageinfo", "Load a memory dump first.")
            return
        self._sync_volatility_config_from_ui()
        if get_volatility_config()["engine"] != "2":
            QMessageBox.information(
                self,
                "imageinfo",
                "Switch Volatility engine to “Volatility 2 (vol.py)” first, and set path to vol.py.",
            )
            return
        if not get_resolved_vol2_script():
            QMessageBox.warning(self, "imageinfo", "Set path to vol.py (Browse) or env VOLATILITY2_VOLPY.")
            return

        eng, prof, script, pyexe = (
            get_volatility_config()["engine"],
            self.vol2_profile_edit.text().strip(),
            self.vol2_script_edit.text().strip(),
            self.vol2_python_edit.text().strip(),
        )
        set_volatility_config(engine="2", vol2_profile="", vol2_script=script, vol2_python=pyexe)
        self.status.setText("Running imageinfo…")
        out = run_volatility("windows.info", self.memory_file, os_type="windows")
        set_volatility_config(engine=eng, vol2_profile=prof, vol2_script=script, vol2_python=pyexe)

        dlg = QDialog(self)
        dlg.setWindowTitle("imageinfo (Volatility 2)")
        vbox = QVBoxLayout(dlg)
        te = QTextEdit()
        te.setReadOnly(True)
        te.setProperty("resultsPanel", "true")
        self._configure_results_panel(te)
        te.setPlainText(out)
        te.setMinimumSize(720, 420)
        vbox.addWidget(te)
        hint = QLabel("Copy one line from “Suggested Profile(s)” into “Volatility 2 — memory profile”, then run analysis.")
        hint.setWordWrap(True)
        vbox.addWidget(hint)
        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.rejected.connect(dlg.accept)
        vbox.addWidget(bb)
        dlg.exec_()
        self.status.setText("imageinfo finished — set profile field, then run Process / Full analysis.")

    def _sync_volatility_config_from_ui(self):
        eng = self.engine_combo.currentData() or "3"
        set_volatility_config(
            engine=eng,
            vol2_profile=self.vol2_profile_edit.text().strip(),
            vol2_script=self.vol2_script_edit.text().strip(),
            vol2_python=self.vol2_python_edit.text().strip(),
        )

    def browse_vol2_script(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select vol.py (Volatility 2 checkout)",
            "",
            "Python (*.py);;All files (*.*)",
        )
        if path:
            self.vol2_script_edit.setText(path)

    def browse_vol2_python(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select python.exe (prefer Python 2.7 for Volatility 2)",
            "",
            "Executable (*.exe);;All files (*.*)",
        )
        if path:
            self.vol2_python_edit.setText(path)

    def _set_busy(self, busy):
        self.btn_load.setEnabled(not busy)
        for b in self._task_buttons:
            b.setEnabled(not busy)
        for w in self._config_busy_widgets:
            w.setEnabled(not busy)

    def pick_report_folder(self):
        default = self.report_dir or (os.path.dirname(self.memory_file) if self.memory_file else "")
        path = QFileDialog.getExistingDirectory(self, "Report output folder", default)
        if path:
            self.report_dir = path
            self.report_folder_label.setText(f"Reports folder: {path}")

    def load_file(self):
        self._sync_volatility_config_from_ui()
        if not volatility_any_backend_ok():
            self.status.setText(
                "No Volatility backend: install Vol 3 (`pip install volatility3`, vol in PATH) "
                "or choose Vol 2 + valid path to vol.py (or set VOLATILITY2_VOLPY)."
            )
            return

        file_path, _ = QFileDialog.getOpenFileName(self, "Select Memory Dump")
        if file_path:
            self.memory_file = file_path
            self.completed_tasks.clear()
            self.last_profile = detect_os_profile(file_path)
            guessed = self.last_profile.get("guessed_os", "windows")
            index = self.os_selector.findText(guessed)
            if index >= 0:
                self.os_selector.setCurrentIndex(index)
            self.label.setText(f"Loaded: {file_path}")
            self.status.setText(
                f"Detected OS: {self.last_profile['guessed_os']} ({self.last_profile['confidence']})"
            )

    def start_task(self, task):
        if not self.memory_file:
            self.status.setText("Status: Load file first!")
            return

        self._sync_volatility_config_from_ui()
        cfg = get_volatility_config()
        if cfg["engine"] == "2" and not get_resolved_vol2_script():
            QMessageBox.warning(
                self,
                "Volatility 2",
                "Set the path to vol.py (Browse) or set the environment variable VOLATILITY2_VOLPY.",
            )
            return

        self._set_busy(True)
        self.thread = WorkerThread(task, self.memory_file)
        self.thread.set_os_type(self.os_selector.currentText())
        self.thread.progress.connect(self.status.setText)
        self.thread.step_done.connect(self.show_result)
        self.thread.all_done.connect(self._analysis_finished)
        self.thread.start()

    def _analysis_finished(self):
        self._set_busy(False)
        self.status.setText("Done ✅")

    def show_result(self, task, result, extra=None):
        self.completed_tasks.add(task)

        if task == "process":
            self.process_tab.setPlainText(result)
            self.last_process_records = get_process_records(self.memory_file, os_type=self.os_selector.currentText())
            self.last_process_tree_records = get_process_tree_records(
                self.memory_file, os_type=self.os_selector.currentText()
            )
            self.last_thread_records = get_thread_records(self.memory_file, os_type=self.os_selector.currentText())
            self.last_dll_records = get_dll_records(self.memory_file, os_type=self.os_selector.currentText())
            self.process_deep_tab.setPlainText(self._format_process_deep_dive())

        elif task == "injection":
            self.injection_tab.setPlainText(result)
            if extra is not None:
                self.last_injection = list(extra)
            else:
                self.last_injection = []

        elif task == "network":
            self.network_tab.setPlainText(result)
            self.last_connection_records = get_connection_records(
                self.memory_file, os_type=self.os_selector.currentText()
            )

        elif task == "secrets":
            self.secrets_tab.setPlainText(result)
            if extra is not None:
                self.last_secrets = extra
            else:
                try:
                    self.last_secrets = json.loads(result)
                except Exception:
                    self.last_secrets = {"raw": result}

        elif task == "yara":
            self.yara_tab.setPlainText(result)
            self.last_yara_matches = extra if extra is not None else []

    def _format_process_deep_dive(self):
        summary = {
            "process_records_count": len(self.last_process_records),
            "process_tree_records_count": len(self.last_process_tree_records),
            "thread_records_count": len(self.last_thread_records),
            "dll_records_count": len(self.last_dll_records),
            "sample_process_records": self.last_process_records[:10],
            "sample_process_tree_records": self.last_process_tree_records[:10],
            "sample_thread_records": self.last_thread_records[:10],
            "sample_dll_records": self.last_dll_records[:10],
        }
        return json.dumps(summary, indent=2)

    def export_report(self):
        if not self.memory_file:
            self.status.setText("Status: Load file first!")
            return

        expected = {"process", "injection", "network", "secrets", "yara"}
        missing = expected - self.completed_tasks
        if missing:
            r = QMessageBox.question(
                self,
                "Incomplete analysis",
                "These steps were not run in this session: "
                + ", ".join(sorted(missing))
                + ".\n\nExport anyway?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if r != QMessageBox.Yes:
                self.status.setText("Export cancelled.")
                return

        self._sync_volatility_config_from_ui()
        vol_meta = dict(get_volatility_config())
        rp = get_resolved_vol2_script()
        if rp:
            vol_meta["vol2_script_resolved"] = rp
        vol_meta["volatility3_status"] = volatility_engine_status()

        report = build_report(
            memory_file=self.memory_file,
            os_profile=self.last_profile,
            process_records=self.last_process_records,
            process_tree_records=self.last_process_tree_records,
            thread_records=self.last_thread_records,
            dll_records=self.last_dll_records,
            suspicious_injection=self.last_injection,
            connection_records=self.last_connection_records,
            secrets=self.last_secrets,
            yara_matches=self.last_yara_matches,
            volatility_meta=vol_meta,
        )
        base_name = os.path.splitext(os.path.basename(self.memory_file))[0]
        out_dir = self.report_dir or os.path.dirname(self.memory_file) or "."
        os.makedirs(out_dir, exist_ok=True)
        out_json = os.path.join(out_dir, f"{base_name}_forensics_report.json")
        out_txt = os.path.join(out_dir, f"{base_name}_forensics_report.txt")
        out_html = os.path.join(out_dir, f"{base_name}_forensics_report.html")
        export_report_json(report, out_json)
        export_report_txt(report, out_txt)
        export_report_html(report, out_html)
        self.status.setText(f"Report exported: {out_json} | {out_txt} | {out_html}")
