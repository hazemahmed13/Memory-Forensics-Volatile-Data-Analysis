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
    QTableWidget,
    QTableWidgetItem,
    QAbstractItemView,
    QHeaderView,
    QProgressBar,
    QSplitter,
    QScrollArea,
    QSizePolicy,
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QPalette, QColor, QFont

from process_analysis import (
    detect_injection,
    detect_injection_details,
    get_dll_records,
    get_process_records,
    get_processes,
    get_process_tree,
    get_process_tree_records,
    get_thread_records,
)
from network_analysis import get_connections, get_connection_records, fetch_network_volatility_output
from secrets_analysis import detect_keys_and_credentials
from yara_scan import format_yara_matches, get_yara_scan_stats, scan_memory
from os_profile import detect_os_profile
from report_export import build_report, export_report_json, export_report_txt, export_report_html
from volatility_runner import (
    cancel_all_volatility_subprocesses,
    reset_volatility_session_for_new_dump,
    generate_linux_symbols_for_dump,
    get_backend_health,
    get_environment_compatibility,
    get_resolved_vol2_script,
    get_symbol_diagnostics,
    get_volatility_config,
    run_volatility,
    set_runtime_log_sink,
    set_volatility_config,
    set_volatility_progress_callback,
    set_volatility_progress_span,
    volatility_any_backend_ok,
    volatility_engine_status,
)
from core.detection.os_detector import detect_target_os
from forensics_logging import setup_forensics_logging
import json
import os
import lzma
import shutil
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed


class ResultsTableWidget(QWidget):
    def __init__(self, title):
        super().__init__()
        self.title = title
        self.rows = []
        self.columns = []
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText(f"Filter {title}...")
        self.table = QTableWidget()
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.filter_input.textChanged.connect(self.apply_filter)

        layout = QVBoxLayout()
        layout.addWidget(self.filter_input)
        layout.addWidget(self.table)
        self.setLayout(layout)

    def set_rows(self, rows):
        self.rows = list(rows or [])
        cols = []
        for row in self.rows:
            for key in row.keys():
                if key not in cols:
                    cols.append(key)
        self.columns = cols if cols else ["Result"]
        self.apply_filter()

    def set_text_result(self, text):
        self.set_rows([{"Result": line} for line in str(text or "").splitlines() if line.strip()] or [{"Result": str(text or "")}])

    def apply_filter(self):
        term = self.filter_input.text().strip().lower()
        visible = []
        for row in self.rows:
            if not term:
                visible.append(row)
                continue
            if any(term in str(v).lower() for v in row.values()):
                visible.append(row)
        self._render_rows(visible)

    def _render_rows(self, rows):
        self.table.setRowCount(len(rows))
        self.table.setColumnCount(len(self.columns))
        self.table.setHorizontalHeaderLabels(self.columns)
        for r, row in enumerate(rows):
            for c, col in enumerate(self.columns):
                self.table.setItem(r, c, QTableWidgetItem(str(row.get(col, ""))))


class WorkerThread(QThread):
    progress = pyqtSignal(str)
    progress_percent = pyqtSignal(int)
    log = pyqtSignal(str)
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
                process_text = get_processes(self.memory_file, os_type=os_type)
                tree_text = get_process_tree(self.memory_file, os_type=os_type)
                process_records = get_process_records(
                    self.memory_file, os_type=os_type, cached_pslist_output=process_text
                )
                process_tree_records = get_process_tree_records(
                    self.memory_file, os_type=os_type, cached_pstree_output=tree_text
                )
                thread_records = get_thread_records(
                    self.memory_file, os_type=os_type, cached_pslist_output=process_text
                )
                dll_records = get_dll_records(self.memory_file, os_type=os_type)
                payload = {
                    "process_records": process_records,
                    "process_tree_records": process_tree_records,
                    "thread_records": thread_records,
                    "dll_records": dll_records,
                }
                return process_text, payload

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
                net_raw = fetch_network_volatility_output(self.memory_file, os_type=os_type)
                data = get_connections(self.memory_file, os_type=os_type, cached_volatility_output=net_raw)
                text = "\n".join(data[:50])
                connection_records = get_connection_records(
                    self.memory_file, os_type=os_type, cached_volatility_output=net_raw
                )
                return text, {"connection_records": connection_records}

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
        interrupted = False
        forced = (os.environ.get("VOLATILITY_FORCE_OS", "") or "").strip().lower()
        if forced in ("windows", "linux", "mac"):
            self.os_type = forced
        else:
            self.os_type = detect_target_os(self.memory_file)
        set_runtime_log_sink(self.log.emit)
        steps_total = 5 if self.task == "full" else 1
        executor = None
        try:
            if self.task == "full":
                all_steps = ["process", "injection", "network", "secrets", "yara"]
                proc_step = all_steps[0]
                remainder = list(all_steps[1:])
                futures_map = {}

                if self.isInterruptionRequested():
                    interrupted = True
                    raise InterruptedError()

                pct_lo_proc = int((0 / steps_total) * 100)
                pct_hi_proc = max(pct_lo_proc + 3, int((1 / steps_total) * 100))
                set_volatility_progress_span(pct_lo_proc, pct_hi_proc)
                set_volatility_progress_callback(lambda p: self.progress_percent.emit(int(p)))
                self.progress.emit(f"Running {proc_step}… (full analysis)")
                self.progress_percent.emit(pct_lo_proc)
                pres, pextra = self._run_one(proc_step)
                self.step_done.emit(proc_step, pres, pextra)
                self.progress_percent.emit(pct_hi_proc)

                if self.isInterruptionRequested():
                    interrupted = True
                    raise InterruptedError()

                set_volatility_progress_callback(None)
                set_volatility_progress_span(0, 100)

                start_parallel = pct_hi_proc
                parallel_budget = max(100 - start_parallel - 2, 1)
                workers = min(max(2, os.cpu_count() or 2), 4, len(remainder))
                executor = ThreadPoolExecutor(max_workers=max(1, workers))
                for st in remainder:
                    if self.isInterruptionRequested():
                        interrupted = True
                        raise InterruptedError()
                    futures_map[executor.submit(self._run_one, st)] = st

                gathered = {}
                done = 0
                total_r = len(remainder) or 1
                for fut in as_completed(futures_map):
                    if self.isInterruptionRequested():
                        interrupted = True
                        cancel_all_volatility_subprocesses()
                        break
                    st_name = futures_map[fut]
                    try:
                        res = fut.result()
                    except Exception as ex:
                        from forensics_logging import log_exception

                        log_exception(f"worker.parallel.{st_name}", ex)
                        gathered[st_name] = (f"[worker error] {ex}", None)
                    else:
                        gathered[st_name] = res
                    done += 1
                    pct = min(
                        99,
                        int(start_parallel + parallel_budget * (done / total_r)),
                    )
                    self.progress_percent.emit(pct)

                for st in remainder:
                    if st not in gathered:
                        continue
                    text, extra = gathered[st]
                    self.progress.emit(f"Publishing {st}…")
                    self.step_done.emit(st, text, extra)

                if not interrupted and not self.isInterruptionRequested():
                    self.progress_percent.emit(100)

            else:
                set_volatility_progress_span(0, 100)
                set_volatility_progress_callback(lambda p: self.progress_percent.emit(int(p)))
                self.progress.emit(f"Running {self.task}…")
                self.progress_percent.emit(0)
                text, extra = self._run_one(self.task)
                self.step_done.emit(self.task, text, extra)
                if not self.isInterruptionRequested():
                    self.progress_percent.emit(100)
        except InterruptedError:
            interrupted = True
            self.progress.emit("Analysis cancelled.")
        except Exception as exc:
            from forensics_logging import log_exception

            log_exception("worker.run", exc)
            try:
                self.log.emit(f"[worker error] {exc}")
            except Exception:
                pass
        finally:
            if executor is not None:
                try:
                    executor.shutdown(wait=False, cancel_futures=True)
                except Exception:
                    try:
                        executor.shutdown(wait=False)
                    except Exception:
                        pass
            set_volatility_progress_callback(None)
            set_volatility_progress_span(0, 100)
            set_runtime_log_sink(None)
            self.all_done.emit()


class OsProfileDetectionThread(QThread):
    """Runs detect_os_profile off the GUI thread."""

    profile_ready = pyqtSignal(dict, str)
    failed = pyqtSignal(str, str)

    def __init__(self, dump_path, parent=None):
        super().__init__(parent)
        self.dump_path = dump_path

    def run(self):
        if self.isInterruptionRequested():
            return
        try:
            prof = detect_os_profile(self.dump_path)
            self.profile_ready.emit(prof, self.dump_path)
        except Exception as exc:
            self.failed.emit(str(exc), self.dump_path)


class Vol2ImageinfoThread(QThread):
    """Runs Volatility 2 imageinfo without blocking the UI."""

    output_ready = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(self, memory_file, restore_engine, restore_prof, restore_script, restore_py, parent=None):
        super().__init__(parent)
        self.memory_file = memory_file
        self._restore = (restore_engine, restore_prof, restore_script, restore_py)

    def run(self):
        try:
            eng, prof, script, pyexe = (
                self._restore[0],
                self._restore[1],
                self._restore[2],
                self._restore[3],
            )
            set_volatility_config(engine="2", vol2_profile="", vol2_script=script, vol2_python=pyexe)
            out = run_volatility("windows.info", self.memory_file, os_type="windows")
            set_volatility_config(engine=eng, vol2_profile=prof, vol2_script=script, vol2_python=pyexe)
            self.output_ready.emit(out or "")
        except Exception as exc:
            eng, prof, script, pyexe = self._restore
            try:
                set_volatility_config(engine=eng, vol2_profile=prof, vol2_script=script, vol2_python=pyexe)
            except Exception:
                pass
            self.failed.emit(str(exc))


class LinuxSymbolsGenerationThread(QThread):
    finished = pyqtSignal(dict)

    def __init__(self, memory_file, parent=None):
        super().__init__(parent)
        self.memory_file = memory_file

    def run(self):
        try:
            res = generate_linux_symbols_for_dump(self.memory_file)
            self.finished.emit(res if isinstance(res, dict) else {"ok": False, "message": str(res)})
        except Exception as exc:
            self.finished.emit({"ok": False, "message": str(exc), "recovery": {}})


class MemoryForensicsApp(QWidget):
    def __init__(self):
        super().__init__()
        setup_forensics_logging()

        self.setWindowTitle("Memory Forensics Tool")
        self.setGeometry(200, 200, 1100, 820)
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

        self.thread = None
        self._profile_thread = None
        self._pending_profile_dump = None
        self._vol2_thread = None
        self._linux_sym_thread = None

        self.label = QLabel("No memory file selected")
        self.status = QLabel("Status: Idle")
        self.report_folder_label = QLabel("Reports folder: next to memory dump")
        self.health_label = QLabel("Backend health: checking…")
        self.linux_symbol_banner = QLabel("")
        self.linux_symbol_banner.setVisible(False)

        self.tabs = QTabWidget()
        self.process_tab = ResultsTableWidget("Processes")
        self.injection_tab = ResultsTableWidget("Injection")
        self.network_tab = ResultsTableWidget("Network")
        self.secrets_tab = ResultsTableWidget("Keys/Creds")
        self.process_deep_tab = ResultsTableWidget("Process Deep Dive")
        self.yara_tab = ResultsTableWidget("YARA")

        self.tabs.addTab(self.process_tab, "Processes")
        self.tabs.addTab(self.process_deep_tab, "Process Deep Dive")
        self.tabs.addTab(self.injection_tab, "Injection")
        self.tabs.addTab(self.network_tab, "Network")
        self.tabs.addTab(self.secrets_tab, "Keys/Creds")
        self.tabs.addTab(self.yara_tab, "YARA")

        self.btn_load = QPushButton("Load Memory Dump")
        self.btn_export = QPushButton("Export Report (JSON + TXT + HTML)")
        self.btn_report_folder = QPushButton("Set report folder…")
        self.btn_health = QPushButton("Refresh Backend Health")
        self.btn_generate_symbols = QPushButton("Generate Linux Symbols")
        self.btn_load_symbol_file = QPushButton("Load Symbol File (.json/.json.xz)")
        self.btn_load_symbol_file.setVisible(False)
        self.btn_check_env = QPushButton("Check Environment Compatibility")
        self.os_selector = QComboBox()
        self.os_selector.addItem("windows", "windows")
        self.os_selector.addItem("linux", "linux")
        self.os_selector.addItem("macos", "mac")
        self.os_selector.setEnabled(True)
        self.os_selector.setToolTip("OS is auto-detected, but you can override.")

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
        self.vmlinux_path_edit = QLineEdit()
        self.vmlinux_path_edit.setPlaceholderText("Linux vmlinux path (optional, for symbol generation)")
        self.btn_browse_vmlinux = QPushButton("Browse vmlinux…")
        self.dwarf2json_path_edit = QLineEdit()
        self.dwarf2json_path_edit.setPlaceholderText("Optional dwarf2json path")
        self.btn_browse_dwarf2json = QPushButton("Browse dwarf2json…")
        self.wsl_path_edit = QLineEdit()
        self.wsl_path_edit.setPlaceholderText("Optional WSL executable path (wsl.exe)")
        self.btn_browse_wsl = QPushButton("Browse wsl.exe…")
        self.btn_vol2_imageinfo = QPushButton("Run imageinfo (Vol 2)…")
        self.btn_vol2_imageinfo.setToolTip(
            "Runs imageinfo without a profile so you can copy a Suggested Profile (e.g. Win7SP1x64)."
        )

        self.vol2_hint = QLabel(
            "Vol 2: use Python 2.7 for official vol.py (otherwise you get SyntaxError on print). "
            "Leave profile empty only for imageinfo; then set profile before pslist / full analysis."
        )
        self.vol2_hint.setWordWrap(True)
        self.vol2_hint.setMinimumHeight(48)
        self.vol2_hint.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.MinimumExpanding)

        self.btn_full = QPushButton("Run full analysis (all steps)")
        self.btn_process = QPushButton("Run Process Analysis")
        self.btn_injection = QPushButton("Detect Injection")
        self.btn_network = QPushButton("Network Scan")
        self.btn_secrets = QPushButton("Detect Keys/Credentials")
        self.btn_yara = QPushButton("YARA Scan")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.log_panel = QTextEdit()
        self.log_panel.setReadOnly(True)
        self.log_panel.setMinimumHeight(260)
        self.log_panel.setObjectName("liveLogConsole")
        self.log_panel.setProperty("logConsole", "true")
        self.log_panel.setLineWrapMode(QTextEdit.NoWrap)
        self.log_panel.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.log_panel.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.log_panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._configure_live_log_console(self.log_panel)
        self.btn_clear_log = QPushButton("Clear log")
        self.btn_clear_log.setProperty("variant", "secondary")
        self.btn_clear_log.clicked.connect(self._clear_live_log)

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
            self.btn_health,
            self.btn_generate_symbols,
            self.btn_load_symbol_file,
            self.btn_check_env,
            self.btn_browse_vol2,
            self.btn_browse_vol2_python,
            self.btn_browse_vmlinux,
            self.btn_browse_dwarf2json,
            self.btn_browse_wsl,
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
            self.vmlinux_path_edit,
            self.btn_browse_vmlinux,
            self.dwarf2json_path_edit,
            self.btn_browse_dwarf2json,
            self.wsl_path_edit,
            self.btn_browse_wsl,
        ]

        # Scrollable upper region: form + results need more height than many windows provide;
        # without this, QSplitter squeezes widgets and they overlap (white clipped lines).
        upper_scroll = QScrollArea()
        upper_scroll.setWidgetResizable(True)
        upper_scroll.setFrameShape(QFrame.NoFrame)
        upper_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        upper_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        upper_scroll.setMinimumHeight(380)
        upper_scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        upper_content = QWidget()
        upper_layout = QVBoxLayout(upper_content)
        upper_layout.setContentsMargins(2, 2, 2, 2)
        upper_layout.setSpacing(10)

        upper_layout.addWidget(self.label)
        upper_layout.addWidget(self.status)
        upper_layout.addWidget(self.report_folder_label)
        upper_layout.addWidget(self.health_label)
        upper_layout.addWidget(self.linux_symbol_banner)

        action_row = QHBoxLayout()
        action_row.setSpacing(8)
        action_row.addWidget(self.btn_load)
        action_row.addWidget(self.btn_report_folder)
        action_row.addWidget(self.btn_export)
        action_row.addWidget(self.btn_health)
        action_row.addWidget(self.btn_generate_symbols)
        action_row.addWidget(self.btn_load_symbol_file)
        action_row.addWidget(self.btn_check_env)
        action_row.addStretch()
        upper_layout.addLayout(action_row)

        config_sep = QFrame()
        config_sep.setFrameShape(QFrame.HLine)
        config_sep.setFixedHeight(1)
        config_sep.setStyleSheet("background-color: #334155; border: none; margin: 0; padding: 0;")
        upper_layout.addWidget(config_sep)

        upper_layout.addWidget(QLabel("Target OS (auto-detected)"))
        upper_layout.addWidget(self.os_selector)
        upper_layout.addWidget(QLabel("Volatility engine"))
        upper_layout.addWidget(self.engine_combo)
        upper_layout.addWidget(QLabel("Volatility 2 — memory profile"))
        upper_layout.addWidget(self.vol2_profile_edit)
        row_vol2 = QHBoxLayout()
        row_vol2.addWidget(self.vol2_script_edit)
        row_vol2.addWidget(self.btn_browse_vol2)
        upper_layout.addLayout(row_vol2)
        upper_layout.addWidget(QLabel("Python interpreter for Vol 2 (Python 2.7 recommended)"))
        row_py2 = QHBoxLayout()
        row_py2.addWidget(self.vol2_python_edit)
        row_py2.addWidget(self.btn_browse_vol2_python)
        upper_layout.addLayout(row_py2)
        upper_layout.addWidget(self.btn_vol2_imageinfo)
        upper_layout.addWidget(self.vol2_hint)
        self.lbl_vmlinux_section = QLabel("Linux vmlinux path (for symbol generation)")
        upper_layout.addWidget(self.lbl_vmlinux_section)
        row_vm = QHBoxLayout()
        row_vm.addWidget(self.vmlinux_path_edit)
        row_vm.addWidget(self.btn_browse_vmlinux)
        upper_layout.addLayout(row_vm)
        self.lbl_dwarf_section = QLabel("dwarf2json path (optional)")
        upper_layout.addWidget(self.lbl_dwarf_section)
        row_dwarf = QHBoxLayout()
        row_dwarf.addWidget(self.dwarf2json_path_edit)
        row_dwarf.addWidget(self.btn_browse_dwarf2json)
        upper_layout.addLayout(row_dwarf)
        self.lbl_wsl_section = QLabel("WSL executable path (optional)")
        upper_layout.addWidget(self.lbl_wsl_section)
        row_wsl = QHBoxLayout()
        row_wsl.addWidget(self.wsl_path_edit)
        row_wsl.addWidget(self.btn_browse_wsl)
        upper_layout.addLayout(row_wsl)
        self._linux_only_widgets = [
            self.lbl_vmlinux_section,
            self.vmlinux_path_edit,
            self.btn_browse_vmlinux,
            self.lbl_dwarf_section,
            self.dwarf2json_path_edit,
            self.btn_browse_dwarf2json,
            self.lbl_wsl_section,
            self.wsl_path_edit,
            self.btn_browse_wsl,
        ]

        analyze_sep = QFrame()
        analyze_sep.setFrameShape(QFrame.HLine)
        analyze_sep.setFixedHeight(1)
        analyze_sep.setStyleSheet("background-color: #334155; border: none; margin: 0; padding: 0;")
        upper_layout.addWidget(analyze_sep)

        upper_layout.addWidget(QLabel("Analysis"))
        analyze_row_1 = QHBoxLayout()
        analyze_row_1.setSpacing(8)
        analyze_row_1.addWidget(self.btn_full)
        analyze_row_1.addWidget(self.btn_process)
        analyze_row_1.addWidget(self.btn_injection)
        upper_layout.addLayout(analyze_row_1)

        analyze_row_2 = QHBoxLayout()
        analyze_row_2.setSpacing(8)
        analyze_row_2.addWidget(self.btn_network)
        analyze_row_2.addWidget(self.btn_secrets)
        analyze_row_2.addWidget(self.btn_yara)
        upper_layout.addLayout(analyze_row_2)

        results_sep = QFrame()
        results_sep.setFrameShape(QFrame.HLine)
        results_sep.setFixedHeight(1)
        results_sep.setStyleSheet("background-color: #334155; border: none; margin: 0; padding: 0;")
        upper_layout.addWidget(results_sep)
        upper_layout.addWidget(QLabel("Results"))
        self.tabs.setMinimumHeight(220)
        upper_layout.addWidget(self.tabs, 1)

        upper_layout.addWidget(QLabel("Progress"))
        self.progress_bar.setMinimumHeight(22)
        upper_layout.addWidget(self.progress_bar)

        upper_scroll.setWidget(upper_content)

        log_section = QWidget()
        log_section_layout = QVBoxLayout(log_section)
        log_section_layout.setContentsMargins(0, 0, 0, 0)
        log_section_layout.setSpacing(6)
        log_header_row = QHBoxLayout()
        log_header_row.addWidget(QLabel("Live Log"))
        log_header_row.addStretch()
        log_header_row.addWidget(self.btn_clear_log)
        log_section_layout.addLayout(log_header_row)
        log_section_layout.addWidget(self.log_panel, 1)
        log_section.setMinimumHeight(200)

        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(upper_scroll)
        splitter.addWidget(log_section)
        # Prefer keeping the controls usable: upper pane gets more resize slack than log.
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([620, 280])

        root_layout = QVBoxLayout()
        root_layout.setContentsMargins(18, 16, 18, 16)
        root_layout.setSpacing(0)
        root_layout.addWidget(splitter)
        self.setLayout(root_layout)
        self.setMinimumSize(900, 700)

        self.btn_load.clicked.connect(self.load_file)
        self.btn_export.clicked.connect(self.export_report)
        self.btn_report_folder.clicked.connect(self.pick_report_folder)
        self.btn_health.clicked.connect(self.refresh_backend_health)
        self.btn_generate_symbols.clicked.connect(self.generate_linux_symbols)
        self.btn_load_symbol_file.clicked.connect(self.load_linux_symbol_file)
        self.btn_check_env.clicked.connect(self.check_environment_compatibility)
        self.btn_full.clicked.connect(lambda: self.start_task("full"))
        self.btn_process.clicked.connect(lambda: self.start_task("process"))
        self.btn_injection.clicked.connect(lambda: self.start_task("injection"))
        self.btn_network.clicked.connect(lambda: self.start_task("network"))
        self.btn_secrets.clicked.connect(lambda: self.start_task("secrets"))
        self.btn_yara.clicked.connect(lambda: self.start_task("yara"))
        self.btn_browse_vol2.clicked.connect(self.browse_vol2_script)
        self.btn_browse_vol2_python.clicked.connect(self.browse_vol2_python)
        self.btn_browse_vmlinux.clicked.connect(self.browse_vmlinux)
        self.btn_browse_dwarf2json.clicked.connect(self.browse_dwarf2json)
        self.btn_browse_wsl.clicked.connect(self.browse_wsl)
        self.btn_vol2_imageinfo.clicked.connect(self.run_vol2_imageinfo)
        self.os_selector.currentIndexChanged.connect(self.refresh_backend_health)
        self.refresh_backend_health()
        self._load_config()

    def _apply_theme(self):
        self.setStyleSheet(
            """
            QWidget {
                background: #0f172a;
                color: #e2e8f0;
                font-family: "Segoe UI", "Inter", Arial, sans-serif;
                font-size: 13px;
            }
            QLabel {
                font-size: 13px;
            }
            QLineEdit, QComboBox, QTextEdit {
                background: #111827;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px;
                color: #e2e8f0;
            }
            QTextEdit, QPlainTextEdit {
                font-family: "Consolas", "Cascadia Mono", "Courier New", monospace;
                font-size: 14px;
                selection-color: #111827;
                selection-background-color: #bfdbfe;
            }
            QTextEdit[resultsPanel="true"], QPlainTextEdit[resultsPanel="true"] {
                background: #020617;
                color: #cbd5e1;
                border: 1px solid #334155;
            }
            QTextEdit[logConsole="true"] {
                background: #1e1e1e;
                color: #b8f0b8;
                border: 1px solid #3c3c3c;
            }
            QTextEdit[logConsole="true"]:read-only {
                background: #1e1e1e;
                color: #d0e8d0;
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
                background: #111827;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 7px 12px;
                min-height: 30px;
                color: #e2e8f0;
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
                border: 1px solid #334155;
                background: #020617;
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
            QTextEdit[logConsole="true"] QScrollBar:vertical {
                background: #2d2d2d;
                width: 14px;
            }
            QTextEdit[logConsole="true"] QScrollBar::handle:vertical {
                background: #5a5a5a;
                min-height: 24px;
            }
            QTextEdit[logConsole="true"] QScrollBar::handle:vertical:hover {
                background: #6e6e6e;
            }
            QTextEdit[logConsole="true"] QScrollBar:horizontal {
                background: #2d2d2d;
                height: 14px;
            }
            QTextEdit[logConsole="true"] QScrollBar::handle:horizontal {
                background: #5a5a5a;
                min-width: 24px;
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

    def _configure_live_log_console(self, widget):
        palette = widget.palette()
        bg = QColor("#1e1e1e")
        fg = QColor("#d0ead0")
        highlight = QColor("#264f78")
        highlighted_text = QColor("#eafaea")

        for group in (QPalette.Active, QPalette.Inactive, QPalette.Disabled):
            palette.setColor(group, QPalette.Base, bg)
            palette.setColor(group, QPalette.Text, fg)
            palette.setColor(group, QPalette.Window, bg)
            palette.setColor(group, QPalette.Button, QColor("#2d2d2d"))
            palette.setColor(group, QPalette.Highlight, highlight)
            palette.setColor(group, QPalette.HighlightedText, highlighted_text)
            palette.setColor(group, QPalette.PlaceholderText, QColor("#7abd7a"))

        widget.setPalette(palette)
        widget.setAutoFillBackground(True)
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.Monospace)
        mono.setPointSize(10)
        widget.setFont(mono)

    def _configure_results_panel(self, widget):
        # Explicit palette prevents washed-out text on some system themes/read-only states.
        palette = widget.palette()
        base = QColor("#020617")
        text = QColor("#cbd5e1")
        highlight = QColor("#1d4ed8")
        highlighted_text = QColor("#e2e8f0")

        for group in (QPalette.Active, QPalette.Inactive, QPalette.Disabled):
            palette.setColor(group, QPalette.Base, base)
            palette.setColor(group, QPalette.Text, text)
            palette.setColor(group, QPalette.Highlight, highlight)
            palette.setColor(group, QPalette.HighlightedText, highlighted_text)
            palette.setColor(group, QPalette.PlaceholderText, QColor("#94a3b8"))

        widget.setPalette(palette)
        widget.setAutoFillBackground(True)
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.Monospace)
        mono.setPointSize(10)
        widget.setFont(mono)

    def _target_os(self):
        return self.os_selector.currentData() or "windows"

    def _config_path(self):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

    def _save_config(self):
        cfg = {
            "engine": self.engine_combo.currentData() or "3",
            "vol2_profile": self.vol2_profile_edit.text().strip(),
            "vol2_script": self.vol2_script_edit.text().strip(),
            "vol2_python": self.vol2_python_edit.text().strip(),
            "vmlinux_path": self.vmlinux_path_edit.text().strip(),
            "dwarf2json_path": self.dwarf2json_path_edit.text().strip(),
            "wsl_path": self.wsl_path_edit.text().strip(),
            "report_dir": self.report_dir or "",
            "last_os": self._target_os(),
        }
        try:
            with open(self._config_path(), "w", encoding="utf-8") as fp:
                json.dump(cfg, fp, indent=2)
        except Exception:
            pass

    def _load_config(self):
        try:
            with open(self._config_path(), "r", encoding="utf-8") as fp:
                cfg = json.load(fp)
        except Exception:
            return
        engine = str(cfg.get("engine", "3"))
        idx = self.engine_combo.findData(engine)
        if idx >= 0:
            self.engine_combo.setCurrentIndex(idx)
        self.vol2_profile_edit.setText(cfg.get("vol2_profile", ""))
        self.vol2_script_edit.setText(cfg.get("vol2_script", ""))
        self.vol2_python_edit.setText(cfg.get("vol2_python", ""))
        self.vmlinux_path_edit.setText(cfg.get("vmlinux_path", ""))
        self.dwarf2json_path_edit.setText(cfg.get("dwarf2json_path", ""))
        self.wsl_path_edit.setText(cfg.get("wsl_path", ""))
        self.report_dir = cfg.get("report_dir") or None
        if self.report_dir:
            self.report_folder_label.setText(f"Reports folder: {self.report_dir}")
        os_idx = self.os_selector.findData(cfg.get("last_os", "windows"))
        if os_idx >= 0:
            self.os_selector.setCurrentIndex(os_idx)
        self._sync_volatility_config_from_ui()
        self.refresh_backend_health()

    def _clear_live_log(self):
        self.log_panel.clear()

    def _append_log(self, line):
        if line is None or line == "":
            return
        self.log_panel.append(str(line))
        scroll = self.log_panel.verticalScrollBar()
        scroll.setValue(scroll.maximum())

    def _symbol_dir_for_os(self, os_type):
        base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "symbols")
        mapped = "mac" if os_type == "mac" else os_type
        target = os.path.join(base, mapped)
        os.makedirs(target, exist_ok=True)
        return target

    def _update_linux_symbol_banner(self, show, message=""):
        self.linux_symbol_banner.setVisible(show)
        self.btn_load_symbol_file.setVisible(show)
        if show:
            self.linux_symbol_banner.setText(message or "Linux dump detected — symbol file required")
        else:
            self.linux_symbol_banner.setText("")

    def load_linux_symbol_file(self):
        if not self.memory_file:
            QMessageBox.warning(self, "Symbol file", "Load a memory dump first.")
            return
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Symbol File (.json/.json.xz)",
            "",
            "Symbols (*.json *.json.xz);;All files (*.*)",
        )
        if not path:
            return
        try:
            target_dir = self._symbol_dir_for_os("linux")
            base = os.path.basename(path)
            if base.lower().endswith(".json.xz"):
                out_name = base[:-3]
                out_path = os.path.join(target_dir, out_name)
                with lzma.open(path, "rb") as src, open(out_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                saved = out_path
            else:
                saved = os.path.join(target_dir, base)
                shutil.copy2(path, saved)
        except Exception as exc:
            QMessageBox.warning(self, "Symbol file", f"Failed to import symbol file: {exc}")
            return
        self._append_log(f"[symbols] Installed Linux ISF: {saved}")
        # Compatibility mirror for environments expecting volatility3/symbols/linux.
        compat_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "volatility3", "symbols", "linux"
        )
        try:
            os.makedirs(compat_dir, exist_ok=True)
            shutil.copy2(saved, os.path.join(compat_dir, os.path.basename(saved)))
        except Exception:
            pass
        self._update_linux_symbol_banner(False)
        self.refresh_backend_health()

    def run_vol2_imageinfo(self):
        if not self.memory_file:
            QMessageBox.warning(self, "imageinfo", "Load a memory dump first.")
            return
        if isinstance(self._vol2_thread, QThread) and self._vol2_thread.isRunning():
            QMessageBox.information(self, "imageinfo", "imageinfo is already running.")
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

        eng = get_volatility_config()["engine"]
        prof = self.vol2_profile_edit.text().strip()
        script = self.vol2_script_edit.text().strip()
        pyexe = self.vol2_python_edit.text().strip()
        self._set_busy(True)
        self.status.setText("Running imageinfo…")
        self._vol2_thread = Vol2ImageinfoThread(self.memory_file, eng, prof, script, pyexe)
        self._vol2_thread.output_ready.connect(self._on_vol2_imageinfo_done)
        self._vol2_thread.failed.connect(self._on_vol2_imageinfo_failed)
        self._vol2_thread.start()

    def _sync_volatility_config_from_ui(self):
        eng = self.engine_combo.currentData() or "3"
        set_volatility_config(
            engine=eng,
            vol2_profile=self.vol2_profile_edit.text().strip(),
            vol2_script=self.vol2_script_edit.text().strip(),
            vol2_python=self.vol2_python_edit.text().strip(),
        )
        vm = self.vmlinux_path_edit.text().strip()
        if vm:
            os.environ["VOLATILITY_LINUX_VMLINUX"] = vm
        dwarf = self.dwarf2json_path_edit.text().strip()
        if dwarf:
            os.environ["VOLATILITY_DWARF2JSON"] = dwarf
        wsl_path = self.wsl_path_edit.text().strip()
        if wsl_path:
            os.environ["VOLATILITY_WSL_PATH"] = wsl_path
        self._save_config()

    def refresh_backend_health(self):
        eff_os = (
            detect_target_os(self.memory_file)
            if self.memory_file
            else (self.os_selector.currentData() or "windows")
        )
        health = get_backend_health(target_os=eff_os)
        env = get_environment_compatibility()
        self.btn_generate_symbols.setEnabled(env.get("linux_symbol_generation_supported", False))
        if not env.get("linux_symbol_generation_supported", False):
            self.btn_generate_symbols.setToolTip(
                "Requires Linux environment or WSL2 with Linux tools."
            )
        else:
            self.btn_generate_symbols.setToolTip("")
        target_os = eff_os
        symbol_root = self._symbol_dir_for_os(target_os if target_os != "macos" else "mac")
        os_symbol_count = 0
        try:
            os_symbol_count = len([n for n in os.listdir(symbol_root) if n.lower().endswith(".json")])
        except Exception:
            os_symbol_count = 0
        issues = list(health.get("issues", []))
        if health.get("vol3_ready") is False:
            icon = "❌"
            state = "error"
            issues.insert(0, "Volatility 3 not callable")
        elif os_symbol_count == 0:
            icon = "⚠️"
            state = "warning"
            issues.insert(0, f"No {target_os} symbol JSON files found")
        else:
            icon = "✅"
            state = "healthy"
        issue_text = " ; ".join(issues[:2]) if issues else "All checks passed"
        self.health_label.setText(
            f"Backend health: {icon} {state} | vol3={health.get('vol3_command') or 'n/a'} | {target_os} symbols={os_symbol_count} | {issue_text}"
        )
        self._sync_linux_ui_visibility(eff_os)

    def _sync_linux_ui_visibility(self, eff_os):
        """Linux-only controls must not appear during Windows analysis."""
        show_linux = bool(self.memory_file) and eff_os == "linux"
        self.btn_generate_symbols.setVisible(show_linux)
        if not show_linux:
            self._update_linux_symbol_banner(False)
            self.btn_load_symbol_file.setVisible(False)
        for w in getattr(self, "_linux_only_widgets", []) or []:
            w.setVisible(show_linux)

    def generate_linux_symbols(self):
        env = get_environment_compatibility()
        if env.get("is_windows") and not env.get("wsl_available"):
            QMessageBox.warning(
                self,
                "Generate Linux Symbols",
                "This feature requires Linux kernel symbol extraction tools (dwarf2json + vmlinux).\n"
                "Please enable WSL2 or switch to Linux environment to continue.",
            )
            return
        if not self.memory_file:
            QMessageBox.information(self, "Generate Linux Symbols", "Load a memory dump first.")
            return
        detected_os = detect_target_os(self.memory_file) if self.memory_file else self._target_os()
        if detected_os != "linux":
            QMessageBox.information(
                self,
                "Generate Linux Symbols",
                "Current dump is not detected as Linux. Load a Linux memory dump to use this action.",
            )
            return
        if isinstance(self._linux_sym_thread, QThread) and self._linux_sym_thread.isRunning():
            QMessageBox.information(self, "Generate Linux Symbols", "Linux symbol generation is already running.")
            return
        self._set_busy(True)
        self.status.setText("Generating Linux symbols…")
        self._linux_sym_thread = LinuxSymbolsGenerationThread(self.memory_file)
        self._linux_sym_thread.finished.connect(self._on_linux_symbols_finished)
        self._linux_sym_thread.start()

    def check_environment_compatibility(self):
        env = get_environment_compatibility()
        cfg = get_volatility_config()
        lines = [
            f"Python version: {platform.python_version()}",
            f"Host OS: {env.get('host')}",
            f"Windows host: {env.get('is_windows')}",
            f"WSL available: {env.get('wsl_available')}",
            f"WSL path: {env.get('wsl_path') or 'not found'}",
            f"vol.py path: {get_resolved_vol2_script() or cfg.get('vol2_script') or 'not set'}",
            f"dwarf2json: {env.get('dwarf2json_path') or self.dwarf2json_path_edit.text().strip() or 'not found'}",
            f"vmlinux candidates: {len(env.get('vmlinux_candidates', []))}",
            "Linux symbol generation support: "
            + ("yes" if env.get("linux_symbol_generation_supported") else "no"),
        ]
        QMessageBox.information(self, "Environment Compatibility", "\n".join(lines))

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

    def browse_vmlinux(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Linux vmlinux debug image",
            "",
            "All files (*.*)",
        )
        if path:
            self.vmlinux_path_edit.setText(path)

    def browse_dwarf2json(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select dwarf2json executable",
            "",
            "Executable (*.exe);;All files (*.*)",
        )
        if path:
            self.dwarf2json_path_edit.setText(path)

    def browse_wsl(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select WSL executable",
            "",
            "Executable (*.exe);;All files (*.*)",
        )
        if path:
            self.wsl_path_edit.setText(path)

    def _set_busy(self, busy):
        self.btn_load.setEnabled(not busy)
        for b in self._task_buttons:
            b.setEnabled(not busy)
        for w in self._config_busy_widgets:
            w.setEnabled(not busy)

    def _stop_running_analysis_thread(self, wait_ms=45000):
        t = getattr(self, "thread", None)
        if isinstance(t, QThread) and t.isRunning():
            t.requestInterruption()
            cancel_all_volatility_subprocesses()
            t.wait(wait_ms)
        self.thread = None

    def _stop_auxiliary_workers(self, wait_ms=6000):
        for name in ("_vol2_thread", "_linux_sym_thread", "_profile_thread"):
            wt = getattr(self, name, None)
            if isinstance(wt, QThread) and wt.isRunning():
                wt.requestInterruption()
                wt.wait(wait_ms)
            setattr(self, name, None)

    def _show_vol2_imageinfo_dialog(self, out):
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
        hint = QLabel(
            "Copy one line from “Suggested Profile(s)” into “Volatility 2 — memory profile”, then run analysis."
        )
        hint.setWordWrap(True)
        vbox.addWidget(hint)
        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.rejected.connect(dlg.accept)
        vbox.addWidget(bb)
        dlg.exec_()

    def _on_vol2_imageinfo_done(self, out):
        self._vol2_thread = None
        self._set_busy(False)
        self._show_vol2_imageinfo_dialog(out)
        self.status.setText("imageinfo finished — set profile field, then run Process / Full analysis.")

    def _on_vol2_imageinfo_failed(self, errmsg):
        self._vol2_thread = None
        self._set_busy(False)
        QMessageBox.warning(self, "imageinfo", f"Volatility 2 imageinfo failed:\n{errmsg}")

    def _on_linux_symbols_finished(self, result):
        self._linux_sym_thread = None
        self._set_busy(False)
        self.refresh_backend_health()
        if result.get("ok"):
            self.status.setText("Linux symbols ready ✅")
            QMessageBox.information(self, "Generate Linux Symbols", result.get("message", "Completed."))
        else:
            self.status.setText("Linux symbol generation failed")
            QMessageBox.warning(self, "Generate Linux Symbols", result.get("message", "Failed."))

    def _on_os_profile_ready(self, profile, dump_path):
        if dump_path != self._pending_profile_dump or dump_path != self.memory_file:
            return
        self._pending_profile_dump = None
        self.last_profile = profile or {"guessed_os": "windows", "confidence": "low", "scores": {}}
        guessed = self.last_profile.get("guessed_os", "windows")
        index = self.os_selector.findData(guessed)
        if index >= 0:
            self.os_selector.setCurrentIndex(index)
        self.label.setText(f"Loaded: {dump_path}")
        self.status.setText(
            f"Detected OS: {self.last_profile['guessed_os']} ({self.last_profile['confidence']})"
        )
        if guessed == "linux":
            self._update_linux_symbol_banner(True, "Linux dump detected — symbol file required")
        else:
            self._update_linux_symbol_banner(False)
        self.refresh_backend_health()

    def _on_os_profile_failed(self, errmsg, dump_path):
        if dump_path != self._pending_profile_dump or dump_path != self.memory_file:
            return
        self._pending_profile_dump = None
        self.last_profile = {"guessed_os": "windows", "confidence": "low", "scores": {}, "error": errmsg}
        self.status.setText(f"OS auto-detect failed: {errmsg} (defaulting windows)")
        self._update_linux_symbol_banner(False)
        self.refresh_backend_health()

    def pick_report_folder(self):
        default = self.report_dir or (os.path.dirname(self.memory_file) if self.memory_file else "")
        path = QFileDialog.getExistingDirectory(self, "Report output folder", default)
        if path:
            self.report_dir = path
            self.report_folder_label.setText(f"Reports folder: {path}")
            self._save_config()

    def load_file(self):
        self._sync_volatility_config_from_ui()
        if not volatility_any_backend_ok():
            self.status.setText(
                "No Volatility backend: install Vol 3 (`pip install volatility3`, vol in PATH) "
                "or choose Vol 2 + valid path to vol.py (or set VOLATILITY2_VOLPY)."
            )
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Memory Dump",
            "",
            "Memory dumps (*.raw *.mem *.dmp *.vmem);;All files (*.*)",
        )
        if file_path:
            canonical = os.path.abspath(file_path)
            self._stop_running_analysis_thread()
            self._stop_auxiliary_workers()
            cancel_all_volatility_subprocesses()
            reset_volatility_session_for_new_dump()

            self.memory_file = canonical
            self.report_dir = os.path.dirname(canonical)
            self.report_folder_label.setText(f"Reports folder: {self.report_dir}")
            self.completed_tasks.clear()
            self._pending_profile_dump = canonical
            self.label.setText(f"Loaded: {canonical}")
            self.status.setText("Detecting target OS via Volatility (background)…")
            self._update_linux_symbol_banner(False)

            self._profile_thread = OsProfileDetectionThread(canonical)
            self._profile_thread.profile_ready.connect(self._on_os_profile_ready)
            self._profile_thread.failed.connect(self._on_os_profile_failed)
            self._profile_thread.start()

    def start_task(self, task):
        if not self.memory_file:
            self.status.setText("Status: Load file first!")
            return

        self._sync_volatility_config_from_ui()
        self._stop_running_analysis_thread()

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
        self.thread.progress.connect(self.status.setText)
        self.thread.progress_percent.connect(self.progress_bar.setValue)
        self.thread.log.connect(self._append_log)
        self.thread.step_done.connect(self.show_result)
        self.thread.all_done.connect(self._analysis_finished)
        self.thread.start()

    def _analysis_finished(self):
        self._set_busy(False)
        self.progress_bar.setValue(100)
        self.status.setText("Done ✅")

    def show_result(self, task, result, extra=None):
        self.completed_tasks.add(task)

        if task == "process":
            self.process_tab.set_text_result(result)
            payload = extra or {}
            self.last_process_records = payload.get("process_records", [])
            self.last_process_tree_records = payload.get("process_tree_records", [])
            self.last_thread_records = payload.get("thread_records", [])
            self.last_dll_records = payload.get("dll_records", [])
            self.process_deep_tab.set_rows(self._process_deep_rows())

        elif task == "injection":
            self.injection_tab.set_text_result(result)
            if extra is not None:
                self.last_injection = list(extra)
            else:
                self.last_injection = []

        elif task == "network":
            self.network_tab.set_text_result(result)
            payload = extra or {}
            self.last_connection_records = payload.get("connection_records", [])

        elif task == "secrets":
            self.secrets_tab.set_text_result(result)
            if extra is not None:
                self.last_secrets = extra
            else:
                try:
                    self.last_secrets = json.loads(result)
                except Exception:
                    self.last_secrets = {"raw": result}

        elif task == "yara":
            self.yara_tab.set_text_result(result)
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

    def _process_deep_rows(self):
        rows = []
        for item in self.last_process_records[:200]:
            row = dict(item)
            row["_type"] = "process"
            rows.append(row)
        for item in self.last_process_tree_records[:200]:
            row = dict(item)
            row["_type"] = "tree"
            rows.append(row)
        for item in self.last_thread_records[:200]:
            row = dict(item)
            row["_type"] = "thread"
            rows.append(row)
        for item in self.last_dll_records[:200]:
            row = dict(item)
            row["_type"] = "module"
            rows.append(row)
        return rows

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
        detected_os = detect_target_os(self.memory_file)
        vol_meta["symbol_diagnostics"] = get_symbol_diagnostics(
            self.memory_file, detected_os
        )
        vol_meta["yara_scan_stats"] = get_yara_scan_stats()

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
