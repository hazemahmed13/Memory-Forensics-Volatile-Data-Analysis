import json
import os
import sys

from os_profile import detect_os_profile
from network_analysis import get_connections
from network_analysis import get_connection_records
from process_analysis import (
    detect_injection,
    get_dll_records,
    get_process_records,
    get_process_tree_records,
    get_processes,
    get_thread_records,
)
from report_export import build_report, export_report_json, export_report_txt, export_report_html
from secrets_analysis import detect_keys_and_credentials
from volatility_runner import (
    get_symbol_diagnostics,
    get_resolved_vol2_script,
    get_volatility_config,
    set_volatility_config,
    volatility_any_backend_ok,
    volatility_engine_status,
)
from yara_scan import format_yara_matches, scan_memory
from forensics_logging import setup_forensics_logging


def run_cli():
    setup_forensics_logging()

    eng = input("Volatility engine [3/2] (default 3): ").strip().lower() or "3"
    vol2_profile = ""
    vol2_script = ""
    vol2_python = ""
    vol3_symbol_dirs = ""
    if eng in ("2", "vol2", "volatility2"):
        vol2_script = input("Path to Volatility 2 vol.py: ").strip()
        vol2_profile = input(
            "Vol2 memory profile (e.g. Win7SP1x64; leave empty for imageinfo-only / OS probe): "
        ).strip()
        vol2_python = input(
            "Path to Python 2.7 python.exe for vol.py (required for official Vol2; or leave empty if VOLATILITY2_PYTHON is set): "
        ).strip()
    else:
        vol3_symbol_dirs = input(
            "Volatility 3 symbol dirs (optional; sep by ';' or ','; or use VOLATILITY_SYMBOL_DIRS): "
        ).strip()

    set_volatility_config(
        engine=eng,
        vol2_profile=vol2_profile,
        vol2_script=vol2_script,
        vol2_python=vol2_python,
        vol3_symbol_dirs=vol3_symbol_dirs,
    )

    if not volatility_any_backend_ok():
        print(
            "No Volatility backend found. Install Volatility 3 (vol in PATH), "
            "or for Vol 2 provide a valid path to vol.py / set VOLATILITY2_VOLPY."
        )
        return

    memory_file = input("Enter memory dump path: ").strip()
    if not os.path.exists(memory_file):
        print("Invalid memory dump path.")
        return

    profile = detect_os_profile(memory_file)
    guessed = profile["guessed_os"]
    print(f"[+] Auto-detected OS profile: {guessed} (confidence: {profile['confidence']})")

    os_type = guessed
    print(f"[+] Analysis profile selected automatically: {os_type}")

    print("\n[+] Processes:")
    process_raw = get_processes(memory_file, os_type=os_type)
    print(process_raw)
    process_records = get_process_records(memory_file, os_type=os_type)
    print(f"[+] Parsed process records: {len(process_records)}")
    process_tree_records = get_process_tree_records(memory_file, os_type=os_type)
    print(f"[+] Parsed process tree records: {len(process_tree_records)}")
    thread_records = get_thread_records(memory_file, os_type=os_type)
    print(f"[+] Parsed thread records: {len(thread_records)}")
    dll_records = get_dll_records(memory_file, os_type=os_type)
    print(f"[+] Parsed DLL/module records: {len(dll_records)}")

    print("\n[+] Suspicious Injection:")
    suspicious = detect_injection(memory_file, os_type=os_type)
    if suspicious:
        for item in suspicious:
            print(item)
    else:
        print("No suspicious injection patterns found.")

    print("\n[+] Network Connections:")
    connections = get_connections(memory_file, os_type=os_type)
    for conn in connections[:20]:
        print(conn)
    connection_records = get_connection_records(memory_file, os_type=os_type)
    print(f"[+] Parsed connection records: {len(connection_records)}")

    print("\n[+] Encryption Keys / Credentials:")
    findings = detect_keys_and_credentials(memory_file, os_type=os_type)
    print(json.dumps(findings, indent=2))

    print("\n[+] YARA Scan:")
    matches = scan_memory(memory_file)
    print(format_yara_matches(matches))

    save_report = input("Export report files? [y/n] (default y): ").strip().lower() or "y"
    if save_report == "y":
        vol_meta = dict(get_volatility_config())
        rp = get_resolved_vol2_script()
        if rp:
            vol_meta["vol2_script_resolved"] = rp
        vol_meta["volatility3_status"] = volatility_engine_status()
        vol_meta["symbol_diagnostics"] = get_symbol_diagnostics(memory_file, os_type)

        report = build_report(
            memory_file=memory_file,
            os_profile=profile,
            process_records=process_records,
            process_tree_records=process_tree_records,
            thread_records=thread_records,
            dll_records=dll_records,
            suspicious_injection=suspicious,
            connection_records=connection_records,
            secrets=findings,
            yara_matches=matches,
            volatility_meta=vol_meta,
        )
        base_name = os.path.splitext(os.path.basename(memory_file))[0]
        out_dir = os.path.dirname(os.path.abspath(memory_file)) or "."
        os.makedirs(out_dir, exist_ok=True)
        out_json = os.path.join(out_dir, f"{base_name}_forensics_report.json")
        out_txt = os.path.join(out_dir, f"{base_name}_forensics_report.txt")
        out_html = os.path.join(out_dir, f"{base_name}_forensics_report.html")
        export_report_json(report, out_json)
        export_report_txt(report, out_txt)
        export_report_html(report, out_html)
        print(f"[+] Report exported: {out_json}")
        print(f"[+] Report exported: {out_txt}")
        print(f"[+] Report exported: {out_html}")


def run_gui():
    from PyQt5.QtCore import Qt
    from PyQt5.QtWidgets import QApplication
    from ui import MemoryForensicsApp

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MemoryForensicsApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    mode = input("Run mode [cli/gui] (default gui): ").strip().lower() or "gui"
    if mode == "cli":
        run_cli()
    else:
        run_gui()
