# Project 3: Memory Forensics & Volatile Data Analysis

This project provides a practical memory forensics workflow for memory dumps using:
- Volatility3 for process/network/memory artifact extraction
- YARA for malware signature detection
- Python for glue logic and custom detection
- PyQt5 for interactive GUI analysis

## Features

1. **Memory Dump Parser (Windows/Linux/Mac)**
   - Auto-detects likely OS profile from memory artifacts.
   - Allows manual override (`windows`, `linux`, `mac`) in CLI or GUI.
   - Uses OS-specific Volatility plugins with fallback attempts.

2. **Process Extraction & Injection Analysis**
   - Process listing via `pslist` with fallback.
   - Injection indicators from `malfind` (RWX memory, VAD/injection/shellcode hints).
   - Parses table-like output into structured process records.

3. **Network Socket Recovery**
   - Connection extraction via `netscan` / `netstat` plugin families.
   - Returns likely socket lines (TCP/UDP/endpoints).
   - Parses table-like output into structured connection records.

4. **Encryption Key & Credential Detection**
   - Detects possible AES keys, passwords, tokens, private key headers.
   - Falls back to direct printable-string extraction from memory dump if plugin fails.

5. **YARA Signature Scanning**
   - Compiles `rules.yar` and scans memory dump.
   - Returns clean list of matched rule names.

6. **Structured Report Export**
   - Exports full analysis to JSON and TXT.
   - Includes metadata, parsed records, findings, and YARA results.

## Project Files

- `main.py`: CLI/GUI entrypoint
- `ui.py`: PyQt5 interface
- `volatility_runner.py`: volatility execution + plugin fallback helper
- `process_analysis.py`: process and injection analysis
- `network_analysis.py`: network analysis
- `secrets_analysis.py`: keys/credentials detection
- `yara_scan.py`: YARA scan helpers
- `os_profile.py`: automatic OS profile detection
- `parsers.py`: volatility text-to-record parsing helpers
- `report_export.py`: JSON/TXT report generation
- `rules.yar`: initial YARA rules
- `TEST_WORKFLOW.md`: demo and validation checklist

## Installation

```bash
python -m pip install -r requirements.txt
```

Also ensure Volatility3 CLI is available as `vol` in PATH.

## Run

### GUI (default)
```bash
python main.py
```
Choose `gui` when prompted.

### CLI
```bash
python main.py
```
Choose `cli`, then provide:
- memory dump path
- target OS profile (or accept auto-detected default)
- export confirmation for report files

## Notes

- Use legally obtained memory dumps only.
- Large dumps can take time depending on plugin and system resources.
- For grading/demo, follow `TEST_WORKFLOW.md`.

## Requirement Coverage Evidence

1. **Memory Dump Parser (Windows/Linux/Mac)**
   - OS profiling and parser flow: `os_profile.py`, `volatility_runner.py`
   - Report evidence fields: `os_profile`, `memory_file`

2. **Process Extraction & Analysis (threads, DLLs, code caves)**
   - Process and injection modules: `process_analysis.py`
   - Plugins used: `pslist/psscan`, `pstree`, `threads`, `dlllist` (or closest platform fallback), `malfind`
   - Report evidence fields: `process_records`, `process_tree_records`, `thread_records`, `dll_records`, `suspicious_injection`

3. **Network Socket Recovery & Connection Tracking**
   - Network module: `network_analysis.py`
   - Plugins used: `netscan` / `netstat` family
   - Report evidence fields: `connection_records`

4. **Encryption Key & Credential Detection**
   - Detection module: `secrets_analysis.py`
   - Report evidence field: `secrets_findings`

5. **YARA Signature Scanning for Known Malware**
   - YARA module: `yara_scan.py`, rules file: `rules.yar`
   - Report evidence field: `yara_matches`
