# Demo & Validation Workflow

Use this checklist during submission/demo to prove expected behavior.

## 1) Environment Check

- [ ] `python -m pip install -r requirements.txt`
- [ ] `vol` command works in terminal
- [ ] `python main.py` launches successfully

## 2) GUI Demo Path

- [ ] Load a memory dump file
- [ ] Confirm auto OS detection appears in status
- [ ] Run Process Analysis
- [ ] Run Injection Detection
- [ ] Run Network Scan
- [ ] Run Keys/Credentials Detection
- [ ] Run YARA Scan
- [ ] Export report from GUI
- [ ] Verify generated files:
  - [ ] `<dump_name>_forensics_report.json`
  - [ ] `<dump_name>_forensics_report.txt`

## 3) CLI Demo Path

- [ ] Start with `python main.py` then choose `cli`
- [ ] Enter memory dump path
- [ ] Check auto-detected OS prompt
- [ ] Run full analysis
- [ ] Export report when prompted

## 4) Expected Output Checks

- [ ] Process output includes table/raw lines
- [ ] Parsed process records count is shown
- [ ] Network output includes probable socket lines
- [ ] Parsed network records count is shown
- [ ] Secrets output is valid JSON
- [ ] YARA output displays matching rule names or "No YARA matches found."

## 5) Risk Notes

- [ ] If plugins fail for a profile, fallback plugins are attempted
- [ ] If strings plugin fails, secrets module uses direct printable-string extraction
- [ ] Large dumps may take longer (normal)
