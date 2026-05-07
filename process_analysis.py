from volatility_runner import run_first_available
from parsers import parse_volatility_table
from collections import OrderedDict
import re


PROCESS_PLUGIN = {
    "windows": ["windows.pslist", "windows.psscan"],
    "linux": ["linux.pslist", "linux.psscan"],
    "mac": ["mac.pslist", "mac.pstree"],
}

PROCESS_TREE_PLUGIN = {
    "windows": ["windows.pstree"],
    "linux": ["linux.pstree", "linux.pslist"],
    "mac": ["mac.pstree", "mac.pslist"],
}

THREADS_PLUGIN = {
    "windows": ["windows.threads"],
    "linux": ["linux.pslist"],
    "mac": ["mac.pslist"],
}

DLLS_PLUGIN = {
    "windows": ["windows.dlllist"],
    "linux": ["linux.elfs", "linux.lsof"],
    "mac": ["mac.lsmod", "mac.list_files"],
}

INJECTION_PLUGIN = {
    "windows": ["windows.malfind"],
    "linux": ["linux.malfind"],
    "mac": ["mac.malfind"],
}


def get_processes(memory_file, os_type="windows"):
    plugins = PROCESS_PLUGIN.get(os_type.lower(), PROCESS_PLUGIN["windows"])
    return run_first_available(plugins, memory_file, os_type=os_type.lower())


def _extract_pid_process_patterns(output):
    """Extract PID/process hints from free-form malfind output."""
    extracted = []
    pid_patterns = [
        re.compile(r"\bPID\s*[:=]\s*(\d+)\b", re.IGNORECASE),
        re.compile(r"\bPid\s+(\d+)\b", re.IGNORECASE),
    ]
    process_patterns = [
        re.compile(r"\bProcess\s*[:=]\s*([^\r\n|]+)", re.IGNORECASE),
        re.compile(r"\bImageFileName\s*[:=]\s*([^\r\n|]+)", re.IGNORECASE),
    ]

    current_pid = ""
    current_proc = ""
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        for pat in pid_patterns:
            m = pat.search(stripped)
            if m:
                current_pid = m.group(1).strip()
                break

        for pat in process_patterns:
            m = pat.search(stripped)
            if m:
                current_proc = m.group(1).strip()
                break

        if current_pid or current_proc:
            parts = []
            if current_pid:
                parts.append(f"PID {current_pid}")
            if current_proc:
                parts.append(f"Process {current_proc}")
            extracted.append(" | ".join(parts))

    return extracted


def detect_injection_details(memory_file, os_type="windows"):
    plugins = INJECTION_PLUGIN.get(os_type.lower(), INJECTION_PLUGIN["windows"])
    output = run_first_available(plugins, memory_file, os_type=os_type.lower())
    if (
        output.startswith("[volatility error]")
        or output.startswith("[volatility warning]")
        or output.startswith("[runner error]")
    ):
        # Return the execution issue so CLI/GUI does not show a false "No injection detected".
        return {
            "summary": [output],
            "raw_output": output,
            "entities": [],
        }

    # Prefer structured parsing when plugin returns table output.
    parsed_rows = parse_volatility_table(output, min_columns=4)
    structured_hits = []
    for row in parsed_rows:
        lowered = {str(k).lower(): str(v) for k, v in row.items()}
        pid = lowered.get("pid", "").strip()
        proc = lowered.get("process", "").strip()
        protection = lowered.get("protection", "").strip()
        tag = lowered.get("tag", "").strip()

        # malfind rows are suspicious by design; prioritize rows with execution + write protection.
        prot_lower = protection.lower()
        is_rwx = "execute" in prot_lower and "write" in prot_lower
        if is_rwx or protection or tag:
            msg_parts = []
            if pid:
                msg_parts.append(f"PID {pid}")
            if proc:
                msg_parts.append(f"Process {proc}")
            if tag:
                msg_parts.append(f"Tag {tag}")
            if protection:
                msg_parts.append(f"Protection {protection}")
            if msg_parts:
                structured_hits.append(" | ".join(msg_parts))

    pattern_entities = _extract_pid_process_patterns(output)

    if structured_hits:
        suspicious = structured_hits
    else:
        suspicious = []
        all_candidate_lines = []
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            all_candidate_lines.append(stripped)
            if (
                "PAGE_EXECUTE_READWRITE" in stripped
                or "injection" in stripped.lower()
                or "shellcode" in stripped.lower()
                or "vad" in stripped.lower()
            ):
                suspicious.append(stripped)

        # Fallback: malfind output itself is suspicious by nature; if keyword filters miss,
        # keep meaningful plugin rows instead of returning empty.
        if not suspicious:
            ignored_prefixes = ("Volatility", "Progress:")
            for line in all_candidate_lines:
                if line.startswith(ignored_prefixes):
                    continue
                if set(line) == {"-"}:
                    continue
                if line.lower().startswith("pid") and "process" in line.lower():
                    continue
                suspicious.append(line)

    # Keep output readable: collapse repeated identical findings with count.
    counts = OrderedDict()
    for item in suspicious:
        counts[item] = counts.get(item, 0) + 1

    summarized = []
    for item, count in counts.items():
        if count > 1:
            summarized.append(f"{item} (x{count})")
        else:
            summarized.append(item)

    return {
        "summary": summarized,
        "raw_output": output,
        "entities": pattern_entities,
    }


def detect_injection(memory_file, os_type="windows"):
    details = detect_injection_details(memory_file, os_type=os_type)
    return details.get("summary", [])


def get_process_records(memory_file, os_type="windows"):
    output = get_processes(memory_file, os_type=os_type)
    if output.startswith("[volatility error]") or output.startswith("[runner error]"):
        return []
    return parse_volatility_table(output, min_columns=3)


def get_process_tree(memory_file, os_type="windows"):
    plugins = PROCESS_TREE_PLUGIN.get(os_type.lower(), PROCESS_TREE_PLUGIN["windows"])
    return run_first_available(plugins, memory_file, os_type=os_type.lower())


def get_process_tree_records(memory_file, os_type="windows"):
    output = get_process_tree(memory_file, os_type=os_type)
    if output.startswith("[volatility error]") or output.startswith("[runner error]"):
        return []
    return parse_volatility_table(output, min_columns=3)


def get_thread_records(memory_file, os_type="windows"):
    plugins = THREADS_PLUGIN.get(os_type.lower(), THREADS_PLUGIN["windows"])
    output = run_first_available(plugins, memory_file, os_type=os_type.lower())
    if output.startswith("[volatility error]") or output.startswith("[runner error]"):
        return []
    return parse_volatility_table(output, min_columns=3)


def get_dll_records(memory_file, os_type="windows"):
    plugins = DLLS_PLUGIN.get(os_type.lower(), DLLS_PLUGIN["windows"])
    output = run_first_available(plugins, memory_file, os_type=os_type.lower())
    if output.startswith("[volatility error]") or output.startswith("[runner error]"):
        return []
    return parse_volatility_table(output, min_columns=3)