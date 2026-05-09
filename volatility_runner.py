import os
import shutil
import re
import subprocess
import sys
import json
import platform
import threading
from collections import OrderedDict
from functools import lru_cache

from forensics_logging import log_volatility

# --- Global runtime config (GUI/CLI set before analysis) ---
_ENGINE = "3"  # "3" or "2"
_VOL2_PROFILE = ""
_VOL2_SCRIPT = ""  # path to vol.py (Volatility 2)
_VOL2_PYTHON = ""  # path to python.exe for Vol2 (usually Python 2.7)
_VOL3_SYMBOL_DIRS = ""
_LAST_LINUX_RECOVERY = {}
_RUNTIME_LOG_SINK = None

# Bound concurrent Volatility subprocesses globally (heavy RAM / I/O contention).
_VOL_SUBPROC_SEM = threading.BoundedSemaphore(max(1, min(4, int(os.environ.get("VOLATILITY_MAX_CONCURRENT", "4")))))
_ACTIVE_PROC_LOCK = threading.Lock()
_ACTIVE_PROCESSES = []
LINUX_VALIDATION_LOCK = threading.Lock()

# Optional fine-grained progress (0–100) per subprocess; WorkerThread sets spans per step.
_VOL_PROGRESS_LO = 0
_VOL_PROGRESS_HI = 100
_STREAM_PROG_LOCK = threading.Lock()
_STREAM_LINE_COUNT = 0

# LRU-ish session cache: same plugin + dump + engine config ⇒ skip re-invocation within one session.
_OUTPUT_CACHE_ORDERED = OrderedDict()
_OUTPUT_CACHE_LIMIT = max(64, min(2048, int(os.environ.get("VOLATILITY_CACHE_MAX", "512"))))


def cancel_all_volatility_subprocesses():
    """Terminate Popen-backed Volatility children (called when user aborts analysis / loads new dump)."""
    with _ACTIVE_PROC_LOCK:
        snapshots = list(_ACTIVE_PROCESSES)
    for p in snapshots:
        try:
            if p.poll() is None:
                p.terminate()
        except Exception:
            pass


def clear_volatility_output_cache():
    """Invalidate Volatility stdout cache (e.g. when loading another memory dump)."""
    global _OUTPUT_CACHE_ORDERED
    _OUTPUT_CACHE_ORDERED.clear()


def clear_preflight_requirements_cache():
    """Prevent stale LRU preflight keyed to old dump paths."""
    _preflight_requirements.cache_clear()


def set_volatility_progress_span(lo=0, hi=100):
    """Map streaming line-count progress callbacks into integer percent bucket [lo, hi]."""
    global _VOL_PROGRESS_LO, _VOL_PROGRESS_HI
    _VOL_PROGRESS_LO = max(0, min(99, int(lo)))
    _VOL_PROGRESS_HI = max(_VOL_PROGRESS_LO + 1, min(100, int(hi)))


def _emit_stream_progress_increment():
    global _STREAM_LINE_COUNT
    with _STREAM_PROG_LOCK:
        _STREAM_LINE_COUNT += 1
        ln = _STREAM_LINE_COUNT
    if _RUNTIME_PROGRESS_THROTTLE and ln % _RUNTIME_PROGRESS_THROTTLE != 0:
        return
    span = max(1, _VOL_PROGRESS_HI - _VOL_PROGRESS_LO)
    frac = min(1.0, ln / 320.0)
    pct = int(_VOL_PROGRESS_LO + span * frac)
    pct = max(_VOL_PROGRESS_LO, min(_VOL_PROGRESS_HI, pct))
    if _VOL_PROGRESS_CALLBACK:
        try:
            _VOL_PROGRESS_CALLBACK(pct)
        except Exception:
            pass


_RUNTIME_PROGRESS_THROTTLE = max(5, min(80, int(os.environ.get("VOLATILITY_PROGRESS_LOG_EVERY_LINES", "15"))))
_VOL_PROGRESS_CALLBACK = None


def set_volatility_progress_callback(cb):
    """Thread-safe-ish: emit must be queued (e.g. PyQt signal.emit). Callable taking int percent 0–100."""
    global _VOL_PROGRESS_CALLBACK
    _VOL_PROGRESS_CALLBACK = cb if callable(cb) else None


def _dump_mtime_sig(path):
    try:
        st = os.stat(path)
        return (path, getattr(st, "st_mtime_ns", int(st.st_mtime * 10**9)), st.st_size)
    except Exception:
        return (path, 0, 0)


def _output_cache_key(memory_file, normalized_plugin, extra_args, os_type):
    cfg = get_volatility_config()
    ex = tuple(extra_args or ())
    sig = (
        _dump_mtime_sig(memory_file),
        cfg["engine"],
        cfg["vol2_profile"],
        cfg["vol2_script"],
        cfg["vol2_python"],
        cfg["vol3_symbol_dirs"],
    )
    return (normalized_plugin.lower(), sig, ex, (os_type or "").lower())


def _cache_get_output(key):
    if key not in _OUTPUT_CACHE_ORDERED:
        return None
    _OUTPUT_CACHE_ORDERED.move_to_end(key)
    return _OUTPUT_CACHE_ORDERED[key]


def _cache_put_output(key, value):
    if key in _OUTPUT_CACHE_ORDERED:
        del _OUTPUT_CACHE_ORDERED[key]
    _OUTPUT_CACHE_ORDERED[key] = value
    while len(_OUTPUT_CACHE_ORDERED) > _OUTPUT_CACHE_LIMIT:
        _OUTPUT_CACHE_ORDERED.popitem(last=False)

# Volatility 2 plugins that typically run without --profile
_VOL2_PLUGINS_NO_PROFILE = frozenset({"imageinfo", "kdbgscan", "kpcrscan"})

# Map Volatility 3 dotted plugin names -> Volatility 2 CLI plugin names
_V3_TO_V2 = {
    "windows.pslist.pslist": "pslist",
    "windows.psscan.psscan": "psscan",
    "windows.pstree.pstree": "pstree",
    "windows.threads.threads": "threads",
    "windows.dlllist.dlllist": "dlllist",
    "windows.malfind.malfind": "malfind",
    "windows.netscan.netscan": "netscan",
    "windows.netstat.netstat": "netscan",
    "windows.strings.strings": "strings",
    "windows.info.info": "imageinfo",
    "windows.banner.banner": "imageinfo",
    "windows.pslist": "pslist",
    "windows.psscan": "psscan",
    "windows.pstree": "pstree",
    "windows.threads": "threads",
    "windows.dlllist": "dlllist",
    "windows.malfind": "malfind",
    "windows.netscan": "netscan",
    "windows.strings": "strings",
    "windows.info": "imageinfo",
    "windows.banner": "imageinfo",
    "linux.pslist": "linux_pslist",
    "linux.psscan": "linux_pslist",
    "linux.pstree": "linux_pslist",
    "linux.elfs": "linux_lsof",
    "linux.lsof": "linux_lsof",
    "linux.malfind": "linux_malfind",
    "linux.netstat": "linux_netstat",
    "linux.sockstat": "linux_netstat",
    "linux.bash": "linux_bash",
    "linux.envars": "linux_bash",
    "linux.banner": "linux_banner",
    "linux.banners": "linux_banner",
    "mac.pslist": "mac_pslist",
    "mac.pstree": "mac_pslist",
    "mac.malfind": "mac_malfind",
    "mac.netstat": "mac_netstat",
    "mac.ifconfig": "mac_ifconfig",
    "mac.bash": "mac_bash",
    "mac.banner": "mac_version",
    "mac.lsmod": "mac_lsmod",
    "mac.list_files": "mac_list_files",
}

# Canonical Volatility 3 plugin names per family.
_V3_CANONICAL = {
    "windows.pslist": "windows.pslist.PsList",
    "windows.psscan": "windows.psscan.PsScan",
    "windows.pstree": "windows.pstree.PsTree",
    "windows.threads": "windows.threads.Threads",
    "windows.dlllist": "windows.dlllist.DllList",
    "windows.malfind": "windows.malfind.Malfind",
    "windows.netscan": "windows.netscan.NetScan",
    "windows.netstat": "windows.netstat.NetStat",
    "windows.strings": "windows.strings.Strings",
    "windows.info": "windows.info.Info",
    "linux.pslist": "linux.pslist.PsList",
    "linux.psscan": "linux.psscan.PsScan",
    "linux.pstree": "linux.pstree.PsTree",
    "linux.netstat": "linux.sockstat.Sockstat",
    "linux.lsof": "linux.lsof.Lsof",
    "linux.elfs": "linux.elfs.Elfs",
    "linux.malfind": "linux.malfind.Malfind",
    "linux.bash": "linux.bash.Bash",
    "linux.envars": "linux.envars.Envars",
    "linux.banners": "banners.Banners",
    "linux.banner": "banners.Banners",
    "mac.pslist": "mac.pslist.PsList",
    "mac.pstree": "mac.pstree.PsTree",
    "mac.malfind": "mac.malfind.Malfind",
    "mac.netstat": "mac.netstat.Netstat",
    "mac.ifconfig": "mac.ifconfig.Ifconfig",
    "mac.bash": "mac.bash.Bash",
    "mac.lsmod": "mac.lsmod.Lsmod",
    "mac.list_files": "mac.list_files.List_Files",
}


def set_volatility_config(
    engine="3", vol2_profile="", vol2_script="", vol2_python="", vol3_symbol_dirs=""
):
    """engine: '3' or '2'. For Vol2, set vol2_script (path to vol.py) and usually vol2_profile."""
    global _ENGINE, _VOL2_PROFILE, _VOL2_SCRIPT, _VOL2_PYTHON, _VOL3_SYMBOL_DIRS
    _ENGINE = "2" if str(engine).strip() in ("2", "vol2", "volatility2") else "3"
    _VOL2_PROFILE = (vol2_profile or "").strip()
    _VOL2_SCRIPT = (vol2_script or "").strip()
    _VOL2_PYTHON = (vol2_python or "").strip()
    _VOL3_SYMBOL_DIRS = (vol3_symbol_dirs or "").strip()


def get_volatility_config():
    return {
        "engine": _ENGINE,
        "vol2_profile": _VOL2_PROFILE,
        "vol2_script": _VOL2_SCRIPT,
        "vol2_python": _VOL2_PYTHON,
        "vol3_symbol_dirs": _VOL3_SYMBOL_DIRS,
    }


def set_runtime_log_sink(sink):
    """Set callable sink(line: str) for live command output."""
    global _RUNTIME_LOG_SINK
    _RUNTIME_LOG_SINK = sink if callable(sink) else None


def _emit_runtime_log(message: str):
    if not message:
        return
    if _RUNTIME_LOG_SINK:
        try:
            _RUNTIME_LOG_SINK(str(message))
        except Exception:
            pass


def _run_streaming_command(cmd, label):
    global _STREAM_LINE_COUNT
    stdout_lines = []
    stderr_lines = []
    with _STREAM_PROG_LOCK:
        _STREAM_LINE_COUNT = 0
    _emit_runtime_log(f"$ {' '.join(cmd)}")
    _VOL_SUBPROC_SEM.acquire()
    process = None
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
        with _ACTIVE_PROC_LOCK:
            _ACTIVE_PROCESSES.append(process)

        def reader(stream, bucket, prefix):
            for line in iter(stream.readline, ""):
                clean = line.rstrip("\n")
                bucket.append(clean)
                _emit_runtime_log(f"[{label}][{prefix}] {clean}")
                _emit_stream_progress_increment()
            stream.close()

        t_out = threading.Thread(target=reader, args=(process.stdout, stdout_lines, "stdout"), daemon=True)
        t_err = threading.Thread(target=reader, args=(process.stderr, stderr_lines, "stderr"), daemon=True)
        t_out.start()
        t_err.start()
        process.wait()
        t_out.join()
        t_err.join()
        rc = process.returncode
    finally:
        if process is not None:
            with _ACTIVE_PROC_LOCK:
                try:
                    _ACTIVE_PROCESSES.remove(process)
                except ValueError:
                    pass
        _VOL_SUBPROC_SEM.release()
    return rc, "\n".join(stdout_lines).strip(), "\n".join(stderr_lines).strip()


def _vol3_command():
    vol_in_path = shutil.which("vol")
    if vol_in_path:
        return [vol_in_path]
    scripts_dir = os.path.join(os.path.dirname(sys.executable), "Scripts")
    vol_exe = os.path.join(scripts_dir, "vol.exe")
    if os.path.exists(vol_exe):
        return [vol_exe]
    return None


def _resolve_interpreter_path(user_path: str):
    """Return absolute path to interpreter if file exists or name is on PATH."""
    user_path = (user_path or "").strip()
    if not user_path:
        return None
    if os.path.isfile(user_path):
        return os.path.abspath(user_path)
    w = shutil.which(user_path)
    return os.path.abspath(w) if w else None


def _vol2_python_executable():
    """Interpreter used to run vol.py. Official Volatility 2 needs Python 2.7, not Python 3."""
    for candidate in (
        get_volatility_config().get("vol2_python", ""),
        os.environ.get("VOLATILITY2_PYTHON", ""),
    ):
        resolved = _resolve_interpreter_path(candidate)
        if resolved:
            return resolved
    return sys.executable


def _resolve_vol2_script(explicit_path=""):
    """Return absolute path to vol.py if found, else None."""
    candidates = []
    if explicit_path:
        candidates.append(explicit_path)
    cfg_script = get_volatility_config().get("vol2_script", "").strip()
    if cfg_script:
        candidates.append(cfg_script)
    envp = os.environ.get("VOLATILITY2_VOLPY", "").strip()
    if envp:
        candidates.append(envp)
    for c in candidates:
        ap = os.path.abspath(os.path.expanduser(c))
        if os.path.isfile(ap):
            return ap
    return None


def volatility_engine_status():
    """Volatility 3 CLI availability."""
    if _vol3_command():
        return "vol"
    try:
        import volatility3  # noqa: F401
        scripts_dir = os.path.join(os.path.dirname(sys.executable), "Scripts")
        if os.path.exists(os.path.join(scripts_dir, "vol.exe")):
            return "python-module"
    except Exception:
        pass
    return "missing"


def volatility2_script_status(vol2_script_override=""):
    """Return 'ok' if vol.py is resolved, else 'missing'."""
    return "ok" if _resolve_vol2_script(vol2_script_override) else "missing"


def get_resolved_vol2_script():
    """Absolute path to vol.py if configured, else None."""
    return _resolve_vol2_script("")


def volatility_any_backend_ok(vol2_script_override=""):
    """True if either Vol3 is usable or a Vol2 vol.py path is configured."""
    if volatility_engine_status() != "missing":
        return True
    return volatility2_script_status(vol2_script_override) == "ok"


def _map_v3_plugin_to_v2(plugin: str) -> str:
    key = plugin.strip().lower()
    if key in _V3_TO_V2:
        return _V3_TO_V2[key]
    if "." in key:
        family, name = key.split(".", 1)
        simple_name = name.split(".")[0]
        if family == "windows":
            return simple_name
        if family == "linux":
            return f"linux_{simple_name}"
        if family == "mac":
            return f"mac_{simple_name}"
    return key


def run_volatility(plugin, memory_file, extra_args=None, os_type="windows"):
    """
    Run a Volatility 3-style plugin name (e.g. windows.pslist).
    When engine is 2, the name is translated to a Vol2 plugin and executed with vol.py.
    """
    extra_args = extra_args or []
    cfg = get_volatility_config()

    normalized_os = (os_type or "windows").strip().lower()
    normalized_plugin = _normalize_plugin_for_os(plugin, normalized_os)

    # Defensive preflight prevents common family/symbol/layer failures.
    preflight = _preflight_requirements(memory_file, normalized_os, normalized_plugin, cfg["engine"])
    if preflight:
        return _sanitize_user_error(preflight, normalized_os)

    cache_key = _output_cache_key(memory_file, normalized_plugin, extra_args, normalized_os)
    cached = _cache_get_output(cache_key)
    if cached is not None:
        _emit_runtime_log(f"[vol-cache hit] {normalized_plugin}")
        return cached

    if cfg["engine"] == "2":
        raw_out = _run_volatility2(normalized_plugin, memory_file, extra_args, os_type=normalized_os)
    else:
        raw_out = _run_volatility3(normalized_plugin, memory_file, extra_args)
    out = _sanitize_user_error(raw_out, normalized_os)
    _cache_put_output(cache_key, out)
    return out


def _normalize_plugin_for_os(plugin: str, os_type: str) -> str:
    """
    Keep plugin family aligned to target OS.
    If callers accidentally pass windows.* for a Linux image, route to linux.* equivalent.
    """
    p = (plugin or "").strip()
    if not p:
        return p
    lower = p.lower()
    if lower in _V3_CANONICAL:
        return _V3_CANONICAL[lower]

    if "." not in lower:
        return p

    family, rest = lower.split(".", 1)
    target = (os_type or "").strip().lower()
    if target in ("windows", "linux", "mac") and family == target:
        base_key = f"{target}.{rest.split('.')[0]}"
        if base_key in _V3_CANONICAL:
            return _V3_CANONICAL[base_key]
    return p


@lru_cache(maxsize=32)
def _preflight_requirements(memory_file: str, os_type: str, plugin: str, engine: str) -> str:
    """
    Validate plugin family and kernel/symbol prerequisites before full plugin execution.
    Returns empty string when checks pass, otherwise a user-facing error string.
    """
    if not memory_file:
        return "[runner error] No memory file provided."
    if not os.path.exists(memory_file):
        return f"[runner error] Memory file not found: {memory_file}"

    if engine == "2":
        # Volatility 2 profile requirements are handled in _run_volatility2.
        return ""

    family = plugin.split(".", 1)[0].lower() if "." in plugin else ""
    if family and family in ("windows", "linux", "mac") and family != os_type:
        return (
            "[runner error] Invalid plugin family requested for detected target OS. "
            f"Detected/selected OS is '{os_type}', but plugin was '{plugin}'."
        )

    # Volatility 3 kernel-backed plugins need a valid translation layer and symbols.
    if os_type == "linux":
        context_error = _validate_linux_context(memory_file)
        if context_error:
            return context_error
    if os_type == "windows":
        probe = _run_volatility3("windows.info.Info", memory_file, [])
        if _is_runner_error(probe):
            return (
                "[volatility error] Windows memory detected/selected, but Volatility could not build the "
                "Windows kernel context (layer_name/symbol_table_name). Ensure matching symbols are available. "
                f"Probe output: {probe}"
            )

    return ""


def _is_runner_error(output: str) -> bool:
    return (
        output.startswith("[volatility error]")
        or output.startswith("[volatility warning]")
        or output.startswith("[runner error]")
    )


def _sanitize_user_error(output: str, os_type: str) -> str:
    """
    Keep UI/CLI experience consistent by hiding backend symbol internals.
    Detailed diagnostics remain available in report metadata/logs.
    """
    if not output or not isinstance(output, str):
        return output
    low = output.lower()
    if os_type == "linux":
        if (
            "symbol directory" in low
            or "symbol_table_name" in low
            or "kernel.layer_name" in low
            or "unable to build linux kernel context" in low
            or "isf" in low
            or "vmlinux" in low
        ):
            return (
                "[volatility error] Linux analysis requires generated kernel symbols (ISF). "
                "Workflow: vmlinux -> dwarf2json -> symbols/linux/<kernel>.json. "
                "vmlinux is mandatory; analysis is blocked until kernel context can be built."
            )
    return output


def _run_volatility3(plugin, memory_file, extra_args):
    try:
        vol_cmd = _vol3_command()
        if not vol_cmd:
            return "[runner error] Volatility 3 executable not found. Install volatility3 or add `vol` to PATH."
        cmd = vol_cmd + _vol3_symbol_dir_args() + ["-f", memory_file, plugin] + list(extra_args)
        rc, stdout, stderr = _run_streaming_command(cmd, "vol3")
        if rc != 0 and stderr:
            err = stderr
            log_volatility(plugin, memory_file, f"rc={rc} stderr={err[:800]}")
            return f"[volatility error] {err}"
        output = stdout
        if not output and stderr:
            warn = stderr
            log_volatility(plugin, memory_file, f"empty stdout stderr={warn[:800]}")
            return f"[volatility warning] {warn}"

        return output
    except Exception as exc:
        log_volatility(plugin, memory_file, f"exception={exc!r}")
        return f"[runner error] {exc}"


def _vol3_symbol_dir_args():
    args = []
    for directory in _resolved_symbol_dirs():
        args.extend(["-s", directory])
    return args


def _resolved_symbol_dirs():
    configured = (get_volatility_config().get("vol3_symbol_dirs", "") or "").strip()
    env_dirs = (os.environ.get("VOLATILITY_SYMBOL_DIRS", "") or "").strip()
    raw_values = [configured, env_dirs]
    candidates = []
    for raw in raw_values:
        if not raw:
            continue
        parts = re.split(r"[;,]", raw) if (";" in raw or "," in raw) else raw.split(os.pathsep)
        for item in parts:
            d = item.strip().strip('"')
            if d:
                candidates.append(os.path.abspath(os.path.expanduser(d)))

    # Common local defaults for project-level symbol repositories.
    project_defaults = [
        os.path.abspath(os.path.join(os.getcwd(), "symbols")),
        os.path.abspath(os.path.join(os.getcwd(), "symbols", "linux")),
        os.path.abspath(os.path.join(os.getcwd(), "volatility3", "symbols")),
        os.path.abspath(os.path.join(os.getcwd(), "volatility3", "symbols", "linux")),
    ]
    for d in project_defaults:
        # Bootstrap default directories so first-time users do not fail on path existence.
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass
        candidates.append(d)

    unique = []
    seen = set()
    for d in candidates:
        key = d.lower()
        if key in seen:
            continue
        seen.add(key)
        if os.path.isdir(d):
            unique.append(d)
    return unique


def _extract_linux_kernel_version(banner_output: str) -> str:
    if not banner_output:
        return ""
    # Example: Linux version 6.19.14+kali-amd64 ...
    match = re.search(r"Linux version\s+([^\s]+)", banner_output, flags=re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _normalize_kernel_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


def _linux_symbol_match_exists(kernel_version: str, symbol_dirs):
    if not kernel_version:
        return False
    expected = _normalize_kernel_token(kernel_version)
    for symbol_dir in symbol_dirs:
        try:
            for name in os.listdir(symbol_dir):
                nlow = name.lower()
                if not (nlow.endswith(".json") or nlow.endswith(".json.xz")):
                    continue
                if expected and expected in _normalize_kernel_token(name):
                    return True
        except Exception:
            continue
    return False


def _list_symbol_jsons(symbol_dirs):
    files = []
    for symbol_dir in symbol_dirs:
        try:
            for name in os.listdir(symbol_dir):
                nlow = name.lower()
                if nlow.endswith(".json") or nlow.endswith(".json.xz"):
                    files.append(os.path.join(symbol_dir, name))
        except Exception:
            continue
    return files


def _candidate_vmlinux_paths():
    raw = (os.environ.get("VOLATILITY_LINUX_VMLINUX", "") or "").strip()
    candidates = []
    if raw:
        parts = re.split(r"[;,]", raw) if (";" in raw or "," in raw) else raw.split(os.pathsep)
        for item in parts:
            p = item.strip().strip('"')
            if p:
                candidates.append(os.path.abspath(os.path.expanduser(p)))

    candidates.extend(
        [
            os.path.abspath(os.path.join(os.getcwd(), "vmlinux")),
            os.path.abspath(os.path.join(os.getcwd(), "symbols", "vmlinux")),
            os.path.abspath(os.path.join(os.getcwd(), "symbols", "linux", "vmlinux")),
        ]
    )
    return [p for p in candidates if os.path.isfile(p)]


def _is_windows_host() -> bool:
    return platform.system().lower().startswith("win")


def _is_wsl_host() -> bool:
    try:
        text = platform.release().lower() + " " + platform.version().lower()
        return "microsoft" in text or "wsl" in text
    except Exception:
        return False


def _has_wsl_bridge() -> bool:
    if not _is_windows_host():
        return False
    custom = (os.environ.get("VOLATILITY_WSL_PATH", "") or "").strip().strip('"')
    if custom and os.path.isfile(custom):
        return True
    return bool(shutil.which("wsl") or shutil.which("wsl.exe"))


def _resolve_wsl_executable() -> str:
    custom = (os.environ.get("VOLATILITY_WSL_PATH", "") or "").strip().strip('"')
    if custom and os.path.isfile(custom):
        return os.path.abspath(custom)
    return shutil.which("wsl.exe") or shutil.which("wsl") or ""


def _win_to_wsl_path(path: str) -> str:
    if not path:
        return ""
    norm = os.path.abspath(path).replace("\\", "/")
    if len(norm) >= 2 and norm[1] == ":":
        drive = norm[0].lower()
        rest = norm[2:]
        if rest.startswith("/"):
            rest = rest[1:]
        return f"/mnt/{drive}/{rest}"
    return norm


def _resolve_dwarf2json_path() -> str:
    """
    Resolve dwarf2json from env, PATH, and common local tool locations.
    """
    env_path = (os.environ.get("VOLATILITY_DWARF2JSON", "") or "").strip()
    if env_path:
        ep = os.path.abspath(os.path.expanduser(env_path.strip('"')))
        if os.path.isfile(ep):
            return ep

    path_hit = shutil.which("dwarf2json") or shutil.which("dwarf2json.exe")
    if path_hit:
        return os.path.abspath(path_hit)

    local_candidates = [
        os.path.abspath(os.path.join(os.getcwd(), "dwarf2json")),
        os.path.abspath(os.path.join(os.getcwd(), "dwarf2json.exe")),
        os.path.abspath(os.path.join(os.getcwd(), "tools", "dwarf2json")),
        os.path.abspath(os.path.join(os.getcwd(), "tools", "dwarf2json.exe")),
        os.path.abspath(os.path.join(os.getcwd(), "bin", "dwarf2json")),
        os.path.abspath(os.path.join(os.getcwd(), "bin", "dwarf2json.exe")),
    ]
    for p in local_candidates:
        if os.path.isfile(p):
            return p
    return ""


def _vmlinux_matches_kernel(vmlinux_path: str, kernel_version: str) -> bool:
    """
    Strict version matching guard: vmlinux filename/path must contain the
    normalized dump kernel token.
    """
    if not vmlinux_path or not kernel_version:
        return False
    kernel_token = _normalize_kernel_token(kernel_version)
    path_token = _normalize_kernel_token(vmlinux_path)
    return bool(kernel_token and kernel_token in path_token)


def _validate_isf_json(isf_path: str, kernel_version: str):
    if not isf_path or not os.path.isfile(isf_path):
        return False, "isf_file_missing"
    try:
        if os.path.getsize(isf_path) <= 0:
            return False, "isf_file_empty"
    except Exception:
        return False, "isf_stat_failed"

    try:
        with open(isf_path, "r", encoding="utf-8") as fp:
            data = json.load(fp)
    except Exception:
        return False, "isf_json_invalid"

    if not isinstance(data, dict):
        return False, "isf_json_not_object"

    # Basic ISF structural sanity for Volatility symbols.
    required_any = ("symbols", "base_types", "user_types", "enums")
    if not any(k in data for k in required_any):
        return False, "isf_missing_symbol_structure"

    if kernel_version:
        token = _normalize_kernel_token(kernel_version)
        data_hint = _normalize_kernel_token(
            " ".join(str(data.get(k, "")) for k in ("metadata", "banner", "linux_banner", "name"))
        )
        file_hint = _normalize_kernel_token(os.path.basename(isf_path))
        if token and token not in file_hint and token not in data_hint:
            return False, "isf_kernel_mismatch"

    return True, ""


def _auto_generate_linux_isf(kernel_version: str, symbol_dirs):
    recovery = {
        "attempted": True,
        "success": False,
        "dwarf2json_path": "",
        "vmlinux_candidates": [],
        "vmlinux_used": "",
        "output_json": "",
        "stderr_excerpt": "",
        "reason": "",
    }

    dwarf = _resolve_dwarf2json_path()
    if not dwarf:
        recovery["reason"] = "dwarf2json_not_found"
        return recovery
    recovery["dwarf2json_path"] = dwarf

    vmlinux_paths = _candidate_vmlinux_paths()
    recovery["vmlinux_candidates"] = list(vmlinux_paths)
    if not vmlinux_paths:
        recovery["reason"] = "vmlinux_required_for_isf_generation"
        return recovery

    target_dir = None
    for d in symbol_dirs:
        low = d.lower()
        if low.endswith(os.path.join("symbols", "linux").lower()) or low.endswith("linux"):
            target_dir = d
            break
    if not target_dir and symbol_dirs:
        target_dir = symbol_dirs[0]
    if not target_dir:
        recovery["reason"] = "symbol_dir_not_available"
        return recovery

    os.makedirs(target_dir, exist_ok=True)
    safe_tag = re.sub(r"[^A-Za-z0-9._+-]+", "_", kernel_version or "linux-kernel")
    out_path = os.path.join(target_dir, f"{safe_tag}.json")
    if os.path.exists(out_path):
        ok, reason = _validate_isf_json(out_path, kernel_version)
        recovery["success"] = ok
        recovery["output_json"] = out_path if ok else ""
        recovery["reason"] = "already_exists" if ok else reason
        return recovery

    for vm in vmlinux_paths:
        try:
            if kernel_version and not _vmlinux_matches_kernel(vm, kernel_version):
                recovery["stderr_excerpt"] = (
                    f"vmlinux version mismatch: dump kernel={kernel_version}, path={vm}"
                )[:1200]
                recovery["reason"] = "vmlinux_kernel_mismatch"
                continue
            recovery["vmlinux_used"] = vm
            result = subprocess.run([dwarf, "linux", "--elf", vm], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                with open(out_path, "w", encoding="utf-8") as fp:
                    fp.write(result.stdout)
                ok, reason = _validate_isf_json(out_path, kernel_version)
                recovery["success"] = ok
                recovery["output_json"] = out_path if ok else ""
                recovery["reason"] = "generated" if ok else reason
                if ok:
                    return recovery
                recovery["stderr_excerpt"] = (
                    f"generated ISF validation failed: {reason}"
                )[:1200]
                try:
                    os.remove(out_path)
                except Exception:
                    pass
            recovery["stderr_excerpt"] = (result.stderr or "").strip()[:1200]
            log_volatility("linux.isf.autogen", vm, f"rc={result.returncode} stderr={recovery['stderr_excerpt']}")
        except Exception:
            continue

    recovery["reason"] = recovery["reason"] or "generation_failed"
    return recovery


def _validate_linux_context(memory_file: str) -> str:
    """
    Build Linux context prerequisites before executing Linux plugins:
    - acquire banner and kernel version
    - validate symbol repository presence and likely symbol match
    - verify kernel layer/symbol table creation using linux.pslist
    """
    with LINUX_VALIDATION_LOCK:
        return _validate_linux_context_locked(memory_file)


def _validate_linux_context_locked(memory_file: str) -> str:
    banner_probe = _run_volatility3("banners.Banners", memory_file, [])
    kernel_version = _extract_linux_kernel_version(banner_probe)
    symbol_dirs = _resolved_symbol_dirs()

    if not symbol_dirs:
        return (
            "[volatility error] Linux memory detected, but no Volatility symbol directory is configured. "
            "Set VOLATILITY_SYMBOL_DIRS or provide symbols in ./symbols (or ./symbols/linux), then retry. "
            "Required workflow: generate Linux ISF JSON using dwarf2json from unstripped vmlinux and place it "
            "in a configured symbols directory."
        )

    symbol_jsons = _list_symbol_jsons(symbol_dirs)
    recovery = {"attempted": False, "success": False, "reason": "not_needed"}
    autogen_attempted = False

    if not symbol_jsons:
        recovery = _auto_generate_linux_isf(kernel_version, symbol_dirs)
        autogen_attempted = True
        if recovery.get("success"):
            symbol_jsons = _list_symbol_jsons(symbol_dirs)
    _LAST_LINUX_RECOVERY[memory_file] = recovery
    if not symbol_jsons:
        joined = ", ".join(symbol_dirs)
        reason = recovery.get("reason", "unknown")
        if reason == "vmlinux_required_for_isf_generation":
            return (
                "[volatility error] Linux analysis cannot continue: vmlinux required for ISF generation. "
                "ISF is not downloaded automatically. Generate symbols with: "
                "dwarf2json linux --elf <vmlinux> > symbols/linux/<kernel>.json"
            )
        return (
            "[volatility error] Linux memory detected, but no usable ISF symbols are available. "
            f"Checked directories: {joined}. "
            "ISF must be generated from matching vmlinux using dwarf2json."
        )

    no_filename_match = bool(kernel_version and not _linux_symbol_match_exists(kernel_version, symbol_dirs))
    if no_filename_match:
        if not autogen_attempted:
            recovery = _auto_generate_linux_isf(kernel_version, symbol_dirs)
            autogen_attempted = True
            _LAST_LINUX_RECOVERY[memory_file] = recovery

    # Validate matched ISF content before context probe.
    matched = []
    token = _normalize_kernel_token(kernel_version)
    for p in symbol_jsons:
        if token and token in _normalize_kernel_token(os.path.basename(p)):
            matched.append(p)
    if matched:
        for isf_path in matched:
            ok, reason = _validate_isf_json(isf_path, kernel_version)
            if ok:
                break
            log_volatility("linux.isf.validate", isf_path, f"reason={reason}")
        else:
            return (
                "[volatility error] Linux memory detected, but symbol validation failed for matched kernel metadata. "
                "Automatic recovery could not produce a validated symbol file."
            )

    kernel_probe = _run_volatility3("linux.pslist.PsList", memory_file, [])
    if _is_runner_error(kernel_probe):
        # Single controlled retry only.
        if not autogen_attempted:
            recovery = _auto_generate_linux_isf(kernel_version, symbol_dirs)
            _LAST_LINUX_RECOVERY[memory_file] = recovery
            autogen_attempted = True
            kernel_probe = _run_volatility3("linux.pslist.PsList", memory_file, [])
    if _is_runner_error(kernel_probe):
        joined = ", ".join(symbol_dirs)
        if no_filename_match:
            return (
                "[volatility error] Linux memory detected, but symbol filename likely does not match dump kernel version. "
                f"Detected kernel: {kernel_version or 'unknown'}. "
                "Use a symbol filename containing the kernel token (for example, "
                "'6.19.14+kali-amd64.json.xz') or regenerate ISF and retry. "
                f"Checked directories: {joined}."
            )
        return (
            "[volatility error] Linux memory detected, but kernel context initialization failed "
            "(kernel.layer_name / kernel.symbol_table_name). "
            f"Detected kernel: {kernel_version or 'unknown'}. Symbol directories: {joined}. "
            "A valid matching ISF generated from vmlinux is required before plugin execution."
        )

    return ""


def get_symbol_diagnostics(memory_file: str, os_type: str):
    """
    Return symbol diagnostics that can be embedded in reports.
    """
    os_name = (os_type or "").strip().lower()
    out = {
        "os_type": os_name,
        "symbol_dirs": _resolved_symbol_dirs(),
        "symbol_json_files": [],
        "vmlinux_candidates": [],
        "kernel_version": "",
        "isfinfo_candidates": [],
        "best_match_isf": "",
        "isfinfo_raw_excerpt": "",
        "linux_recovery": _LAST_LINUX_RECOVERY.get(memory_file, {}),
    }
    if not memory_file or not os.path.exists(memory_file) or get_volatility_config().get("engine") != "3":
        return out

    if os_name == "linux":
        banner = _run_volatility3("banners.Banners", memory_file, [])
        out["kernel_version"] = _extract_linux_kernel_version(banner)
        out["vmlinux_candidates"] = _candidate_vmlinux_paths()
    out["symbol_json_files"] = _list_symbol_jsons(out["symbol_dirs"])[:50]

    isfinfo = _run_volatility3("isfinfo.IsfInfo", memory_file, [])
    if not _is_runner_error(isfinfo):
        out["isfinfo_candidates"] = _parse_isfinfo_candidates(isfinfo, os_name, out["kernel_version"])
        out["best_match_isf"] = _pick_best_isf_candidate(
            out["isfinfo_candidates"], out["kernel_version"], os_name
        )
        out["isfinfo_raw_excerpt"] = "\n".join(isfinfo.splitlines()[:30])
    else:
        out["isfinfo_raw_excerpt"] = isfinfo
    return out


def get_backend_health():
    """
    Lightweight startup health check for deterministic troubleshooting.
    """
    cfg = get_volatility_config()
    symbol_dirs = _resolved_symbol_dirs()
    symbol_jsons = _list_symbol_jsons(symbol_dirs)
    dwarf = _resolve_dwarf2json_path()
    vol3 = _vol3_command()
    vol2_script = _resolve_vol2_script(cfg.get("vol2_script", ""))
    vmlinux_candidates = _candidate_vmlinux_paths()

    checks = {
        "vol3_ready": bool(vol3),
        "vol3_command": vol3[0] if vol3 else "",
        "dwarf2json_ready": bool(dwarf),
        "dwarf2json_path": dwarf or "",
        "symbol_dirs": symbol_dirs,
        "symbol_json_count": len(symbol_jsons),
        "vmlinux_candidates": vmlinux_candidates,
        "vol2_script_ready": bool(vol2_script),
        "vol2_script_path": vol2_script or "",
    }

    issues = []
    if not checks["vol3_ready"] and not checks["vol2_script_ready"]:
        issues.append("No active Volatility backend found.")
    if checks["vol3_ready"] and not symbol_dirs:
        issues.append("No symbol directories detected for Volatility 3.")
    if checks["vol3_ready"] and len(symbol_jsons) == 0:
        issues.append("No symbol JSON files found. Linux requires ISF generated from matching vmlinux.")
    if checks["vol3_ready"] and not checks["dwarf2json_ready"]:
        issues.append("dwarf2json not found (cannot generate Linux ISF automatically).")
    if checks["vol3_ready"] and len(vmlinux_candidates) == 0:
        issues.append("No vmlinux candidate found (required for Linux ISF generation).")

    checks["status"] = "healthy" if not issues else "warning"
    checks["issues"] = issues
    return checks


def get_environment_compatibility():
    wsl_available = _has_wsl_bridge()
    is_windows = _is_windows_host()
    wsl_path = _resolve_wsl_executable()
    return {
        "host": platform.system(),
        "is_windows": is_windows,
        "is_wsl": _is_wsl_host(),
        "wsl_available": wsl_available,
        "wsl_path": wsl_path,
        "dwarf2json_path": _resolve_dwarf2json_path(),
        "vmlinux_candidates": _candidate_vmlinux_paths(),
        "linux_symbol_generation_supported": (not is_windows) or wsl_available,
    }


def _human_recovery_message(reason: str) -> str:
    if reason == "dwarf2json_not_found":
        return (
            "dwarf2json tool was not found. Install it or set VOLATILITY_DWARF2JSON to its full path "
            "(for example: C:\\tools\\dwarf2json.exe)."
        )
    if reason == "vmlinux_required_for_isf_generation":
        return (
            "Matching vmlinux was not found. Set VOLATILITY_LINUX_VMLINUX to the exact kernel debug image path."
        )
    if reason == "vmlinux_kernel_mismatch":
        return "Found vmlinux, but it does not match the dump kernel version."
    if reason == "isf_json_invalid":
        return "Generated ISF JSON is invalid."
    if reason == "isf_kernel_mismatch":
        return "Generated ISF does not match the dump kernel version."
    if reason == "missing_linux_environment":
        return (
            "Linux symbol generation requires Linux tools. Please enable WSL2 or run this feature in Linux."
        )
    if reason == "use_wsl2_or_linux_vm":
        return "Please run symbol generation in WSL2 or a Linux VM."
    return f"Linux symbol generation failed ({reason})."


def _structured_error(err_type: str, message: str, suggestion: str, reason: str, recovery=None):
    return {
        "ok": False,
        "status": "failed",
        "type": err_type,
        "reason": reason,
        "suggestion": suggestion,
        "message": message,
        "recovery": recovery or {},
    }


class SymbolGenerator:
    def generate_linux_symbols(self, dump_path):
        raise NotImplementedError


class WindowsSymbolGenerator(SymbolGenerator):
    def generate_linux_symbols(self, dump_path):
        msg = (
            "Linux symbol generation requires WSL2 or Linux environment. "
            "Please run this feature inside Ubuntu/WSL."
        )
        log_volatility("linux.isf.generate", dump_path, "missing_linux_environment")
        return _structured_error(
            err_type="LINUX_SYMBOLS_MISSING",
            message=msg,
            suggestion="Configure WSL2 or set VOLATILITY_LINUX_VMLINUX path.",
            reason="missing_linux_environment",
        )


class LinuxSymbolGenerator(SymbolGenerator):
    def generate_linux_symbols(self, dump_path):
        return _generate_linux_symbols_native(dump_path)


class WSLSymbolGenerator(SymbolGenerator):
    def generate_linux_symbols(self, dump_path):
        if not _has_wsl_bridge():
            return WindowsSymbolGenerator().generate_linux_symbols(dump_path)
        return _generate_linux_symbols_via_wsl(dump_path)


def _select_symbol_generator():
    if _is_windows_host():
        if _has_wsl_bridge():
            return WSLSymbolGenerator()
        return WindowsSymbolGenerator()
    return LinuxSymbolGenerator()


def _generate_linux_symbols_native(memory_file: str):
    if not memory_file or not os.path.isfile(memory_file):
        return _structured_error(
            err_type="LINUX_SYMBOLS_MISSING",
            message="Memory dump file not found.",
            suggestion="Load a valid memory dump path.",
            reason="dump_not_found",
        )

    banner = _run_volatility3("banners.Banners", memory_file, [])
    kernel_version = _extract_linux_kernel_version(banner)
    if not kernel_version:
        return {
            **_structured_error(
                err_type="LINUX_SYMBOLS_MISSING",
                message="Could not detect Linux kernel banner from dump.",
                suggestion="Verify dump integrity and Linux profile detection.",
                reason="kernel_banner_not_detected",
            ),
            "recovery": {"reason": "kernel_banner_not_detected"},
        }

    symbol_dirs = _resolved_symbol_dirs()
    recovery = _auto_generate_linux_isf(kernel_version, symbol_dirs)
    _LAST_LINUX_RECOVERY[memory_file] = recovery

    if recovery.get("success"):
        msg = (
            f"Linux symbols generated/available for kernel {kernel_version}: "
            f"{recovery.get('output_json', '')}"
        )
        log_volatility("linux.isf.generate", memory_file, msg)
        return {"ok": True, "status": "ok", "reason": "generated", "suggestion": "", "message": msg, "recovery": recovery}

    reason = recovery.get("reason", "unknown")
    stderr_excerpt = recovery.get("stderr_excerpt", "")
    msg = _human_recovery_message(reason)
    if stderr_excerpt:
        log_volatility("linux.isf.generate", memory_file, f"{msg} stderr={stderr_excerpt}")
    else:
        log_volatility("linux.isf.generate", memory_file, msg)
    return {
        **_structured_error(
            err_type="LINUX_SYMBOLS_MISSING",
            message=msg,
            suggestion="Configure WSL2 or set VOLATILITY_LINUX_VMLINUX path.",
            reason=reason,
        ),
        "recovery": recovery,
    }


def _generate_linux_symbols_via_wsl(memory_file: str):
    if not memory_file or not os.path.isfile(memory_file):
        return _structured_error(
            err_type="LINUX_SYMBOLS_MISSING",
            message="Memory dump file not found.",
            suggestion="Load a valid memory dump path.",
            reason="dump_not_found",
        )
    banner = _run_volatility3("banners.Banners", memory_file, [])
    kernel_version = _extract_linux_kernel_version(banner)
    if not kernel_version:
        return _structured_error(
            err_type="LINUX_SYMBOLS_MISSING",
            message="Could not detect Linux kernel banner from dump.",
            suggestion="Verify dump integrity and Linux profile detection.",
            reason="kernel_banner_not_detected",
        )

    vmlinux_paths = _candidate_vmlinux_paths()
    if not vmlinux_paths:
        return {
            **_structured_error(
                err_type="LINUX_SYMBOLS_MISSING",
                message="Linux symbol generation requires vmlinux or WSL2 setup.",
                suggestion="Configure WSL2 or set VOLATILITY_LINUX_VMLINUX path.",
                reason="vmlinux_required_for_isf_generation",
            ),
            "recovery": {"vmlinux_candidates": []},
        }

    matching_vm = ""
    for vm in vmlinux_paths:
        if _vmlinux_matches_kernel(vm, kernel_version):
            matching_vm = vm
            break
    if not matching_vm:
        return {
            **_structured_error(
                err_type="LINUX_SYMBOLS_MISSING",
                message="Matching vmlinux was not found for the dump kernel.",
                suggestion="Provide exact kernel debug image path in VOLATILITY_LINUX_VMLINUX.",
                reason="vmlinux_kernel_mismatch",
            ),
            "recovery": {"vmlinux_candidates": vmlinux_paths},
        }

    symbol_dirs = _resolved_symbol_dirs()
    target_dir = ""
    for d in symbol_dirs:
        if d.lower().endswith(os.path.join("symbols", "linux").lower()) or d.lower().endswith("linux"):
            target_dir = d
            break
    if not target_dir and symbol_dirs:
        target_dir = symbol_dirs[0]
    if not target_dir:
        return _structured_error(
            err_type="LINUX_SYMBOLS_MISSING",
            message="No symbol directory available.",
            suggestion="Ensure symbols folder exists and is writable.",
            reason="symbol_dir_not_available",
        )
    os.makedirs(target_dir, exist_ok=True)
    safe_tag = re.sub(r"[^A-Za-z0-9._+-]+", "_", kernel_version or "linux-kernel")
    out_path = os.path.join(target_dir, f"{safe_tag}.json")
    wsl_vm = _win_to_wsl_path(matching_vm)
    wsl_out = _win_to_wsl_path(out_path)

    cmd = f"dwarf2json linux --elf '{wsl_vm}' > '{wsl_out}'"
    wsl_exe = _resolve_wsl_executable() or "wsl.exe"
    proc = subprocess.run([wsl_exe, "sh", "-lc", cmd], capture_output=True, text=True)
    if proc.returncode != 0:
        stderr_excerpt = (proc.stderr or "").strip()[:1200]
        log_volatility("linux.isf.generate.wsl", memory_file, f"rc={proc.returncode} stderr={stderr_excerpt}")
        return {
            **_structured_error(
                err_type="LINUX_SYMBOLS_MISSING",
                message="WSL symbol generation failed.",
                suggestion="Check WSL distro/tools and retry.",
                reason="generation_failed",
            ),
            "recovery": {"stderr_excerpt": stderr_excerpt, "vmlinux_used": matching_vm},
        }

    ok, reason = _validate_isf_json(out_path, kernel_version)
    if not ok:
        return {
            **_structured_error(
                err_type="LINUX_SYMBOLS_MISSING",
                message=_human_recovery_message(reason),
                suggestion="Verify vmlinux and kernel match, then retry.",
                reason=reason,
            ),
            "recovery": {"output_json": out_path, "vmlinux_used": matching_vm},
        }

    msg = f"Linux symbols generated via WSL for kernel {kernel_version}: {out_path}"
    log_volatility("linux.isf.generate.wsl", memory_file, msg)
    return {
        "ok": True,
        "status": "ok",
        "reason": "generated_via_wsl",
        "suggestion": "",
        "message": msg,
        "recovery": {"output_json": out_path, "vmlinux_used": matching_vm},
    }


def generate_linux_symbols_for_dump(memory_file: str):
    """
    Explicit backend action to generate Linux ISF symbols for a dump.
    Returns structured status for UI and logs outcome to forensics log.
    """
    generator = _select_symbol_generator()
    return generator.generate_linux_symbols(memory_file)


def _parse_isfinfo_candidates(isfinfo_output: str, os_name: str, kernel_version: str):
    wanted_kernel = _normalize_kernel_token(kernel_version)
    candidates = []
    for raw in isfinfo_output.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if os_name == "linux" and "linux" not in low and "kali" not in low:
            continue
        if ".json" not in low:
            continue
        if wanted_kernel and wanted_kernel not in _normalize_kernel_token(low):
            continue
        candidates.append(line)
    # Keep report compact and deterministic.
    return candidates[:20]


def _pick_best_isf_candidate(candidates, kernel_version: str, os_name: str) -> str:
    if not candidates:
        return ""
    wanted = _normalize_kernel_token(kernel_version)
    os_tag = (os_name or "").lower()

    scored = []
    for line in candidates:
        low = line.lower()
        score = 0
        if wanted and wanted in _normalize_kernel_token(low):
            score += 5
        if os_tag and os_tag in low:
            score += 2
        # Prefer likely symbol JSON paths/entries over generic lines.
        if ".json" in low:
            score += 1
        scored.append((score, len(line), line))

    # Highest score first, then shortest line for stable readability.
    scored.sort(key=lambda x: (-x[0], x[1], x[2]))
    return scored[0][2]


def _run_volatility2(plugin, memory_file, extra_args, os_type="windows"):
    _ = os_type  # reserved for future per-OS mapping tweaks
    try:
        script = _resolve_vol2_script(get_volatility_config()["vol2_script"])
        if not script:
            return (
                "[runner error] Volatility 2: set path to vol.py (UI field or env VOLATILITY2_VOLPY). "
                "Official vol.py needs Python 2.7 — set “Python for Vol 2” in the GUI or env VOLATILITY2_PYTHON."
            )

        v2_plugin = _map_v3_plugin_to_v2(plugin)
        profile = get_volatility_config()["vol2_profile"]
        need_profile = v2_plugin not in _VOL2_PLUGINS_NO_PROFILE
        if need_profile and not profile:
            return (
                "[runner error] Volatility 2: set memory profile (e.g. Win7SP1x64). "
                "In the GUI use “Run imageinfo (Vol 2)…” and copy a line from Suggested Profile(s); "
                "or run: python vol.py -f <dump> imageinfo"
            )

        py = _vol2_python_executable()
        cmd = [py, script, "-f", memory_file]
        if profile:
            cmd.extend(["--profile", profile])
        cmd.extend(list(extra_args))
        cmd.append(v2_plugin)

        rc, stdout, stderr = _run_streaming_command(cmd, "vol2")
        if rc != 0 and stderr:
            err = stderr
            log_volatility(f"v2:{v2_plugin}", memory_file, f"rc={rc} stderr={err[:800]}")
            if "SyntaxError" in err and ("print" in err or "Missing parentheses" in err):
                err += (
                    "\n\n[hint] Volatility 2’s vol.py is Python 2 code. Point “Python for Vol 2” to "
                    "python.exe from Python 2.7 (or set VOLATILITY2_PYTHON), not Python 3."
                )
            return f"[volatility error] {err}"
        output = stdout
        if not output and stderr:
            warn = stderr
            log_volatility(f"v2:{v2_plugin}", memory_file, f"empty stdout stderr={warn[:800]}")
            return f"[volatility warning] {warn}"

        return output
    except Exception as exc:
        log_volatility(plugin, memory_file, f"v2 exception={exc!r}")
        return f"[runner error] {exc}"


def run_first_available(plugins, memory_file, extra_args=None, os_type="windows"):
    last_error = ""
    for plugin in plugins:
        output = run_volatility(plugin, memory_file, extra_args=extra_args, os_type=os_type)
        if not output.startswith("[volatility error]") and not output.startswith("[runner error]"):
            return output
        last_error = output
    return last_error or "[volatility error] no plugin candidates were provided"
