import os
import shutil
import subprocess
import sys

from forensics_logging import log_volatility

# --- Global runtime config (GUI/CLI set before analysis) ---
_ENGINE = "3"  # "3" or "2"
_VOL2_PROFILE = ""
_VOL2_SCRIPT = ""  # path to vol.py (Volatility 2)
_VOL2_PYTHON = ""  # path to python.exe for Vol2 (usually Python 2.7)

# Volatility 2 plugins that typically run without --profile
_VOL2_PLUGINS_NO_PROFILE = frozenset({"imageinfo", "kdbgscan", "kpcrscan"})

# Map Volatility 3 dotted plugin names -> Volatility 2 CLI plugin names
_V3_TO_V2 = {
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


def set_volatility_config(engine="3", vol2_profile="", vol2_script="", vol2_python=""):
    """engine: '3' or '2'. For Vol2, set vol2_script (path to vol.py) and usually vol2_profile."""
    global _ENGINE, _VOL2_PROFILE, _VOL2_SCRIPT, _VOL2_PYTHON
    _ENGINE = "2" if str(engine).strip() in ("2", "vol2", "volatility2") else "3"
    _VOL2_PROFILE = (vol2_profile or "").strip()
    _VOL2_SCRIPT = (vol2_script or "").strip()
    _VOL2_PYTHON = (vol2_python or "").strip()


def get_volatility_config():
    return {
        "engine": _ENGINE,
        "vol2_profile": _VOL2_PROFILE,
        "vol2_script": _VOL2_SCRIPT,
        "vol2_python": _VOL2_PYTHON,
    }


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
    key = plugin.strip()
    if key in _V3_TO_V2:
        return _V3_TO_V2[key]
    if "." in key:
        family, name = key.split(".", 1)
        if family == "windows":
            return name
        if family == "linux":
            return f"linux_{name}"
        if family == "mac":
            return f"mac_{name}"
    return key


def run_volatility(plugin, memory_file, extra_args=None, os_type="windows"):
    """
    Run a Volatility 3-style plugin name (e.g. windows.pslist).
    When engine is 2, the name is translated to a Vol2 plugin and executed with vol.py.
    """
    extra_args = extra_args or []
    cfg = get_volatility_config()

    if cfg["engine"] == "2":
        return _run_volatility2(plugin, memory_file, extra_args, os_type=os_type)
    return _run_volatility3(plugin, memory_file, extra_args)


def _run_volatility3(plugin, memory_file, extra_args):
    try:
        vol_cmd = _vol3_command()
        if not vol_cmd:
            return "[runner error] Volatility 3 executable not found. Install volatility3 or add `vol` to PATH."
        cmd = vol_cmd + ["-f", memory_file, plugin] + list(extra_args)
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0 and result.stderr.strip():
            err = result.stderr.strip()
            log_volatility(plugin, memory_file, f"rc={result.returncode} stderr={err[:800]}")
            return f"[volatility error] {err}"

        output = result.stdout.strip()
        if not output and result.stderr.strip():
            warn = result.stderr.strip()
            log_volatility(plugin, memory_file, f"empty stdout stderr={warn[:800]}")
            return f"[volatility warning] {warn}"

        return output
    except Exception as exc:
        log_volatility(plugin, memory_file, f"exception={exc!r}")
        return f"[runner error] {exc}"


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

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0 and result.stderr.strip():
            err = result.stderr.strip()
            log_volatility(f"v2:{v2_plugin}", memory_file, f"rc={result.returncode} stderr={err[:800]}")
            if "SyntaxError" in err and ("print" in err or "Missing parentheses" in err):
                err += (
                    "\n\n[hint] Volatility 2’s vol.py is Python 2 code. Point “Python for Vol 2” to "
                    "python.exe from Python 2.7 (or set VOLATILITY2_PYTHON), not Python 3."
                )
            return f"[volatility error] {err}"

        output = result.stdout.strip()
        if not output and result.stderr.strip():
            warn = result.stderr.strip()
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
