import os

try:
    import yara as _yara

    _YARA_IMPORT_OK = True
    _YaraSyntaxError = _yara.SyntaxError
    _YaraError = _yara.Error
except ImportError:
    _yara = None
    _YARA_IMPORT_OK = False

    class _YaraImportDummy(Exception):
        """Placeholder so except-clause types exist when yara-python is not installed."""

        pass

    _YaraSyntaxError = _YaraImportDummy
    _YaraError = _YaraImportDummy


def _yara_debug(message: str) -> None:
    """Set FORENSICS_YARA_DEBUG=1 to log rule discovery, compile, match, and errors to forensics_tool.log."""
    if not (os.environ.get("FORENSICS_YARA_DEBUG", "").strip()):
        return
    try:
        from forensics_logging import setup_forensics_logging

        setup_forensics_logging().info("yara %s", message)
    except Exception:
        pass


def _yara_version_string():
    if not _YARA_IMPORT_OK or _yara is None:
        return "n/a"
    for attr in ("YARA_VERSION", "__version__"):
        v = getattr(_yara, attr, None)
        if v:
            return str(v)
    return "unknown"


def _resolve_rule_path(rule_file: str) -> str:
    if os.path.isabs(rule_file):
        return os.path.abspath(rule_file)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(base_dir, rule_file))


def _compile_rules(resolved_rule_path: str):
    """Compile a single .yar/.yara file or all such files in a directory."""
    if os.path.isdir(resolved_rule_path):
        names = sorted(os.listdir(resolved_rule_path))
        paths = []
        for name in names:
            low = name.lower()
            if low.endswith(".yar") or low.endswith(".yara"):
                p = os.path.join(resolved_rule_path, name)
                if os.path.isfile(p):
                    paths.append(p)
        if not paths:
            raise FileNotFoundError(
                "No .yar/.yara files found under rules directory: %s" % resolved_rule_path
            )
        _yara_debug("compile_dir path=%r files=%s" % (resolved_rule_path, [os.path.basename(p) for p in paths]))
        filepaths = {"r%d" % i: p for i, p in enumerate(paths)}
        return _yara.compile(filepaths=filepaths)
    if not os.path.isfile(resolved_rule_path):
        raise FileNotFoundError("YARA rule file not found: %s" % resolved_rule_path)
    _yara_debug("compile_file path=%r" % (resolved_rule_path,))
    return _yara.compile(filepath=resolved_rule_path)


def scan_memory(memory_file, rule_file="rules.yar"):
    """
    Scan a memory image with YARA. Returns a list of yara.Match on success, or a str error message.

    Optional env:
      FORENSICS_YARA_DEBUG=1  — log compile/match stages
      YARA_SCAN_TIMEOUT=<sec> — passed to yara match() when > 0 (library-dependent)
    """
    _yara_debug(
        "scan_memory start import_ok=%s yara_lib=%s mem=%r rule=%r"
        % (_YARA_IMPORT_OK, _yara_version_string(), memory_file, rule_file)
    )
    if not _YARA_IMPORT_OK:
        return (
            "[yara] The 'yara' Python module is not installed (pip install yara-python). "
            "YARA scanning is unavailable."
        )
    try:
        if not memory_file or not os.path.isfile(memory_file):
            msg = "[yara] Memory file not found or not a regular file: %r" % (memory_file,)
            _yara_debug(msg)
            return msg

        resolved_rules = _resolve_rule_path(rule_file)
        _yara_debug("resolved_rules=%r exists=%s" % (resolved_rules, os.path.exists(resolved_rules)))
        rules = _compile_rules(resolved_rules)

        timeout_raw = (os.environ.get("YARA_SCAN_TIMEOUT", "") or "").strip()
        match_kw = {}
        if timeout_raw.isdigit() and int(timeout_raw) > 0:
            match_kw["timeout"] = int(timeout_raw)
            _yara_debug("match with timeout=%s" % match_kw["timeout"])

        _yara_debug("match start path=%r" % (memory_file,))
        matches = rules.match(memory_file, **match_kw)
        n = len(matches) if matches else 0
        _yara_debug("match done count=%s rules=%s" % (n, [m.rule for m in matches] if matches else []))
        return matches
    except _YaraSyntaxError as e:
        _yara_debug("SyntaxError: %s" % e)
        return "[yara] Rule syntax error: %s" % e
    except _YaraError as e:
        _yara_debug("yara.Error: %s" % e)
        return "[yara] %s" % e
    except Exception as e:
        _yara_debug("exception %s: %s" % (type(e).__name__, e))
        return "[yara] %s" % e


def format_yara_matches(matches):
    if isinstance(matches, str):
        return matches
    if not matches:
        return "No YARA matches found."
    try:
        return "\n".join([f"- {match.rule}" for match in matches])
    except Exception as e:
        _yara_debug("format_yara_matches error: %s" % e)
        return "[yara] Could not format match results: %s" % e
