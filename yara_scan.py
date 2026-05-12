import json
import os
from collections import defaultdict

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

_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_RULES_ROOT = os.path.join(_PROJECT_DIR, "rules")
_CONFIG_CANDIDATES = (
    os.path.join(_DEFAULT_RULES_ROOT, "yara_config.json"),
    os.path.join(_PROJECT_DIR, "yara_config.json"),
)

# (substring in path/rule, sort weight) — higher runs first in grouped output (forensic triage).
_PRIORITY_TAGS = (
    ("injection", 50),
    ("inject", 45),
    ("shellcode", 45),
    ("malleable", 40),
    ("creds", 40),
    ("credential", 40),
    ("mimikatz", 40),
    ("lsass", 40),
    ("sekurlsa", 40),
    ("dump", 35),
    ("malware", 30),
    ("trojan", 28),
    ("apt", 25),
    ("persistence", 20),
    ("phishing", 15),
)

_LAST_SCAN_STATS = {
    "rules_root": "",
    "config_path": "",
    "files_discovered": 0,
    "files_after_category_filter": 0,
    "files_compiled_ok": 0,
    "compile_failures": [],
    "categories_enabled": [],
}


def get_yara_scan_stats():
    """Metadata from the last scan_memory() call (compile failures, counts)."""
    return dict(_LAST_SCAN_STATS)


def _yara_debug(message: str) -> None:
    if not (os.environ.get("FORENSICS_YARA_DEBUG", "").strip()):
        return
    try:
        from forensics_logging import setup_forensics_logging

        setup_forensics_logging().info("yara %s", message)
    except Exception:
        pass


def _log_compile_failure(rule_path: str, err: str) -> None:
    try:
        from forensics_logging import setup_forensics_logging

        setup_forensics_logging().warning("yara_compile_fail file=%s err=%s", rule_path, err[:500])
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


def _load_yara_config():
    """Load JSON config from rules/yara_config.json or project yara_config.json."""
    cfg = {"yara_rules_path": "", "enabled_categories": []}
    chosen = ""
    for path in _CONFIG_CANDIDATES:
        if os.path.isfile(path):
            chosen = path
            try:
                with open(path, "r", encoding="utf-8") as fp:
                    merged = {**cfg, **json.load(fp)}
                cfg["yara_rules_path"] = (merged.get("yara_rules_path") or "").strip()
                cats = merged.get("enabled_categories")
                cfg["enabled_categories"] = list(cats) if isinstance(cats, list) else []
            except Exception as exc:
                _yara_debug("config_load_fail %s: %s" % (path, exc))
            break
    return cfg, chosen


def _resolve_rules_root(config):
    raw = (config.get("yara_rules_path") or "").strip()
    if raw:
        return os.path.abspath(os.path.expanduser(raw.strip('"')))
    return os.path.abspath(_DEFAULT_RULES_ROOT)


def _discover_yar_files(rules_root):
    if not os.path.isdir(rules_root):
        return []
    out = []
    skip_names = {"yara_config.json", "yara_config.example.json"}
    for root, dirs, files in os.walk(rules_root):
        dirs[:] = sorted(dirs)
        for name in sorted(files):
            if name in skip_names:
                continue
            low = name.lower()
            if low.endswith(".yar") or low.endswith(".yara"):
                p = os.path.join(root, name)
                if os.path.isfile(p):
                    out.append(os.path.abspath(p))
    legacy = os.path.join(_PROJECT_DIR, "rules.yar")
    if os.path.isfile(legacy):
        ap = os.path.abspath(legacy)
        if ap not in out:
            out.append(ap)
    return sorted(set(out))


def _category_for_rule(rule_path, rules_root):
    """Top-level folder under rules_root, or 'root' / 'project_root' for files outside the tree."""
    try:
        rel = os.path.relpath(rule_path, rules_root)
    except ValueError:
        return "project_root"
    parts = [p for p in rel.replace("\\", "/").split("/") if p and p != ".."]
    if len(parts) >= 2:
        return (parts[0] or "root").lower()
    if len(parts) == 1:
        return "root"
    return "root"


def _path_matches_enabled_categories(rule_path, rules_root, enabled_categories):
    if not enabled_categories:
        return True
    try:
        rel = os.path.relpath(rule_path, rules_root)
    except ValueError:
        return True
    parts = [p.lower() for p in rel.replace("\\", "/").split("/") if p and p != ".."]
    if not parts:
        return True
    cats = [c.strip().lower() for c in enabled_categories if str(c).strip()]
    if not cats:
        return True
    return any(p in cats for p in parts)


def _priority_score(match_dict):
    blob = " ".join(
        [
            str(match_dict.get("rule", "")),
            str(match_dict.get("rule_file", "")),
            str(match_dict.get("category", "")),
        ]
    ).lower()
    s = 0
    for tag, w in _PRIORITY_TAGS:
        if tag in blob:
            s = max(s, w)
    return s


def _string_hits_from_match(match):
    """Best-effort string hit descriptions across yara-python versions."""
    hits = []
    try:
        for s in match.strings:
            ident = getattr(s, "identifier", "?")
            for inst in getattr(s, "instances", []) or []:
                off = getattr(inst, "offset", 0)
                md = getattr(inst, "matched_data", None)
                if md is None and isinstance(inst, tuple) and len(inst) >= 2:
                    off, md = inst[0], inst[-1]
                if isinstance(md, (bytes, bytearray)):
                    preview = bytes(md[:48]).hex()
                    hits.append("%s@%s hex=%s…" % (ident, off, preview))
                else:
                    hits.append("%s@%s" % (ident, off))
                if len(hits) >= 40:
                    return hits
    except Exception:
        pass
    try:
        for tup in match.strings or []:
            if isinstance(tup, tuple) and len(tup) >= 3:
                off, ident, data = tup[0], tup[1], tup[2]
                if isinstance(data, (bytes, bytearray)):
                    hits.append("%s@%s hex=%s…" % (ident, off, bytes(data[:32]).hex()))
                else:
                    hits.append("%s@%s" % (ident, off))
            if len(hits) >= 40:
                break
    except Exception:
        pass
    return hits


def _match_to_dict(yara_match, rule_path, rules_root):
    return {
        "rule": yara_match.rule,
        "rule_file": rule_path,
        "category": _category_for_rule(rule_path, rules_root),
        "strings": _string_hits_from_match(yara_match),
        "priority_score": _priority_score(
            {"rule": yara_match.rule, "rule_file": rule_path, "category": _category_for_rule(rule_path, rules_root)}
        ),
    }


def _scan_recursive_configured(memory_file, match_kw, rules_root, enabled_categories):
    global _LAST_SCAN_STATS
    failures = []
    results = []
    all_files = _discover_yar_files(rules_root)
    filtered = [
        p
        for p in all_files
        if _path_matches_enabled_categories(p, rules_root, enabled_categories)
    ]
    _LAST_SCAN_STATS = {
        "rules_root": rules_root,
        "config_path": "",
        "files_discovered": len(all_files),
        "files_after_category_filter": len(filtered),
        "files_compiled_ok": 0,
        "compile_failures": failures,
        "categories_enabled": list(enabled_categories or []),
    }
    _yara_debug(
        "recursive_scan root=%r discovered=%s after_filter=%s"
        % (rules_root, len(all_files), len(filtered))
    )
    if not filtered:
        return results, "No .yar/.yara files matched the current filters under: %s" % rules_root

    for path in filtered:
        try:
            rules = _yara.compile(filepath=path)
            _LAST_SCAN_STATS["files_compiled_ok"] += 1
            ms = rules.match(memory_file, **match_kw)
            for m in ms or []:
                results.append(_match_to_dict(m, path, rules_root))
        except (_YaraSyntaxError, _YaraError) as e:
            err = str(e)
            failures.append({"file": path, "error": err})
            _log_compile_failure(path, err)
            _yara_debug("compile_skip path=%r err=%s" % (path, err[:200]))
        except Exception as e:
            err = "%s: %s" % (type(e).__name__, e)
            failures.append({"file": path, "error": err})
            _log_compile_failure(path, err)
            _yara_debug("compile_skip path=%r err=%s" % (path, err[:200]))

    _LAST_SCAN_STATS["compile_failures"] = list(failures)
    return results, None


def _legacy_single_file_scan(memory_file, rule_path, match_kw):
    """Single-file compile (explicit rule_file argument)."""
    global _LAST_SCAN_STATS
    if not os.path.isfile(rule_path):
        return [], "YARA rule file not found: %s" % rule_path
    failures = []
    results = []
    rules_root = os.path.dirname(os.path.abspath(rule_path))
    _LAST_SCAN_STATS = {
        "rules_root": rules_root,
        "config_path": "",
        "files_discovered": 1,
        "files_after_category_filter": 1,
        "files_compiled_ok": 0,
        "compile_failures": failures,
        "categories_enabled": [],
    }
    try:
        rules = _yara.compile(filepath=rule_path)
        _LAST_SCAN_STATS["files_compiled_ok"] = 1
        for m in rules.match(memory_file, **match_kw) or []:
            results.append(_match_to_dict(m, rule_path, rules_root))
    except Exception as e:
        err = str(e)
        failures.append({"file": rule_path, "error": err})
        _log_compile_failure(rule_path, err)
        _LAST_SCAN_STATS["compile_failures"] = failures
        return [], err
    return results, None


def scan_memory(memory_file, rule_file=None):
    """
    Scan memory with YARA.

    - rule_file is None: load ``rules/yara_config.json`` (or project ``yara_config.json``),
      recursively compile every .yar under the configured rules tree (per-file; invalid rules skipped).
    - rule_file is a path to one .yar/.yara or a directory (non-recursive flat dir kept for compatibility):
      for a directory, recursive walk is used the same as the default rules root.

    Returns a list of match dicts, or a string error message.
    """
    global _LAST_SCAN_STATS
    _yara_debug(
        "scan_memory start import_ok=%s lib=%s mem=%r rule_file=%r"
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

        timeout_raw = (os.environ.get("YARA_SCAN_TIMEOUT", "") or "").strip()
        match_kw = {}
        if timeout_raw.isdigit() and int(timeout_raw) > 0:
            match_kw["timeout"] = int(timeout_raw)
            _yara_debug("match timeout=%s" % match_kw["timeout"])

        if rule_file is not None and str(rule_file).strip():
            resolved = (
                os.path.abspath(os.path.expanduser(str(rule_file).strip().strip('"')))
                if os.path.isabs(str(rule_file).strip())
                else os.path.abspath(os.path.join(_PROJECT_DIR, str(rule_file).strip()))
            )
            if os.path.isfile(resolved):
                results, err = _legacy_single_file_scan(memory_file, resolved, match_kw)
                if err and not results:
                    return "[yara] %s" % err
                return _sort_match_dicts(results)
            if os.path.isdir(resolved):
                results, _ = _scan_recursive_configured(memory_file, match_kw, resolved, [])
                return _sort_match_dicts(results)
            return "[yara] Rule path not found: %s" % resolved

        cfg, cfg_path = _load_yara_config()
        rules_root = _resolve_rules_root(cfg)
        enabled = cfg.get("enabled_categories") or []
        if not os.path.isdir(rules_root):
            return "[yara] Rules directory does not exist: %s" % rules_root

        results, hint = _scan_recursive_configured(memory_file, match_kw, rules_root, enabled)
        _LAST_SCAN_STATS["config_path"] = cfg_path
        if isinstance(hint, str) and not results:
            return "[yara] %s" % hint
        _yara_debug("match total_hits=%s compile_failures=%s" % (len(results), len(_LAST_SCAN_STATS.get("compile_failures", []))))
        return _sort_match_dicts(results)
    except _YaraSyntaxError as e:
        _yara_debug("SyntaxError: %s" % e)
        return "[yara] Rule syntax error: %s" % e
    except _YaraError as e:
        _yara_debug("yara.Error: %s" % e)
        return "[yara] %s" % e
    except Exception as e:
        _yara_debug("exception %s: %s" % (type(e).__name__, e))
        return "[yara] %s" % e


def _sort_match_dicts(results):
    if not results:
        return results
    return sorted(
        results,
        key=lambda m: (-int(m.get("priority_score", 0)), m.get("category", ""), m.get("rule", "")),
    )


def _yara_rule_label(item):
    if isinstance(item, dict):
        return item.get("rule") or ""
    return getattr(item, "rule", str(item))


def format_yara_matches(matches):
    if isinstance(matches, str):
        return matches
    if not matches:
        return "No YARA matches found."
    try:
        if isinstance(matches[0], dict):
            groups = defaultdict(list)
            for m in matches:
                groups[m.get("category") or "unknown"].append(m)
            lines = []
            for cat in sorted(
                groups.keys(),
                key=lambda c: (
                    -max((int(x.get("priority_score", 0)) for x in groups[c]), default=0),
                    c,
                ),
            ):
                lines.append("== %s ==" % cat.upper())
                for m in sorted(groups[cat], key=lambda x: (-int(x.get("priority_score", 0)), x.get("rule", ""))):
                    lines.append("  Rule: %s" % m.get("rule", ""))
                    lines.append("  File: %s" % m.get("rule_file", ""))
                    strs = m.get("strings") or []
                    if strs:
                        lines.append("  Strings:")
                        for s in strs[:12]:
                            lines.append("    - %s" % s)
                        if len(strs) > 12:
                            lines.append("    … (%s more)" % (len(strs) - 12))
                    lines.append("")
            return "\n".join(lines).strip()
        return "\n".join([f"- {_yara_rule_label(match)}" for match in matches])
    except Exception as e:
        _yara_debug("format_yara_matches error: %s" % e)
        return "[yara] Could not format match results: %s" % e
